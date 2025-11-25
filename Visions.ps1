#requires -version 5.1

<#
.SYNOPSIS
    Network Path Tracer - Analyzes device configs and visualizes network paths
.DESCRIPTION
    Pure PowerShell + WPF tool that parses network device configurations,
    infers topology, and provides interactive path tracing visualization.
    No external modules required - uses only native Windows components.
.PARAMETER ConfigPath
    Path to directory containing device configuration files
.EXAMPLE
    .\NetworkPathTracer.ps1 -ConfigPath "C:\NetworkConfigs"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = $null
)

# Add required assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

#region Data Classes

class NetworkInterface {
    [string]$Name
    [string]$IPAddress
    [string]$SubnetMask
    [string]$Description
    [string]$Status = "up"
    [int]$CIDR
    [string]$Network
    [string]$VRF = "global"
    [string]$ACL_In
    [string]$ACL_Out
    [string]$ServicePolicy_In
    [string]$ServicePolicy_Out
    [bool]$NATInside
    [bool]$NATOutside

    NetworkInterface([string]$name) {
        $this.Name = $name
    }
}

class Route {
    [string]$Destination
    [string]$Mask
    [string]$NextHop
    [int]$Metric = 0
    [string]$Protocol
    [string]$ExitInterface
    [string]$VRF = "global"
    [int]$AdminDistance = 1  # Default for static routes

    Route([string]$dest, [string]$mask, [string]$nextHop) {
        $this.Destination = $dest
        $this.Mask = $mask
        $this.NextHop = $nextHop
    }
}

class NetworkDevice {
    [string]$Hostname
    [string]$DeviceType = "Unknown"
    [string]$Vendor = "Cisco"
    [string]$Model
    [hashtable]$Interfaces = @{}
    [System.Collections.ArrayList]$Routes = @()
    [hashtable]$CDPNeighbors = @{}
    [string]$ConfigContent
    [double]$X = 0
    [double]$Y = 0
    [hashtable]$ACLs = @{}  # Name -> ACL object
    [System.Collections.ArrayList]$NATRules = @()
    [hashtable]$QoSClassMaps = @{}  # Name -> QoSClassMap
    [hashtable]$QoSPolicyMaps = @{}  # Name -> QoSPolicyMap
    [System.Collections.ArrayList]$BGPNeighbors = @()
    [hashtable]$BGPNetworks = @{}  # Network/CIDR -> VRF (BGP originated routes)
    [hashtable]$OSPFProcesses = @{}  # ProcessID -> OSPFProcess
    [int]$BGP_ASN = 0
    [string]$BGP_RouterID
    [bool]$BGPRedistributeConnected = $false
    [bool]$BGPRedistributeStatic = $false
    [System.Collections.ArrayList]$ManualRoutes = @()  # User-added routes via UI

    NetworkDevice([string]$hostname) {
        $this.Hostname = $hostname
    }
}

class Connection {
    [NetworkDevice]$Device1
    [NetworkDevice]$Device2
    [string]$Interface1
    [string]$Interface2
    [string]$ConnectionType = "L3" # L3, CDP, WAN

    Connection([NetworkDevice]$dev1, [NetworkDevice]$dev2) {
        $this.Device1 = $dev1
        $this.Device2 = $dev2
    }
}

class ACLEntry {
    [int]$Sequence
    [string]$Action  # permit, deny
    [string]$Protocol  # ip, tcp, udp, icmp, etc.
    [string]$SourceIP
    [string]$SourceWildcard
    [string]$DestIP
    [string]$DestWildcard
    [string]$SourcePort
    [string]$DestPort
    [string]$RawLine

    ACLEntry([int]$seq, [string]$action, [string]$line) {
        $this.Sequence = $seq
        $this.Action = $action
        $this.RawLine = $line
    }
}

class ACL {
    [string]$Name
    [string]$Type  # standard, extended
    [System.Collections.ArrayList]$Entries = @()

    ACL([string]$name, [string]$type) {
        $this.Name = $name
        $this.Type = $type
    }
}

class NATRule {
    [string]$Type  # static, dynamic, pat
    [string]$InsideLocal
    [string]$InsideGlobal
    [string]$OutsideLocal
    [string]$OutsideGlobal
    [string]$Interface
    [string]$ACL
    [string]$Pool
    [bool]$Overload

    NATRule([string]$type) {
        $this.Type = $type
    }
}

class QoSClassMap {
    [string]$Name
    [string]$MatchType  # match-any, match-all
    [System.Collections.ArrayList]$MatchCriteria = @()

    QoSClassMap([string]$name) {
        $this.Name = $name
    }
}

class QoSPolicyMap {
    [string]$Name
    [hashtable]$Classes = @{}  # ClassName -> Actions

    QoSPolicyMap([string]$name) {
        $this.Name = $name
    }
}

class BGPNeighbor {
    [string]$IPAddress
    [int]$RemoteAS
    [string]$Description
    [string]$VRF = "global"
    [bool]$RouteReflectorClient
    [string]$UpdateSource

    BGPNeighbor([string]$ip, [int]$asn) {
        $this.IPAddress = $ip
        $this.RemoteAS = $asn
    }
}

class OSPFProcess {
    [int]$ProcessID
    [string]$RouterID
    [string]$VRF = "global"
    [hashtable]$Networks = @{}  # Network -> Area
    [System.Collections.ArrayList]$PassiveInterfaces = @()

    OSPFProcess([int]$processId) {
        $this.ProcessID = $processId
    }
}

#endregion

#region Config Parsers

function Parse-CiscoConfig {
    param([string]$Content, [string]$Filename)

    $device = [NetworkDevice]::new("Unknown")
    $device.ConfigContent = $Content
    $device.Vendor = "Cisco"

    # Pre-compile regex patterns for performance
    $rxHostname = [regex]'^hostname\s+(.+)$'
    $rxInterface = [regex]'^interface\s+(.+)$'
    $rxIpAddress = [regex]'^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)'
    $rxDescription = [regex]'^\s*description\s+(.+)$'
    $rxShutdown = [regex]'^\s*shutdown\s*$'
    $rxNoShutdown = [regex]'^\s*no shutdown\s*$'
    $rxVrfForwarding = [regex]'^\s*vrf forwarding\s+(.+)$'
    $rxIpVrfForwarding = [regex]'^\s*ip vrf forwarding\s+(.+)$'
    $rxStaticRoute = [regex]'^ip route\s+(?:vrf\s+(\S+)\s+)?(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)(?:\s+(\d+))?'
    $rxOspf = [regex]'^router ospf'
    $rxTunnelInterface = [regex]'^(Tunnel|Loopback|Virtual-Template)'

    # ACL patterns
    $rxACLStandard = [regex]'^ip access-list standard\s+(.+)$'
    $rxACLExtended = [regex]'^ip access-list extended\s+(.+)$'
    $rxACLEntry = [regex]'^\s*(permit|deny)\s+(.+)$'
    $rxACLGroup = [regex]'^\s*ip access-group\s+(\S+)\s+(in|out)'

    # NAT patterns
    $rxNATInside = [regex]'^\s*ip nat inside\s*$'
    $rxNATOutside = [regex]'^\s*ip nat outside\s*$'
    $rxNATStatic = [regex]'^ip nat inside source static\s+(\S+)\s+(\S+)'
    $rxNATPAT = [regex]'^ip nat inside source list\s+(\S+)\s+interface\s+(\S+)\s+overload'

    # QoS patterns
    $rxClassMap = [regex]'^class-map\s+(?:match-(\w+)\s+)?(.+)$'
    $rxPolicyMap = [regex]'^policy-map\s+(.+)$'
    $rxServicePolicy = [regex]'^\s*service-policy\s+(input|output)\s+(.+)$'

    # BGP patterns
    $rxBGP = [regex]'^router bgp\s+(\d+)'
    $rxBGPRouterID = [regex]'^\s*bgp router-id\s+(\d+\.\d+\.\d+\.\d+)'
    $rxBGPNeighbor = [regex]'^\s*neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+remote-as\s+(\d+)'
    $rxBGPNetwork = [regex]'^\s*network\s+(\d+\.\d+\.\d+\.\d+)(?:\s+mask\s+(\d+\.\d+\.\d+\.\d+))?'
    $rxBGPRedistribute = [regex]'^\s*redistribute\s+(connected|static|ospf|rip)'

    # OSPF patterns
    $rxOSPFProcess = [regex]'^router ospf\s+(\d+)(?:\s+vrf\s+(\S+))?'
    $rxOSPFRouterID = [regex]'^\s*router-id\s+(\d+\.\d+\.\d+\.\d+)'
    $rxOSPFNetwork = [regex]'^\s*network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+area\s+(\S+)'
    $rxOSPFPassive = [regex]'^\s*passive-interface\s+(.+)$'

    $lines = $Content -split "`n"
    $currentInterface = $null
    $currentVRF = "global"
    $currentACL = $null
    $currentACLSeq = 10
    $currentQoSClassMap = $null
    $currentQoSPolicyMap = $null
    $currentQoSClass = $null
    $currentBGP = $false
    $currentBGPVRF = "global"
    $currentOSPF = $null

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()

        # Parse hostname
        $m = $rxHostname.Match($line)
        if ($m.Success) {
            $device.Hostname = $m.Groups[1].Value.Trim()
            continue
        }

        # Parse interface
        $m = $rxInterface.Match($line)
        if ($m.Success) {
            $ifaceName = $m.Groups[1].Value.Trim()
            $currentInterface = [NetworkInterface]::new($ifaceName)
            $currentInterface.VRF = $currentVRF  # Inherit current VRF context
            $device.Interfaces[$ifaceName] = $currentInterface

            # Determine device type from interfaces (tentative - may be overridden later)
            # Note: Don't assume physical interfaces = router, both routers and switches have them
            if ($ifaceName -match '^Vlan') {
                # Vlan interfaces indicate a switch (tentative)
                if ($device.DeviceType -eq "Unknown") {
                    $device.DeviceType = "Switch"
                }
            }
            if ($rxTunnelInterface.IsMatch($ifaceName)) {
                $device.DeviceType = "Router"  # Tunnel = definitely router
            }
            continue
        }

        # Parse VRF forwarding (newer syntax)
        if ($currentInterface) {
            $m = $rxVrfForwarding.Match($line)
            if ($m.Success) {
                $currentInterface.VRF = $m.Groups[1].Value.Trim()
                continue
            }

            # Parse VRF forwarding (older syntax)
            $m = $rxIpVrfForwarding.Match($line)
            if ($m.Success) {
                $currentInterface.VRF = $m.Groups[1].Value.Trim()
                continue
            }
        }

        # Parse IP address
        if ($currentInterface) {
            $m = $rxIpAddress.Match($line)
            if ($m.Success) {
                $ip = $m.Groups[1].Value
                $mask = $m.Groups[2].Value

                # Validate IP and mask
                if ((Test-ValidIPAddress -IP $ip) -and (Test-ValidSubnetMask -Mask $mask)) {
                    $currentInterface.IPAddress = $ip
                    $currentInterface.SubnetMask = $mask
                    $currentInterface.CIDR = ConvertTo-CIDR -SubnetMask $mask
                    $currentInterface.Network = Get-NetworkAddress -IP $ip -Mask $mask
                }
                else {
                    Write-Warning "Invalid IP/Mask on $($device.Hostname) $($currentInterface.Name): $ip $mask"
                }
                continue
            }
        }

        # Parse interface description
        if ($currentInterface) {
            $m = $rxDescription.Match($line)
            if ($m.Success) {
                $currentInterface.Description = $m.Groups[1].Value.Trim()
                continue
            }
        }

        # Parse no shutdown (interface is up)
        if ($currentInterface) {
            if ($rxNoShutdown.IsMatch($line)) {
                $currentInterface.Status = "up"
                continue
            }
        }

        # Parse interface shutdown status
        if ($currentInterface) {
            if ($rxShutdown.IsMatch($line)) {
                $currentInterface.Status = "down"
                continue
            }
        }

        # Parse interface ACL bindings
        if ($currentInterface) {
            $m = $rxACLGroup.Match($line)
            if ($m.Success) {
                $aclName = $m.Groups[1].Value
                $direction = $m.Groups[2].Value
                if ($direction -eq "in") {
                    $currentInterface.ACL_In = $aclName
                } else {
                    $currentInterface.ACL_Out = $aclName
                }
                continue
            }
        }

        # Parse interface NAT inside/outside
        if ($currentInterface) {
            if ($rxNATInside.IsMatch($line)) {
                $currentInterface.NATInside = $true
                continue
            }
            if ($rxNATOutside.IsMatch($line)) {
                $currentInterface.NATOutside = $true
                continue
            }
        }

        # Parse interface QoS service policy
        if ($currentInterface) {
            $m = $rxServicePolicy.Match($line)
            if ($m.Success) {
                $direction = $m.Groups[1].Value
                $policyName = $m.Groups[2].Value.Trim()
                if ($direction -eq "input") {
                    $currentInterface.ServicePolicy_In = $policyName
                } else {
                    $currentInterface.ServicePolicy_Out = $policyName
                }
                continue
            }
        }

        # Parse static routes (with optional VRF)
        $m = $rxStaticRoute.Match($line)
        if ($m.Success) {
            $routeVRF = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { "global" }
            $destination = $m.Groups[2].Value
            $mask = $m.Groups[3].Value
            $nextHop = $m.Groups[4].Value

            # Validate before adding
            if ((Test-ValidIPAddress -IP $destination) -and (Test-ValidSubnetMask -Mask $mask)) {
                $route = [Route]::new($destination, $mask, $nextHop)
                $route.Protocol = "Static"

                if ($m.Groups[5].Success) {
                    $route.Metric = [int]$m.Groups[5].Value
                }

                # Store VRF info in ExitInterface field (we can add VRF property to Route class later)
                $route.ExitInterface = $routeVRF

                [void]$device.Routes.Add($route)
            }
            continue
        }

        # Parse ACL definitions (standard/extended)
        $m = $rxACLStandard.Match($line)
        if ($m.Success) {
            $aclName = $m.Groups[1].Value.Trim()
            $currentACL = [ACL]::new($aclName, "standard")
            $device.ACLs[$aclName] = $currentACL
            $currentACLSeq = 10
            $currentInterface = $null  # Exit interface context
            continue
        }

        $m = $rxACLExtended.Match($line)
        if ($m.Success) {
            $aclName = $m.Groups[1].Value.Trim()
            $currentACL = [ACL]::new($aclName, "extended")
            $device.ACLs[$aclName] = $currentACL
            $currentACLSeq = 10
            $currentInterface = $null
            continue
        }

        # Parse ACL entries
        if ($currentACL) {
            $m = $rxACLEntry.Match($line)
            if ($m.Success) {
                $action = $m.Groups[1].Value
                $entry = [ACLEntry]::new($currentACLSeq, $action, $line)

                # Parse extended ACL details
                $rest = $m.Groups[2].Value
                if ($rest -match '^(\S+)\s+(.+)') {
                    $entry.Protocol = $matches[1]
                    # Further parsing of source/dest could be added here
                }

                [void]$currentACL.Entries.Add($entry)
                $currentACLSeq += 10
                continue
            }
        }

        # Parse NAT rules
        $m = $rxNATStatic.Match($line)
        if ($m.Success) {
            $nat = [NATRule]::new("static")
            $nat.InsideLocal = $m.Groups[1].Value
            $nat.InsideGlobal = $m.Groups[2].Value
            [void]$device.NATRules.Add($nat)
            continue
        }

        $m = $rxNATPAT.Match($line)
        if ($m.Success) {
            $nat = [NATRule]::new("pat")
            $nat.ACL = $m.Groups[1].Value
            $nat.Interface = $m.Groups[2].Value
            $nat.Overload = $true
            [void]$device.NATRules.Add($nat)
            continue
        }

        # Parse QoS class-map
        $m = $rxClassMap.Match($line)
        if ($m.Success) {
            $matchType = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { "match-all" }
            $className = $m.Groups[2].Value.Trim()
            $currentQoSClassMap = [QoSClassMap]::new($className)
            $currentQoSClassMap.MatchType = $matchType
            $device.QoSClassMaps[$className] = $currentQoSClassMap
            $currentInterface = $null
            continue
        }

        # Parse QoS policy-map
        $m = $rxPolicyMap.Match($line)
        if ($m.Success) {
            $policyName = $m.Groups[1].Value.Trim()
            $currentQoSPolicyMap = [QoSPolicyMap]::new($policyName)
            $device.QoSPolicyMaps[$policyName] = $currentQoSPolicyMap
            $currentInterface = $null
            continue
        }

        # Parse BGP
        $m = $rxBGP.Match($line)
        if ($m.Success) {
            $device.BGP_ASN = [int]$m.Groups[1].Value
            $currentBGP = $true
            $device.DeviceType = "Router"
            $currentInterface = $null
            continue
        }

        # Parse BGP router-id
        if ($currentBGP) {
            $m = $rxBGPRouterID.Match($line)
            if ($m.Success) {
                $device.BGP_RouterID = $m.Groups[1].Value
                continue
            }
        }

        # Parse BGP neighbors
        if ($currentBGP) {
            $m = $rxBGPNeighbor.Match($line)
            if ($m.Success) {
                $neighborIP = $m.Groups[1].Value
                $remoteAS = [int]$m.Groups[2].Value
                $neighbor = [BGPNeighbor]::new($neighborIP, $remoteAS)
                $neighbor.VRF = $currentBGPVRF
                [void]$device.BGPNeighbors.Add($neighbor)
                continue
            }
        }

        # Parse BGP network statements
        if ($currentBGP) {
            $m = $rxBGPNetwork.Match($line)
            if ($m.Success) {
                $networkIP = $m.Groups[1].Value
                $networkMask = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { "255.255.255.0" }  # Default Class C if no mask

                # Calculate network address and CIDR
                $networkAddr = Get-NetworkAddress -IP $networkIP -Mask $networkMask
                $cidr = ConvertTo-CIDR -SubnetMask $networkMask
                $networkKey = "$networkAddr/$cidr"

                $device.BGPNetworks[$networkKey] = $currentBGPVRF
                continue
            }
        }

        # Parse BGP redistribute statements
        if ($currentBGP) {
            $m = $rxBGPRedistribute.Match($line)
            if ($m.Success) {
                $redistributeType = $m.Groups[1].Value
                if ($redistributeType -eq "connected") {
                    $device.BGPRedistributeConnected = $true
                }
                elseif ($redistributeType -eq "static") {
                    $device.BGPRedistributeStatic = $true
                }
                continue
            }
        }

        # Parse OSPF process
        $m = $rxOSPFProcess.Match($line)
        if ($m.Success) {
            $ospfProcessNum = [int]$m.Groups[1].Value
            $vrfName = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { "global" }
            $currentOSPF = [OSPFProcess]::new($ospfProcessNum)
            $currentOSPF.VRF = $vrfName
            $device.OSPFProcesses[$ospfProcessNum] = $currentOSPF
            $device.DeviceType = "Router"
            $currentInterface = $null
            continue
        }

        # Parse OSPF router-id
        if ($currentOSPF) {
            $m = $rxOSPFRouterID.Match($line)
            if ($m.Success) {
                $currentOSPF.RouterID = $m.Groups[1].Value
                continue
            }
        }

        # Parse OSPF network statements
        if ($currentOSPF) {
            $m = $rxOSPFNetwork.Match($line)
            if ($m.Success) {
                $network = $m.Groups[1].Value
                $wildcard = $m.Groups[2].Value
                $area = $m.Groups[3].Value
                $currentOSPF.Networks["$network/$wildcard"] = $area
                continue
            }
        }

        # Parse OSPF passive interfaces
        if ($currentOSPF) {
            $m = $rxOSPFPassive.Match($line)
            if ($m.Success) {
                $ifaceName = $m.Groups[1].Value.Trim()
                [void]$currentOSPF.PassiveInterfaces.Add($ifaceName)
                continue
            }
        }
    }

    # If no hostname found, use filename
    if ($device.Hostname -eq "Unknown") {
        $device.Hostname = [System.IO.Path]::GetFileNameWithoutExtension($Filename)
    }

    # Final device type determination based on routing capabilities
    # This overrides tentative interface-based detection
    $routingScore = 0
    $switchScore = 0

    # Check for routing protocols (STRONG router indicators)
    if ($device.BGP_ASN -gt 0) { $routingScore += 10 }  # BGP = strong indicator
    if ($device.OSPFProcesses.Count -gt 0) { $routingScore += 10 }  # OSPF = strong indicator

    # Check for multiple VRFs (VRF-aware routing)
    $vrfCount = 0
    $vrfs = @{}
    foreach ($iface in $device.Interfaces.Values) {
        if ($iface.VRF -and $iface.VRF -ne "global") {
            $vrfs[$iface.VRF] = $true
        }
    }
    $vrfCount = $vrfs.Count
    if ($vrfCount -ge 1) { $routingScore += 5 }  # VRFs = routing feature
    if ($vrfCount -ge 3) { $routingScore += 5 }  # Many VRFs = enterprise router

    # Check for tunnel interfaces (VPN/MPLS) - strong router indicator
    $hasTunnels = $false
    foreach ($iface in $device.Interfaces.Values) {
        if ($iface.Name -match '^Tunnel') {
            $hasTunnels = $true
            $routingScore += 8
            break
        }
    }

    # Check for NAT (router feature)
    if ($device.NATRules.Count -gt 0) { $routingScore += 3 }

    # Check for static routes (weak indicator - L3 switches also have routes)
    if ($device.Routes.Count -gt 5) { $routingScore += 2 }  # Only count if many routes

    # Count Vlan interfaces (STRONG switch indicator)
    $vlanCount = 0
    foreach ($iface in $device.Interfaces.Values) {
        if ($iface.Name -match '^Vlan') {
            $vlanCount++
        }
    }
    if ($vlanCount -ge 5) { $switchScore += 10 }  # Many Vlans = definitely a switch
    elseif ($vlanCount -ge 2) { $switchScore += 5 }  # Some Vlans = likely a switch

    # Determine final device type
    # Priority: Routing protocols > Switch indicators > Tentative detection
    if ($routingScore -ge 10) {
        # Has routing protocols (BGP/OSPF) = definitely a router
        $device.DeviceType = "Router"
    }
    elseif ($switchScore -ge 10 -and $routingScore -lt 10) {
        # Many Vlans and no routing protocols = definitely a switch
        $device.DeviceType = "Switch"
    }
    elseif ($routingScore -ge 8 -and $device.DeviceType -ne "Switch") {
        # Has tunnels or strong routing features = router
        $device.DeviceType = "Router"
    }
    # Otherwise: keep tentative interface-based detection

    return $device
}

function ConvertTo-CIDR {
    param([string]$SubnetMask)

    $octets = $SubnetMask -split '\.'
    $binary = ($octets | ForEach-Object { [Convert]::ToString([int]$_, 2).PadLeft(8, '0') }) -join ''
    return ($binary.ToCharArray() | Where-Object { $_ -eq '1' }).Count
}

function ConvertFrom-CIDR {
    param([int]$CIDR)

    # Create binary string with $CIDR number of 1s followed by 0s
    $binary = ('1' * $CIDR).PadRight(32, '0')

    # Convert to 4 octets
    $octets = for ($i = 0; $i -lt 32; $i += 8) {
        [Convert]::ToInt32($binary.Substring($i, 8), 2)
    }

    return $octets -join '.'
}

function Get-NetworkAddress {
    param([string]$IP, [string]$Mask)
    
    $ipOctets = $IP -split '\.'
    $maskOctets = $Mask -split '\.'
    
    $networkOctets = for ($i = 0; $i -lt 4; $i++) {
        [int]$ipOctets[$i] -band [int]$maskOctets[$i]
    }
    
    return $networkOctets -join '.'
}

function Test-ValidIPAddress {
    param([string]$IP)

    if (-not $IP) { return $false }

    try {
        $octets = $IP -split '\.'
        if ($octets.Count -ne 4) { return $false }

        foreach ($octet in $octets) {
            $num = [int]$octet
            if ($num -lt 0 -or $num -gt 255) { return $false }
        }
        return $true
    }
    catch {
        return $false
    }
}

function Test-ValidSubnetMask {
    param([string]$Mask)

    if (-not $Mask) { return $false }

    try {
        $octets = $Mask -split '\.'
        if ($octets.Count -ne 4) { return $false }

        # Convert to binary and check it's contiguous 1s followed by 0s
        $binary = ""
        foreach ($octet in $octets) {
            $num = [int]$octet
            if ($num -lt 0 -or $num -gt 255) { return $false }
            $binary += [Convert]::ToString($num, 2).PadLeft(8, '0')
        }

        # Valid mask: all 1s must come before all 0s
        if ($binary -match '^1*0*$') {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Test-SameSubnet {
    param([string]$IP1, [string]$Mask1, [string]$IP2, [string]$Mask2)

    if ($Mask1 -ne $Mask2) { return $false }

    $net1 = Get-NetworkAddress -IP $IP1 -Mask $Mask1
    $net2 = Get-NetworkAddress -IP $IP2 -Mask $Mask2

    return $net1 -eq $net2
}

#endregion

#region Analysis Functions

function Test-ACLMatch {
    param(
        [ACL]$ACL,
        [string]$SourceIP,
        [string]$DestIP,
        [string]$Protocol = "ip"
    )

    if (-not $ACL) { return @{Action="permit"; Reason="No ACL"} }

    # Simple ACL evaluation (can be extended for full match logic)
    foreach ($entry in $ACL.Entries) {
        # For now, return first matching entry
        # Full implementation would parse source/dest and match against traffic
        if ($entry.Protocol -eq $Protocol -or $entry.Protocol -eq "ip") {
            return @{
                Action = $entry.Action
                Reason = "ACL $($ACL.Name) line $($entry.Sequence)"
                Entry = $entry
            }
        }
    }

    # Implicit deny at end
    return @{Action="deny"; Reason="Implicit deny (end of ACL)"}
}

function Apply-NATTranslation {
    param(
        [NetworkDevice]$Device,
        [string]$SourceIP,
        [string]$Interface
    )

    # Check for static NAT
    foreach ($nat in $Device.NATRules) {
        if ($nat.Type -eq "static" -and $nat.InsideLocal -eq $SourceIP) {
            return @{
                Translated = $true
                NewIP = $nat.InsideGlobal
                Type = "Static NAT"
            }
        }
    }

    # Check for PAT (overload)
    foreach ($nat in $Device.NATRules) {
        if ($nat.Type -eq "pat" -and $nat.Interface -eq $Interface) {
            # Get interface IP for PAT
            $iface = $Device.Interfaces[$Interface]
            if ($iface -and $iface.IPAddress) {
                return @{
                    Translated = $true
                    NewIP = $iface.IPAddress
                    Type = "PAT (Overload)"
                }
            }
        }
    }

    return @{Translated=$false}
}

function Get-QoSMarking {
    param(
        [NetworkDevice]$Device,
        [string]$PolicyMapName,
        [string]$Protocol = "ip"
    )

    if (-not $PolicyMapName -or -not $Device.QoSPolicyMaps.ContainsKey($PolicyMapName)) {
        return @{Applied=$false}
    }

    $policyMap = $Device.QoSPolicyMaps[$PolicyMapName]

    # Simple QoS analysis - return policy exists
    return @{
        Applied = $true
        PolicyMap = $policyMap.Name
        Classes = $policyMap.Classes.Keys -join ", "
    }
}

function Build-RoutingTable {
    param(
        [NetworkDevice]$Device,
        [string]$VRF = "global",
        [System.Collections.ArrayList]$AllDevices = $null
    )

    $routingTable = @()

    # Add manual routes (highest priority, Admin Distance = 0)
    foreach ($route in $Device.ManualRoutes) {
        if ($route.VRF -eq $VRF) {
            $routingTable += @{
                Destination = $route.Destination
                Mask = $route.Mask
                NextHop = $route.NextHop
                Metric = $route.Metric
                AdminDistance = 0
                Protocol = "Manual"
                ExitInterface = $route.ExitInterface
            }
        }
    }

    # Add static routes (Admin Distance = 1)
    foreach ($route in $Device.Routes) {
        if ($route.VRF -eq $VRF -or $route.ExitInterface -eq $VRF) {
            $routingTable += @{
                Destination = $route.Destination
                Mask = $route.Mask
                NextHop = $route.NextHop
                Metric = $route.Metric
                AdminDistance = 1
                Protocol = "Static"
                ExitInterface = $route.ExitInterface
            }
        }
    }

    # Add OSPF routes (Admin Distance = 110)
    foreach ($ospfProc in $Device.OSPFProcesses.Values) {
        if ($ospfProc.VRF -eq $VRF) {
            foreach ($network in $ospfProc.Networks.Keys) {
                # OSPF-advertised networks would be learned routes
                # For now, we just note OSPF is running
                # In real implementation, would need OSPF database
            }
        }
    }

    # Add BGP routes (Admin Distance = 20 for eBGP, 200 for iBGP)
    if ($Device.BGP_ASN -gt 0) {
        # 1. Add locally originated BGP network statements
        foreach ($networkKey in $Device.BGPNetworks.Keys) {
            $networkVRF = $Device.BGPNetworks[$networkKey]
            if ($networkVRF -eq $VRF) {
                # Parse network/cidr
                if ($networkKey -match '^(.+)/(\d+)$') {
                    $network = $matches[1]
                    $cidr = [int]$matches[2]

                    # Calculate mask from CIDR
                    $mask = ConvertFrom-CIDR -CIDR $cidr

                    # Find which interface this network is on (if connected)
                    $exitIface = $null
                    foreach ($iface in $Device.Interfaces.Values) {
                        if ($iface.Network -eq $network -and $iface.CIDR -eq $cidr) {
                            $exitIface = $iface.Name
                            break
                        }
                    }

                    # Add as local BGP originated route (AD = 200 for locally originated)
                    $routingTable += @{
                        Destination = $network
                        Mask = $mask
                        NextHop = "Local"
                        Metric = 0
                        AdminDistance = 200
                        Protocol = "BGP-Local"
                        ExitInterface = $exitIface
                    }
                }
            }
        }

        # 2. Add BGP-redistributed connected routes
        if ($Device.BGPRedistributeConnected) {
            # Already added as connected routes above, but mark them as BGP candidates
        }

        # 3. Add routes learned from BGP neighbors (including iBGP)
        foreach ($neighbor in $Device.BGPNeighbors) {
            if ($neighbor.VRF -eq $VRF -or ($neighbor.VRF -eq "global" -and $VRF -eq "global")) {
                # Determine if eBGP or iBGP
                $isIBGP = ($neighbor.RemoteAS -eq $Device.BGP_ASN)
                $adminDistance = if ($isIBGP) { 200 } else { 20 }

                # For eBGP: Add default route (common WAN scenario)
                if (-not $isIBGP) {
                    $routingTable += @{
                        Destination = "0.0.0.0"
                        Mask = "0.0.0.0"
                        NextHop = $neighbor.IPAddress
                        Metric = 0
                        AdminDistance = $adminDistance
                        Protocol = "eBGP"
                        ExitInterface = $null  # Will be determined by next hop lookup
                    }
                }

                # For iBGP: Learn routes from peer's BGP networks
                if ($isIBGP -and $AllDevices) {
                    # Find the iBGP peer device
                    foreach ($peerDevice in $AllDevices) {
                        if ($peerDevice.BGP_ASN -eq $neighbor.RemoteAS) {
                            # Check if this device has the neighbor IP
                            $isPeer = $false
                            foreach ($iface in $peerDevice.Interfaces.Values) {
                                if ($iface.IPAddress -eq $neighbor.IPAddress) {
                                    $isPeer = $true
                                    break
                                }
                            }

                            if ($isPeer) {
                                # Learn all BGP networks from this iBGP peer
                                foreach ($peerNetworkKey in $peerDevice.BGPNetworks.Keys) {
                                    $peerVRF = $peerDevice.BGPNetworks[$peerNetworkKey]
                                    if ($peerVRF -eq $VRF) {
                                        # Parse network/cidr
                                        if ($peerNetworkKey -match '^(.+)/(\d+)$') {
                                            $network = $matches[1]
                                            $cidr = [int]$matches[2]
                                            $mask = ConvertFrom-CIDR -CIDR $cidr

                                            # Add as iBGP-learned route
                                            $routingTable += @{
                                                Destination = $network
                                                Mask = $mask
                                                NextHop = $neighbor.IPAddress
                                                Metric = 0
                                                AdminDistance = 200
                                                Protocol = "iBGP"
                                                ExitInterface = $null  # Will be determined by next hop lookup
                                            }
                                        }
                                    }
                                }

                                # Also learn peer's connected routes if redistribute connected
                                if ($peerDevice.BGPRedistributeConnected) {
                                    foreach ($iface in $peerDevice.Interfaces.Values) {
                                        if ($iface.VRF -eq $VRF -and $iface.IPAddress -and $iface.Network) {
                                            $routingTable += @{
                                                Destination = $iface.Network
                                                Mask = $iface.SubnetMask
                                                NextHop = $neighbor.IPAddress
                                                Metric = 0
                                                AdminDistance = 200
                                                Protocol = "iBGP-Connected"
                                                ExitInterface = $null
                                            }
                                        }
                                    }
                                }

                                # Learn peer's static routes if redistribute static
                                if ($peerDevice.BGPRedistributeStatic) {
                                    foreach ($route in $peerDevice.Routes) {
                                        if ($route.VRF -eq $VRF) {
                                            $routingTable += @{
                                                Destination = $route.Destination
                                                Mask = $route.Mask
                                                NextHop = $neighbor.IPAddress
                                                Metric = 0
                                                AdminDistance = 200
                                                Protocol = "iBGP-Static"
                                                ExitInterface = $null
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    # Add connected routes (Admin Distance = 0)
    foreach ($iface in $Device.Interfaces.Values) {
        if ($iface.VRF -eq $VRF -and $iface.IPAddress -and $iface.Status -eq "up") {
            $routingTable += @{
                Destination = $iface.Network
                Mask = $iface.SubnetMask
                NextHop = "Connected"
                Metric = 0
                AdminDistance = 0
                Protocol = "Connected"
                ExitInterface = $iface.Name
            }
        }
    }

    return $routingTable
}

function Find-BestRoute {
    param(
        [array]$RoutingTable,
        [string]$DestIP
    )

    $matchingRoutes = @()

    foreach ($route in $RoutingTable) {
        $destNetwork = Get-NetworkAddress -IP $route.Destination -Mask $route.Mask
        $testNetwork = Get-NetworkAddress -IP $DestIP -Mask $route.Mask

        if ($destNetwork -eq $testNetwork) {
            $cidr = ConvertTo-CIDR -SubnetMask $route.Mask
            $matchingRoutes += $route | Add-Member -MemberType NoteProperty -Name CIDR -Value $cidr -PassThru
        }
    }

    if ($matchingRoutes.Count -eq 0) {
        return $null
    }

    # Sort by longest prefix match (highest CIDR), then admin distance, then metric
    $bestRoute = $matchingRoutes |
        Sort-Object -Property @{Expression={$_.CIDR}; Descending=$true},
                              @{Expression={$_.AdminDistance}; Descending=$false},
                              @{Expression={$_.Metric}; Descending=$false} |
        Select-Object -First 1

    return $bestRoute
}

#endregion

#region Topology Builder

function Build-NetworkTopology {
    param([System.Collections.ArrayList]$Devices)

    $connections = @()

    # Performance optimization: Build subnet+VRF lookup hashtable (O(n) instead of O(n²))
    # Key format: "VRF:Network/CIDR" e.g., "global:10.10.10.0/24" or "CORP:10.10.10.0/24"
    $subnetMap = @{}

    Write-Host "  Building topology from interface subnets..." -ForegroundColor Cyan
    Write-Host "    Analyzing devices for connectivity..." -ForegroundColor Gray
    Write-Host "" -ForegroundColor Gray

    # First pass: collect all interface details for debugging
    $allInterfaces = @()
    foreach ($device in $Devices) {
        $deviceHasConnections = $false
        $interfacesWithIP = 0
        $interfacesWithoutSubnet = 0

        foreach ($iface in $device.Interfaces.Values) {
            # Count interfaces with IPs
            if ($iface.IPAddress) {
                $interfacesWithIP++

                # Track all interfaces for detailed output
                $allInterfaces += @{
                    Device = $device.Hostname
                    Interface = $iface.Name
                    IP = $iface.IPAddress
                    Mask = $iface.SubnetMask
                    Network = $iface.Network
                    CIDR = $iface.CIDR
                    VRF = $iface.VRF
                    HasSubnet = ($iface.Network -and $iface.SubnetMask)
                }
            }

            # Skip interfaces without IP addresses or network calculation
            if (-not $iface.IPAddress) {
                continue
            }

            if (-not $iface.Network -or -not $iface.SubnetMask) {
                $interfacesWithoutSubnet++
                Write-Host "    DEBUG: $($device.Hostname) $($iface.Name) ($($iface.IPAddress)) - missing subnet mask" -ForegroundColor DarkYellow
                continue
            }

            # Create unique key with VRF and network
            $key = "$($iface.VRF):$($iface.Network)/$($iface.CIDR)"

            if (-not $subnetMap.ContainsKey($key)) {
                $subnetMap[$key] = @()
            }

            # Store device and interface reference
            $subnetMap[$key] += @{
                Device = $device
                Interface = $iface
            }
            $deviceHasConnections = $true
        }

        # Detailed diagnostics for devices without connections
        if (-not $deviceHasConnections) {
            if ($device.Interfaces.Count -eq 0) {
                Write-Host "    WARNING: $($device.Hostname) has NO interfaces in config" -ForegroundColor Red
            }
            elseif ($interfacesWithIP -eq 0) {
                Write-Host "    WARNING: $($device.Hostname) has $($device.Interfaces.Count) interface(s) but NONE have IP addresses" -ForegroundColor Yellow
            }
            elseif ($interfacesWithoutSubnet -gt 0) {
                Write-Host "    WARNING: $($device.Hostname) has $interfacesWithIP interface(s) with IPs but ALL are missing subnet masks" -ForegroundColor Yellow
            }
        }
    }

    # Show detailed interface inventory if any interfaces found
    if ($allInterfaces.Count -gt 0) {
        Write-Host ""
        Write-Host "  Interface Inventory (for connectivity troubleshooting):" -ForegroundColor Cyan
        $validCount = ($allInterfaces | Where-Object { $_.HasSubnet }).Count
        $invalidCount = ($allInterfaces | Where-Object { -not $_.HasSubnet }).Count
        Write-Host "    Total interfaces with IPs: $($allInterfaces.Count)" -ForegroundColor Gray
        Write-Host "    Valid (with subnet): $validCount" -ForegroundColor Green
        Write-Host "    Invalid (missing subnet): $invalidCount" -ForegroundColor Yellow

        if ($invalidCount -gt 0) {
            Write-Host ""
            Write-Host "    Interfaces missing subnet masks (will NOT be connected):" -ForegroundColor Yellow
            foreach ($iface in ($allInterfaces | Where-Object { -not $_.HasSubnet })) {
                Write-Host "      $($iface.Device) - $($iface.Interface) - $($iface.IP)" -ForegroundColor DarkYellow
            }
        }
        Write-Host ""
    }

    # Now find connections only within same VRF+subnet (much faster!)
    Write-Host "    Creating connections from shared subnets..." -ForegroundColor Gray
    $isolatedCount = 0
    $connectedSubnets = 0

    foreach ($key in $subnetMap.Keys) {
        $members = $subnetMap[$key]

        # Warn about isolated subnets
        if ($members.Count -eq 1) {
            $isolatedDevice = $members[0].Device.Hostname
            $isolatedIface = $members[0].Interface.Name
            $isolatedIP = $members[0].Interface.IPAddress
            Write-Host "    ISOLATED: $isolatedDevice $isolatedIface ($isolatedIP) has no neighbors in $key" -ForegroundColor DarkGray
            $isolatedCount++
            continue
        }

        # Show connected subnet
        $deviceList = ($members | ForEach-Object { "$($_.Device.Hostname):$($_.Interface.Name)" }) -join ", "
        Write-Host "    CONNECTED: Subnet $key has $($members.Count) members: $deviceList" -ForegroundColor Green
        $connectedSubnets++

        # Create connections between all pairs in this subnet
        for ($i = 0; $i -lt $members.Count; $i++) {
            for ($j = $i + 1; $j -lt $members.Count; $j++) {
                $member1 = $members[$i]
                $member2 = $members[$j]

                # Don't connect device to itself
                if ($member1.Device.Hostname -eq $member2.Device.Hostname) { continue }

                $conn = [Connection]::new($member1.Device, $member2.Device)
                $conn.Interface1 = $member1.Interface.Name
                $conn.Interface2 = $member2.Interface.Name
                $conn.ConnectionType = "L3"
                $connections += $conn
            }
        }
    }

    Write-Host ""
    Write-Host "  Building WAN peering connections..." -ForegroundColor Cyan

    # Add connections based on BGP peering relationships
    # Create stub devices for external WAN peers we don't have configs for
    $bgpPeeringCount = 0
    $externalWANDevices = @()

    foreach ($device in $Devices) {
        if ($device.BGPNeighbors.Count -gt 0) {
            foreach ($neighbor in $device.BGPNeighbors) {
                # Find the peer device by matching an interface with the neighbor IP
                $peerDevice = $null
                foreach ($otherDevice in $Devices) {
                    if ($otherDevice.Hostname -eq $device.Hostname) { continue }

                    foreach ($iface in $otherDevice.Interfaces.Values) {
                        if ($iface.IPAddress -eq $neighbor.IPAddress) {
                            $peerDevice = $otherDevice
                            break
                        }
                    }
                    if ($peerDevice) { break }
                }

                if (-not $peerDevice) {
                    # Create external WAN device stub for this BGP peer
                    $externalDeviceName = "WAN-Peer-AS$($neighbor.RemoteAS)-$($neighbor.IPAddress -replace '\.', '-')"

                    # Check if we already created this external device
                    $peerDevice = $Devices | Where-Object { $_.Hostname -eq $externalDeviceName } | Select-Object -First 1

                    if (-not $peerDevice) {
                        $peerDevice = [NetworkDevice]::new($externalDeviceName)
                        $peerDevice.DeviceType = "External-WAN"
                        $peerDevice.BGP_ASN = $neighbor.RemoteAS

                        # Create a virtual interface on the external device
                        $virtualIface = [NetworkInterface]::new("WAN-Interface")
                        $virtualIface.IPAddress = $neighbor.IPAddress
                        # Try to determine subnet from local interface
                        foreach ($iface in $device.Interfaces.Values) {
                            if ($iface.IPAddress -and $iface.Network) {
                                if (Test-SameSubnet -IP1 $iface.IPAddress -Mask1 $iface.SubnetMask -IP2 $neighbor.IPAddress -Mask2 $iface.SubnetMask) {
                                    $virtualIface.SubnetMask = $iface.SubnetMask
                                    $virtualIface.CIDR = $iface.CIDR
                                    $virtualIface.Network = $iface.Network
                                    $virtualIface.VRF = $iface.VRF
                                    break
                                }
                            }
                        }
                        $peerDevice.Interfaces["WAN-Interface"] = $virtualIface

                        [void]$Devices.Add($peerDevice)
                        $externalWANDevices += $externalDeviceName
                        Write-Host "    Created external WAN device: $externalDeviceName (AS$($neighbor.RemoteAS))" -ForegroundColor DarkCyan
                    }
                }

                # Check if connection already exists
                $existingConn = $connections | Where-Object {
                    ($_.Device1.Hostname -eq $device.Hostname -and $_.Device2.Hostname -eq $peerDevice.Hostname) -or
                    ($_.Device2.Hostname -eq $device.Hostname -and $_.Device1.Hostname -eq $peerDevice.Hostname)
                } | Select-Object -First 1

                if (-not $existingConn) {
                    # Create BGP peering connection
                    $conn = [Connection]::new($device, $peerDevice)

                    # Find local interface
                    $localIface = $null
                    foreach ($iface in $device.Interfaces.Values) {
                        if ($iface.IPAddress -and $iface.Network) {
                            # Check if neighbor IP is in same subnet
                            if (Test-SameSubnet -IP1 $iface.IPAddress -Mask1 $iface.SubnetMask -IP2 $neighbor.IPAddress -Mask2 $iface.SubnetMask) {
                                $localIface = $iface.Name
                                break
                            }
                        }
                    }

                    $remoteIface = "WAN-Interface"
                    if ($peerDevice.DeviceType -ne "External-WAN") {
                        foreach ($iface in $peerDevice.Interfaces.Values) {
                            if ($iface.IPAddress -eq $neighbor.IPAddress) {
                                $remoteIface = $iface.Name
                                break
                            }
                        }
                    }

                    $conn.Interface1 = if ($localIface) { $localIface } else { "BGP-Peering" }
                    $conn.Interface2 = $remoteIface
                    $conn.ConnectionType = "BGP-Peering"
                    $connections += $conn
                    $bgpPeeringCount++

                    if ($peerDevice.DeviceType -eq "External-WAN") {
                        Write-Host "    BGP Peering: $($device.Hostname) (AS$($device.BGP_ASN)) <-> EXTERNAL WAN (AS$($neighbor.RemoteAS))" -ForegroundColor Magenta
                    } else {
                        Write-Host "    BGP Peering: $($device.Hostname) (AS$($device.BGP_ASN)) <-> $($peerDevice.Hostname) (AS$($neighbor.RemoteAS))" -ForegroundColor Magenta
                    }
                }
            }
        }
    }

    # Add connections based on OSPF adjacencies (if not already connected)
    $ospfAdjacencyCount = 0
    foreach ($device in $Devices) {
        if ($device.OSPFProcesses.Count -gt 0) {
            # For each OSPF-enabled interface, find potential neighbors
            foreach ($iface in $device.Interfaces.Values) {
                if (-not $iface.IPAddress -or -not $iface.Network) { continue }

                # Check if this interface is in an OSPF network
                $inOspfNetwork = $false
                foreach ($ospfProc in $device.OSPFProcesses.Values) {
                    # Check if interface is passive (no adjacencies)
                    if ($ospfProc.PassiveInterfaces -contains $iface.Name) {
                        continue
                    }

                    # Simple check: if OSPF is running and interface has IP, assume it could form adjacency
                    if ($ospfProc.Networks.Count -gt 0) {
                        $inOspfNetwork = $true
                        break
                    }
                }

                if ($inOspfNetwork) {
                    # Find other devices on the same subnet with OSPF
                    foreach ($otherDevice in $Devices) {
                        if ($otherDevice.Hostname -eq $device.Hostname) { continue }
                        if ($otherDevice.OSPFProcesses.Count -eq 0) { continue }

                        foreach ($otherIface in $otherDevice.Interfaces.Values) {
                            if (-not $otherIface.IPAddress) { continue }

                            # Check if on same subnet
                            if ($iface.Network -eq $otherIface.Network -and $iface.CIDR -eq $otherIface.CIDR -and $iface.VRF -eq $otherIface.VRF) {
                                # Check if connection already exists
                                $existingConn = $connections | Where-Object {
                                    ($_.Device1.Hostname -eq $device.Hostname -and $_.Device2.Hostname -eq $otherDevice.Hostname) -or
                                    ($_.Device2.Hostname -eq $device.Hostname -and $_.Device1.Hostname -eq $otherDevice.Hostname)
                                } | Select-Object -First 1

                                if (-not $existingConn) {
                                    $conn = [Connection]::new($device, $otherDevice)
                                    $conn.Interface1 = $iface.Name
                                    $conn.Interface2 = $otherIface.Name
                                    $conn.ConnectionType = "OSPF-Adjacency"
                                    $connections += $conn
                                    $ospfAdjacencyCount++

                                    Write-Host "    OSPF Adjacency: $($device.Hostname):$($iface.Name) <-> $($otherDevice.Hostname):$($otherIface.Name)" -ForegroundColor Cyan
                                }
                                break
                            }
                        }
                    }
                }
            }
        }
    }

    Write-Host ""
    Write-Host "  Topology Summary:" -ForegroundColor Cyan
    Write-Host "    Connected subnets: $connectedSubnets" -ForegroundColor Green
    Write-Host "    BGP peerings: $bgpPeeringCount" -ForegroundColor Magenta
    Write-Host "    OSPF adjacencies: $ospfAdjacencyCount" -ForegroundColor Cyan
    if ($externalWANDevices.Count -gt 0) {
        Write-Host "    External WAN devices created: $($externalWANDevices.Count)" -ForegroundColor DarkCyan
    }
    Write-Host "    Isolated interfaces: $isolatedCount" -ForegroundColor Yellow
    Write-Host "    Total connections created: $($connections.Count)" -ForegroundColor Green
    Write-Host "    Total devices (including external WAN): $($Devices.Count)" -ForegroundColor Gray

    return $connections
}

function Calculate-Layout {
    param([System.Collections.ArrayList]$Devices, [array]$Connections)

    # Tree-based hierarchical layout that respects network architecture
    # Routers at top, switches/devices connected to routers below them

    if ($Devices.Count -eq 0) { return }

    # Canvas dimensions
    $canvasWidth = 3000
    $canvasHeight = 2000
    $marginX = 150
    $marginY = 200
    $verticalSpacing = 350  # Space between layers

    # Build adjacency list and identify WAN links
    $adjacency = @{}
    $wanLinks = @{}  # Track WAN connections
    $lanLinks = @{}  # Track LAN connections

    foreach ($device in $Devices) {
        $adjacency[$device.Hostname] = @()
        $wanLinks[$device.Hostname] = @()
        $lanLinks[$device.Hostname] = @()
    }

    foreach ($conn in $Connections) {
        $adjacency[$conn.Device1.Hostname] += $conn.Device2
        $adjacency[$conn.Device2.Hostname] += $conn.Device1

        # Identify WAN vs LAN based on interface types
        $isWAN = $false

        # WAN interface patterns: Serial, Tunnel, Dialer, Cellular
        if ($conn.Interface1 -match '^(Serial|Tunnel|Dialer|Cellular|ATM|Frame-Relay)' -or
            $conn.Interface2 -match '^(Serial|Tunnel|Dialer|Cellular|ATM|Frame-Relay)') {
            $isWAN = $true
        }

        # Also check if devices are explicitly named as branch/remote/wan
        if (($conn.Device1.Hostname -match '(?i)(branch|remote|site)' -and
             $conn.Device2.Hostname -match '(?i)(wan|hub|hq|datacenter|core)') -or
            ($conn.Device2.Hostname -match '(?i)(branch|remote|site)' -and
             $conn.Device1.Hostname -match '(?i)(wan|hub|hq|datacenter|core)')) {
            $isWAN = $true
        }

        if ($isWAN) {
            $wanLinks[$conn.Device1.Hostname] += $conn.Device2
            $wanLinks[$conn.Device2.Hostname] += $conn.Device1
        } else {
            $lanLinks[$conn.Device1.Hostname] += $conn.Device2
            $lanLinks[$conn.Device2.Hostname] += $conn.Device1
        }
    }

    # Find root devices (core/WAN routers with routing protocols or high connectivity)
    $roots = @()
    $connectionCount = @{}
    foreach ($device in $Devices) {
        $connectionCount[$device.Hostname] = $adjacency[$device.Hostname].Count
    }

    $maxConnections = ($connectionCount.Values | Measure-Object -Maximum).Maximum

    foreach ($device in $Devices) {
        $isRoot = $false

        # Root criteria (in priority order):
        # 1. Has routing protocols (BGP/OSPF)
        if ($device.BGP_ASN -gt 0 -or $device.OSPFProcesses.Count -gt 0) {
            $isRoot = $true
        }
        # 2. Named as core/WAN/ISP/Internet
        elseif ($device.Hostname -match "(?i)(core|wan|isp|internet|backbone|mpls|transit|gateway)") {
            $isRoot = $true
        }
        # 3. Router with high connectivity (>= 80% of max)
        elseif ($device.DeviceType -eq "Router" -and $connectionCount[$device.Hostname] -ge ($maxConnections * 0.8)) {
            $isRoot = $true
        }

        if ($isRoot) {
            $roots += $device
        }
    }

    # If no roots found, pick highest connectivity routers
    if ($roots.Count -eq 0) {
        $routers = $Devices | Where-Object { $_.DeviceType -eq "Router" }
        if ($routers.Count -gt 0) {
            $roots = $routers | Sort-Object { $connectionCount[$_.Hostname] } -Descending | Select-Object -First ([Math]::Max(1, [Math]::Ceiling($routers.Count / 3)))
        } else {
            # No routers, pick highest connectivity devices
            $roots = $Devices | Sort-Object { $connectionCount[$_.Hostname] } -Descending | Select-Object -First ([Math]::Max(1, [Math]::Ceiling($Devices.Count / 4)))
        }
    }

    # Assign layers using BFS from roots (prioritize LAN connectivity)
    $deviceLayers = @{}
    $visited = @{}
    $queue = New-Object System.Collections.Queue

    # Start with roots at layer 0
    foreach ($root in $roots) {
        $deviceLayers[$root.Hostname] = 0
        $visited[$root.Hostname] = $true
        $queue.Enqueue($root.Hostname)
    }

    # BFS to assign layers - use LAN links primarily for hierarchy
    while ($queue.Count -gt 0) {
        $currentName = $queue.Dequeue()
        $currentLayer = $deviceLayers[$currentName]

        # Process LAN neighbors first (creates proper hierarchy)
        foreach ($neighbor in $lanLinks[$currentName]) {
            if (-not $visited[$neighbor.Hostname]) {
                $visited[$neighbor.Hostname] = $true
                $deviceLayers[$neighbor.Hostname] = $currentLayer + 1
                $queue.Enqueue($neighbor.Hostname)
            }
        }

        # Then process WAN neighbors (but don't create deep hierarchy for branches)
        foreach ($neighbor in $wanLinks[$currentName]) {
            if (-not $visited[$neighbor.Hostname]) {
                $visited[$neighbor.Hostname] = $true
                # WAN branches go one layer down from hub
                $deviceLayers[$neighbor.Hostname] = $currentLayer + 1
                $queue.Enqueue($neighbor.Hostname)
            }
        }
    }

    # Identify branch sites connected to same WAN hub and normalize their layers
    $wanHubs = @()
    foreach ($device in $Devices) {
        if ($wanLinks[$device.Hostname].Count -ge 2 -and
            $device.Hostname -match '(?i)(wan|hub|hq|datacenter|core|mpls)') {
            $wanHubs += $device
        }
    }

    # Group branches by their WAN hub and set them to same layer
    foreach ($hub in $wanHubs) {
        $hubLayer = $deviceLayers[$hub.Hostname]
        $branchLayer = $hubLayer + 1

        foreach ($branch in $wanLinks[$hub.Hostname]) {
            # If this is a branch site, normalize to branch layer
            if ($branch.Hostname -match '(?i)(branch|remote|site)' -or
                ($wanLinks[$branch.Hostname].Count -le 2 -and $lanLinks[$branch.Hostname].Count -le 2)) {
                $deviceLayers[$branch.Hostname] = $branchLayer
            }
        }
    }

    # Handle disconnected devices (assign to bottom layer)
    $maxLayer = 0
    if ($deviceLayers.Count -gt 0) {
        $maxLayer = ($deviceLayers.Values | Measure-Object -Maximum).Maximum
    }
    foreach ($device in $Devices) {
        if (-not $deviceLayers.ContainsKey($device.Hostname)) {
            $deviceLayers[$device.Hostname] = $maxLayer + 1
        }
    }

    # Group devices by layer
    $layers = @{}
    foreach ($device in $Devices) {
        $layer = $deviceLayers[$device.Hostname]
        if (-not $layers.ContainsKey($layer)) {
            $layers[$layer] = @()
        }
        $layers[$layer] += $device
    }

    # Position devices layer by layer
    $layerNumbers = $layers.Keys | Sort-Object
    foreach ($layerNum in $layerNumbers) {
        $devicesInLayer = $layers[$layerNum]
        $y = $marginY + ($layerNum * $verticalSpacing)

        # Limit Y to canvas bounds
        if ($y -gt $canvasHeight - $marginY) {
            $y = $canvasHeight - $marginY
        }

        if ($devicesInLayer.Count -eq 1) {
            # Single device - center it
            $devicesInLayer[0].X = $canvasWidth / 2
            $devicesInLayer[0].Y = $y
        }
        else {
            # Multiple devices - spread horizontally
            # Group by parent router if possible
            $availableWidth = $canvasWidth - (2 * $marginX)
            $spacing = $availableWidth / ($devicesInLayer.Count - 1)

            # Try to position devices near their parents (devices in layer above)
            if ($layerNum -gt 0 -and $layers.ContainsKey($layerNum - 1)) {
                $parents = $layers[$layerNum - 1]
                $positioned = @{}

                # Group branches by their WAN hub parent
                $hubGroups = @{}
                foreach ($device in $devicesInLayer) {
                    $parent = $null
                    $isWANBranch = $false

                    # Find parent (check WAN links first for branches)
                    foreach ($neighbor in $wanLinks[$device.Hostname]) {
                        if ($deviceLayers[$neighbor.Hostname] -eq ($layerNum - 1)) {
                            $parent = $neighbor
                            $isWANBranch = $true
                            break
                        }
                    }

                    # If no WAN parent, check LAN links
                    if (-not $parent) {
                        foreach ($neighbor in $lanLinks[$device.Hostname]) {
                            if ($deviceLayers[$neighbor.Hostname] -eq ($layerNum - 1)) {
                                $parent = $neighbor
                                break
                            }
                        }
                    }

                    if ($parent) {
                        $parentName = $parent.Hostname
                        if (-not $hubGroups.ContainsKey($parentName)) {
                            $hubGroups[$parentName] = @()
                        }
                        $hubGroups[$parentName] += $device
                    }
                }

                # Position each hub's children grouped together
                $currentX = $marginX
                foreach ($hubName in $hubGroups.Keys) {
                    $parent = $Devices | Where-Object { $_.Hostname -eq $hubName }
                    $children = $hubGroups[$hubName]

                    if ($children.Count -eq 1) {
                        # Single child - position under parent
                        $children[0].X = $parent.X
                        $children[0].Y = $y
                        $positioned[$children[0].Hostname] = $true
                    }
                    else {
                        # Multiple children - spread them around parent's X
                        $groupWidth = ($children.Count - 1) * 200
                        $groupStartX = $parent.X - ($groupWidth / 2)

                        for ($i = 0; $i -lt $children.Count; $i++) {
                            $children[$i].X = $groupStartX + ($i * 200)
                            $children[$i].Y = $y
                            $positioned[$children[$i].Hostname] = $true
                        }
                    }
                }

                # Position remaining devices (not connected to parent layer)
                $unpositioned = $devicesInLayer | Where-Object { -not $positioned.ContainsKey($_.Hostname) }
                if ($unpositioned.Count -gt 0) {
                    $startX = $marginX
                    foreach ($device in $unpositioned) {
                        $device.X = $startX
                        $device.Y = $y
                        $startX += $spacing
                    }
                }
            }
            else {
                # First layer or no parent layer - spread evenly
                for ($i = 0; $i -lt $devicesInLayer.Count; $i++) {
                    $devicesInLayer[$i].X = $marginX + ($i * $spacing)
                    $devicesInLayer[$i].Y = $y
                }
            }
        }
    }

    # Apply force-directed refinement (gentler, fewer iterations)
    for ($iteration = 0; $iteration -lt 3; $iteration++) {
        foreach ($device in $Devices) {
            $forceX = 0
            $myLayer = $deviceLayers[$device.Hostname]

            # Spring force: pull toward connected neighbors (X axis only)
            foreach ($neighbor in $adjacency[$device.Hostname]) {
                $neighborLayer = $deviceLayers[$neighbor.Hostname]
                # Only apply force for devices in same or adjacent layers
                if ([Math]::Abs($neighborLayer - $myLayer) -le 1) {
                    $dx = $neighbor.X - $device.X
                    $distance = [Math]::Abs($dx)
                    if ($distance -gt 0) {
                        $forceX += ($dx / $distance) * [Math]::Min($distance / 100, 1)
                    }
                }
            }

            # Repulsion force: push away from devices in same layer
            foreach ($other in $Devices) {
                if ($other.Hostname -eq $device.Hostname) { continue }
                if ($deviceLayers[$other.Hostname] -ne $myLayer) { continue }

                $dx = $device.X - $other.X
                $distance = [Math]::Abs($dx)
                $minDistance = 250
                if ($distance -gt 0 -and $distance -lt $minDistance) {
                    $forceX += ($dx / $distance) * ($minDistance - $distance) / 40
                }
            }

            # Apply force (small movement)
            $device.X += $forceX * 0.2

            # Keep within canvas bounds
            $device.X = [Math]::Max($marginX, [Math]::Min($canvasWidth - $marginX, $device.X))
        }
    }
}

#endregion

#region Path Tracing

function Test-IPInSubnet {
    param([string]$IP, [string]$Network, [string]$Mask)

    if (-not $IP -or -not $Network -or -not $Mask) { return $false }

    try {
        $ipNetwork = Get-NetworkAddress -IP $IP -Mask $Mask
        return $ipNetwork -eq $Network
    }
    catch {
        return $false
    }
}

function Find-NextHop {
    param(
        [NetworkDevice]$Device,
        [string]$DestIP,
        [array]$Connections
    )

    # Find best matching route using longest prefix match
    $bestMatch = $null
    $longestPrefix = -1

    foreach ($route in $Device.Routes) {
        if (Test-IPInSubnet -IP $DestIP -Network (Get-NetworkAddress -IP $route.Destination -Mask $route.Mask) -Mask $route.Mask) {
            $cidr = ConvertTo-CIDR -SubnetMask $route.Mask
            if ($cidr -gt $longestPrefix) {
                $longestPrefix = $cidr
                $bestMatch = $route
            }
        }
    }

    if ($bestMatch) {
        # Find next hop device via connections
        foreach ($conn in $Connections) {
            $localDevice = $null
            $remoteDevice = $null
            $localIface = $null

            if ($conn.Device1.Hostname -eq $Device.Hostname) {
                $localDevice = $conn.Device1
                $remoteDevice = $conn.Device2
                $localIface = $Device.Interfaces[$conn.Interface1]
            }
            elseif ($conn.Device2.Hostname -eq $Device.Hostname) {
                $localDevice = $conn.Device2
                $remoteDevice = $conn.Device1
                $localIface = $Device.Interfaces[$conn.Interface2]
            }

            # Check if next hop is reachable via this connection
            if ($localIface -and $localIface.IPAddress) {
                if (Test-SameSubnet -IP1 $localIface.IPAddress -Mask1 $localIface.SubnetMask -IP2 $bestMatch.NextHop -Mask2 $localIface.SubnetMask) {
                    return $remoteDevice.Hostname
                }
            }
        }
    }

    # Fallback: check if destination is directly connected
    foreach ($iface in $Device.Interfaces.Values) {
        if ($iface.IPAddress -and $iface.SubnetMask) {
            if (Test-SameSubnet -IP1 $iface.IPAddress -Mask1 $iface.SubnetMask -IP2 $DestIP -Mask2 $iface.SubnetMask) {
                # Destination is directly connected, find which device
                foreach ($conn in $Connections) {
                    if ($conn.Device1.Hostname -eq $Device.Hostname) {
                        $remoteIface = $conn.Device2.Interfaces[$conn.Interface2]
                        if ($remoteIface.IPAddress -eq $DestIP) {
                            return $conn.Device2.Hostname
                        }
                    }
                    elseif ($conn.Device2.Hostname -eq $Device.Hostname) {
                        $remoteIface = $conn.Device1.Interfaces[$conn.Interface1]
                        if ($remoteIface.IPAddress -eq $DestIP) {
                            return $conn.Device1.Hostname
                        }
                    }
                }
            }
        }
    }

    return $null
}

function Find-Path {
    param(
        [NetworkDevice]$Source,
        [NetworkDevice]$Destination,
        [System.Collections.ArrayList]$AllDevices,
        [array]$Connections
    )

    # Simple BFS path finding
    $queue = New-Object System.Collections.Queue
    $visited = @{}
    $parent = @{}

    $queue.Enqueue($Source.Hostname)
    $visited[$Source.Hostname] = $true

    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()

        if ($current -eq $Destination.Hostname) {
            # Reconstruct path
            $path = @()
            $node = $current
            while ($node) {
                $path = @($node) + $path
                $node = $parent[$node]
            }
            return $path
        }

        # Find neighbors
        $neighbors = $Connections | Where-Object {
            $_.Device1.Hostname -eq $current -or $_.Device2.Hostname -eq $current
        }

        foreach ($conn in $neighbors) {
            $neighbor = if ($conn.Device1.Hostname -eq $current) {
                $conn.Device2.Hostname
            } else {
                $conn.Device1.Hostname
            }

            if (-not $visited[$neighbor]) {
                $visited[$neighbor] = $true
                $parent[$neighbor] = $current
                $queue.Enqueue($neighbor)
            }
        }
    }

    return @() # No path found
}

function Find-RoutingPath {
    param(
        [NetworkDevice]$Source,
        [string]$SourceIP,
        [string]$DestIP,
        [System.Collections.ArrayList]$AllDevices,
        [array]$Connections,
        [int]$MaxHops = 30
    )

    <#
    .SYNOPSIS
    Finds path based on ROUTING TABLES, not just connectivity.
    Shows which interface traffic exits based on destination IP.

    .DESCRIPTION
    This simulates actual packet forwarding:
    1. Start at source device
    2. Look up destination in routing table
    3. Find next hop
    4. Determine which interface reaches next hop
    5. Move to next hop device
    6. Repeat until destination reached or loop detected
    #>

    $path = @()
    $currentDevice = $Source
    $currentIP = $SourceIP
    $hopCount = 0
    $visitedDevices = @{}
    $previousExitInterface = $null  # Track exit interface from previous hop

    while ($hopCount -lt $MaxHops) {
        $hopCount++

        # Add current device to path
        $pathHop = @{
            Device = $currentDevice
            HopNumber = $hopCount
        }

        # Determine entry interface (where traffic arrives from previous hop)
        if ($hopCount -gt 1 -and $previousExitInterface) {
            # Find the connection and get the interface on current device
            foreach ($conn in $Connections) {
                if ($conn.Device1.Hostname -eq $path[$path.Count - 1].Device.Hostname -and
                    $conn.Interface1 -eq $previousExitInterface -and
                    $conn.Device2.Hostname -eq $currentDevice.Hostname) {
                    $pathHop.EntryInterface = $conn.Interface2
                    $entryIface = $currentDevice.Interfaces[$conn.Interface2]
                    if ($entryIface) {
                        $pathHop.EntryIP = $entryIface.IPAddress
                    }
                    break
                }
                elseif ($conn.Device2.Hostname -eq $path[$path.Count - 1].Device.Hostname -and
                        $conn.Interface2 -eq $previousExitInterface -and
                        $conn.Device1.Hostname -eq $currentDevice.Hostname) {
                    $pathHop.EntryInterface = $conn.Interface1
                    $entryIface = $currentDevice.Interfaces[$conn.Interface1]
                    if ($entryIface) {
                        $pathHop.EntryIP = $entryIface.IPAddress
                    }
                    break
                }
            }
        }

        # Check if we've reached destination device
        $destinationReached = $false
        foreach ($iface in $currentDevice.Interfaces.Values) {
            if ($iface.IPAddress -eq $DestIP -or
                (Test-SameSubnet -IP1 $iface.IPAddress -Mask1 $iface.SubnetMask -IP2 $DestIP -Mask2 $iface.SubnetMask)) {
                $destinationReached = $true
                $pathHop.ExitInterface = $iface.Name
                $pathHop.ExitIP = $iface.IPAddress
                $pathHop.Reason = "Destination $DestIP is directly connected on this interface"
                break
            }
        }

        if ($destinationReached) {
            $path += $pathHop
            break
        }

        # Special handling for External-WAN devices (stubs without full routing tables)
        if ($currentDevice.DeviceType -eq "External-WAN") {
            # WAN stub devices pass traffic through - find the exit interface that leads away from where we came
            $exitInterface = $null
            $nextHopIP = $null

            # Find all interfaces that aren't the entry interface
            foreach ($iface in $currentDevice.Interfaces.Values) {
                if ($iface.Name -ne $pathHop.EntryInterface) {
                    $exitInterface = $iface
                    $nextHopIP = "WAN-Forwarded"  # Placeholder - WAN handles routing
                    $pathHop.Reason = "Traffic forwarded through WAN provider (assumed proper routing)"
                    break
                }
            }

            # If only one interface (typical for WAN stubs), find any connected device
            if (-not $exitInterface -and $currentDevice.Interfaces.Count -gt 0) {
                $exitInterface = $currentDevice.Interfaces.Values | Select-Object -First 1
                $nextHopIP = "WAN-Forwarded"
                $pathHop.Reason = "Traffic forwarded through WAN provider (assumed proper routing)"
            }

            if (-not $exitInterface) {
                $pathHop.Reason = "WAN device has no exit interface"
                $pathHop.Error = $true
                $path += $pathHop
                break
            }

            $pathHop.ExitInterface = $exitInterface.Name
            $pathHop.ExitIP = $exitInterface.IPAddress
            $pathHop.ExitVRF = if ($exitInterface.VRF) { $exitInterface.VRF } else { "global" }
            $pathHop.NextHop = "WAN-Network"
            $path += $pathHop

            # Store exit interface for next hop's entry interface tracking
            $previousExitInterface = $exitInterface.Name

            # Find next device via connection - prefer devices that aren't the previous hop
            $nextDevice = $null
            foreach ($conn in $Connections) {
                if ($conn.Device1.Hostname -eq $currentDevice.Hostname -and $conn.Interface1 -eq $exitInterface.Name) {
                    # Skip if this is going back to where we came from
                    if ($path.Count -gt 1 -and $conn.Device2.Hostname -eq $path[$path.Count - 1].Device.Hostname) {
                        continue
                    }
                    $nextDevice = $conn.Device2
                    break
                }
                elseif ($conn.Device2.Hostname -eq $currentDevice.Hostname -and $conn.Interface2 -eq $exitInterface.Name) {
                    # Skip if this is going back to where we came from
                    if ($path.Count -gt 1 -and $conn.Device1.Hostname -eq $path[$path.Count - 1].Device.Hostname) {
                        continue
                    }
                    $nextDevice = $conn.Device1
                    break
                }
            }

            if (-not $nextDevice) {
                $pathHop.Reason += " | No next device found from WAN"
                $pathHop.Error = $true
                break
            }

            # Loop detection
            if ($visitedDevices.ContainsKey($nextDevice.Hostname)) {
                $pathHop.Reason += " | ROUTING LOOP DETECTED"
                $pathHop.Error = $true
                break
            }

            $visitedDevices[$nextDevice.Hostname] = $true
            $currentDevice = $nextDevice
            continue
        }

        # Build routing table for current device (normal devices, not WAN stubs)
        # Need to determine VRF - use first interface's VRF or global
        $deviceVRF = "global"
        if ($currentDevice.Interfaces.Count -gt 0) {
            $firstIface = $currentDevice.Interfaces.Values | Select-Object -First 1
            if ($firstIface.VRF) {
                $deviceVRF = $firstIface.VRF
            }
        }

        $routingTable = Build-RoutingTable -Device $currentDevice -VRF $deviceVRF -AllDevices $AllDevices
        $bestRoute = Find-BestRoute -RoutingTable $routingTable -DestIP $DestIP

        if (-not $bestRoute) {
            $pathHop.Reason = "No route to destination $DestIP"
            $pathHop.Error = $true
            $path += $pathHop
            break
        }

        # Determine exit interface based on routing decision
        $exitInterface = $null
        $nextHopIP = $bestRoute.NextHop

        if ($bestRoute.Protocol -eq "Connected") {
            # Directly connected - use the interface from routing table
            $exitInterface = $currentDevice.Interfaces[$bestRoute.ExitInterface]
            $pathHop.Reason = "Destination is on connected subnet $($bestRoute.Destination)/$($bestRoute.Mask)"
        }
        else {
            # Need to find which interface can reach next hop
            foreach ($iface in $currentDevice.Interfaces.Values) {
                if ($iface.IPAddress -and $iface.SubnetMask) {
                    # Check if next hop is in this interface's subnet
                    if (Test-SameSubnet -IP1 $iface.IPAddress -Mask1 $iface.SubnetMask -IP2 $nextHopIP -Mask2 $iface.SubnetMask) {
                        $exitInterface = $iface
                        $pathHop.Reason = "Route to $($bestRoute.Destination)/$(ConvertTo-CIDR -SubnetMask $bestRoute.Mask) via $nextHopIP [Protocol: $($bestRoute.Protocol), AD: $($bestRoute.AdminDistance), Metric: $($bestRoute.Metric)]"
                        break
                    }
                }
            }
        }

        if (-not $exitInterface) {
            $pathHop.Reason = "Cannot find interface to reach next hop $nextHopIP"
            $pathHop.Error = $true
            $path += $pathHop
            break
        }

        $pathHop.ExitInterface = $exitInterface.Name
        $pathHop.ExitIP = $exitInterface.IPAddress
        $pathHop.ExitVRF = $exitInterface.VRF
        $pathHop.NextHop = $nextHopIP
        $path += $pathHop

        # Store exit interface for next hop's entry interface tracking
        $previousExitInterface = $exitInterface.Name

        # Find next device via connection
        $nextDevice = $null
        foreach ($conn in $Connections) {
            if ($conn.Device1.Hostname -eq $currentDevice.Hostname -and $conn.Interface1 -eq $exitInterface.Name) {
                $nextDevice = $conn.Device2
                break
            }
            elseif ($conn.Device2.Hostname -eq $currentDevice.Hostname -and $conn.Interface2 -eq $exitInterface.Name) {
                $nextDevice = $conn.Device1
                break
            }
        }

        if (-not $nextDevice) {
            $pathHop.Reason += " | No connected device found on this interface"
            $pathHop.Error = $true
            break
        }

        # Loop detection
        if ($visitedDevices.ContainsKey($nextDevice.Hostname)) {
            $pathHop.Reason += " | ROUTING LOOP DETECTED"
            $pathHop.Error = $true
            break
        }

        $visitedDevices[$nextDevice.Hostname] = $true
        $currentDevice = $nextDevice
    }

    if ($hopCount -ge $MaxHops) {
        $path[-1].Reason += " | Maximum hop count reached"
        $path[-1].Error = $true
    }

    return $path
}

function Get-ComprehensivePathAnalysis {
    param(
        [array]$Path,  # Array of device hostnames
        [System.Collections.ArrayList]$AllDevices,
        [array]$Connections,
        [string]$SourceIP = "10.10.10.100",  # Simulated source
        [string]$DestIP = "10.20.20.100"     # Simulated destination
    )

    $analysis = @()

    for ($i = 0; $i -lt $Path.Count; $i++) {
        $deviceName = $Path[$i]
        $device = $AllDevices | Where-Object { $_.Hostname -eq $deviceName }

        $hopAnalysis = @{
            HopNumber = $i + 1
            DeviceName = $deviceName
            DeviceType = $device.DeviceType
            Analysis = @()
        }

        if ($i -lt $Path.Count - 1) {
            # Find connection to next hop
            $nextDevice = $Path[$i + 1]
            $conn = $Connections | Where-Object {
                ($_.Device1.Hostname -eq $deviceName -and $_.Device2.Hostname -eq $nextDevice) -or
                ($_.Device2.Hostname -eq $deviceName -and $_.Device1.Hostname -eq $nextDevice)
            } | Select-Object -First 1

            if ($conn) {
                $exitIfaceName = if ($conn.Device1.Hostname -eq $deviceName) { $conn.Interface1 } else { $conn.Interface2 }
                $exitIface = $device.Interfaces[$exitIfaceName]

                $hopAnalysis.ExitInterface = $exitIfaceName
                $hopAnalysis.ExitIP = $exitIface.IPAddress
                $hopAnalysis.VRF = $exitIface.VRF

                # Build routing table
                $routingTable = Build-RoutingTable -Device $device -VRF $exitIface.VRF -AllDevices $AllDevices
                $bestRoute = Find-BestRoute -RoutingTable $routingTable -DestIP $DestIP

                if ($bestRoute) {
                    $hopAnalysis.Analysis += "[Routing] $($bestRoute.Protocol) route via $($bestRoute.NextHop) [AD: $($bestRoute.AdminDistance), Metric: $($bestRoute.Metric)]"
                }

                # Check outbound ACL
                if ($exitIface.ACL_Out) {
                    $acl = $device.ACLs[$exitIface.ACL_Out]
                    $aclResult = Test-ACLMatch -ACL $acl -SourceIP $SourceIP -DestIP $DestIP
                    if ($aclResult.Action -eq "deny") {
                        $hopAnalysis.Analysis += "[ACL-DENY] Outbound ACL ($($exitIface.ACL_Out)): DENIED - $($aclResult.Reason)"
                        $hopAnalysis.Blocked = $true
                    } else {
                        $hopAnalysis.Analysis += "[ACL-PERMIT] Outbound ACL ($($exitIface.ACL_Out)): PERMITTED"
                    }
                }

                # Check NAT
                if ($exitIface.NATInside -or $exitIface.NATOutside) {
                    $natResult = Apply-NATTranslation -Device $device -SourceIP $SourceIP -Interface $exitIfaceName
                    if ($natResult.Translated) {
                        $hopAnalysis.Analysis += "[NAT] $SourceIP -> $($natResult.NewIP) ($($natResult.Type))"
                        $SourceIP = $natResult.NewIP  # Update source IP for next hop
                    }
                }

                # Check QoS
                if ($exitIface.ServicePolicy_Out) {
                    $qosResult = Get-QoSMarking -Device $device -PolicyMapName $exitIface.ServicePolicy_Out
                    if ($qosResult.Applied) {
                        $hopAnalysis.Analysis += "[QoS] Policy $($qosResult.PolicyMap) applied"
                    }
                }

                # Check BGP/OSPF if configured
                if ($device.BGP_ASN -gt 0) {
                    $hopAnalysis.Analysis += "[BGP] AS$($device.BGP_ASN) configured ($($device.BGPNeighbors.Count) neighbors)"
                }
                if ($device.OSPFProcesses.Count -gt 0) {
                    $processes = $device.OSPFProcesses.Keys -join ", "
                    $hopAnalysis.Analysis += "[OSPF] Process(es): $processes"
                }
            }
        }

        $analysis += $hopAnalysis
    }

    return $analysis
}

#endregion

#region GUI

function Show-RoutingTableDialog {
    param(
        [System.Collections.ArrayList]$Devices,
        [System.Windows.Window]$ParentWindow
    )

    # Create XAML for routing table dialog
    [xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Routing Table Management" Height="600" Width="900"
    WindowStartupLocation="CenterOwner">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Device Selection -->
        <StackPanel Grid.Row="0" Background="#F0F0F0" Margin="5" Orientation="Horizontal">
            <Label Content="Device:" VerticalAlignment="Center" Margin="5"/>
            <ComboBox Name="DeviceCombo" Width="200" Margin="5" VerticalAlignment="Center"/>
            <Label Content="(Select a device to view/edit its routing table)" VerticalAlignment="Center" Margin="20,0,0,0" Foreground="Gray" FontStyle="Italic"/>
        </StackPanel>

        <!-- Routing Table Display -->
        <Border Grid.Row="1" BorderBrush="#CCCCCC" BorderThickness="1" Margin="5">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>

                <Label Grid.Row="0" Content="Routes (parsed from config + manual entries):" FontWeight="Bold" Background="#F0F0F0"/>

                <DataGrid Grid.Row="1" Name="RoutesDataGrid" AutoGenerateColumns="False"
                          CanUserAddRows="False" CanUserDeleteRows="False"
                          IsReadOnly="True" GridLinesVisibility="All">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Destination" Binding="{Binding Destination}" Width="120"/>
                        <DataGridTextColumn Header="Mask" Binding="{Binding Mask}" Width="120"/>
                        <DataGridTextColumn Header="Next Hop" Binding="{Binding NextHop}" Width="120"/>
                        <DataGridTextColumn Header="Protocol" Binding="{Binding Protocol}" Width="100"/>
                        <DataGridTextColumn Header="Metric" Binding="{Binding Metric}" Width="60"/>
                        <DataGridTextColumn Header="Admin Distance" Binding="{Binding AdminDistance}" Width="100"/>
                        <DataGridTextColumn Header="VRF" Binding="{Binding VRF}" Width="80"/>
                        <DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="100"/>
                    </DataGrid.Columns>
                </DataGrid>
            </Grid>
        </Border>

        <!-- Add Manual Route Controls -->
        <GroupBox Grid.Row="2" Header="Add Manual Route" Margin="5" Padding="10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <!-- First row -->
                <Label Grid.Row="0" Grid.Column="0" Content="Destination:" VerticalAlignment="Center" Margin="0,0,5,5"/>
                <TextBox Grid.Row="0" Grid.Column="1" Name="DestBox" Text="0.0.0.0" Margin="0,0,10,5" VerticalContentAlignment="Center"/>

                <Label Grid.Row="0" Grid.Column="2" Content="Mask:" VerticalAlignment="Center" Margin="0,0,5,5"/>
                <TextBox Grid.Row="0" Grid.Column="3" Name="MaskBox" Text="0.0.0.0" Margin="0,0,10,5" VerticalContentAlignment="Center"/>

                <Label Grid.Row="0" Grid.Column="4" Content="Next Hop:" VerticalAlignment="Center" Margin="0,0,5,5"/>
                <TextBox Grid.Row="0" Grid.Column="5" Name="NextHopBox" Text="10.0.0.1" Margin="0,0,10,5" VerticalContentAlignment="Center"/>

                <!-- Second row -->
                <Label Grid.Row="1" Grid.Column="0" Content="Metric:" VerticalAlignment="Center" Margin="0,0,5,0"/>
                <TextBox Grid.Row="1" Grid.Column="1" Name="MetricBox" Text="0" Margin="0,0,10,0" VerticalContentAlignment="Center"/>

                <Label Grid.Row="1" Grid.Column="2" Content="VRF:" VerticalAlignment="Center" Margin="0,0,5,0"/>
                <TextBox Grid.Row="1" Grid.Column="3" Name="VRFBox" Text="global" Margin="0,0,10,0" VerticalContentAlignment="Center"/>

                <Button Grid.Row="1" Grid.Column="4" Grid.ColumnSpan="2" Name="AddRouteButton" Content="Add Route" Width="120" Margin="5,0,10,0" Padding="5"/>
                <Button Grid.Row="1" Grid.Column="6" Name="DeleteSelectedButton" Content="Delete Selected" Width="120" Margin="0,0,0,0" Padding="5"/>
            </Grid>
        </GroupBox>
    </Grid>
</Window>
"@

    # Load XAML
    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $dialog = [Windows.Markup.XamlReader]::Load($reader)
    $dialog.Owner = $ParentWindow

    # Get controls
    $deviceCombo = $dialog.FindName("DeviceCombo")
    $routesDataGrid = $dialog.FindName("RoutesDataGrid")
    $destBox = $dialog.FindName("DestBox")
    $maskBox = $dialog.FindName("MaskBox")
    $nextHopBox = $dialog.FindName("NextHopBox")
    $metricBox = $dialog.FindName("MetricBox")
    $vrfBox = $dialog.FindName("VRFBox")
    $addRouteButton = $dialog.FindName("AddRouteButton")
    $deleteSelectedButton = $dialog.FindName("DeleteSelectedButton")

    # Populate device combo
    foreach ($device in $Devices) {
        [void]$deviceCombo.Items.Add($device.Hostname)
    }

    # Function to refresh routing table display
    function Refresh-RoutingTableDisplay {
        if (-not $deviceCombo.SelectedItem) {
            $routesDataGrid.ItemsSource = $null
            return
        }

        $selectedDevice = $Devices | Where-Object { $_.Hostname -eq $deviceCombo.SelectedItem }
        if (-not $selectedDevice) { return }

        # Build complete routing table for display
        $displayRoutes = @()

        # Add manual routes (highest priority)
        foreach ($route in $selectedDevice.ManualRoutes) {
            $displayRoutes += [PSCustomObject]@{
                Destination = $route.Destination
                Mask = $route.Mask
                NextHop = $route.NextHop
                Protocol = "Manual"
                Metric = $route.Metric
                AdminDistance = 0
                VRF = $route.VRF
                Source = "Manual"
            }
        }

        # Add parsed routes from config
        foreach ($route in $selectedDevice.Routes) {
            $displayRoutes += [PSCustomObject]@{
                Destination = $route.Destination
                Mask = $route.Mask
                NextHop = $route.NextHop
                Protocol = $route.Protocol
                Metric = $route.Metric
                AdminDistance = $route.AdminDistance
                VRF = $route.VRF
                Source = "Config"
            }
        }

        # Add connected routes
        foreach ($ifaceName in $selectedDevice.Interfaces.Keys) {
            $iface = $selectedDevice.Interfaces[$ifaceName]
            if ($iface.IPAddress -and $iface.Network -and $iface.Status -eq "up") {
                $displayRoutes += [PSCustomObject]@{
                    Destination = $iface.Network
                    Mask = $iface.SubnetMask
                    NextHop = "0.0.0.0"
                    Protocol = "Connected"
                    Metric = 0
                    AdminDistance = 0
                    VRF = $iface.VRF
                    Source = "Connected"
                }
            }
        }

        # Sort by destination
        $displayRoutes = $displayRoutes | Sort-Object -Property Destination,VRF
        $routesDataGrid.ItemsSource = $displayRoutes
    }

    # Device selection changed event
    $deviceCombo.Add_SelectionChanged({
        Refresh-RoutingTableDisplay
    })

    # Add route button click event
    $addRouteButton.Add_Click({
        if (-not $deviceCombo.SelectedItem) {
            [System.Windows.MessageBox]::Show("Please select a device first.", "Device Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $selectedDevice = $Devices | Where-Object { $_.Hostname -eq $deviceCombo.SelectedItem }
        if (-not $selectedDevice) { return }

        # Validate inputs
        $dest = $destBox.Text.Trim()
        $mask = $maskBox.Text.Trim()
        $nextHop = $nextHopBox.Text.Trim()
        $metric = 0
        $vrf = $vrfBox.Text.Trim()

        if ([string]::IsNullOrWhiteSpace($dest) -or [string]::IsNullOrWhiteSpace($mask) -or [string]::IsNullOrWhiteSpace($nextHop)) {
            [System.Windows.MessageBox]::Show("Please fill in all required fields (Destination, Mask, Next Hop).", "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        # Try to parse metric
        if (-not [int]::TryParse($metricBox.Text.Trim(), [ref]$metric)) {
            [System.Windows.MessageBox]::Show("Metric must be a valid integer.", "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        # Create new route
        $newRoute = [Route]::new($dest, $mask, $nextHop)
        $newRoute.Metric = $metric
        $newRoute.VRF = if ([string]::IsNullOrWhiteSpace($vrf)) { "global" } else { $vrf }
        $newRoute.Protocol = "Manual"
        $newRoute.AdminDistance = 0

        # Add to device's manual routes
        [void]$selectedDevice.ManualRoutes.Add($newRoute)

        # Refresh display
        Refresh-RoutingTableDisplay

        [System.Windows.MessageBox]::Show("Route added successfully!", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    })

    # Delete selected route button
    $deleteSelectedButton.Add_Click({
        if (-not $deviceCombo.SelectedItem) {
            [System.Windows.MessageBox]::Show("Please select a device first.", "Device Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        if (-not $routesDataGrid.SelectedItem) {
            [System.Windows.MessageBox]::Show("Please select a route to delete.", "Route Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $selectedRoute = $routesDataGrid.SelectedItem
        if ($selectedRoute.Source -ne "Manual") {
            [System.Windows.MessageBox]::Show("Only manually added routes can be deleted.", "Cannot Delete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $selectedDevice = $Devices | Where-Object { $_.Hostname -eq $deviceCombo.SelectedItem }
        if (-not $selectedDevice) { return }

        # Find and remove the route
        $routeToRemove = $null
        foreach ($route in $selectedDevice.ManualRoutes) {
            if ($route.Destination -eq $selectedRoute.Destination -and
                $route.Mask -eq $selectedRoute.Mask -and
                $route.NextHop -eq $selectedRoute.NextHop -and
                $route.VRF -eq $selectedRoute.VRF) {
                $routeToRemove = $route
                break
            }
        }

        if ($routeToRemove) {
            [void]$selectedDevice.ManualRoutes.Remove($routeToRemove)
            Refresh-RoutingTableDisplay
            [System.Windows.MessageBox]::Show("Route deleted successfully!", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })

    # Show dialog
    [void]$dialog.ShowDialog()
}

function Show-NetworkMap {
    param(
        [System.Collections.ArrayList]$Devices,
        [array]$Connections
    )
    
    # Create XAML
    [xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Network Path Tracer" Height="700" Width="1000"
    WindowStartupLocation="CenterScreen">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="200"/>
        </Grid.RowDefinitions>
        
        <!-- Toolbar -->
        <StackPanel Grid.Row="0" Background="#F0F0F0" Margin="5">
            <!-- First row: Device selection -->
            <StackPanel Orientation="Horizontal" Margin="0,5,0,5">
                <Label Content="Source Device:" VerticalAlignment="Center" Width="100"/>
                <ComboBox Name="SourceCombo" Width="150" Margin="5,0,0,0"/>
                <Label Content="Destination Device:" VerticalAlignment="Center" Margin="20,0,0,0" Width="130"/>
                <ComboBox Name="DestCombo" Width="150" Margin="5,0,0,0"/>
                <Button Name="TraceButton" Content="Trace Path" Width="100" Margin="20,0,5,0" Padding="5"/>
                <Button Name="ClearButton" Content="Clear" Width="80" Margin="5,0,0,0" Padding="5"/>
                <Button Name="ManageRoutesButton" Content="Manage Routes" Width="110" Margin="5,0,0,0" Padding="5"/>
            </StackPanel>
            <!-- Second row: Source interface/IP specification -->
            <StackPanel Orientation="Horizontal" Margin="0,0,0,5">
                <Label Content="Source Interface:" VerticalAlignment="Center" Width="100"/>
                <ComboBox Name="SourceInterfaceCombo" Width="200" Margin="5,0,0,0"/>
                <Label Content="Source IP:" VerticalAlignment="Center" Margin="10,0,0,0" Width="70"/>
                <TextBox Name="SourceIPBox" Width="120" Margin="5,0,0,0" Text="10.10.10.100" VerticalContentAlignment="Center"/>
                <CheckBox Name="UseRoutingCheckBox" Content="Use Routing Tables" VerticalAlignment="Center" Margin="20,0,0,0" IsChecked="True"/>
            </StackPanel>
            <!-- Third row: Destination interface/IP specification -->
            <StackPanel Orientation="Horizontal" Margin="0,0,0,5">
                <Label Content="Dest Interface:" VerticalAlignment="Center" Width="100"/>
                <ComboBox Name="DestInterfaceCombo" Width="200" Margin="5,0,0,0"/>
                <Label Content="Dest IP:" VerticalAlignment="Center" Margin="10,0,0,0" Width="70"/>
                <TextBox Name="DestIPBox" Width="120" Margin="5,0,0,0" Text="10.20.20.100" VerticalContentAlignment="Center"/>
            </StackPanel>
            <!-- Fourth row: Zoom and view controls -->
            <StackPanel Orientation="Horizontal" Margin="0,0,0,5">
                <Label Content="Zoom:" VerticalAlignment="Center" Width="100"/>
                <Button Name="ZoomInButton" Content="+" Width="30" Margin="5,0,2,0" Padding="5" FontWeight="Bold"/>
                <Button Name="ZoomOutButton" Content="-" Width="30" Margin="2,0,2,0" Padding="5" FontWeight="Bold"/>
                <Button Name="ZoomResetButton" Content="Reset" Width="50" Margin="2,0,5,0" Padding="5"/>
                <Label Name="ZoomLabel" Content="100%" VerticalAlignment="Center" Width="50" Margin="5,0,0,0"/>
                <CheckBox Name="FilterPathDevicesCheckBox" Content="Show only path devices" VerticalAlignment="Center" Margin="20,0,0,0" IsChecked="False"/>
                <Label Content="(Use mouse wheel or drag to pan)" VerticalAlignment="Center" Margin="20,0,0,0" Foreground="Gray" FontStyle="Italic"/>
            </StackPanel>
        </StackPanel>
        
        <!-- Canvas for network diagram -->
        <Border Grid.Row="1" BorderBrush="#CCCCCC" BorderThickness="1" Margin="5">
            <ScrollViewer Name="CanvasScroller" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto">
                <Canvas Name="NetworkCanvas" Background="White" Width="3000" Height="2000">
                    <Canvas.RenderTransform>
                        <TransformGroup>
                            <ScaleTransform x:Name="CanvasScale"/>
                            <TranslateTransform x:Name="CanvasTranslate"/>
                        </TransformGroup>
                    </Canvas.RenderTransform>
                </Canvas>
            </ScrollViewer>
        </Border>
        
        <!-- Details panel -->
        <Grid Grid.Row="2" Margin="5">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>
            <Border BorderBrush="#CCCCCC" BorderThickness="1">
                <Grid>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    <Label Grid.Row="0" Content="Path Details:" FontWeight="Bold" Background="#F0F0F0"/>
                    <TextBox Grid.Row="1" Name="DetailsBox" IsReadOnly="True" 
                             VerticalScrollBarVisibility="Auto" FontFamily="Consolas" Padding="5"/>
                </Grid>
            </Border>
        </Grid>
    </Grid>
</Window>
"@

    # Load XAML
    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)
    
    # Get controls
    $canvas = $window.FindName("NetworkCanvas")
    $canvasScroller = $window.FindName("CanvasScroller")
    $sourceCombo = $window.FindName("SourceCombo")
    $destCombo = $window.FindName("DestCombo")
    $sourceInterfaceCombo = $window.FindName("SourceInterfaceCombo")
    $destInterfaceCombo = $window.FindName("DestInterfaceCombo")
    $sourceIPBox = $window.FindName("SourceIPBox")
    $destIPBox = $window.FindName("DestIPBox")
    $useRoutingCheckBox = $window.FindName("UseRoutingCheckBox")
    $traceButton = $window.FindName("TraceButton")
    $clearButton = $window.FindName("ClearButton")
    $manageRoutesButton = $window.FindName("ManageRoutesButton")
    $filterPathDevicesCheckBox = $window.FindName("FilterPathDevicesCheckBox")
    $detailsBox = $window.FindName("DetailsBox")
    $zoomInButton = $window.FindName("ZoomInButton")
    $zoomOutButton = $window.FindName("ZoomOutButton")
    $zoomResetButton = $window.FindName("ZoomResetButton")
    $zoomLabel = $window.FindName("ZoomLabel")

    # Get canvas transform for zoom/pan
    $canvasTransform = $canvas.RenderTransform
    $canvasScale = $canvasTransform.Children[0]
    $canvasTranslate = $canvasTransform.Children[1]

    # Zoom level tracking
    $script:zoomLevel = 1.0
    $script:zoomMin = 0.1
    $script:zoomMax = 3.0
    $script:zoomStep = 0.1

    # Populate device combo boxes
    foreach ($device in $Devices) {
        [void]$sourceCombo.Items.Add($device.Hostname)
        [void]$destCombo.Items.Add($device.Hostname)
    }

    # Event handler: Populate interfaces when source device changes
    $sourceCombo.Add_SelectionChanged({
        $sourceInterfaceCombo.Items.Clear()
        $sourceIPBox.Text = ""

        if ($sourceCombo.SelectedItem) {
            $selectedDevice = $Devices | Where-Object { $_.Hostname -eq $sourceCombo.SelectedItem }

            if ($selectedDevice -and $selectedDevice.Interfaces) {
                # Add interfaces with their IPs for easy selection
                foreach ($ifaceName in $selectedDevice.Interfaces.Keys) {
                    $iface = $selectedDevice.Interfaces[$ifaceName]
                    if ($iface.IPAddress) {
                        $displayText = "$ifaceName ($($iface.IPAddress))"
                        [void]$sourceInterfaceCombo.Items.Add($displayText)
                    }
                }

                # Don't auto-select - let user choose which interface/IP they want to use as source
                # This gives more control over the source IP for the trace
            }
        }
    })

    # Event handler: Auto-fill IP when source interface is selected
    $sourceInterfaceCombo.Add_SelectionChanged({
        if ($sourceInterfaceCombo.SelectedItem -and $sourceCombo.SelectedItem) {
            $selectedDevice = $Devices | Where-Object { $_.Hostname -eq $sourceCombo.SelectedItem }

            if ($selectedDevice) {
                # Extract interface name from "InterfaceName (IP)" format
                $selectedText = $sourceInterfaceCombo.SelectedItem.ToString()
                if ($selectedText -match '^(.+?)\s+\((.+?)\)$') {
                    $ifaceName = $matches[1]
                    $ifaceIP = $matches[2]
                    $sourceIPBox.Text = $ifaceIP
                }
            }
        }
    })

    # Event handler: Populate interfaces when destination device changes
    $destCombo.Add_SelectionChanged({
        $destInterfaceCombo.Items.Clear()
        $destIPBox.Text = ""

        if ($destCombo.SelectedItem) {
            $selectedDevice = $Devices | Where-Object { $_.Hostname -eq $destCombo.SelectedItem }

            if ($selectedDevice -and $selectedDevice.Interfaces) {
                # Add interfaces with their IPs for easy selection
                foreach ($ifaceName in $selectedDevice.Interfaces.Keys) {
                    $iface = $selectedDevice.Interfaces[$ifaceName]
                    if ($iface.IPAddress) {
                        $displayText = "$ifaceName ($($iface.IPAddress))"
                        [void]$destInterfaceCombo.Items.Add($displayText)
                    }
                }

                # Don't auto-select - let user choose which interface/IP they want to trace to
                # This allows tracing to any interface on the device, not just the first one
            }
        }
    })

    # Event handler: Auto-fill IP when destination interface is selected
    $destInterfaceCombo.Add_SelectionChanged({
        if ($destInterfaceCombo.SelectedItem -and $destCombo.SelectedItem) {
            $selectedDevice = $Devices | Where-Object { $_.Hostname -eq $destCombo.SelectedItem }

            if ($selectedDevice) {
                # Extract interface name from "InterfaceName (IP)" format
                $selectedText = $destInterfaceCombo.SelectedItem.ToString()
                if ($selectedText -match '^(.+?)\s+\((.+?)\)$') {
                    $ifaceName = $matches[1]
                    $ifaceIP = $matches[2]
                    $destIPBox.Text = $ifaceIP
                }
            }
        }
    })

    # Zoom helper function
    function Set-Zoom {
        param([double]$newZoom)

        $script:zoomLevel = [Math]::Max($script:zoomMin, [Math]::Min($script:zoomMax, $newZoom))
        $canvasScale.ScaleX = $script:zoomLevel
        $canvasScale.ScaleY = $script:zoomLevel
        $zoomLabel.Content = "$([Math]::Round($script:zoomLevel * 100))%"

        # Update canvas size based on zoom
        $canvas.Width = 3000 * $script:zoomLevel
        $canvas.Height = 2000 * $script:zoomLevel
    }

    # Zoom button event handlers
    $zoomInButton.Add_Click({
        Set-Zoom ($script:zoomLevel + $script:zoomStep)
    })

    $zoomOutButton.Add_Click({
        Set-Zoom ($script:zoomLevel - $script:zoomStep)
    })

    $zoomResetButton.Add_Click({
        Set-Zoom 1.0
        $canvasTranslate.X = 0
        $canvasTranslate.Y = 0
    })

    # Mouse wheel zoom support
    $canvas.Add_MouseWheel({
        param($sender, $e)

        if ($e.Delta -gt 0) {
            # Zoom in
            Set-Zoom ($script:zoomLevel + $script:zoomStep)
        } else {
            # Zoom out
            Set-Zoom ($script:zoomLevel - $script:zoomStep)
        }
        $e.Handled = $true
    })

    # Canvas panning support (drag to pan)
    $script:isPanning = $false
    $script:panStartPoint = $null

    $canvas.Add_MouseLeftButtonDown({
        param($sender, $e)
        $script:isPanning = $true
        $script:panStartPoint = $e.GetPosition($canvasScroller)
        $canvas.CaptureMouse()
        $e.Handled = $true
    })

    $canvas.Add_MouseLeftButtonUp({
        param($sender, $e)
        $script:isPanning = $false
        $canvas.ReleaseMouseCapture()
        $e.Handled = $true
    })

    $canvas.Add_MouseMove({
        param($sender, $e)
        if ($script:isPanning -and $script:panStartPoint) {
            $currentPoint = $e.GetPosition($canvasScroller)
            $deltaX = $currentPoint.X - $script:panStartPoint.X
            $deltaY = $currentPoint.Y - $script:panStartPoint.Y

            $canvasScroller.ScrollToHorizontalOffset($canvasScroller.HorizontalOffset - $deltaX)
            $canvasScroller.ScrollToVerticalOffset($canvasScroller.VerticalOffset - $deltaY)

            $script:panStartPoint = $currentPoint
            $e.Handled = $true
        }
    })

    # Store UI element references for efficient updates (avoids full redraw)
    $script:deviceElements = @{}
    $script:connectionElements = @{}
    $script:highlightElements = @()
    $script:highlightedDevices = @{}  # Track which devices are currently highlighted
    $script:highlightedConnections = @{}  # Track which connections are currently highlighted

    # Draw network topology (initial draw only)
    function Draw-Topology {
        param([bool]$ForceRedraw = $false)

        if (-not $ForceRedraw -and $script:deviceElements.Count -gt 0) {
            # Already drawn, skip
            return
        }

        $canvas.Children.Clear()
        $script:deviceElements.Clear()
        $script:connectionElements.Clear()

        # Draw connections first (so they appear behind nodes)
        foreach ($conn in $Connections) {
            $line = New-Object System.Windows.Shapes.Line
            $line.X1 = $conn.Device1.X
            $line.Y1 = $conn.Device1.Y
            $line.X2 = $conn.Device2.X
            $line.Y2 = $conn.Device2.Y
            $line.Stroke = [System.Windows.Media.Brushes]::Gray
            $line.StrokeThickness = 2
            $line.Tag = $conn
            [void]$canvas.Children.Add($line)

            # Store reference for efficient updates
            $connKey = "$($conn.Device1.Hostname)-$($conn.Device2.Hostname)"
            $script:connectionElements[$connKey] = $line
        }

        # Draw devices
        foreach ($device in $Devices) {
            # Device circle
            $ellipse = New-Object System.Windows.Shapes.Ellipse
            $ellipse.Width = 60
            $ellipse.Height = 60
            $ellipse.Fill = [System.Windows.Media.Brushes]::LightBlue
            $ellipse.Stroke = [System.Windows.Media.Brushes]::DarkBlue
            $ellipse.StrokeThickness = 2
            [System.Windows.Controls.Canvas]::SetLeft($ellipse, $device.X - 30)
            [System.Windows.Controls.Canvas]::SetTop($ellipse, $device.Y - 30)
            $ellipse.Tag = $device
            [void]$canvas.Children.Add($ellipse)

            # Device label
            $textBlock = New-Object System.Windows.Controls.TextBlock
            $textBlock.Text = $device.Hostname
            $textBlock.FontSize = 11
            $textBlock.FontWeight = [System.Windows.FontWeights]::Bold
            $textBlock.TextAlignment = [System.Windows.TextAlignment]::Center
            $textBlock.Width = 100
            [System.Windows.Controls.Canvas]::SetLeft($textBlock, $device.X - 50)
            [System.Windows.Controls.Canvas]::SetTop($textBlock, $device.Y + 35)
            [void]$canvas.Children.Add($textBlock)

            # Device type label
            $typeLabel = New-Object System.Windows.Controls.TextBlock
            $typeLabel.Text = $device.DeviceType
            $typeLabel.FontSize = 9
            $typeLabel.Foreground = [System.Windows.Media.Brushes]::Gray
            $typeLabel.TextAlignment = [System.Windows.TextAlignment]::Center
            $typeLabel.Width = 100
            [System.Windows.Controls.Canvas]::SetLeft($typeLabel, $device.X - 50)
            [System.Windows.Controls.Canvas]::SetTop($typeLabel, $device.Y + 50)
            [void]$canvas.Children.Add($typeLabel)

            # Store reference
            $script:deviceElements[$device.Hostname] = @{
                Ellipse = $ellipse
                Label = $textBlock
                TypeLabel = $typeLabel
            }
        }
    }

    # Clear highlights only (efficient - doesn't redraw everything)
    function Clear-Highlights {
        # Remove highlight overlay elements
        foreach ($elem in $script:highlightElements) {
            [void]$canvas.Children.Remove($elem)
        }
        $script:highlightElements.Clear()

        # Reset ONLY previously highlighted connections
        foreach ($connKey in $script:highlightedConnections.Keys) {
            if ($script:connectionElements.ContainsKey($connKey)) {
                $script:connectionElements[$connKey].Stroke = [System.Windows.Media.Brushes]::Gray
                $script:connectionElements[$connKey].StrokeThickness = 2
            }
        }
        $script:highlightedConnections.Clear()

        # Reset ONLY previously highlighted devices
        foreach ($deviceName in $script:highlightedDevices.Keys) {
            if ($script:deviceElements.ContainsKey($deviceName)) {
                $script:deviceElements[$deviceName].Ellipse.Fill = [System.Windows.Media.Brushes]::LightBlue
                $script:deviceElements[$deviceName].Ellipse.Stroke = [System.Windows.Media.Brushes]::DarkBlue
                $script:deviceElements[$deviceName].Ellipse.StrokeThickness = 2
            }
        }
        $script:highlightedDevices.Clear()
    }

    function Reset-AllDevices {
        # Remove highlight overlay elements
        foreach ($elem in $script:highlightElements) {
            [void]$canvas.Children.Remove($elem)
        }
        $script:highlightElements.Clear()

        # Reset ALL connection colors
        foreach ($line in $script:connectionElements.Values) {
            $line.Stroke = [System.Windows.Media.Brushes]::Gray
            $line.StrokeThickness = 2
        }
        $script:highlightedConnections.Clear()

        # Reset ALL device colors
        foreach ($devElements in $script:deviceElements.Values) {
            $devElements.Ellipse.Fill = [System.Windows.Media.Brushes]::LightBlue
            $devElements.Ellipse.Stroke = [System.Windows.Media.Brushes]::DarkBlue
            $devElements.Ellipse.StrokeThickness = 2
        }
        $script:highlightedDevices.Clear()
    }

    Draw-Topology
    
    # Trace button handler
    $traceButton.Add_Click({
        if (-not $sourceCombo.SelectedItem -or -not $destCombo.SelectedItem) {
            [System.Windows.MessageBox]::Show("Please select both source and destination devices.", "Selection Required")
            return
        }

        # Get user inputs
        $sourceIP = $sourceIPBox.Text.Trim()
        $destIP = $destIPBox.Text.Trim()
        $useRouting = $useRoutingCheckBox.IsChecked

        # Validate IP addresses
        if (-not (Test-ValidIPAddress -IP $sourceIP)) {
            [System.Windows.MessageBox]::Show("Invalid source IP address: $sourceIP`n`nPlease enter a valid IP address (e.g., 10.10.10.100)", "Validation Error")
            return
        }

        if (-not (Test-ValidIPAddress -IP $destIP)) {
            [System.Windows.MessageBox]::Show("Invalid destination IP address: $destIP`n`nPlease enter a valid IP address (e.g., 10.20.20.100)", "Validation Error")
            return
        }

        $srcDevice = $Devices | Where-Object { $_.Hostname -eq $sourceCombo.SelectedItem }
        $dstDevice = $Devices | Where-Object { $_.Hostname -eq $destCombo.SelectedItem }

        # Clear previous highlights
        Clear-Highlights

        # Use routing-aware or connectivity-based path finding
        if ($useRouting) {
            # ROUTING-AWARE PATH FINDING - simulates actual packet forwarding
            $routingPath = Find-RoutingPath -Source $srcDevice -SourceIP $sourceIP -DestIP $destIP -AllDevices $Devices -Connections $Connections

            if ($routingPath.Count -eq 0 -or $routingPath[0].Error) {
                $errorMsg = if ($routingPath.Count -gt 0) { $routingPath[0].Error } else { "No routing path found" }
                $detailsBox.Text = "ROUTING-AWARE PATH TRACE FAILED`n" +
                                   "Source: $($srcDevice.Hostname) ($sourceIP)`n" +
                                   "Destination: $destIP`n" +
                                   "=" * 80 + "`n`n" +
                                   "ERROR: $errorMsg"
                return
            }

            # Extract device names for highlighting
            $path = @($routingPath | ForEach-Object { $_.Device.Hostname })

            # Highlight connections in path
            for ($i = 0; $i -lt $path.Count - 1; $i++) {
                $dev1Name = $path[$i]
                $dev2Name = $path[$i + 1]

                $conn = $Connections | Where-Object {
                    ($_.Device1.Hostname -eq $dev1Name -and $_.Device2.Hostname -eq $dev2Name) -or
                    ($_.Device2.Hostname -eq $dev1Name -and $_.Device1.Hostname -eq $dev2Name)
                } | Select-Object -First 1

                if ($conn) {
                    $line = New-Object System.Windows.Shapes.Line
                    $line.X1 = $conn.Device1.X
                    $line.Y1 = $conn.Device1.Y
                    $line.X2 = $conn.Device2.X
                    $line.Y2 = $conn.Device2.Y
                    $line.Stroke = [System.Windows.Media.Brushes]::Green
                    $line.StrokeThickness = 4
                    [void]$canvas.Children.Add($line)
                    $script:highlightElements += $line

                    # Track highlighted connection
                    $connKey = "$dev1Name-$dev2Name"
                    $script:highlightedConnections[$connKey] = $true
                }
            }

            # Highlight devices in path (ONLY devices in path)
            foreach ($deviceName in $path) {
                if ($script:deviceElements.ContainsKey($deviceName)) {
                    $script:deviceElements[$deviceName].Ellipse.Fill = [System.Windows.Media.Brushes]::LightGreen
                    $script:deviceElements[$deviceName].Ellipse.Stroke = [System.Windows.Media.Brushes]::DarkGreen
                    $script:deviceElements[$deviceName].Ellipse.StrokeThickness = 3

                    # Track highlighted device
                    $script:highlightedDevices[$deviceName] = $true
                }
            }

            # Display routing-aware path details
            $details = "=" * 80 + "`n"
            $details += "                     ROUTING-AWARE PATH TRACE`n"
            $details += "=" * 80 + "`n"
            $details += "`n"
            $details += "Source Device:      $($srcDevice.Hostname) [$($srcDevice.DeviceType)]`n"
            $details += "Source IP:          $sourceIP`n"
            $details += "Destination IP:     $destIP`n"
            $details += "Trace Time:         $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"
            $details += "`n"
            $details += "=" * 80 + "`n`n"

            $currentIP = $sourceIP
            foreach ($hop in $routingPath) {
                $details += "+" + ("-" * 78) + "+`n"
                $details += "| HOP $($hop.HopNumber): $($hop.Device.Hostname) [$($hop.Device.DeviceType)]"
                $details += " " * (73 - $hop.Device.Hostname.Length - $hop.Device.DeviceType.Length - 10) + "|`n"
                $details += "+" + ("-" * 78) + "+`n"

                # Device capabilities summary
                $capabilities = @()
                if ($hop.Device.BGP_ASN -gt 0) { $capabilities += "BGP AS$($hop.Device.BGP_ASN)" }
                if ($hop.Device.OSPFProcesses.Count -gt 0) { $capabilities += "OSPF" }
                if ($hop.Device.Routes.Count -gt 0) { $capabilities += "$($hop.Device.Routes.Count) routes" }
                if ($hop.Device.NATRules.Count -gt 0) { $capabilities += "NAT" }
                if ($capabilities.Count -gt 0) {
                    $details += "  Device Capabilities: $($capabilities -join ', ')`n`n"
                }

                # INGRESS - Show how traffic arrives at this device
                if ($hop.EntryInterface) {
                    $details += "  +- INGRESS TRAFFIC " + ("-" * 46) + "+`n"
                    $entryIface = $hop.Device.Interfaces[$hop.EntryInterface]
                    $details += "  | Traffic enters from previous hop via interface:                |`n"
                    $details += "  |   Interface: $($hop.EntryInterface)"
                    $details += " " * (57 - $hop.EntryInterface.Length) + "|`n"
                    if ($hop.EntryIP) {
                        $details += "  |   IP Address: $($hop.EntryIP)"
                        if ($entryIface.SubnetMask) {
                            $details += "/$($entryIface.CIDR)"
                        }
                        $details += " " * (56 - $hop.EntryIP.Length - $(if($entryIface.CIDR){$entryIface.CIDR.ToString().Length + 1}else{0})) + "|`n"
                    }
                    if ($entryIface -and $entryIface.Description) {
                        $details += "  |   Description: $($entryIface.Description.Substring(0, [Math]::Min($entryIface.Description.Length, 45)))"
                        $details += " " * (43 - [Math]::Min($entryIface.Description.Length, 45)) + "|`n"
                    }
                    if ($entryIface -and $entryIface.VRF -and $entryIface.VRF -ne "global") {
                        $details += "  |   VRF: $($entryIface.VRF)"
                        $details += " " * (58 - $entryIface.VRF.Length) + "|`n"
                    }
                    $details += "  |                                                                 |`n"
                    $details += "  | Packet Details:                                                 |`n"
                    $details += "  |   Source IP: $currentIP"
                    $details += " " * (51 - $currentIP.Length) + "|`n"
                    $details += "  |   Destination IP: $destIP"
                    $details += " " * (47 - $destIP.Length) + "|`n"
                    $details += "  +" + ("-" * 65) + "+`n`n"
                }
                elseif ($hop.HopNumber -eq 1) {
                    $details += "  +- TRAFFIC ORIGINATES HERE " + ("-" * 38) + "+`n"
                    $details += "  | This is the source device where the traffic begins             |`n"
                    $details += "  |   Source IP: $currentIP"
                    $details += " " * (51 - $currentIP.Length) + "|`n"
                    $details += "  |   Destination IP: $destIP"
                    $details += " " * (47 - $destIP.Length) + "|`n"
                    $details += "  +" + ("-" * 65) + "+`n`n"
                }

                # ROUTING DECISION - Show routing logic
                if ($hop.ExitInterface) {
                    $details += "  +- ROUTING DECISION " + ("-" * 45) + "+`n"

                    # Parse the Reason field to extract routing protocol and details
                    $routingProto = "Unknown"
                    $routeDetails = $hop.Reason

                    if ($hop.Reason -match '\[Protocol: (\w+)') {
                        $routingProto = $matches[1]
                        $details += "  | Routing Protocol: $routingProto"
                        $details += " " * (49 - $routingProto.Length) + "|`n"
                    }

                    if ($hop.Reason -match 'AD: (\d+)') {
                        $ad = $matches[1]
                        $details += "  | Administrative Distance: $ad"
                        $details += " " * (39 - $ad.Length) + "|`n"
                    }

                    if ($hop.Reason -match 'Metric: (\d+)') {
                        $metric = $matches[1]
                        $details += "  | Metric: $metric"
                        $details += " " * (53 - $metric.Length) + "|`n"
                    }

                    if ($hop.Reason -match 'Route to ([^ ]+)') {
                        $destSubnet = $matches[1]
                        $details += "  | Matched Route: $destSubnet"
                        $details += " " * (45 - $destSubnet.Length) + "|`n"
                    }

                    if ($hop.Reason -match 'connected subnet' -or $routingProto -eq "Connected") {
                        $details += "  | Type: Directly Connected Subnet                                |`n"
                    }
                    elseif ($routingProto -eq "Static") {
                        $details += "  | Type: Static Route                                              |`n"
                    }
                    elseif ($routingProto -eq "BGP") {
                        $details += "  | Type: BGP Learned Route (Dynamic)                               |`n"
                    }
                    elseif ($routingProto -eq "OSPF") {
                        $details += "  | Type: OSPF Learned Route (Dynamic)                              |`n"
                    }

                    if ($hop.NextHop) {
                        $details += "  |                                                                 |`n"
                        $details += "  | Next Hop Gateway: $($hop.NextHop)"
                        $details += " " * (44 - $hop.NextHop.Length) + "|`n"
                        $details += "  |   (Traffic will be forwarded to this IP address)               |`n"
                    }

                    $details += "  +" + ("-" * 65) + "+`n`n"

                    # EGRESS - Show how traffic leaves this device
                    $details += "  +- EGRESS TRAFFIC " + ("-" * 47) + "+`n"
                    $exitIface = $hop.Device.Interfaces[$hop.ExitInterface]
                    $details += "  | Traffic exits to next hop via interface:                       |`n"
                    $details += "  |   Interface: $($hop.ExitInterface)"
                    $details += " " * (57 - $hop.ExitInterface.Length) + "|`n"
                    $details += "  |   IP Address: $($hop.ExitIP)"
                    if ($exitIface.SubnetMask) {
                        $details += "/$($exitIface.CIDR)"
                    }
                    $details += " " * (56 - $hop.ExitIP.Length - $(if($exitIface.CIDR){$exitIface.CIDR.ToString().Length + 1}else{0})) + "|`n"
                    if ($exitIface -and $exitIface.Description) {
                        $details += "  |   Description: $($exitIface.Description.Substring(0, [Math]::Min($exitIface.Description.Length, 45)))"
                        $details += " " * (43 - [Math]::Min($exitIface.Description.Length, 45)) + "|`n"
                    }
                    if ($exitIface -and $exitIface.VRF -and $exitIface.VRF -ne "global") {
                        $details += "  |   VRF: $($exitIface.VRF)"
                        $details += " " * (58 - $exitIface.VRF.Length) + "|`n"
                    }
                    $details += "  +" + ("-" * 65) + "+`n`n"

                    # Show device-to-device traversal (if not the last hop)
                    if ($hop.HopNumber -lt $routingPath.Count) {
                        $nextHop = $routingPath[$hop.HopNumber]  # Next hop in array (HopNumber is 1-based)

                        $details += "  +- DEVICE-TO-DEVICE TRAVERSAL " + ("-" * 34) + "+`n"
                        $details += "  |                                                                 |`n"
                        $details += "  | Traffic Flow:                                                   |`n"
                        $details += "  |   FROM: $($hop.Device.Hostname)"
                        $details += " " * (56 - $hop.Device.Hostname.Length) + "|`n"
                        $details += "  |     Exit Interface: $($hop.ExitInterface) ($($hop.ExitIP))"
                        $details += " " * (35 - $hop.ExitInterface.Length - $hop.ExitIP.Length) + "|`n"

                        # Find the physical connection
                        $connection = $null
                        foreach ($conn in $Connections) {
                            if (($conn.Device1.Hostname -eq $hop.Device.Hostname -and $conn.Interface1 -eq $hop.ExitInterface) -or
                                ($conn.Device2.Hostname -eq $hop.Device.Hostname -and $conn.Interface2 -eq $hop.ExitInterface)) {
                                $connection = $conn
                                break
                            }
                        }

                        if ($connection) {
                            # Determine the subnet they share and connection type
                            $exitIface = $hop.Device.Interfaces[$hop.ExitInterface]

                            $details += "  |                                                                 |`n"
                            $details += "  |   === Physical Link ===                                         |`n"

                            # Show connection type
                            if ($connection.ConnectionType -eq "BGP-Peering") {
                                $details += "  |   Connection Type: BGP Peering (WAN)                           |`n"
                                $details += "  |   Protocol: BGP                                                 |`n"

                                # Show AS numbers if available
                                if ($hop.Device.BGP_ASN -gt 0) {
                                    $details += "  |   Local AS: $($hop.Device.BGP_ASN)"
                                    $details += " " * (52 - $hop.Device.BGP_ASN.ToString().Length) + "|`n"
                                }

                                $peerAS = ($hop.Device.BGPNeighbors | Where-Object { $_.IPAddress -eq $nextHop.EntryIP -or $Connections | Where-Object { $_.Device2.Hostname -eq $nextHop.Device.Hostname } }).RemoteAS
                                if ($peerAS) {
                                    $details += "  |   Remote AS: $peerAS"
                                    $details += " " * (51 - $peerAS.ToString().Length) + "|`n"
                                }
                            }
                            elseif ($connection.ConnectionType -eq "OSPF-Adjacency") {
                                $details += "  |   Connection Type: OSPF Adjacency (WAN/LAN)                    |`n"
                                $details += "  |   Protocol: OSPF                                                |`n"
                            }
                            else {
                                $details += "  |   Connection Type: Layer 3 (Routed)                            |`n"
                            }

                            # Show subnet information
                            if ($exitIface -and $exitIface.Network -and $exitIface.CIDR) {
                                $details += "  |   Shared Subnet: $($exitIface.Network)/$($exitIface.CIDR)"
                                $details += " " * (41 - $exitIface.Network.Length - $exitIface.CIDR.ToString().Length) + "|`n"

                                if ($exitIface.VRF -and $exitIface.VRF -ne "global") {
                                    $details += "  |   VRF: $($exitIface.VRF)"
                                    $details += " " * (58 - $exitIface.VRF.Length) + "|`n"
                                }
                            }

                            # Show WAN link type if applicable
                            if ($hop.ExitInterface -match '^(Serial|Tunnel|Dialer|Cellular|ATM|Frame-Relay)') {
                                $linkType = $hop.ExitInterface -replace '(\d+/\d+|\d+).*', ''
                                $details += "  |   WAN Interface Type: $linkType"
                                $details += " " * (42 - $linkType.Length) + "|`n"
                            }
                        }

                        $details += "  |                                                                 |`n"
                        $details += "  |   TO: $($nextHop.Device.Hostname)"
                        $details += " " * (58 - $nextHop.Device.Hostname.Length) + "|`n"

                        if ($nextHop.EntryInterface) {
                            $details += "  |     Entry Interface: $($nextHop.EntryInterface)"
                            if ($nextHop.EntryIP) {
                                $details += " ($($nextHop.EntryIP))"
                            }
                            $entryLen = $nextHop.EntryInterface.Length + $(if($nextHop.EntryIP){$nextHop.EntryIP.Length + 3}else{0})
                            $details += " " * (43 - $entryLen) + "|`n"
                        }

                        $details += "  |                                                                 |`n"
                        $details += "  | Routing Decision:                                               |`n"
                        $details += "  |   Next hop gateway $($hop.NextHop) is reachable via"
                        $details += " " * (24 - $hop.NextHop.Length) + "|`n"
                        $details += "  |   the shared subnet on $($hop.ExitInterface)"
                        $details += " " * (42 - $hop.ExitInterface.Length) + "|`n"
                        $details += "  |                                                                 |`n"
                        $details += "  | Result: Packet forwarded from $($hop.Device.Hostname) to $($nextHop.Device.Hostname)"
                        $totalLen = $hop.Device.Hostname.Length + $nextHop.Device.Hostname.Length + 36
                        if ($totalLen -lt 65) {
                            $details += " " * (65 - $totalLen)
                        }
                        $details += "|`n"
                        $details += "  +" + ("-" * 65) + "+`n`n"
                    }

                    # Run comprehensive analysis for this hop
                    $device = $hop.Device
                    $outInterface = $device.Interfaces | Where-Object { $_.Name -eq $hop.ExitInterface } | Select-Object -First 1
                    $hasAnalysis = $false

                    # Check for NAT translation
                    if ($outInterface -and $outInterface.NATOutside) {
                        $natResult = Apply-NATTranslation -Device $device -SourceIP $currentIP -Interface $hop.ExitInterface
                        if ($natResult.Translated) {
                            if (-not $hasAnalysis) {
                                $details += "  +- PACKET ANALYSIS " + ("-" * 46) + "+`n"
                                $hasAnalysis = $true
                            }
                            $details += "  |                                                                 |`n"
                            $details += "  | [!] NAT Translation Applied:                                    |`n"
                            $details += "  |   Type: $($natResult.Type)"
                            $details += " " * (57 - $natResult.Type.Length) + "|`n"
                            $details += "  |   Original Source IP: $currentIP"
                            $details += " " * (41 - $currentIP.Length) + "|`n"
                            $details += "  |   Translated Source IP: $($natResult.NewIP)"
                            $details += " " * (37 - $natResult.NewIP.Length) + "|`n"
                            $details += "  |   (Packet source address changed for internet routing)         |`n"
                            $currentIP = $natResult.NewIP
                        }
                    }

                    # Check for ACL
                    if ($outInterface -and $outInterface.ACL_Out) {
                        $acl = $device.ACLs[$outInterface.ACL_Out]
                        if ($acl) {
                            $aclResult = Test-ACLMatch -ACL $acl -SourceIP $currentIP -DestIP $destIP
                            if (-not $hasAnalysis) {
                                $details += "  +- PACKET ANALYSIS " + ("-" * 46) + "+`n"
                                $hasAnalysis = $true
                            }
                            $details += "  |                                                                 |`n"
                            if ($aclResult.Action -eq "deny") {
                                $details += "  | [X] ACL DENIED - Traffic Blocked!                               |`n"
                                $details += "  |   ACL Name: $($acl.Name)"
                                $details += " " * (55 - $acl.Name.Length) + "|`n"
                                $details += "  |   Action: DENY                                                  |`n"
                                $details += "  |   Reason: $($aclResult.Reason.Substring(0, [Math]::Min($aclResult.Reason.Length, 50)))"
                                $details += " " * (49 - [Math]::Min($aclResult.Reason.Length, 50)) + "|`n"
                                if ($hasAnalysis) {
                                    $details += "  +" + ("-" * 65) + "+`n`n"
                                }
                                $details += "  +" + ("=" * 65) + "+`n"
                                $details += "  | *** PATH BLOCKED AT THIS HOP ***                                |`n"
                                $details += "  +" + ("=" * 65) + "+`n`n"
                                $details += "=" * 80 + "`n"
                                $details += "RESULT: Traffic DENIED - path blocked by ACL/firewall`n"
                                $detailsBox.Text = $details
                                return
                            } else {
                                $details += "  | [OK] ACL Checked - Traffic Permitted                            |`n"
                                $details += "  |   ACL Name: $($acl.Name)"
                                $details += " " * (55 - $acl.Name.Length) + "|`n"
                                $details += "  |   Action: PERMIT                                                |`n"
                            }
                        }
                    }

                    # Check for QoS
                    if ($outInterface -and $outInterface.ServicePolicy_Out) {
                        $qosResult = Get-QoSMarking -Device $device -PolicyMapName $outInterface.ServicePolicy_Out
                        if ($qosResult.Applied) {
                            if (-not $hasAnalysis) {
                                $details += "  +- PACKET ANALYSIS " + ("-" * 46) + "+`n"
                                $hasAnalysis = $true
                            }
                            $details += "  |                                                                 |`n"
                            $details += "  | [QoS] QoS Policy Applied:                                       |`n"
                            $details += "  |   Policy Map: $($qosResult.PolicyMap)"
                            $details += " " * (53 - $qosResult.PolicyMap.Length) + "|`n"
                            $details += "  |   (Traffic may be marked, shaped, or prioritized)              |`n"
                        }
                    }

                    if ($hasAnalysis) {
                        $details += "  +" + ("-" * 65) + "+`n`n"
                    }
                }

                if ($hop.Error) {
                    $details += "`n"
                    $details += "  +" + ("=" * 65) + "+`n"
                    $details += "  | *** PATH FAILED - CANNOT CONTINUE ***                           |`n"
                    $details += "  +" + ("=" * 65) + "+`n"
                    $details += "  Error: $($hop.Error)`n`n"
                    $details += "=" * 80 + "`n"
                    $details += "RESULT: Path FAILED`n"
                    $details += "Reason: $($hop.Error)`n"
                    $detailsBox.Text = $details
                    return
                }

                $details += "`n"
            }

            # Final summary
            $details += "=" * 80 + "`n"
            $details += "                      PATH TRACE COMPLETE`n"
            $details += "=" * 80 + "`n`n"
            $details += "RESULT: [OK] Path is VALID - traffic would be forwarded successfully`n`n"

            $details += "PATH STATISTICS:`n"
            $details += "  Total Hops:           $($routingPath.Count)`n"
            $details += "  Routing Method:       Table-based forwarding (longest prefix match)`n"

            # Count routing protocols used
            $protoCount = @{}
            foreach ($hop in $routingPath) {
                if ($hop.Reason -match '\[Protocol: (\w+)') {
                    $proto = $matches[1]
                    if (-not $protoCount.ContainsKey($proto)) {
                        $protoCount[$proto] = 0
                    }
                    $protoCount[$proto]++
                }
            }
            if ($protoCount.Count -gt 0) {
                $details += "  Protocols Used:       $($protoCount.Keys -join ', ')`n"
            }

            # Count NAT/ACL/QoS applications
            $natApplied = ($routingPath | Where-Object { $_.ExitInterface -and ($_.Device.NATRules.Count -gt 0) }).Count
            $aclChecked = ($routingPath | Where-Object { $_.ExitInterface }).Count

            if ($natApplied -gt 0) {
                $details += "  NAT Translations:     $natApplied hop(s)`n"
            }
            $details += "  Security Checks:      $aclChecked interface(s) checked`n"
            $details += "`n"
            $details += "=" * 80 + "`n"

            $detailsBox.Text = $details

            # Apply device filter if checkbox is checked (only if path has multiple hops)
            if ($filterPathDevicesCheckBox.IsChecked -and $script:highlightedDevices.Count -gt 1) {
                # Hide all devices not in path
                foreach ($deviceName in $script:deviceElements.Keys) {
                    if (-not $script:highlightedDevices.ContainsKey($deviceName)) {
                        $script:deviceElements[$deviceName].Ellipse.Visibility = [System.Windows.Visibility]::Collapsed
                        $script:deviceElements[$deviceName].Label.Visibility = [System.Windows.Visibility]::Collapsed
                        $script:deviceElements[$deviceName].TypeLabel.Visibility = [System.Windows.Visibility]::Collapsed
                    }
                }

                # Hide connections not in path
                foreach ($connKey in $script:connectionElements.Keys) {
                    if (-not $script:highlightedConnections.ContainsKey($connKey)) {
                        # Also check reverse connection
                        $parts = $connKey -split '-'
                        $reverseKey = "$($parts[1])-$($parts[0])"
                        if (-not $script:highlightedConnections.ContainsKey($reverseKey)) {
                            $script:connectionElements[$connKey].Visibility = [System.Windows.Visibility]::Collapsed
                        }
                    }
                }
            } elseif ($filterPathDevicesCheckBox.IsChecked -and $script:highlightedDevices.Count -le 1) {
                # Path trace didn't complete - show warning
                [System.Windows.MessageBox]::Show("Please complete a successful path trace before filtering devices.`n`nCurrent path has $($script:highlightedDevices.Count) device(s). Need at least 2 for filtering.", "No Path Traced", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                $filterPathDevicesCheckBox.IsChecked = $false
            }

        } else {
            # CONNECTIVITY-BASED PATH FINDING - original BFS algorithm
            $path = Find-Path -Source $srcDevice -Destination $dstDevice -AllDevices $Devices -Connections $Connections

            if ($path.Count -eq 0) {
                $detailsBox.Text = "No path found between $($srcDevice.Hostname) and $($dstDevice.Hostname)"
                return
            }

            # Highlight connections in path
            for ($i = 0; $i -lt $path.Count - 1; $i++) {
                $dev1Name = $path[$i]
                $dev2Name = $path[$i + 1]

                $conn = $Connections | Where-Object {
                    ($_.Device1.Hostname -eq $dev1Name -and $_.Device2.Hostname -eq $dev2Name) -or
                    ($_.Device2.Hostname -eq $dev1Name -and $_.Device1.Hostname -eq $dev2Name)
                } | Select-Object -First 1

                if ($conn) {
                    $line = New-Object System.Windows.Shapes.Line
                    $line.X1 = $conn.Device1.X
                    $line.Y1 = $conn.Device1.Y
                    $line.X2 = $conn.Device2.X
                    $line.Y2 = $conn.Device2.Y
                    $line.Stroke = [System.Windows.Media.Brushes]::Green
                    $line.StrokeThickness = 4
                    [void]$canvas.Children.Add($line)
                    $script:highlightElements += $line

                    # Track highlighted connection
                    $connKey = "$dev1Name-$dev2Name"
                    $script:highlightedConnections[$connKey] = $true
                }
            }

            # Highlight devices in path (ONLY devices in path)
            foreach ($deviceName in $path) {
                if ($script:deviceElements.ContainsKey($deviceName)) {
                    $script:deviceElements[$deviceName].Ellipse.Fill = [System.Windows.Media.Brushes]::LightGreen
                    $script:deviceElements[$deviceName].Ellipse.Stroke = [System.Windows.Media.Brushes]::DarkGreen
                    $script:deviceElements[$deviceName].Ellipse.StrokeThickness = 3

                    # Track highlighted device
                    $script:highlightedDevices[$deviceName] = $true
                }
            }

            # Get comprehensive path analysis
            $comprehensiveAnalysis = Get-ComprehensivePathAnalysis -Path $path -AllDevices $Devices -Connections $Connections

            # Display comprehensive path details
            $details = "COMPREHENSIVE PATH ANALYSIS`n"
            $details += "Path from $($srcDevice.Hostname) to $($dstDevice.Hostname):`n"
            $details += "=" * 80 + "`n`n"

            $pathBlocked = $false

            foreach ($hop in $comprehensiveAnalysis) {
                $details += "Hop $($hop.HopNumber): $($hop.DeviceName) ($($hop.DeviceType))`n"

                if ($hop.ExitInterface) {
                    $details += "  Exit Interface: $($hop.ExitInterface) ($($hop.ExitIP))"
                    if ($hop.VRF -ne "global") {
                        $details += " [VRF: $($hop.VRF)]"
                    }
                    $details += "`n"
                }

                # Display all analysis results
                foreach ($analysisLine in $hop.Analysis) {
                    $details += "  $analysisLine`n"
                }

                if ($hop.Blocked) {
                    $details += "`n  *** PATH BLOCKED AT THIS HOP ***`n"
                    $pathBlocked = $true
                    break
                }

                $details += "`n"
            }

            if ($pathBlocked) {
                $details += "`n" + "=" * 80 + "`n"
                $details += "RESULT: Traffic DENIED - path blocked by ACL/firewall`n"
            } else {
                $details += "=" * 80 + "`n"
                $details += "RESULT: Path is VALID - traffic would be forwarded successfully`n"
            }

            # Add summary statistics
            $details += "`nPATH STATISTICS:`n"
            $details += "  Total Hops: $($path.Count)`n"
            $aclCount = ($comprehensiveAnalysis | Where-Object { $_.Analysis -match "ACL" }).Count
            $natCount = ($comprehensiveAnalysis | Where-Object { $_.Analysis -match "NAT" }).Count
            $qosCount = ($comprehensiveAnalysis | Where-Object { $_.Analysis -match "QoS" }).Count
            if ($aclCount -gt 0) { $details += "  ACL Checks: $aclCount`n" }
            if ($natCount -gt 0) { $details += "  NAT Translations: $natCount`n" }
            if ($qosCount -gt 0) { $details += "  QoS Policies: $qosCount`n" }

            $detailsBox.Text = $details

            # Apply device filter if checkbox is checked (only if path has multiple hops)
            if ($filterPathDevicesCheckBox.IsChecked -and $script:highlightedDevices.Count -gt 1) {
                # Hide all devices not in path
                foreach ($deviceName in $script:deviceElements.Keys) {
                    if (-not $script:highlightedDevices.ContainsKey($deviceName)) {
                        $script:deviceElements[$deviceName].Ellipse.Visibility = [System.Windows.Visibility]::Collapsed
                        $script:deviceElements[$deviceName].Label.Visibility = [System.Windows.Visibility]::Collapsed
                        $script:deviceElements[$deviceName].TypeLabel.Visibility = [System.Windows.Visibility]::Collapsed
                    }
                }

                # Hide connections not in path
                foreach ($connKey in $script:connectionElements.Keys) {
                    if (-not $script:highlightedConnections.ContainsKey($connKey)) {
                        # Also check reverse connection
                        $parts = $connKey -split '-'
                        $reverseKey = "$($parts[1])-$($parts[0])"
                        if (-not $script:highlightedConnections.ContainsKey($reverseKey)) {
                            $script:connectionElements[$connKey].Visibility = [System.Windows.Visibility]::Collapsed
                        }
                    }
                }
            } elseif ($filterPathDevicesCheckBox.IsChecked -and $script:highlightedDevices.Count -le 1) {
                # Path trace didn't complete - show warning
                [System.Windows.MessageBox]::Show("Please complete a successful path trace before filtering devices.`n`nCurrent path has $($script:highlightedDevices.Count) device(s). Need at least 2 for filtering.", "No Path Traced", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                $filterPathDevicesCheckBox.IsChecked = $false
            }
        }
    })
    
    # Clear button handler
    $clearButton.Add_Click({
        Reset-AllDevices  # Reset ALL devices to default colors
        $detailsBox.Text = ""

        # Clear all selections
        $sourceCombo.SelectedIndex = -1
        $destCombo.SelectedIndex = -1
        $sourceInterfaceCombo.Items.Clear()
        $destInterfaceCombo.Items.Clear()
        $sourceIPBox.Text = "10.10.10.100"  # Reset to default
        $destIPBox.Text = "10.20.20.100"    # Reset to default
        $useRoutingCheckBox.IsChecked = $true  # Reset to default
        $filterPathDevicesCheckBox.IsChecked = $false  # Reset filter

        # Show all devices again
        foreach ($devElements in $script:deviceElements.Values) {
            $devElements.Ellipse.Visibility = [System.Windows.Visibility]::Visible
            $devElements.Label.Visibility = [System.Windows.Visibility]::Visible
            $devElements.TypeLabel.Visibility = [System.Windows.Visibility]::Visible
        }
        foreach ($line in $script:connectionElements.Values) {
            $line.Visibility = [System.Windows.Visibility]::Visible
        }
    })

    # Manage Routes button handler
    $manageRoutesButton.Add_Click({
        Show-RoutingTableDialog -Devices $Devices -ParentWindow $window
    })

    # Filter path devices checkbox handler
    $filterPathDevicesCheckBox.Add_Checked({
        # When checked, hide all devices that are not in the current path
        if ($script:highlightedDevices.Count -gt 1) {
            # Hide all devices not in path
            foreach ($deviceName in $script:deviceElements.Keys) {
                if (-not $script:highlightedDevices.ContainsKey($deviceName)) {
                    $script:deviceElements[$deviceName].Ellipse.Visibility = [System.Windows.Visibility]::Collapsed
                    $script:deviceElements[$deviceName].Label.Visibility = [System.Windows.Visibility]::Collapsed
                    $script:deviceElements[$deviceName].TypeLabel.Visibility = [System.Windows.Visibility]::Collapsed
                }
            }

            # Hide connections not in path
            foreach ($connKey in $script:connectionElements.Keys) {
                if (-not $script:highlightedConnections.ContainsKey($connKey)) {
                    # Also check reverse connection
                    $parts = $connKey -split '-'
                    $reverseKey = "$($parts[1])-$($parts[0])"
                    if (-not $script:highlightedConnections.ContainsKey($reverseKey)) {
                        $script:connectionElements[$connKey].Visibility = [System.Windows.Visibility]::Collapsed
                    }
                }
            }
        } else {
            # Not enough devices in path - uncheck and warn
            [System.Windows.MessageBox]::Show("Please complete a successful path trace before filtering devices.`n`nCurrent path has $($script:highlightedDevices.Count) device(s). Need at least 2 for filtering.", "No Path Traced", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            $filterPathDevicesCheckBox.IsChecked = $false
        }
    })

    $filterPathDevicesCheckBox.Add_Unchecked({
        # Show all devices again
        foreach ($devElements in $script:deviceElements.Values) {
            $devElements.Ellipse.Visibility = [System.Windows.Visibility]::Visible
            $devElements.Label.Visibility = [System.Windows.Visibility]::Visible
            $devElements.TypeLabel.Visibility = [System.Windows.Visibility]::Visible
        }
        foreach ($line in $script:connectionElements.Values) {
            $line.Visibility = [System.Windows.Visibility]::Visible
        }
    })

    # Show window
    [void]$window.ShowDialog()
}

#endregion

#region Main

function Main {
    Write-Host "Network Path Tracer - Starting..." -ForegroundColor Cyan
    Write-Host ""
    
    # Get config path
    if (-not $ConfigPath) {
        $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderBrowser.Description = "Select folder containing network device configuration files"
        $folderBrowser.ShowNewFolderButton = $false
        
        if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $ConfigPath = $folderBrowser.SelectedPath
        } else {
            Write-Host "No folder selected. Using demo mode with sample data." -ForegroundColor Yellow
            # Create demo devices
            $devices = New-Object System.Collections.ArrayList
            
            $r1 = [NetworkDevice]::new("Branch-A")
            $r1.DeviceType = "Router"
            $if1 = [NetworkInterface]::new("GigabitEthernet0/0")
            $if1.IPAddress = "10.1.1.1"
            $if1.SubnetMask = "255.255.255.0"
            $r1.Interfaces["GigabitEthernet0/0"] = $if1
            [void]$devices.Add($r1)
            
            $r2 = [NetworkDevice]::new("Core-Router")
            $r2.DeviceType = "Router"
            $if2 = [NetworkInterface]::new("GigabitEthernet0/0")
            $if2.IPAddress = "10.1.1.2"
            $if2.SubnetMask = "255.255.255.0"
            $r2.Interfaces["GigabitEthernet0/0"] = $if2
            $if3 = [NetworkInterface]::new("GigabitEthernet0/1")
            $if3.IPAddress = "10.2.1.1"
            $if3.SubnetMask = "255.255.255.0"
            $r2.Interfaces["GigabitEthernet0/1"] = $if3
            [void]$devices.Add($r2)
            
            $r3 = [NetworkDevice]::new("Branch-B")
            $r3.DeviceType = "Router"
            $if4 = [NetworkInterface]::new("GigabitEthernet0/0")
            $if4.IPAddress = "10.2.1.2"
            $if4.SubnetMask = "255.255.255.0"
            $r3.Interfaces["GigabitEthernet0/0"] = $if4
            [void]$devices.Add($r3)
            
            Calculate-Layout -Devices $devices -Connections @()
            $connections = Build-NetworkTopology -Devices $devices
            
            Show-NetworkMap -Devices $devices -Connections $connections
            return
        }
    }
    
    # Load and parse config files
    $configFiles = Get-ChildItem -Path $ConfigPath -File -Include *.txt,*.cfg,*.conf -Recurse
    
    if ($configFiles.Count -eq 0) {
        Write-Host "No configuration files found in: $ConfigPath" -ForegroundColor Red
        Write-Host "Looking for files with extensions: .txt, .cfg, .conf" -ForegroundColor Yellow
        return
    }
    
    Write-Host "Found $($configFiles.Count) configuration file(s)" -ForegroundColor Green
    
    $devices = New-Object System.Collections.ArrayList
    
    foreach ($file in $configFiles) {
        try {
            Write-Host "  Parsing: $($file.Name)..." -ForegroundColor Gray
            $content = Get-Content -Path $file.FullName -Raw -ErrorAction Stop

            # Detect vendor (currently only Cisco, but extensible)
            $device = Parse-CiscoConfig -Content $content -Filename $file.Name

            # Validate parsed device
            if ($device.Interfaces.Count -eq 0) {
                Write-Warning "    No interfaces found in $($file.Name) - config may be incomplete"
            }

            [void]$devices.Add($device)

            Write-Host "    Device: $($device.Hostname) | Type: $($device.DeviceType) | Interfaces: $($device.Interfaces.Count)" -ForegroundColor Gray
        }
        catch {
            Write-Host "    ERROR: Failed to parse $($file.Name): $_" -ForegroundColor Red
            Write-Host "    Skipping this file and continuing..." -ForegroundColor Yellow
            continue
        }
    }
    
    Write-Host ""
    Write-Host "Building network topology..." -ForegroundColor Cyan
    
    # Build topology
    $connections = Build-NetworkTopology -Devices $devices
    Write-Host "  Found $($connections.Count) connection(s)" -ForegroundColor Green
    
    # Calculate layout
    Calculate-Layout -Devices $devices -Connections $connections
    
    Write-Host ""
    Write-Host "Launching GUI..." -ForegroundColor Cyan
    Write-Host ""
    
    # Show GUI
    Show-NetworkMap -Devices $devices -Connections $connections
}

# Run main
Main

#endregion
