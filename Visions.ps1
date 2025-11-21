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
    [hashtable]$OSPFProcesses = @{}  # ProcessID -> OSPFProcess
    [int]$BGP_ASN = 0
    [string]$BGP_RouterID

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

    OSPFProcess([int]$pid) {
        $this.ProcessID = $pid
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

            # Determine device type from interfaces
            if ($ifaceName -match '^(TenGigabitEthernet|GigabitEthernet|FastEthernet|Ethernet)') {
                if ($device.DeviceType -eq "Unknown") {
                    $device.DeviceType = "Router"
                }
            }
            if ($ifaceName -match '^Vlan') {
                $device.DeviceType = "Switch"
            }
            if ($rxTunnelInterface.IsMatch($ifaceName)) {
                $device.DeviceType = "Router"
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

        # Parse OSPF process
        $m = $rxOSPFProcess.Match($line)
        if ($m.Success) {
            $processID = [int]$m.Groups[1].Value
            $vrfName = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { "global" }
            $currentOSPF = [OSPFProcess]::new($processID)
            $currentOSPF.VRF = $vrfName
            $device.OSPFProcesses[$processID] = $currentOSPF
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

    return $device
}

function ConvertTo-CIDR {
    param([string]$SubnetMask)
    
    $octets = $SubnetMask -split '\.'
    $binary = ($octets | ForEach-Object { [Convert]::ToString([int]$_, 2).PadLeft(8, '0') }) -join ''
    return ($binary.ToCharArray() | Where-Object { $_ -eq '1' }).Count
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
        [string]$VRF = "global"
    )

    $routingTable = @()

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
    # This would require BGP RIB which we don't have from static configs

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

    foreach ($device in $Devices) {
        foreach ($iface in $device.Interfaces.Values) {
            # Skip interfaces without IP addresses
            if (-not $iface.IPAddress -or -not $iface.Network) { continue }

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
        }
    }

    # Now find connections only within same VRF+subnet (much faster!)
    foreach ($key in $subnetMap.Keys) {
        $members = $subnetMap[$key]

        # Need at least 2 devices in same subnet to create connection
        if ($members.Count -lt 2) { continue }

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

    return $connections
}

function Calculate-Layout {
    param([System.Collections.ArrayList]$Devices, [array]$Connections)
    
    # Simple circular layout
    $centerX = 400
    $centerY = 300
    $radius = 200
    
    for ($i = 0; $i -lt $Devices.Count; $i++) {
        $angle = ($i / $Devices.Count) * 2 * [Math]::PI
        $Devices[$i].X = $centerX + ($radius * [Math]::Cos($angle))
        $Devices[$i].Y = $centerY + ($radius * [Math]::Sin($angle))
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

    while ($hopCount -lt $MaxHops) {
        $hopCount++

        # Add current device to path
        $pathHop = @{
            Device = $currentDevice
            HopNumber = $hopCount
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

        # Build routing table for current device
        # Need to determine VRF - use first interface's VRF or global
        $deviceVRF = "global"
        if ($currentDevice.Interfaces.Count -gt 0) {
            $firstIface = $currentDevice.Interfaces.Values | Select-Object -First 1
            if ($firstIface.VRF) {
                $deviceVRF = $firstIface.VRF
            }
        }

        $routingTable = Build-RoutingTable -Device $currentDevice -VRF $deviceVRF
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
                        $pathHop.Reason = "Route to $($bestRoute.Destination)/$($ConvertTo-CIDR -SubnetMask $bestRoute.Mask) via $nextHopIP [Protocol: $($bestRoute.Protocol), AD: $($bestRoute.AdminDistance), Metric: $($bestRoute.Metric)]"
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
                $routingTable = Build-RoutingTable -Device $device -VRF $exitIface.VRF
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
            </StackPanel>
            <!-- Second row: IP specification -->
            <StackPanel Orientation="Horizontal" Margin="0,0,0,5">
                <Label Content="Source IP:" VerticalAlignment="Center" Width="100"/>
                <TextBox Name="SourceIPBox" Width="120" Margin="5,0,0,0" Text="10.10.10.100" VerticalContentAlignment="Center"/>
                <Label Content="Destination IP:" VerticalAlignment="Center" Margin="20,0,0,0" Width="130"/>
                <TextBox Name="DestIPBox" Width="120" Margin="5,0,0,0" Text="10.20.20.100" VerticalContentAlignment="Center"/>
                <CheckBox Name="UseRoutingCheckBox" Content="Use Routing Tables" VerticalAlignment="Center" Margin="20,0,0,0" IsChecked="True"/>
            </StackPanel>
        </StackPanel>
        
        <!-- Canvas for network diagram -->
        <Border Grid.Row="1" BorderBrush="#CCCCCC" BorderThickness="1" Margin="5">
            <ScrollViewer HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto">
                <Canvas Name="NetworkCanvas" Background="White" Width="800" Height="600"/>
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
    $sourceCombo = $window.FindName("SourceCombo")
    $destCombo = $window.FindName("DestCombo")
    $sourceIPBox = $window.FindName("SourceIPBox")
    $destIPBox = $window.FindName("DestIPBox")
    $useRoutingCheckBox = $window.FindName("UseRoutingCheckBox")
    $traceButton = $window.FindName("TraceButton")
    $clearButton = $window.FindName("ClearButton")
    $detailsBox = $window.FindName("DetailsBox")
    
    # Populate combo boxes
    foreach ($device in $Devices) {
        [void]$sourceCombo.Items.Add($device.Hostname)
        [void]$destCombo.Items.Add($device.Hostname)
    }
    
    # Store UI element references for efficient updates (avoids full redraw)
    $script:deviceElements = @{}
    $script:connectionElements = @{}
    $script:highlightElements = @()

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
        # Remove highlight elements
        foreach ($elem in $script:highlightElements) {
            [void]$canvas.Children.Remove($elem)
        }
        $script:highlightElements.Clear()

        # Reset connection colors
        foreach ($line in $script:connectionElements.Values) {
            $line.Stroke = [System.Windows.Media.Brushes]::Gray
            $line.StrokeThickness = 2
        }

        # Reset device colors
        foreach ($devElements in $script:deviceElements.Values) {
            $devElements.Ellipse.Fill = [System.Windows.Media.Brushes]::LightBlue
            $devElements.Ellipse.Stroke = [System.Windows.Media.Brushes]::DarkBlue
            $devElements.Ellipse.StrokeThickness = 2
        }
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
                }
            }

            # Highlight devices in path
            foreach ($deviceName in $path) {
                if ($script:deviceElements.ContainsKey($deviceName)) {
                    $script:deviceElements[$deviceName].Ellipse.Fill = [System.Windows.Media.Brushes]::LightGreen
                    $script:deviceElements[$deviceName].Ellipse.Stroke = [System.Windows.Media.Brushes]::DarkGreen
                    $script:deviceElements[$deviceName].Ellipse.StrokeThickness = 3
                }
            }

            # Display routing-aware path details
            $details = "ROUTING-AWARE PATH TRACE`n"
            $details += "Source: $($srcDevice.Hostname) ($sourceIP)`n"
            $details += "Destination: $destIP`n"
            $details += "=" * 80 + "`n`n"

            $currentIP = $sourceIP
            foreach ($hop in $routingPath) {
                $details += "Hop $($hop.HopNumber): $($hop.Device.Hostname) ($($hop.Device.Type))`n"
                $details += "  Current Source IP: $currentIP`n"

                if ($hop.ExitInterface) {
                    $details += "  Exit Interface: $($hop.ExitInterface) ($($hop.ExitIP))"
                    if ($hop.VRF -ne "global") {
                        $details += " [VRF: $($hop.VRF)]"
                    }
                    $details += "`n"
                    $details += "  [Routing] $($hop.Reason)`n"

                    if ($hop.NextHop) {
                        $details += "  Next Hop: $($hop.NextHop)`n"
                    }

                    # Run comprehensive analysis for this hop
                    $device = $hop.Device
                    $outInterface = $device.Interfaces | Where-Object { $_.Name -eq $hop.ExitInterface } | Select-Object -First 1

                    # Check for NAT translation
                    if ($outInterface -and $outInterface.NATOutside) {
                        $natResult = Apply-NATTranslation -Device $device -SourceIP $currentIP -Interface $hop.ExitInterface
                        if ($natResult.Translated) {
                            $details += "  [NAT] $currentIP -> $($natResult.NewIP) ($($natResult.Type))`n"
                            $currentIP = $natResult.NewIP
                        }
                    }

                    # Check for ACL
                    if ($outInterface -and $outInterface.ACL_Out) {
                        $acl = $device.ACLs[$outInterface.ACL_Out]
                        if ($acl) {
                            $aclResult = Test-ACLMatch -ACL $acl -SourceIP $currentIP -DestIP $destIP
                            if ($aclResult.Action -eq "deny") {
                                $details += "  [ACL-DENY] Outbound ACL ($($acl.Name)): DENIED - $($aclResult.Reason)`n"
                                $details += "`n  *** PATH BLOCKED AT THIS HOP ***`n"
                                $details += "`n" + "=" * 80 + "`n"
                                $details += "RESULT: Traffic DENIED - path blocked by ACL/firewall`n"
                                $detailsBox.Text = $details
                                return
                            } else {
                                $details += "  [ACL-PERMIT] Outbound ACL ($($acl.Name)): PERMITTED`n"
                            }
                        }
                    }

                    # Check for QoS
                    if ($outInterface -and $outInterface.ServicePolicy_Out) {
                        $qosResult = Get-QoSMarking -Device $device -PolicyMapName $outInterface.ServicePolicy_Out
                        if ($qosResult.Applied) {
                            $details += "  [QoS] Policy $($qosResult.PolicyMap) applied`n"
                        }
                    }

                    # Display BGP info
                    if ($device.BGP_ASN) {
                        $neighborCount = ($device.BGPNeighbors | Where-Object { $_.VRF -eq $hop.VRF }).Count
                        if ($neighborCount -gt 0) {
                            $details += "  [BGP] AS$($device.BGP_ASN) configured ($neighborCount neighbors)`n"
                        }
                    }

                    # Display OSPF info
                    if ($device.OSPFProcesses.Count -gt 0) {
                        $ospfProcs = ($device.OSPFProcesses.Values | Where-Object { $_.VRF -eq $hop.VRF -or ($_.VRF -eq "global" -and $hop.VRF -eq "global") })
                        if ($ospfProcs.Count -gt 0) {
                            $procIDs = ($ospfProcs | ForEach-Object { $_.ProcessID }) -join ", "
                            $details += "  [OSPF] Process(es): $procIDs`n"
                        }
                    }
                }

                if ($hop.Error) {
                    $details += "  ERROR: $($hop.Error)`n"
                    $details += "`n  *** PATH CANNOT CONTINUE ***`n"
                    $details += "`n" + "=" * 80 + "`n"
                    $details += "RESULT: Path FAILED - $($hop.Error)`n"
                    $detailsBox.Text = $details
                    return
                }

                $details += "`n"
            }

            $details += "=" * 80 + "`n"
            $details += "RESULT: Path is VALID - traffic would be forwarded successfully`n"
            $details += "`nPATH STATISTICS:`n"
            $details += "  Total Hops: $($routingPath.Count)`n"
            $details += "  Routing Decision: Based on routing tables (longest prefix match)`n"

            $detailsBox.Text = $details

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
                }
            }

            # Highlight devices in path
            foreach ($deviceName in $path) {
                if ($script:deviceElements.ContainsKey($deviceName)) {
                    $script:deviceElements[$deviceName].Ellipse.Fill = [System.Windows.Media.Brushes]::LightGreen
                    $script:deviceElements[$deviceName].Ellipse.Stroke = [System.Windows.Media.Brushes]::DarkGreen
                    $script:deviceElements[$deviceName].Ellipse.StrokeThickness = 3
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
        }
    })
    
    # Clear button handler
    $clearButton.Add_Click({
        Clear-Highlights
        $detailsBox.Text = ""
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
