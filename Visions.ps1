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

    NetworkInterface([string]$name) {
        $this.Name = $name
    }
}

class Route {
    [string]$Destination
    [string]$Mask
    [string]$NextHop
    [int]$Metric
    [string]$Protocol
    [string]$ExitInterface
    
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

    $lines = $Content -split "`n"
    $currentInterface = $null
    $currentVRF = "global"

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

        # Parse OSPF
        if ($rxOspf.IsMatch($line)) {
            $device.DeviceType = "Router"
            continue
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
        <StackPanel Grid.Row="0" Orientation="Horizontal" Background="#F0F0F0" Margin="5">
            <Label Content="Source:" VerticalAlignment="Center"/>
            <ComboBox Name="SourceCombo" Width="150" Margin="5"/>
            <Label Content="Destination:" VerticalAlignment="Center" Margin="10,0,0,0"/>
            <ComboBox Name="DestCombo" Width="150" Margin="5"/>
            <Button Name="TraceButton" Content="Trace Path" Width="100" Margin="10,5,5,5" Padding="5"/>
            <Button Name="ClearButton" Content="Clear" Width="80" Margin="5" Padding="5"/>
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

        $srcDevice = $Devices | Where-Object { $_.Hostname -eq $sourceCombo.SelectedItem }
        $dstDevice = $Devices | Where-Object { $_.Hostname -eq $destCombo.SelectedItem }

        $path = Find-Path -Source $srcDevice -Destination $dstDevice -AllDevices $Devices -Connections $Connections

        if ($path.Count -eq 0) {
            $detailsBox.Text = "No path found between $($srcDevice.Hostname) and $($dstDevice.Hostname)"
            Clear-Highlights
            return
        }

        # Clear previous highlights (efficient - no full redraw)
        Clear-Highlights

        # Highlight connections in path (update existing elements + add overlays)
        for ($i = 0; $i -lt $path.Count - 1; $i++) {
            $dev1Name = $path[$i]
            $dev2Name = $path[$i + 1]

            $conn = $Connections | Where-Object {
                ($_.Device1.Hostname -eq $dev1Name -and $_.Device2.Hostname -eq $dev2Name) -or
                ($_.Device2.Hostname -eq $dev1Name -and $_.Device1.Hostname -eq $dev2Name)
            } | Select-Object -First 1

            if ($conn) {
                # Create highlight overlay line
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

        # Highlight devices in path (update existing elements + add overlays)
        foreach ($deviceName in $path) {
            $device = $Devices | Where-Object { $_.Hostname -eq $deviceName }

            # Update existing device element colors
            if ($script:deviceElements.ContainsKey($deviceName)) {
                $script:deviceElements[$deviceName].Ellipse.Fill = [System.Windows.Media.Brushes]::LightGreen
                $script:deviceElements[$deviceName].Ellipse.Stroke = [System.Windows.Media.Brushes]::DarkGreen
                $script:deviceElements[$deviceName].Ellipse.StrokeThickness = 3
            }
        }

        # Display path details
        $details = "Path from $($srcDevice.Hostname) to $($dstDevice.Hostname):`n"
        $details += "=" * 60 + "`n`n"

        for ($i = 0; $i -lt $path.Count; $i++) {
            $deviceName = $path[$i]
            $device = $Devices | Where-Object { $_.Hostname -eq $deviceName }

            $details += "Hop $($i + 1): $deviceName ($($device.DeviceType))`n"

            if ($i -lt $path.Count - 1) {
                $nextDevice = $path[$i + 1]
                $conn = $Connections | Where-Object {
                    ($_.Device1.Hostname -eq $deviceName -and $_.Device2.Hostname -eq $nextDevice) -or
                    ($_.Device2.Hostname -eq $deviceName -and $_.Device1.Hostname -eq $nextDevice)
                } | Select-Object -First 1

                if ($conn) {
                    $ifaceName = if ($conn.Device1.Hostname -eq $deviceName) { $conn.Interface1 } else { $conn.Interface2 }
                    $iface = $device.Interfaces[$ifaceName]
                    if ($iface) {
                        $details += "  Exit Interface: $ifaceName ($($iface.IPAddress)"
                        if ($iface.VRF -ne "global") {
                            $details += " [VRF: $($iface.VRF)]"
                        }
                        $details += ")`n"
                    }
                }
                $details += "`n"
            }
        }

        $detailsBox.Text = $details
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
