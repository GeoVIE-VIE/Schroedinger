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
    
    $lines = $Content -split "`n"
    $currentInterface = $null
    
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        
        # Parse hostname
        if ($line -match '^hostname\s+(.+)$') {
            $device.Hostname = $matches[1].Trim()
        }
        
        # Parse interface
        if ($line -match '^interface\s+(.+)$') {
            $ifaceName = $matches[1].Trim()
            $currentInterface = [NetworkInterface]::new($ifaceName)
            $device.Interfaces[$ifaceName] = $currentInterface
            
            # Determine device type from interfaces
            if ($ifaceName -match '^(GigabitEthernet|FastEthernet|Ethernet)') {
                if ($device.DeviceType -eq "Unknown") {
                    $device.DeviceType = "Router"
                }
            }
            if ($ifaceName -match '^Vlan') {
                $device.DeviceType = "Switch"
            }
        }
        
        # Parse IP address
        if ($currentInterface -and $line -match '^\s*ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)') {
            $currentInterface.IPAddress = $matches[1]
            $currentInterface.SubnetMask = $matches[2]
            $currentInterface.CIDR = ConvertTo-CIDR -SubnetMask $matches[2]
            $currentInterface.Network = Get-NetworkAddress -IP $matches[1] -Mask $matches[2]
        }
        
        # Parse interface description
        if ($currentInterface -and $line -match '^\s*description\s+(.+)$') {
            $currentInterface.Description = $matches[1].Trim()
        }
        
        # Parse interface shutdown status
        if ($currentInterface -and $line -match '^\s*shutdown\s*$') {
            $currentInterface.Status = "down"
        }
        
        # Parse static routes
        if ($line -match '^ip route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?') {
            $route = [Route]::new($matches[1], $matches[2], $matches[3])
            $route.Protocol = "Static"
            if ($matches[4]) {
                $route.Metric = [int]$matches[4]
            }
            [void]$device.Routes.Add($route)
        }
        
        # Parse OSPF
        if ($line -match '^router ospf') {
            $device.DeviceType = "Router"
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
    
    # Find L3 connections by matching subnets
    for ($i = 0; $i -lt $Devices.Count; $i++) {
        for ($j = $i + 1; $j -lt $Devices.Count; $j++) {
            $dev1 = $Devices[$i]
            $dev2 = $Devices[$j]
            
            foreach ($if1 in $dev1.Interfaces.Values) {
                if (-not $if1.IPAddress) { continue }
                
                foreach ($if2 in $dev2.Interfaces.Values) {
                    if (-not $if2.IPAddress) { continue }
                    
                    if (Test-SameSubnet -IP1 $if1.IPAddress -Mask1 $if1.SubnetMask `
                                       -IP2 $if2.IPAddress -Mask2 $if2.SubnetMask) {
                        
                        $conn = [Connection]::new($dev1, $dev2)
                        $conn.Interface1 = $if1.Name
                        $conn.Interface2 = $if2.Name
                        $conn.ConnectionType = "L3"
                        $connections += $conn
                    }
                }
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
    
    # Draw network topology
    function Draw-Topology {
        $canvas.Children.Clear()
        
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
            $canvas.Children.Add($line)
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
            $canvas.Children.Add($ellipse)
            
            # Device label
            $textBlock = New-Object System.Windows.Controls.TextBlock
            $textBlock.Text = $device.Hostname
            $textBlock.FontSize = 11
            $textBlock.FontWeight = [System.Windows.FontWeights]::Bold
            $textBlock.TextAlignment = [System.Windows.TextAlignment]::Center
            $textBlock.Width = 100
            [System.Windows.Controls.Canvas]::SetLeft($textBlock, $device.X - 50)
            [System.Windows.Controls.Canvas]::SetTop($textBlock, $device.Y + 35)
            $canvas.Children.Add($textBlock)
            
            # Device type label
            $typeLabel = New-Object System.Windows.Controls.TextBlock
            $typeLabel.Text = $device.DeviceType
            $typeLabel.FontSize = 9
            $typeLabel.Foreground = [System.Windows.Media.Brushes]::Gray
            $typeLabel.TextAlignment = [System.Windows.TextAlignment]::Center
            $typeLabel.Width = 100
            [System.Windows.Controls.Canvas]::SetLeft($typeLabel, $device.X - 50)
            [System.Windows.Controls.Canvas]::SetTop($typeLabel, $device.Y + 50)
            $canvas.Children.Add($typeLabel)
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
            Draw-Topology
            return
        }
        
        # Highlight path
        Draw-Topology
        
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
                $canvas.Children.Add($line)
            }
        }
        
        # Highlight devices in path
        foreach ($deviceName in $path) {
            $device = $Devices | Where-Object { $_.Hostname -eq $deviceName }
            $ellipse = New-Object System.Windows.Shapes.Ellipse
            $ellipse.Width = 60
            $ellipse.Height = 60
            $ellipse.Fill = [System.Windows.Media.Brushes]::LightGreen
            $ellipse.Stroke = [System.Windows.Media.Brushes]::DarkGreen
            $ellipse.StrokeThickness = 3
            [System.Windows.Controls.Canvas]::SetLeft($ellipse, $device.X - 30)
            [System.Windows.Controls.Canvas]::SetTop($ellipse, $device.Y - 30)
            $canvas.Children.Add($ellipse)
            
            # Re-add label
            $textBlock = New-Object System.Windows.Controls.TextBlock
            $textBlock.Text = $device.Hostname
            $textBlock.FontSize = 11
            $textBlock.FontWeight = [System.Windows.FontWeights]::Bold
            $textBlock.TextAlignment = [System.Windows.TextAlignment]::Center
            $textBlock.Width = 100
            [System.Windows.Controls.Canvas]::SetLeft($textBlock, $device.X - 50)
            [System.Windows.Controls.Canvas]::SetTop($textBlock, $device.Y + 35)
            $canvas.Children.Add($textBlock)
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
                        $details += "  Exit Interface: $ifaceName ($($iface.IPAddress))`n"
                    }
                }
                $details += "`n"
            }
        }
        
        $detailsBox.Text = $details
    })
    
    # Clear button handler
    $clearButton.Add_Click({
        Draw-Topology
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
        Write-Host "  Parsing: $($file.Name)..." -ForegroundColor Gray
        $content = Get-Content -Path $file.FullName -Raw
        
        # Detect vendor (currently only Cisco, but extensible)
        $device = Parse-CiscoConfig -Content $content -Filename $file.Name
        [void]$devices.Add($device)
        
        Write-Host "    Device: $($device.Hostname) | Type: $($device.DeviceType) | Interfaces: $($device.Interfaces.Count)" -ForegroundColor Gray
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
