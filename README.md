# Network Path Tracer

## Overview
A self-contained PowerShell + WPF network analysis tool that:
- Parses Cisco device configuration files (extensible to other vendors)
- Automatically infers network topology from IP addressing
- Provides interactive visualization
- Traces paths between any two devices
- **Zero external dependencies** - uses only native Windows components

## Requirements
- Windows PowerShell 5.1 or later (built into Windows 10/11)
- No additional modules or software required

## How to Use

### Method 1: Run with Config Folder
```powershell
.\NetworkPathTracer.ps1 -ConfigPath "C:\Path\To\Your\Configs"
```

### Method 2: Run and Select Folder via GUI
```powershell
.\NetworkPathTracer.ps1
```
A folder browser dialog will appear - select your configs folder.

### Method 3: Demo Mode (No Configs)
```powershell
.\NetworkPathTracer.ps1
```
Click "Cancel" on the folder browser to see a demo with sample data.

## Testing with Sample Configs
Sample configuration files are included in the `sample-configs` folder:
- branch-a.txt - Branch office router
- branch-b.txt - Second branch router  
- core-router.txt - Core/aggregation router
- datacenter.txt - Data center router

To test:
```powershell
.\NetworkPathTracer.ps1 -ConfigPath ".\sample-configs"
```

## Supported Config File Types
The tool looks for files with these extensions:
- .txt
- .cfg
- .conf

## What It Parses (Cisco)
Currently supports parsing:
- **Hostname** - Device identification
- **Interfaces** - All interface types (GigabitEthernet, FastEthernet, Vlan, etc.)
- **IP Addresses** - Interface IP and subnet mask
- **Interface Descriptions** - Documentation
- **Interface Status** - Up/down (shutdown command)
- **Static Routes** - ip route statements
- **OSPF** - Basic router ospf detection
- **Device Type** - Inferred from interface types

## How Topology is Inferred

### Layer 3 Connections
Devices are connected if they have interfaces in the same subnet:
- Device A: 10.10.10.1/30
- Device B: 10.10.10.2/30
→ Connection detected!

### Future Enhancements (Ready for Extension)
The code structure is ready for:
- CDP/LLDP neighbor parsing
- BGP peer relationships  
- MPLS VPN detection
- Other vendor configs (Juniper, Arista, etc.)

## GUI Features

### Main Window Components

1. **Toolbar** (Top)
   - Source device dropdown
   - Destination device dropdown
   - "Trace Path" button
   - "Clear" button

2. **Network Canvas** (Middle)
   - Visual topology diagram
   - Devices shown as circles
   - Connections shown as lines
   - Device names and types labeled
   - Zoomable/scrollable

3. **Path Details** (Bottom)
   - Hop-by-hop path information
   - Interface details
   - IP addresses

### How to Trace a Path

1. Select a **Source** device from dropdown
2. Select a **Destination** device from dropdown
3. Click **Trace Path**
4. The path will be highlighted in green
5. Hop-by-hop details appear in the bottom panel

### Visual Indicators
- **Blue circles** = Normal devices
- **Green circles** = Devices in traced path
- **Gray lines** = Network connections
- **Green thick lines** = Active path connections

## Extending for Other Vendors

The code is structured with vendor-agnostic classes and separate parser functions:

```powershell
# Add a new parser function
function Parse-JuniperConfig {
    param([string]$Content, [string]$Filename)
    
    $device = [NetworkDevice]::new("Unknown")
    $device.Vendor = "Juniper"
    
    # Parse Juniper syntax...
    # set system host-name ...
    # set interfaces ge-0/0/0 unit 0 family inet address ...
    
    return $device
}

# Then in the main loop, detect vendor and call appropriate parser
if ($content -match 'set system host-name') {
    $device = Parse-JuniperConfig -Content $content -Filename $file.Name
} else {
    $device = Parse-CiscoConfig -Content $content -Filename $file.Name
}
```

## Architecture

### Data Classes
- `NetworkInterface` - Represents a network interface
- `Route` - Represents a routing table entry
- `NetworkDevice` - Represents a network device (router, switch, etc.)
- `Connection` - Represents a connection between two devices

### Processing Pipeline
1. **Parse Configs** - Extract structured data from text configs
2. **Build Topology** - Infer connections based on IP addressing
3. **Calculate Layout** - Position devices for visualization
4. **Path Finding** - BFS algorithm to find routes
5. **Visualization** - WPF rendering with interactivity

## Limitations

### Current Version
- **Static analysis only** - Based on configs, not live state
- **No dynamic routing state** - Can't simulate OSPF SPF calculations
- **Basic path finding** - Simple shortest path, not metric-aware yet
- **Circular layout** - Simple positioning (can be enhanced)

### Known Gaps (Easy to Add)
- ACL analysis along path
- QoS policy visualization
- VLAN/trunk analysis for switches
- BGP path selection
- More sophisticated layout algorithms (force-directed, hierarchical)

## Troubleshooting

### "No configuration files found"
- Ensure files have .txt, .cfg, or .conf extensions
- Check that the folder path is correct

### "No path found"
- Devices might not be connected via IP addressing
- Check that interface IPs are in the same subnets
- Verify configs were parsed correctly (check console output)

### GUI doesn't appear
- Ensure you're running on Windows
- Verify PowerShell execution policy allows scripts:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```

## Future Enhancement Ideas

### Short Term
- Export topology to Visio/PDF
- Save/load topology data
- Filter devices by type
- Show routing table details
- Interface statistics if available in config

### Medium Term  
- ACL permit/deny analysis
- VLAN topology for switches
- Multiple path display (ECMP)
- Import from network management systems
- Configuration compliance checks

### Long Term
- Live device connection (SSH)
- Compare config vs. running state
- Change impact analysis
- Capacity planning integration
- Integration with monitoring systems

## Contributing

To extend this tool:

1. **Add vendor support**: Create new Parse-*VendorName*Config functions
2. **Enhance topology**: Improve Build-NetworkTopology with CDP/LLDP
3. **Better layouts**: Implement hierarchical or force-directed layouts
4. **More analysis**: Add ACL, QoS, BGP analysis functions
5. **Export options**: Add PDF, Excel, Visio export

## License
This is a demonstration tool. Use and modify as needed for your environment.

## Support
This tool is provided as-is. It demonstrates the approach for network config analysis and visualization using only native Windows components.
