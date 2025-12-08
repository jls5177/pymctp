# pymctp-sample-vendorextension

**Sample vendor extension for pymctp** - A complete example demonstrating how to create custom MCTP vendor-specific layers.

This package serves as a reference implementation for creating your own vendor extensions for pymctp. Use it as a template to build your own company-specific MCTP protocol implementations.

## What This Demonstrates

- ✅ Creating custom VDM (Vendor Defined Message) packets
- ✅ Auto-binding custom packets to MCTP transport layers
- ✅ Registering as a pymctp extension via entry points
- ✅ **Extending the pymctp CLI with custom commands**
- ✅ Proper package structure and organization
- ✅ Documentation and examples

## Installation

```bash
pip install pymctp-sample-vendorextension
```

## Usage

Once installed, the extension is automatically discovered and loaded by pymctp:

```python
import pymctp
from pymctp.layers import __all_extensions__

# Verify the extension is loaded
print(__all_extensions__)  # Should include 'sample-vendor'

# Use the custom packet types
from pymctp_sample_vendorextension.layers.mctp import SampleVendorPacket
from pymctp.layers.mctp.vdpci import VdPciHdrPacket

# Create a packet with your custom vendor ID
pkt = VdPciHdrPacket(vendor_id=0x9999, rq=1, vdm_cmd_code=0x01) / \
      SampleVendorPacket(command=0x10, data=b"Hello")

print(pkt.summary())
```

### CLI Commands

This extension also adds custom commands to the `pymctp` CLI:

```bash
# Display sample vendor protocol information
pymctp sample-vendor info

# Craft a get-version request packet
pymctp sample-vendor get-version-request --component-id 1

# Craft a custom vendor packet
pymctp craft-sample-vendor --command 0x10 --data "deadbeef"
```

Run `pymctp --help` to see all available commands including those from extensions.

## Creating Your Own Extension

This package demonstrates the complete structure needed for a vendor extension:

### 1. Package Structure

```
your-extension/
├── pyproject.toml                    # Package metadata and entry points
├── README.md
└── src/
    └── your_package_name/
        ├── __init__.py
        ├── __about__.py
        ├── layers/
        │   ├── __init__.py           # Layer entry point target
        │   └── mctp/
        │       ├── __init__.py
        │       └── your_protocol.py  # Your custom packets
        └── cli/                      # Optional CLI extensions
            ├── __init__.py
            └── commands.py           # Your CLI commands
```

### 2. Define Custom Packets

```python
# your_protocol.py
from scapy.packet import Packet
from scapy.fields import XByteField, ByteField
from pymctp.layers.mctp.vdpci import VdPciHdrPacket
from scapy.packet import bind_layers

# Your vendor ID (get official ID from PCI-SIG)
YOUR_VENDOR_ID = 0x9999

class YourVendorPacket(Packet):
    name = "YOUR-VENDOR"
    fields_desc = [
        XByteField("command", 0),
        ByteField("status", 0),
        # Add your fields here
    ]

# Bind to MCTP VDM layer
bind_layers(VdPciHdrPacket, YourVendorPacket,
            vendor_id=YOUR_VENDOR_ID,
            vdm_cmd_code=0x01)
```

### 3. Create CLI Commands (Optional)

```python
# cli/commands.py
import click

@click.command()
def my_command():
    """My vendor-specific command."""
    click.echo("Hello from my extension!")
```

### 4. Register Entry Points

In `pyproject.toml`:

```toml
# Register layer extensions
[project.entry-points."pymctp.extensions"]
your-company = "your_package_name.layers"

# Register CLI commands (optional)
[project.entry-points."pymctp.cli_commands"]
my-command = "your_package_name.cli.commands:my_command"
```

### 5. Create layers/__init__.py

```python
# layers/__init__.py
"""Your company layer definitions.

This module is automatically loaded by pymctp's plugin system.
"""

from .mctp import *

__all__ = []
```

## Example: Custom Vendor Protocol

This package includes a complete example of a custom vendor protocol implementation. See the source code in `src/pymctp_sample_vendorextension/layers/mctp/` for details.

## Files in This Package

### Layer Extensions
- **`layers/mctp/sample_vendor.py`** - Example custom VDM packet definitions
- **`layers/__init__.py`** - Auto-registers layers with pymctp

### CLI Extensions
- **`cli/sample_commands.py`** - Example CLI commands and command groups
- Shows both single commands and command groups
- Demonstrates packet crafting utilities

### Configuration
- **`pyproject.toml`** - Entry point registration for both layers and CLI
- **`__about__.py`** - Version information

## Learning More

- [Extension Development Guide](../../EXTENSIONS.md) - Layer extensions
- [CLI Extensions Guide](../../CLI-EXTENSIONS.md) - CLI command extensions
- [pymctp Documentation](../../packages/pymctp/README.md)
- [MCTP Specification](https://www.dmtf.org/standards/pmci)

## License

MIT - This is sample code, feel free to use it as a template for your own extensions!
