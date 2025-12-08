# pymctp-sample-vendorextension

**Sample vendor extension for pymctp** - A complete example demonstrating how to create custom MCTP vendor-specific layers.

This package serves as a reference implementation for creating your own vendor extensions for pymctp. Use it as a template to build your own company-specific MCTP protocol implementations.

## What This Demonstrates

- ✅ Creating custom VDM (Vendor Defined Message) packets
- ✅ Auto-binding custom packets to MCTP transport layers
- ✅ Registering as a pymctp extension via entry points
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

## Creating Your Own Extension

This package demonstrates the complete structure needed for a vendor extension:

### 1. Package Structure

```
your-extension/
├── pyproject.toml                    # Package metadata and entry point
├── README.md
└── src/
    └── your_package_name/
        ├── __init__.py
        ├── __about__.py
        └── layers/
            ├── __init__.py           # Entry point target
            └── mctp/
                ├── __init__.py
                └── your_protocol.py  # Your custom packets
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

### 3. Register Entry Point

In `pyproject.toml`:

```toml
[project.entry-points."pymctp.extensions"]
your-company = "your_package_name.layers"
```

### 4. Create layers/__init__.py

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

- **`sample_vendor.py`** - Example custom VDM packet definitions
- **`layers/__init__.py`** - Auto-registers layers with pymctp
- **`__about__.py`** - Version information

## Learning More

- [Extension Development Guide](../../EXTENSIONS.md)
- [pymctp Documentation](../../packages/pymctp/README.md)
- [MCTP Specification](https://www.dmtf.org/standards/pmci)

## License

MIT - This is sample code, feel free to use it as a template for your own extensions!
