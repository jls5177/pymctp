# pymctp-oem-microsoft

Microsoft OEM extensions for the pymctp library.

This package provides Microsoft-specific MCTP and IPMI layer implementations,
including:

- Microsoft VDM (Vendor Defined Messages) protocols
- Cerberus challenge protocol
- Microsoft-specific IPMI commands
- Custom OEM extensions for Microsoft hardware

## Installation

```bash
pip install pymctp-oem-microsoft
```

## Usage

This package automatically registers its layers with pymctp when imported.
Simply install the package and the layers will be automatically discovered:

```python
import pymctp

# Microsoft layers are automatically available
from pymctp.layers.mctp.vdpci import VdPciHdrPacket
# Microsoft-specific bindings are already registered
```

## Requirements

- pymctp >= 0.1.0

## License

MIT
