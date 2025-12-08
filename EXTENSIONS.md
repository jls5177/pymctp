<!--
SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>

SPDX-License-Identifier: MIT
-->

# PyMCTP Extension Development Guide

This guide explains how to create and distribute pymctp extensions for OEM-specific or custom MCTP/IPMI layer implementations.

## Table of Contents

- [Overview](#overview)
- [Extension Architecture](#extension-architecture)
- [Creating an Extension](#creating-an-extension)
- [Package Structure](#package-structure)
- [Registering Your Extension](#registering-your-extension)
- [Testing Your Extension](#testing-your-extension)
- [Publishing Your Extension](#publishing-your-extension)
- [CLI Extensions](#cli-extensions)

## Overview

PyMCTP uses Python's entry points mechanism to automatically discover and load extensions. Extensions are separate Python packages that register themselves via the `pymctp.extensions` entry point group.

When pymctp is imported, it automatically:
1. Discovers all registered extensions via entry points
2. Imports the registered modules
3. Registers extensions into the pymctp namespace (e.g., pymctp.oem.microsoft)
4. Allows the extension's layer bindings to register automatically via decorators

This design keeps OEM-specific code separate from the core library while maintaining seamless integration.

Extensions are automatically accessible under the `pymctp.oem` namespace based on their entry point name:
- Entry point `microsoft` → `pymctp.oem.microsoft`
- Entry point `sample-vendor` → `pymctp.oem.sample_vendor` (hyphens converted to underscores)

## Extension Architecture

PyMCTP's layer binding system uses decorators that automatically register Scapy layer bindings:

- `@AutobindMessageType(msg_type)` - Binds a message header to MCTP transport layer
- `@AutobindControlMsg(cmd_code)` - Binds a control message to ControlHdrPacket
- `@AutobindPLDMMsg(pldm_type, cmd_code)` - Binds a PLDM message to PldmHdrPacket
- `@AutobindVDMMsg(vendor_id, cmd_code)` - Binds a VDM message to VdPciHdrPacket

You can also use Scapy's `bind_layers()` directly for more complex bindings.

## Creating an Extension

### Step 1: Set Up Package Structure

Create a new Python package with the following structure:

```
your-extension/
├── pyproject.toml
├── README.md
└── src/
    └── your_package_name/
        ├── __init__.py
        ├── __about__.py
        └── layers/
            ├── __init__.py
            ├── ipmi/
            │   ├── __init__.py
            │   └── your_ipmi_layers.py
            └── mctp/
                ├── __init__.py
                └── your_mctp_layers.py
```

### Step 2: Implement Your Layers

Create your layer definitions using pymctp's base classes:

```python
# src/your_package_name/layers/mctp/your_mctp_layers.py

from scapy.packet import Packet, bind_layers
from scapy.fields import XByteField, XLEShortField

from pymctp.layers.mctp import VdPciHdrPacket
from pymctp.layers.mctp.vdpci import VdPCIVendorIds, AutobindVDMMsg

# Define your vendor ID (if not already in VdPCIVendorIds)
YOUR_VENDOR_ID = 0x1234

# Define your packet class
class YourVendorPacket(Packet):
    name = "YOUR-VENDOR"
    fields_desc = [
        XByteField("command", 0),
        XLEShortField("param", 0),
    ]

# Bind it to the VDM header using the decorator
from pymctp.layers.mctp.vdpci.vdpci import AutobindVDMMsg

# Or use decorator approach if AutobindVDMMsg is available as a class decorator:
# @AutobindVDMMsg(YOUR_VENDOR_ID, 0x00)
# class YourVendorPacket(Packet):
#     ...

# Or bind directly:
bind_layers(VdPciHdrPacket, YourVendorPacket,
            vendor_id=YOUR_VENDOR_ID,
            vdm_cmd_code=0x00)
```

### Step 3: Create Layer Exports

In your `layers/__init__.py`, import all your layer modules:

```python
# src/your_package_name/layers/__init__.py

"""Your extension layer definitions.

This module is automatically loaded by pymctp's plugin system.
"""

from .ipmi import *
from .mctp import *

__all__ = []
```

### Step 4: Configure pyproject.toml

Register your extension using the `pymctp.extensions` entry point:

```toml
[project]
name = "pymctp-your-extension"
version = "0.1.0"
description = "Your description"
requires-python = ">=3.8"
dependencies = [
    "pymctp>=0.1.0",
]

# Register as a pymctp extension
[project.entry-points."pymctp.extensions"]
your_extension = "your_package_name.layers"
```

The entry point name (`your_extension`) can be any unique identifier. The value must point to the module that imports all your layer definitions.

## Package Structure

### Recommended Structure

```
pymctp-oem-yourcompany/
├── README.md                    # Package documentation
├── LICENSE                      # License file
├── pyproject.toml              # Package configuration
└── src/
    └── pymctp_oem_yourcompany/
        ├── __init__.py         # Package root
        ├── __about__.py        # Version info
        └── layers/
            ├── __init__.py     # Import all layers (entry point target)
            ├── ipmi/
            │   ├── __init__.py
            │   └── *.py        # IPMI layer implementations
            └── mctp/
                ├── __init__.py
                └── vdpci/      # Or other protocol dirs
                    ├── __init__.py
                    └── *.py    # MCTP layer implementations
```

### Naming Conventions

- Package name: `pymctp-<category>-<name>` (e.g., `pymctp-oem-microsoft`)
- Python module: Use underscores instead of hyphens (e.g., `pymctp_oem_microsoft`)
- Entry point name: Short, descriptive (e.g., `microsoft`, `intel`, `custom`)

## Registering Your Extension

The critical part is the entry point registration in `pyproject.toml`:

```toml
[project.entry-points."pymctp.extensions"]
your_name = "your_module.layers"
```

This tells pymctp:
- Entry point group: `pymctp.extensions` (required, must be exact)
- Extension name: `your_name` (can be any unique identifier)
- Module to load: `your_module.layers` (must be importable)

When this module is imported, all its layer definitions and bindings are registered automatically.

## Testing Your Extension

### Local Development

Install both packages in editable mode:

```bash
# Install core pymctp in editable mode
cd /path/to/pymctp
pip install -e .

# Install your extension in editable mode
cd /path/to/your-extension
pip install -e .
```

### Verify Auto-Discovery

Test that your extension is discovered:

```python
import pymctp

# Check if your extension was loaded
from pymctp.layers import __all_extensions__
print(__all_extensions__)  # Should include your extension name

# Access your extension via the pymctp namespace
# If your entry point is 'microsoft', it will be at:
from pymctp.oem.microsoft import YourCustomLayer

# Or for 'sample-vendor' entry point:
from pymctp.oem.sample_vendor import YourCustomLayer

# Test your layers
from pymctp.layers.mctp.vdpci import VdPciHdrPacket

# Your bindings should work automatically
data = b'...'  # Your test data
pkt = VdPciHdrPacket(data)
print(pkt.summary())
```

### Unit Tests

Create tests for your layers:

```python
# tests/test_your_layers.py

import pytest
from scapy.compat import raw
from pymctp.layers.mctp.vdpci import VdPciHdrPacket
from your_package_name.layers.mctp import YourVendorPacket

def test_your_vendor_packet_decode():
    # Test data
    data = b'...'

    # Decode
    pkt = VdPciHdrPacket(data)

    # Verify layer binding worked
    assert isinstance(pkt.payload, YourVendorPacket)
    assert pkt.payload.command == 0x01

def test_your_vendor_packet_encode():
    # Create packet
    pkt = VdPciHdrPacket(...) / YourVendorPacket(command=0x01)

    # Encode
    raw_bytes = raw(pkt)

    # Verify
    assert raw_bytes == b'...'
```

## Publishing Your Extension

### Option 1: Private Distribution

For internal use, you can:
- Host on a private PyPI server
- Install from a git repository: `pip install git+https://github.com/yourorg/your-extension.git`
- Distribute as wheel files: `python -m build` then share the `.whl` file

### Option 2: Public PyPI

1. Build your package:
   ```bash
   python -m build
   ```

2. Publish to PyPI:
   ```bash
   python -m twine upload dist/*
   ```

3. Users can then install:
   ```bash
   pip install pymctp-your-extension
   ```

## Example: Sample Vendor Extension

See the [pymctp-sample-vendorextension](packages/pymctp-sample-vendorextension) package for a complete working example that demonstrates:

- Proper package structure
- Custom VDM (Vendor Defined Message) packet definitions
- Layer bindings with `bind_layers()`
- Entry point registration
- Documentation and comments
- Complete example implementation

Key files to review:
- [pyproject.toml](packages/pymctp-sample-vendorextension/pyproject.toml) - Entry point configuration
- [layers/__init__.py](packages/pymctp-sample-vendorextension/src/pymctp_sample_vendorextension/layers/__init__.py) - Entry point target
- [layers/mctp/sample_vendor.py](packages/pymctp-sample-vendorextension/src/pymctp_sample_vendorextension/layers/mctp/sample_vendor.py) - Complete packet definitions and bindings
- [README.md](packages/pymctp-sample-vendorextension/README.md) - Usage guide

## Troubleshooting

### Extension Not Loading

1. Verify entry point is registered correctly in `pyproject.toml`
2. Check the module path is correct and importable
3. Ensure the extension package is installed: `pip list | grep pymctp`
4. Enable logging to see load errors:
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   from pymctp.layers.plugin_loader import discover_and_load_extensions
   discover_and_load_extensions()
   ```

### Import Errors

- Ensure `pymctp` is listed in your extension's `dependencies`
- Verify all pymctp imports use absolute paths: `from pymctp.layers import ...`
- Don't use relative imports to reference pymctp code

### Layer Bindings Not Working

- Verify your decorators or `bind_layers()` calls are executed when the module is imported
- Check that you're using the correct field names and values for binding
- Test layer bindings explicitly:
  ```python
  from scapy.layers.all import bind_layers
  from pymctp.layers.mctp.vdpci import VdPciHdrPacket

  # Check if binding exists
  print(VdPciHdrPacket._overload_fields)
  ```

## CLI Extensions

In addition to layer extensions, you can also extend the `pymctp` command-line interface with custom commands!

Extension packages can add their own CLI commands that automatically appear in the `pymctp` command-line tool. This is useful for vendor-specific analysis tools, packet crafting utilities, or custom workflows.

### Quick Example

Add CLI commands to your extension by:

1. Creating Click commands in your package:
```python
# your_package/cli/commands.py
import click

@click.command()
def my_command():
    """My custom command."""
    click.echo("Hello from my extension!")
```

2. Registering them in `pyproject.toml`:
```toml
[project.entry-points."pymctp.cli_commands"]
my-command = "your_package.cli.commands:my_command"
```

3. Installing your package:
```bash
pip install your-package
pymctp my-command  # Your command is now available!
```

### Full Documentation

For complete details on creating CLI extensions, including:
- Single commands vs. command groups
- Best practices for naming and organization
- Error handling and help text
- Complete examples

See the dedicated [CLI-EXTENSIONS.md](CLI-EXTENSIONS.md) guide.

### Example Implementation

The [pymctp-sample-vendorextension](packages/pymctp-sample-vendorextension) package includes example CLI extensions:
- Single command: `craft-sample-vendor`
- Command group: `sample-vendor` with subcommands

Check these files:
- [cli/sample_commands.py](packages/pymctp-sample-vendorextension/src/pymctp_sample_vendorextension/cli/sample_commands.py) - CLI implementations
- [pyproject.toml](packages/pymctp-sample-vendorextension/pyproject.toml) - Entry point registration

## Additional Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Click Documentation](https://click.palletsprojects.com/) - CLI framework
- [Python Packaging Guide](https://packaging.python.org/)
- [Entry Points Specification](https://packaging.python.org/specifications/entry-points/)
- [PyMCTP Repository](https://github.com/jls5177/pymctp)
- [CLI Extensions Guide](CLI-EXTENSIONS.md) - Detailed CLI extension documentation
