<!--
SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>

SPDX-License-Identifier: MIT
-->

# PyMCTP - DMTF MCTP Protocol Library

<p align="center">
    <em>A comprehensive Python library for crafting and decoding DMTF MCTP communication packets</em>
</p>

[![build](https://github.com/jls5177/mctp-emu/workflows/Build/badge.svg)](https://github.com/jls5177/mctp-emu/actions)
[![codecov](https://codecov.io/gh/jls5177/mctp-emu/branch/master/graph/badge.svg)](https://codecov.io/gh/jls5177/mctp-emu)
[![PyPI version](https://badge.fury.io/py/pymctp.svg)](https://badge.fury.io/py/pymctp)

## Overview

PyMCTP is a modular Python library for working with DMTF MCTP (Management Component Transport Protocol) packets. The library is organized as a monorepo with multiple packages:

- **Core library** - Protocol layer definitions and packet crafting/decoding
- **OEM extensions** - Vendor-specific protocol implementations
- **Exercisers** - Hardware and virtual device interfaces

## Packages

### Core Package

- **[pymctp](packages/pymctp/)** - Main library with MCTP/IPMI/PLDM protocol support
  ```bash
  pip install pymctp
  ```

### Vendor Extensions

- **[pymctp-sample-vendorextension](packages/pymctp-sample-vendorextension/)** - Sample vendor extension (template/example)
  ```bash
  pip install pymctp-sample-vendorextension
  ```

### Exercisers

- **[pymctp-exerciser-aardvark](packages/pymctp-exerciser-aardvark/)** - Total Phase Aardvark I2C adapter
  ```bash
  pip install pymctp-exerciser-aardvark
  ```

- **[pymctp-exerciser-qemu](packages/pymctp-exerciser-qemu/)** - QEMU I2C/I3C virtual devices
  ```bash
  pip install pymctp-exerciser-qemu
  ```

- **[pymctp-exerciser-serial](packages/pymctp-exerciser-serial/)** - TTY/Serial UART devices
  ```bash
  pip install pymctp-exerciser-serial
  ```

## Quick Start

### Installation

```bash
# Minimal installation (core library only)
pip install pymctp

# With all exercisers
pip install pymctp[all-exercisers]

# Or install specific packages
pip install pymctp pymctp-sample-vendorextension pymctp-exerciser-qemu
```

### Usage Example

```python
from pymctp.layers.mctp import SmbusTransport, TransportHdr
from pymctp.layers.mctp.control import SetEndpointID, ControlHdr

# Craft an MCTP packet
pkt = (
    TransportHdr(src=10, dst=0, som=1, eom=1, msg_type=0)
    / ControlHdr(rq=True, cmd_code=1, instance_id=0x11)
    / SetEndpointID(op=0, eid=29)
)

# Decode a packet
from pymctp.layers import mctp
data = bytes([0x01, 0x0b, 0x0a, 0xc5, 0x00, 0x00, 0x0a, 0x00, 0xff, 0x01, 0x01, 0x0a, 0x02, 0x00, 0x04, 0x01, 0x00])
decoded = mctp.TransportHdrPacket(data)
print(decoded.summary())
```

## Features

- **Protocol Support**: MCTP Control, PLDM, IPMI, VDM, NVMe-MI
- **Extensible Architecture**: Plugin system for layers and exercisers
- **Hardware Interfaces**: Support for physical and virtual devices
- **Scapy Integration**: Built on Scapy for powerful packet manipulation

### Machine Topologies

Describe and run multi-endpoint systems with `MachineBuilder` and `Machine`:

```python
from pymctp.topology import Machine, MachineBuilder

spec = (
    MachineBuilder("lab")
    .defaults(host="127.0.0.1", timeout=60)
    .eids({"owner": 0x08, "ep": 0x0F})
    .device("owner", transport={"type": "i2c-stream", "port": 5570}, physical_address=0x20, roles=["bus-owner"])
    .device("ep", transport={"type": "i2c-stream", "port": 5571}, physical_address=0x21, roles=["simple"])
    .build()
)
with Machine(spec) as machine:
    print(machine.summary())
```

```bash
pymctp machine list
pymctp machine show lab.yaml --json
pymctp machine run lab.yaml --rediscover --timeout 30
```

## Documentation

- **[Core Library Documentation](packages/pymctp/README.md)** - Full API and usage guide
- **[Extension Development](EXTENSIONS.md)** - Creating custom OEM/layer extensions
- **[CLI Extension Development](CLI-EXTENSIONS.md)** - Creating custom CLI commands
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute to the project
- **[Development Guide](DEVELOPMENT.md)** - Development setup, building, and testing

## Development

This is a monorepo containing multiple Python packages. Each package can be developed and published independently.

**For detailed development instructions, see [DEVELOPMENT.md](DEVELOPMENT.md)**

### Repository Structure

```
pymctp/
├── packages/
│   ├── pymctp/                          # Core library
│   ├── pymctp-sample-vendorextension/   # Sample vendor extension (example/template)
│   ├── pymctp-exerciser-aardvark/       # Aardvark exerciser
│   ├── pymctp-exerciser-qemu/           # QEMU exercisers
│   └── pymctp-exerciser-serial/         # Serial exerciser
├── tests/                               # Shared tests
├── examples/                            # Example scripts
├── EXTENSIONS.md                        # Extension development guide
└── MIGRATION.md                         # Migration guide
```

### Development Setup

This project uses [uv](https://docs.astral.sh/uv/) for fast, reliable dependency management.

```bash
# Clone the repository
git clone https://github.com/jls5177/pymctp.git
cd pymctp

# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install all workspace packages and dependencies
uv sync --all-extras
```

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-cov

# Generate XML coverage report (for CI)
make test-xml
```

### Code Quality

```bash
# Format code
make format-all

# Check formatting and linting
make format-check

# Validate license headers
make license-check
```

### Building Packages

```bash
# Build all packages
make build-all

# Or build individually
cd packages/pymctp
uv run python -m build
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature-name`)
3. Make your changes
4. Run tests (`pytest`)
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Links

- **PyPI**: https://pypi.org/project/pymctp/
- **Documentation**: https://github.com/jls5177/pymctp#readme
- **Issues**: https://github.com/jls5177/pymctp/issues
- **Source**: https://github.com/jls5177/pymctp
