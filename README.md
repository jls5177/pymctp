<!--
SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>

SPDX-License-Identifier: MIT
-->

# PyMCTP - Microsoft OEM Extensions (Internal)

<p align="center">
    <em>Microsoft OEM-specific MCTP protocol extensions and examples</em>
</p>

## Overview

This is an internal repository containing Microsoft-specific OEM extensions for the PyMCTP library. This package provides Microsoft proprietary IPMI and MCTP VDM implementations.

**Note**: This repository is for internal use only and is not published to PyPI.

## Packages

### Microsoft OEM Package

- **[pymctp-oem-microsoft](packages/pymctp-oem-microsoft/)** - Microsoft OEM-specific protocol implementations
  - IPMI extensions (Master Mux Write/Read, OVL SoC, Slave Read)
  - MCTP VDM extensions (Cerberus Challenge, MSFT VDM)

## Installation

This package requires the public pymctp library as a dependency:

```bash
# Install the core pymctp library from PyPI
pip install pymctp

# Install the Microsoft OEM package (local development)
pip install -e packages/pymctp_oem_microsoft
```

## Examples

The [examples/](examples/) directory contains various usage examples demonstrating how to use the Microsoft OEM extensions with different hardware and virtual devices.

## Features

- **Microsoft IPMI Extensions**: Custom IPMI commands for Microsoft hardware
- **Microsoft VDM Support**: Vendor-defined messages for Microsoft-specific protocols
- **Cerberus Challenge**: Implementation of Cerberus authentication challenges

## Repository Structure

```
pymctp-internal/
├── packages/
│   └── pymctp-oem-microsoft/    # Microsoft OEM extensions
├── examples/                    # Example scripts
└── tests/                       # Tests
```

## Development

This project uses [uv](https://docs.astral.sh/uv/) for fast, reliable dependency management.

### Development Setup

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install the package and dependencies
uv sync --all-extras
```

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-cov
```

### Building Package

```bash
# Build the package
cd packages/pymctp_oem_microsoft
uv run python -m build
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
