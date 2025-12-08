<!--
SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>

SPDX-License-Identifier: MIT
-->

# PyMCTP

<p align="center">
    <em>PyMCTP is a tool to craft/decode DMTF MCTP communication packets</em>
</p>

[![build](https://github.com/jls5177/mctp-emu/workflows/Build/badge.svg)](https://github.com/jls5177/mctp-emu/actions)
[![codecov](https://codecov.io/gh/jls5177/mctp-emu/branch/master/graph/badge.svg)](https://codecov.io/gh/jls5177/mctp-emu)
[![PyPI version](https://badge.fury.io/py/pymctp.svg)](https://badge.fury.io/py/pymctp)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pymctp.svg)](https://pypi.org/project/pymctp)

-----

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Tools](#command-line-tools)
  - [Decoding MCTP Packets](#decoding-mctp-packets)
  - [Crafting MCTP Packets](#crafting-mctp-packets)
- [Extensions](#extensions)
- [Contributing](#contributing)
- [License](#license)

## Introduction

PyMCTP is a Python library designed to craft and decode DMTF MCTP (Management Component Transport Protocol) communication packets. It provides tools and utilities to work with MCTP packets, making it easier to develop and test MCTP-based communication systems.

## Features

- Utilizes Scapy, a powerful Python library used for interactive packet manipulation and network protocol analysis
- Supports crafting and decoding MCTP packets
- Easy-to-use API
- Extensible plugin architecture for layers and exercisers
- Optional exerciser packages for hardware/virtual device interfaces

### Currently Supported Protocols
* MCTP Control messages: `crafting` and `decoding`
* PLDM Base and Type 2 messages: `decoding`
* Very basic decoding of MCTP Vendor Defined Messages: `decoding`
* IPMI `MasterWriteRead` messages: `decoding`

## Installation

You can install PyMCTP using pip:

```console
# Install core library
pip install pymctp

# Install with all exercisers
pip install pymctp[all-exercisers]

# Or install specific exercisers
pip install pymctp[aardvark]  # Total Phase Aardvark I2C
pip install pymctp[qemu]      # QEMU I2C/I3C
pip install pymctp[serial]    # Serial/UART
```

## Usage

### Command-Line Tools

PyMCTP includes command-line tools for analyzing MCTP packet captures:

```bash
# Show help
pymctp --help

# Analyze a pcap file
pymctp analyze-tcpdump capture.pcap

# Analyze text dump with custom timezone and date
pymctp analyze-tcpdump dump.txt --timezone America/New_York --date 2024-03-20
```

The `analyze-tcpdump` command supports:
- PCAP files (`.pcap`, `.dump`) - standard packet capture format
- Text dumps - hex dump output from tcpdump
- Automatic MCTP packet decoding and display
- Configurable timezone and date handling for timestamps

Run `pymctp analyze-tcpdump --help` for all available options.

#### Extensible CLI

The pymctp CLI can be extended by other packages! Vendor extension packages can add their own commands:

```bash
# After installing a vendor extension package
pip install pymctp-sample-vendorextension

# Vendor-specific commands are automatically available
pymctp sample-vendor info
pymctp craft-sample-vendor --command 0x10 --data "deadbeef"
```

See [CLI-EXTENSIONS.md](../../CLI-EXTENSIONS.md) for details on creating your own CLI extensions.

### Decoding MCTP Packets

Here is a simple example of how to use the PyMCTP library to decode an MCTP Transport packet
```python
from pymctp.layers import mctp
data = "01 0b 0a c5 00 00 0a 00 ff 01 01 0a 02 00 04 01 00"
bdata = bytes([int(x, 16) for x in data.split(" ")])
pkt = mctp.TransportHdrPacket(bdata)
print(f"{pkt.summary()}")
```

```
MCTP 0:5 (0B <-- 0A) (S:E) CTRL / CONTROL RSP (instance_id: 0, cmd_code=10, completion_code=0) / GetRoutingTableEntries (next_hdl=0xFF, cnt=1)  [0x0A:1]
```

Here is a simple example of how to decode an MCTP-over-SMBUS packet:
```python
from pymctp.layers import mctp
data = "20 0F 0C 65 01 0A 43 D0 00 1A 01 00 00 43 00 F4"
bdata = bytes([int(x, 16) for x in data.split(" ")])
pkt = mctp.SmbusTransportPacket(bdata)
print(f"{pkt.summary()}")
```

```
SMBUS (dst=0x20, src=0x65, byte_count=12, pec=0xF4) / MCTP 1:0 (0A <-- 43) (S:E) CTRL / CONTROL RSP (instance_id: 26, cmd_code=1, completion_code=0) / SetEndpointIDPacket (assign_status: accepted, eid_alloc_status: no_pool, eid_setting: 0x43, eid_pool_size: 0)
```

### Crafting MCTP Packets

Here is an example of crafting a complete MCTP-over-SMBUS packet:
```python
from pymctp.layers.mctp import SmbusTransport, TransportHdr
from pymctp.layers.mctp.control import SetEndpointID, SetEndpointIDOperation, ControlHdr
from pymctp.types import MsgTypes, Smbus7bitAddress

pkt = (
    TransportHdr(src=10, dst=0, som=1, eom=1, to=1, tag=7, msg_type=MsgTypes.CTRL)
    / ControlHdr(rq=True, cmd_code=ContrlCmdCodes.SET_ENDPOINT_ID, instance_id=0x11)
    / SetEndpointID(op=SetEndpointIDOperation.SetEID, eid=29)
)

smbus_pkt = SmbusTransport(
    dst_addr=Smbus7bitAddress(0x32),
    src_addr=Smbus7bitAddress(0x10),
    load=pkt
)
```

Here is the same packet decoded to show the raw payload that was generated:
```ipython
>>> print(f"{hexdump(smbus_pkt)}")
0000  64 0F 0A 21 01 00 0A CF 00 91 01 00 1D FC        d..!..........
None
>>> print(f"{smbus_pkt.summary()}")
SMBUS (dst=0x64, src=0x21, byte_count=10, pec=0xFC) / MCTP 0:7 (00 <-- 0A) (S:E:TO) CTRL / CONTROL REQ (instance_id: 17, cmd_code=1) / SetEndpointIDPacket (eid: 0x1D, op: set)
```

Once you have the fully crafted packet, you can convert it to a bytes object to get the raw payload:
```ipython
>>> raw_bytes = raw(smbus_pkt)
>>> hexdump(raw_bytes)
0000  64 0F 0A 21 01 00 0A CF 00 91 01 00 1D FC        d..!..........
>>> type(raw_bytes)
bytes
```

## Extensions

PyMCTP supports an extensible plugin architecture that allows OEM-specific implementations to be packaged separately and automatically discovered at runtime.

### Available Extensions

Extensions provide OEM-specific MCTP and IPMI layer implementations for vendor-specific protocols.

### Installing Extensions

Extensions can be installed independently using pip:

```bash
pip install pymctp-<extension-name>
```

Once installed, extensions are automatically discovered and loaded when you import pymctp. No additional configuration is required.

### Creating Your Own Extensions

To create your own pymctp extension:

1. Create a new Python package with your layer implementations
2. Import pymctp base classes: `from pymctp.layers import ...`
3. Use the existing auto-binding decorators (`@AutobindMessageType`, `@AutobindVDMMsg`, etc.)
4. Register your package as a pymctp extension in `pyproject.toml`:

```toml
[project.entry-points."pymctp.extensions"]
your_extension_name = "your_package.layers"
```

The entry point should reference a module that imports all your layer definitions. When pymctp initializes, it will automatically discover and load your extension, registering all layer bindings.

See the [pymctp-sample-vendorextension](packages/pymctp-sample-vendorextension) package for a complete example.

## Exercisers

PyMCTP supports optional exerciser packages for interfacing with hardware and virtual MCTP devices.

### Available Exercisers

- **pymctp-exerciser-aardvark**: Total Phase Aardvark I2C/SPI adapter support
- **pymctp-exerciser-qemu**: QEMU I2C NetDev and I3C CharDev support
- **pymctp-exerciser-serial**: TTY/Serial UART support

### Installing Exercisers

Exercisers are optional and can be installed separately:

```bash
# Install a specific exerciser
pip install pymctp-exerciser-aardvark

# Or install all exercisers at once
pip install pymctp[all-exercisers]
```

### Using Exercisers

Once installed, exercisers are automatically registered and can be used:

```python
from pymctp.exerciser import get_exerciser, list_exercisers

# List all available exercisers
print(list_exercisers())  # ['aardvark', 'qemu-i2c', 'qemu-i3c', 'serial']

# Get an exerciser class
AardvarkSocket = get_exerciser('aardvark')
socket = AardvarkSocket(port=0, addr=0x20)

# Or import directly
from pymctp.exerciser import AardvarkI2CSocket
socket = AardvarkI2CSocket(port=0, addr=0x20)
```

### Creating Custom Exercisers

You can create your own exerciser packages that automatically integrate with pymctp:

1. Create a Python package with your exerciser implementation
2. Subclass `scapy.supersocket.SuperSocket`
3. Register via entry point in `pyproject.toml`:

```toml
[project.entry-points."pymctp.exercisers"]
my_exerciser = "my_package"
```

4. In your package's `__init__.py`, register the exerciser:

```python
from pymctp.exerciser import register_exerciser
from .my_exerciser import MyExerciserSocket

register_exerciser('my_exerciser', MyExerciserSocket)
```

## Contributing

Contributions are welcome! If you would like to contribute to PyMCTP, please follow these steps:

1. Fork the repository
1. Create a new branch (git checkout -b feature-branch)
1. Make your changes
1. Commit your changes (git commit -am 'Add new feature')
1. Push to the branch (git push origin feature-branch)
1. Create a new Pull Request

Please ensure that your code follows the project's coding standards and includes appropriate tests.

## License

`pymctp` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
