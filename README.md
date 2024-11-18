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
- [Contributing](#contributing)
- [License](#license)

## Introduction

PyMCTP is a Python library designed to craft and decode DMTF MCTP (Management Component Transport Protocol) communication packets. It provides tools and utilities to work with MCTP packets, making it easier to develop and test MCTP-based communication systems.

## Features

- Utilizes Scapy, a powerful Python library used for interactive packet manipulation and network protocol analysis
- Supports crafting and decoding MCTP packets
- Easy-to-use API
- Extensible interface for Physical and Virtual device exercisers:
    - Support for Total Phase Aardvark I2C exerciser
    - Support for QEMU I2C-socket and I3C-chardev drivers

### Currently Supported Protocols
* MCTP Control messages: `crafting` and `decoding`
* PLDM Base and Type 2 messages: `decoding`
* Very basic decoding of MCTP Vendor Defined Messages: `decoding`
* IPMI `MasterWriteRead` messages: `decoding`

## Installation

You can install PyMCTP using pip:

```console
pip install pymctp
```

## Usage

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
