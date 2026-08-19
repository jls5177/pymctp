# pymctp-exerciser-qemu

QEMU I2C and I3C exerciser support for pymctp.

This package provides exerciser implementations for interfacing with QEMU's I2C and I3C virtual devices to send and receive MCTP packets in virtualized environments.

## Installation

```bash
pip install pymctp-exerciser-qemu
```

## Requirements

- pymctp >= 0.1.0
- crc8 >= 0.1.0
- QEMU with I2C/I3C device support

## Exercisers Included

### QemuI2CNetDevSocket

Interfaces with QEMU I2C devices via network sockets.

```python
from pymctp.exerciser import get_exerciser

QemuI2CSocket = get_exerciser('qemu-i2c')
socket = QemuI2CSocket(
    host='localhost',
    port=5555,
    addr=0x20
)
```

### QemuI3CCharDevSocket

Interfaces with QEMU I3C devices via character devices.

```python
from pymctp.exerciser import get_exerciser

QemuI3CSocket = get_exerciser('qemu-i3c')
socket = QemuI3CSocket(
    chardev_path='/tmp/i3c-socket',
    addr=0x20
)
```

### QemuI3CStreamSocket / QemuI2CStreamSocket (TCP "remote target" stream)

Interfaces with QEMU's `i3c-target-remote` / `i2c-target-remote` "remote
target" devices over a single, bidirectional TCP connection per endpoint.
This is different from the netdev/netdev2 transports above, which use a
*pair* of UDP ports (`in_port`/`out_port`): the stream transports use **one
TCP port per endpoint**, with QEMU listening as the TCP server and PyMCTP
connecting as the client. Every message (data, control, and a connect-time
HELLO handshake) is framed the same way on the wire:

```
[u32 length BE][u8 type][body...]
```

`length` counts the bytes of `type` + `body`. See
[`stream_framing.py`](src/pymctp_exerciser_qemu/stream_framing.py) for the
codec and [`qemu_i3c_stream.py`](src/pymctp_exerciser_qemu/qemu_i3c_stream.py) /
[`qemu_i2c_stream.py`](src/pymctp_exerciser_qemu/qemu_i2c_stream.py) for the
per-transport message types.

Use these through `pymctp.automaton.manager.EndpointManager.from_config` with
`ConfigTypes.I3CStream` (`"i3c-stream"`) / `ConfigTypes.I2CStream`
(`"i2c-stream"`), rather than instantiating the sockets directly:

```python
from pymctp.automaton.manager import ConfigTypes, EndpointManager

# I3CStreamSocketConfig fields: host, port, name, dump_hex=True,
# dump_packet=False, connect_timeout=5.0, pid=0, bcr=0, dcr=0, mwl=0, mrl=0,
# static_addr=0, auto_configure=True (sends SET_REG + HOT_JOIN on connect
# for any non-zero register field).
hcp0_config = {
    "context": {
        "supported_msg_types": [],  # e.g. MsgTypes.CTRL, MsgTypes.PLDM
        "assigned_eid": 38,
    },
    "config": {
        "type": ConfigTypes.I3CStream,
        "host": "localhost",
        "port": 5556,
        "name": "HCP0",
    },
}

# I2CStreamSocketConfig fields: host, port, name, dump_hex=True,
# dump_packet=False, connect_timeout=5.0.
hsp1_config = {
    "context": {
        "physical_address": {"address": 0xB0 >> 1},
        "supported_msg_types": [],  # e.g. MsgTypes.CTRL, MsgTypes.PLDM
        "assigned_eid": 34,
    },
    "config": {
        "type": ConfigTypes.I2CStream,
        "host": "localhost",
        "port": 5570,
        "name": "HSP1",
    },
}

hcp0 = EndpointManager.from_config(hcp0_config)
hsp1 = EndpointManager.from_config(hsp1_config)
```

See [`docs/examples/l4a40_qemu_stream.py`](../../docs/examples/l4a40_qemu_stream.py)
for a complete, runnable example.

#### QEMU side

QEMU listens (`server=on`) and PyMCTP connects as the TCP client, one port
per endpoint/bus:

```
-device i3c-target-remote,bus=<bus>,port=<N>,server=on
-device i2c-target-remote,bus=<bus>,address=0x<NN>,port=<N>,server=on
```

When QEMU itself runs inside Docker, publish each stream port with its own
`-p` mapping so PyMCTP (running outside the container) can connect, e.g.
`-p 5556:5556 -p 5570:5570`.

## Auto-Registration

This package automatically registers exercisers with pymctp when installed,
including:
- `qemu-i2c`: QemuI2CNetDevSocket
- `qemu-i3c`: QemuI3CCharDevSocket
- `qemu-i3c-stream`: QemuI3CStreamSocket
- `qemu-i2c-stream`: QemuI2CStreamSocket

## License

MIT
