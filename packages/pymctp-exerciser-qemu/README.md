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
# dump_packet=False, connect_timeout=5.0, master=False, target_address=None.
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

By default (`master=False`), the socket speaks the slave/target model:
WRITE frames are dispatched as parsed `SmbusTransportPacket`s. Each
`send()` supplies one complete outbound SMBus packet, never unsolicited data.
A READ_REQ with a two-byte big-endian length flushes up to 512 pending
packets, in order, using **one READ_RSP frame per whole packet**. The length
is a per-packet capacity, not a total byte budget; if the first pending
packet does not fit, it and all packets behind it remain queued until a
large enough request arrives. An empty queue produces no READ_RSP frame.
Fragmented MCTP messages (SOM through EOM) become visible to READ_REQ only
when the complete message has been queued. The socket advertises this
staging to `SimpleEndpointAM`, which skips its usual 5 ms inter-packet
gap only for direct replies on the slave-mode socket. Master mode and
other transports retain the gap. Incomplete messages remain staged; orphan
continuations are errors. A new SOM with the same EID/tag/direction
discards the previous incomplete message with a warning, then starts fresh.
The slave admits at most 512 packets total, including staged fragments.
Exceeding that limit raises `OverflowError`; if a continuation overflows,
its entire staged message is discarded without publishing any fragments.
See [`qemu_i2c_stream.py`](src/pymctp_exerciser_qemu/qemu_i2c_stream.py).

Setting `master=True` instead speaks QEMU's `i2c-target-remote` *master*
mode (peer-as-master / multi-master, mirroring the old UDP `i2c-netdev`
transport): QEMU masters the (virtual) I2C bus on our behalf, so there is no
READ_REQ/READ_RSP turn-around — every WRITE frame is address-prefixed
instead:

```
WRITE (0x00) body := [addr_byte][data...]
addr_byte        := (i2c_7bit_address << 1) | 0   # write, no R/W bit set
```

* `send()` (peer -> QEMU) transmits the WRITE frame immediately. It keeps
  an existing SMBus destination byte (which is covered by the PEC), or
  prefixes `target_address` (required when `master=True`) only if the
  outgoing packet has no destination byte.
* `recv()` (QEMU -> peer) parses the leading `addr_byte` with the rest of
  the frame as a `SmbusTransportPacket`, preserving its destination address.

```python
hn_config = {
    "context": {
        "physical_address": {"address": 0x10},
        "supported_msg_types": [],  # e.g. MsgTypes.CTRL
        "assigned_eid": 66,
    },
    "config": {
        "type": ConfigTypes.I2CStream,
        "host": "localhost",
        "port": 5574,
        "name": "HN",
        "master": True,
        "target_address": 0x10,
    },
}

hn = EndpointManager.from_config(hn_config)
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

Add `master=on` to have QEMU master the (virtual) I2C bus on our behalf
instead of acting as the slave/target (peer-as-master / multi-master, like
the old `i2c-netdev` transport) — pair this with `master=True` /
`target_address=<BMC addr>` in the matching `I2CStreamSocketConfig`:

```
-device i2c-target-remote,bus=<bus>,address=0x<NN>,port=<N>,server=on,master=on
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
