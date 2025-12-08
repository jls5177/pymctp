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

## Auto-Registration

This package automatically registers both exercisers with pymctp when installed:
- `qemu-i2c`: QemuI2CNetDevSocket
- `qemu-i3c`: QemuI3CCharDevSocket

## License

MIT
