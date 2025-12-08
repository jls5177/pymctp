# pymctp-exerciser-serial

TTY/Serial port exerciser support for pymctp.

This package provides an exerciser implementation for interfacing with serial/UART devices to send and receive MCTP packets over serial connections.

## Installation

```bash
pip install pymctp-exerciser-serial
```

## Requirements

- pymctp >= 0.1.0
- pyserial
- Serial/UART hardware or virtual serial ports

## Usage

```python
from pymctp.exerciser import TTYSerialSocket

# Open a serial connection
socket = TTYSerialSocket(
    tty='/dev/ttyUSB0',  # Serial port device
    baudrate=115200,     # Baud rate
    addr=0x20            # Target address
)

# Send/receive MCTP packets
from pymctp.layers.mctp import UartTransport

pkt = UartTransport(...)
socket.send(pkt)

response = socket.recv()
```

## Auto-Registration

This package automatically registers itself with pymctp when installed. You can access it through the exerciser registry:

```python
from pymctp.exerciser import get_exerciser

SerialSocket = get_exerciser('serial')
```

## License

MIT
