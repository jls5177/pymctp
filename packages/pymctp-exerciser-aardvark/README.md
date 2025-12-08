# pymctp-exerciser-aardvark

Total Phase Aardvark I2C exerciser support for pymctp.

This package provides an exerciser implementation for interfacing with Total Phase Aardvark I2C/SPI adapters to send and receive MCTP packets over I2C.

## Installation

```bash
pip install pymctp-exerciser-aardvark
```

## Requirements

- pymctp >= 0.1.0
- pyaardvark >= 0.7.1
- Total Phase Aardvark I2C/SPI adapter hardware

## Usage

```python
from pymctp.exerciser import AardvarkI2CSocket

# List available Aardvark devices
AardvarkI2CSocket.list_devices()

# Open a connection
socket = AardvarkI2CSocket(
    port=0,  # Device port number
    addr=0x20,  # Target I2C address
    bitrate=100  # I2C bitrate in kHz
)

# Send/receive MCTP packets
from pymctp.layers.mctp import SmbusTransport

pkt = SmbusTransport(...)
socket.send(pkt)

response = socket.recv()
```

## Auto-Registration

This package automatically registers itself with pymctp when installed. You can access it through the exerciser registry:

```python
from pymctp.exerciser import get_exerciser

AardvarkSocket = get_exerciser('aardvark')
```

## License

MIT
