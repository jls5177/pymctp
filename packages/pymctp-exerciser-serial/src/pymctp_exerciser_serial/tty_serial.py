# SPDX-FileCopyrightText: 2025 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import contextlib
import queue
import threading
import time
from operator import itemgetter

from scapy.compat import raw
from scapy.data import MTU
from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from scapy.utils import hexdump, linehexdump

from pymctp.layers import UartTransport
from pymctp.layers.mctp import Smbus7bitAddress, SmbusTransport

try:
    from array import array
    import serial
except RuntimeError:
    # ignore the missing library as this might not be needed in all deployments
    serial = None


class TTYSerialSocket(SuperSocket):
    desc = "read/write to a TTY"

    def __init__(
        self,
        tty,
        baudrate=115200,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        poll_period_ms=10,
        id_str="",
        dump_hex=True,
        dump_packet=False,
        **kwargs,
    ):
        self.tty = tty
        if serial is None:
            msg = "Failed to load pyserial library. Confirm if environment is bootstrapped."
            raise RuntimeError(msg)
        self.id_str = id_str
        self.dump_hex = dump_hex
        self.dump_packet = dump_packet
        self._poll_period_ms = poll_period_ms
        self._baudrate = baudrate
        self._parity = parity
        self._stopbits = stopbits
        self._rx_buffer = bytearray()

        if not self.connect():
            msg = f"Failed to open connection to TTY: {tty}"
            raise RuntimeError(msg)

    def connect(self):
        try:
            self._dev = serial.Serial(
                self.tty,
                baudrate=self._baudrate,
                parity=self._parity,
                stopbits=self._stopbits,
                timeout=0,
            )
            self._dev.reset_input_buffer()
            return True
        except serial.SerialException as err:
            print(f"TTY open failed: {err}")
            return False

    def close(self):
        self._dev.close()

    def send(self, x: Packet) -> int:
        """
        Overloaded Packet.send() method to send data using Aardvark APIs
        """
        sx = raw(x)
        with contextlib.suppress(AttributeError):
            x.sent_time = time.time()

        if self.dump_hex:
            print(f"{self.id_str}>TX> {linehexdump(x, onlyhex=1, dump=True)}")
        if self.dump_packet:
            print(f"{self.id_str}>TX> {x.summary()}")

        # Escape 0x7D and 0x7E bytes in the msg body, not the framing bytes
        frame_count = sx[1:-3].count(0x7E) + sx[1:-3].count(0x7D)
        if frame_count > 0:
            escaped_sx = bytearray([0x7E])
            for b in sx[1:-3]:
                if b in (0x7D, 0x7E):
                    escaped_sx.append(0x7D)
                    escaped_sx.append(b ^ 0x20)
                else:
                    escaped_sx.append(b)
            escaped_sx += sx[-3:]
            if self.dump_hex:
                print(f"{self.id_str}>TX> {linehexdump(escaped_sx, onlyhex=1, dump=True)}")
        else:
            escaped_sx = sx

        rc = self._dev.write(escaped_sx)
        if rc != len(escaped_sx):
            print(f"DEBUG: write failed, expected {len(sx)}, got {rc}")
            return 0
        return len(sx)

    def recv(self, x: int = MTU) -> Packet | None:
        rx_data = self._dev.read(x)
        if self.dump_hex:
            print(f"{self.id_str}<RX< {linehexdump(rx_data, onlyhex=1, dump=True)}")

        # discard new data if missing frame start
        if not len(self._rx_buffer) and (not rx_data or rx_data[:2] != bytes([0x7E, 1])):
            return None

        # discard the frame if missing the frame start
        if len(self._rx_buffer) and self._rx_buffer[:2] != bytes([0x7E, 1]):
            self._rx_buffer = bytearray()

        # buffer the frame data
        self._rx_buffer += rx_data

        # stop parsing if missing the byte count byte
        if len(self._rx_buffer) < 3:
            return None

        byte_count = self._rx_buffer[2]
        frame_end = byte_count + 6
        if len(self._rx_buffer) < frame_end:
            print(f"DEBUG: not enough data to parse, frame_count: {byte_count}, rx_buffer_len: {len(self._rx_buffer)}")
            return None
        # only process the first frame, including any escape characters
        frame_end += self._rx_buffer[1 : byte_count + 3].count(0x7D)
        if len(self._rx_buffer) > frame_end:
            rx_data, self._rx_buffer = self._rx_buffer[:frame_end], self._rx_buffer[frame_end:]
        else:
            rx_data, self._rx_buffer = self._rx_buffer, bytearray()

        # unescape the "rx_data" by skipping all "0x7D" bytes and XOR "0x20" to the next byte
        unescaped_data = bytearray([0x7E])
        i = 1
        while i < len(rx_data[:-3]):
            if rx_data[i] == 0x7D and i + 1 < len(rx_data):
                unescaped_data.append(rx_data[i + 1] ^ 0x20)
                i += 2
            else:
                unescaped_data.append(rx_data[i])
                i += 1
        rx_data = bytes(unescaped_data + rx_data[-3:])
        if self.dump_hex:
            print(f"{self.id_str}<RX< {linehexdump(rx_data, onlyhex=1, dump=True)}")

        # Attempt to parse the packet but mask any parsing errors as no valid packets received
        pkt = None
        with contextlib.suppress(Exception):
            try:
                pkt = UartTransport(rx_data)
                pkt.time = time.time()
            except Exception as err:
                print(f"DEBUG: failed to parse packet: {err}")
                raise

        if pkt and self.dump_packet:
            print(f"{self.id_str}<RX< {pkt.summary()}")

        return pkt

    @staticmethod
    def select(sockets: list[SuperSocket], remain: float | None = None) -> list[SuperSocket]:
        """
        This function is called during sendrecv() routine to select
        the available sockets.

        :param sockets: an array of sockets that need to be selected
        :param remain: remaining timeout (in seconds) to wait for data
        :returns: an array of sockets that were selected and
            the function to be called next to get the packets (i.g. recv)
        """
        tty_socks = [sock for sock in sockets if isinstance(sock, TTYSerialSocket)]
        if len(tty_socks) != 1:
            msg = "TTY can only monitor a single socket at a time"
            raise RuntimeError(msg)
        self = tty_socks[0]
        if self._dev.in_waiting:
            return [self]
        elif len(self._rx_buffer) > 0 and self._rx_buffer.count(0x7E) % 2 == 0:
            return [self]
        return []
