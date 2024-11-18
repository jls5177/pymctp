# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import contextlib
import threading
import time
from operator import itemgetter

from scapy.compat import raw
from scapy.data import MTU
from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from scapy.utils import hexdump, linehexdump

from ..layers.mctp import Smbus7bitAddress, SmbusTransport

try:
    from array import array

    import pyaardvark
except RuntimeError:
    # ignore the missing library as this might not be needed in all deployments
    pyaardvark = None


class AardvarkI2CSocket(SuperSocket):
    desc = "read/write to an Aardvark USB device"

    def __init__(
        self,
        slave_address: Smbus7bitAddress,
        port: int | None = None,
        serial_number: str | None = None,
        enable_i2c_pullups: bool = False,
        enable_target_power: bool = False,
        slave_only: bool = False,
        poll_period_ms: int = 10,
        id_str: str = "",
        dump_hex=True,
        dump_packet=False,
        **kwargs,
    ):
        if pyaardvark is None:
            msg = "Failed to load pyaardvark library. Confirm if environment is bootstrapped."
            raise RuntimeError(msg)
        self.id_str = id_str
        self.dump_hex = dump_hex
        self.dump_packet = dump_packet
        self._slave_address = slave_address
        self._port = port
        self._serial_number = serial_number
        self._enable_i2c_pullups = enable_i2c_pullups
        self._enable_target_power = enable_target_power
        self._dev: pyaardvark.Aardvark | None = None
        self._lock = threading.Lock()
        self._slave_only = slave_only
        self._poll_period_ms = poll_period_ms

        if not self.connect():
            msg = f"Failed to open connection to Aardvark adapter: {slave_address}, {port}"
            raise RuntimeError(msg)

    def connect(self) -> bool:
        """
        Claims the Aardvark device defined when initializing class. This can be used to release the device
        for a short period of time and reconnect without having to recreate the surrounding objects
        (e.g. sessions, answering machines, ...).

        :return: True if claimed device, False if failed or already connected
        """
        if not self._dev or self._dev.handle is None:
            self._dev: pyaardvark.Aardvark = pyaardvark.open(self._port, self._serial_number)
            self._dev.enable_i2c_slave(self._slave_address.address)

            if self._enable_i2c_pullups:
                self._dev.i2c_pullups = self._enable_i2c_pullups
            if self._enable_target_power:
                self._dev.target_power = self._enable_target_power
            self._dev.i2c_stop()
            return True
        return False

    def close(self) -> None:
        """
        Releases the Aardvark device (to allow other applications to claim the device).
        :return: None
        """
        if self._dev:
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

        try:
            with self._lock:
                # API uses 7bit addresses but payload has 8bit address in the first byte
                if self._slave_only:
                    self._dev.i2c_slave_response(sx[1:])
                    # TODO: wait until the msg is received
                else:
                    self._dev.i2c_master_write(sx[0] >> 1, sx[1:])
                    # this causes the stop condition to be skipped, hanging the bus
                    # which is great for testing error handling
                    # self._dev.i2c_master_write(sx[0] >> 1, sx[1:], flags=I2C_NO_STOP)
                    # time.sleep(0.5)
                    # self._dev.i2c_stop()
        except OSError as err:
            print(f"Aardvark write failed: {err}")
            code, *_ = err.args
            if code and code == pyaardvark.I2C_STATUS_SLA_NACK:
                return 0
                # the return value is not checked, just raise the exception
                # pass
            raise

        return len(sx)

    def recv(self, x: int = MTU) -> Packet | None:
        """
        Receives any pending data written to the slave address. Callers should first call "select()" to wait
        for data to be available to be received. This API call will sleep waiting for data if the buffer is
        empty.

        :param x: Ignored but part of overloaded methods signature
        :return: SmbusTransportPacket if available or None if no data is received
        """
        # TODO: read until there is no more data available (might not be needed as the library uses 64K read buffers)
        (i2c_addr, rx_data) = self._dev.i2c_slave_read()
        rx_data = array("B", rx_data)
        rq_sa = array(
            "B",
            [
                i2c_addr << 1,
            ],
        )
        raw_array = rq_sa + rx_data
        raw_bytes = raw_array.tobytes()

        if self.dump_hex:
            print(f"{self.id_str}<RX< {linehexdump(raw_bytes, onlyhex=1, dump=True)}")

        # Attempt to parse the packet but mask any parsing errors as no valid packets received
        pkt = None
        with contextlib.suppress(Exception):
            pkt = SmbusTransport(raw_bytes)
            pkt.time = time.time()

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
        aardvark_socks = [sock for sock in sockets if isinstance(sock, AardvarkI2CSocket)]
        if len(aardvark_socks) != 1:
            msg = "AardvarkI2C can only monitor a single socket at a time"
            raise RuntimeError(msg)
        self = aardvark_socks[0]

        # use "remain" if it is less than the pre-defined poll period
        events = self._dev.poll(int(min(self._poll_period_ms, (remain or 1) * 1000)))
        if pyaardvark.POLL_I2C_WRITE in events:
            transmit_size = self._dev.i2c_slave_last_transmit_size()
            print(f"DEBUG: last transmit size {transmit_size}")
        if pyaardvark.POLL_I2C_READ in events:
            return [self]
        if events and pyaardvark.POLL_I2C_WRITE not in events:
            print(f"DEBUG: events {events}")
        return []

    @staticmethod
    def show_devices() -> None:
        """
        Prints the Aardvark adapters present in the system to
        :return: None
        """
        devices = pyaardvark.find_devices()
        for dev in devices:
            port, serial_number, in_use = itemgetter("port", "serial_number", "in_use")(dev)
            print(f"{port}) {serial_number} [{'in-used' if in_use else 'free'}]")
