# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import contextlib
import select
import socket
import time

from scapy.compat import raw
from scapy.data import MTU
from scapy.interfaces import _GlobInterfaceType, network_name
from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from scapy.utils import linehexdump

from pymctp.layers.mctp import I3CTransportPacket, TransportHdrPacket


class QemuI3CNetDevSocket(SuperSocket):
    """SuperSocket backed by a QEMU i3c-target-netdev UDP socket.

    The QEMU ``i3c-target-netdev`` device bridges an I3C target device to a
    network backend.  The wire protocol is raw bytes with no additional framing:

    * **RX (QEMU → exerciser)**: raw bytes written by the I3C master during a
      private write, delivered as a single UDP datagram on I3C STOP.
    * **TX (exerciser → QEMU)**: raw bytes placed into the device's TX FIFO to
      be returned to the I3C master on the next private read.

    QEMU invocation example::

        -netdev socket,id=i3c-hcp0,udp=127.0.0.1:5556,localaddr=127.0.0.1:5560
        -device i3c-target-netdev,netdev=i3c-hcp0,bus=...,address=0x08

    Corresponding socket creation::

        sock = QemuI3CNetDevSocket(
            iface="127.0.0.1", in_port=5556,
            iface_out="127.0.0.1", out_port=5560,
        )
    """

    desc = "read/write to a QEMU I3C NetDev Socket"

    def __init__(
        self,
        family: int = socket.AF_INET,
        type: int = socket.SOCK_DGRAM,  # noqa: A002
        proto: int = 0,
        iface: _GlobInterfaceType | None = None,
        iface_out: _GlobInterfaceType | None = None,
        in_port=0,
        out_port=None,
        id_str="",
        dump_hex=True,
        dump_packet=False,
        poll_period_ms: int = 10,
        **kwargs,
    ):
        self.id_str = id_str
        self.dump_hex = dump_hex
        self.dump_packet = dump_packet
        self._poll_period_ms = poll_period_ms
        fd = socket.socket(family, type, proto)
        assert fd != -1
        self.ins = self.outs = fd

        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if iface is not None:
            try:
                iface2 = network_name(iface)
                self.iface = iface2
            except Exception:
                self.iface = iface
        else:
            self.iface = "any"

        self.ins.bind((self.iface, in_port))
        if out_port:
            self.out_port = out_port
            self.iface_out = iface_out

    def send(self, x: Packet) -> int:
        """Send a packet to the QEMU i3c-target-netdev peer.

        The MCTP packet is wrapped in an ``I3CTransportPacket`` which appends
        a trailing CRC-8 PEC byte.  The Linux ``mctp-i3c`` driver requires this
        PEC and will silently drop frames that are missing it.
        """
        # Wrap with I3C transport to append PEC; raw() triggers post_build.
        wrapped = I3CTransportPacket(load=x)
        sx = raw(wrapped)
        with contextlib.suppress(AttributeError):
            x.sent_time = time.time()

        if not self.outs:
            return 0

        if self.out_port:
            try:
                result = self.outs.sendto(sx, (self.iface_out, self.out_port))
            except Exception as e:
                print(f"Failed sending data: {e}")
                raise
            else:
                if self.dump_hex:
                    print(f"{self.id_str}>TX> {linehexdump(sx, onlyhex=1, dump=True)}")
                if self.dump_packet:
                    print(f"{self.id_str}>TX> {x.summary()}")
                return result
        else:
            return self.outs.send(sx)

    def recv(self, x: int = MTU) -> Packet | None:
        """Receive a packet sent by the I3C master via QEMU.

        The datagram contains the raw bytes written by the I3C master during a
        private write, delivered on I3C STOP.  The last byte is a trailing PEC
        (CRC-8) appended by the Linux ``mctp-i3c`` driver; it is stripped
        before parsing the remaining bytes as an MCTP transport header.
        """
        try:
            raw_bytes = self.ins.recv(x)
        except socket.error:
            return None

        if not raw_bytes:
            return None

        if self.dump_hex:
            print(f"{self.id_str}<RX< {linehexdump(raw_bytes, onlyhex=1, dump=True)}")

        # Minimum: 4-byte MCTP transport header + 1-byte PEC
        if len(raw_bytes) < 5:
            return None

        # Strip the trailing PEC byte before parsing MCTP
        mctp_bytes = I3CTransportPacket.strip_pec(raw_bytes)
        pkt = TransportHdrPacket(mctp_bytes)
        pkt.time = time.time()
        if pkt and self.dump_packet:
            print(f"{self.id_str}<RX< {pkt.summary()}")
        return pkt

    @staticmethod
    def select(sockets: list[SuperSocket], remain: float | None = None) -> list[SuperSocket]:
        """Custom select that avoids blocking indefinitely on I3C netdev sockets."""
        qemu_sockets = [sock for sock in sockets if isinstance(sock, QemuI3CNetDevSocket)]
        if not qemu_sockets:
            return []

        socket_fds = [sock.ins for sock in qemu_sockets]

        poll_periods = [x._poll_period_ms for x in qemu_sockets]
        timeout_ms = min(poll_periods + [(remain or 1) * 1000])
        timeout_s = timeout_ms / 1000.0

        try:
            ready_fds, _, _ = select.select(socket_fds, [], [], timeout_s)
        except select.error:
            return []

        return [sock for sock in qemu_sockets if sock.ins in ready_fds]
