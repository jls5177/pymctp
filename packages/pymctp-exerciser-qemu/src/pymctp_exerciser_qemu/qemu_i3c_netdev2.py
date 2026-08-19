# SPDX-FileCopyrightText: 2025 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import contextlib
import logging
import select
import socket
import struct
import time
from enum import IntEnum

from scapy.compat import raw
from scapy.data import MTU
from scapy.interfaces import _GlobInterfaceType, network_name
from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from scapy.utils import linehexdump

from pymctp.layers.mctp import I3CTransport, I3CTransportPacket, TransportHdrPacket

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------


class NetDev2MsgType(IntEnum):
    """Frame type tags shared by both directions (type 0x00 is DATA in both)."""

    DATA = 0x00
    SET_REG = 0x01
    HOT_JOIN = 0x02
    HOT_REMOVE = 0x03
    IBI_REQ = 0x04
    CCC_NOTIFY = 0x05
    EVENT = 0x06


class NetDev2FieldId(IntEnum):
    """SET_REG field identifiers (service → QEMU, type 0x01)."""

    PID = 0x00
    BCR = 0x01
    DCR = 0x02
    MWL = 0x03
    MRL = 0x04
    MXDS = 0x05
    GETCAPS = 0x06
    GETSTATUS = 0x07
    STATIC_ADDR = 0x08


class NetDev2CccCode(IntEnum):
    """CCC codes carried in CCC_NOTIFY frames (QEMU → service, type 0x05)."""

    ENEC = 0x00
    DISEC = 0x01
    RSTDAA = 0x06
    ENTDAA = 0x07
    ENEC_DIRECT = 0x80
    DISEC_DIRECT = 0x81
    SETNEWDA = 0x88
    SETMWL = 0x89
    SETMRL = 0x8A


class NetDev2EventId(IntEnum):
    """Event identifiers carried in EVENT frames (QEMU → service, type 0x06)."""

    CONNECTED = 0x00
    DISCONNECTED = 0x01
    HJ_ACK = 0x02
    HJ_NACK = 0x03
    BUS_STOP = 0x04


# ---------------------------------------------------------------------------
# Socket implementation
# ---------------------------------------------------------------------------


class QemuI3CNetDev2Socket(SuperSocket):
    """SuperSocket backed by a QEMU ``i3c-target-netdev2`` UDP socket.

    The ``i3c-target-netdev2`` device extends the raw-byte ``i3c-target-netdev``
    protocol with a 1-byte type tag at the front of every UDP datagram.

    Frame format::

        [1 byte: type] [payload...]

    **Outbound (service → QEMU)** types:

    * ``0x00`` DATA    — private read response bytes
    * ``0x01`` SET_REG — device register update
    * ``0x02`` HOT_JOIN
    * ``0x03`` HOT_REMOVE
    * ``0x04`` IBI_REQ — IBI with mandatory data byte

    **Inbound (QEMU → service)** types:

    * ``0x00`` DATA        — private write data from master
    * ``0x05`` CCC_NOTIFY  — CCC state change (updates local state)
    * ``0x06`` EVENT       — bus event (logged)

    QEMU invocation example::

        -netdev socket,id=i3c-hcp0,udp=127.0.0.1:5556,localaddr=127.0.0.1:5560
        -device i3c-target-netdev2,netdev=i3c-hcp0,bus=...,address=0x08

    Corresponding socket creation::

        sock = QemuI3CNetDev2Socket(
            iface="127.0.0.1", in_port=5556,
            iface_out="127.0.0.1", out_port=5560,
            pid=0x000000000001, bcr=0x00, dcr=0xCC,
        )
    """

    desc = "read/write to a QEMU I3C NetDev2 Socket"

    def __init__(
        self,
        family: int = socket.AF_INET,
        type: int = socket.SOCK_DGRAM,  # noqa: A002
        proto: int = 0,
        iface: _GlobInterfaceType | None = None,
        iface_out: _GlobInterfaceType | None = None,
        in_port: int = 0,
        out_port: int | None = None,
        id_str: str = "",
        dump_hex: bool = True,
        dump_packet: bool = False,
        poll_period_ms: int = 10,
        # Device configuration defaults
        pid: int = 0,
        bcr: int = 0,
        dcr: int = 0,
        mwl: int = 0,
        mrl: int = 0,
        static_addr: int = 0,
        **kwargs,
    ):
        self.id_str = id_str
        self.dump_hex = dump_hex
        self.dump_packet = dump_packet
        self._poll_period_ms = poll_period_ms

        # Device register state
        self.pid = pid
        self.bcr = bcr
        self.dcr = dcr
        self.mwl = mwl
        self.mrl = mrl
        self.static_addr = static_addr
        self.dynamic_addr: int = 0
        # Set by ENEC(ENINT) / cleared by DISEC(ENINT): whether the controller
        # has enabled this device to raise IBIs (in-band interrupts).
        self.ibi_enabled: bool = False

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

    # ------------------------------------------------------------------
    # High-level send helpers
    # ------------------------------------------------------------------

    def configure(
        self,
        pid: int | None = None,
        bcr: int | None = None,
        dcr: int | None = None,
        mwl: int | None = None,
        mrl: int | None = None,
        static_addr: int | None = None,
    ) -> None:
        """Send SET_REG frames for each non-None parameter.

        Only the fields explicitly passed (i.e. not ``None``) are transmitted.
        Instance state is updated to match.
        """
        if pid is not None:
            self.pid = pid
            self.send_set_reg(NetDev2FieldId.PID, struct.pack(">Q", pid)[2:])  # 6 bytes big-endian
        if bcr is not None:
            self.bcr = bcr
            self.send_set_reg(NetDev2FieldId.BCR, bytes([bcr]))
        if dcr is not None:
            self.dcr = dcr
            self.send_set_reg(NetDev2FieldId.DCR, bytes([dcr]))
        if mwl is not None:
            self.mwl = mwl
            self.send_set_reg(NetDev2FieldId.MWL, struct.pack(">H", mwl))
        if mrl is not None:
            self.mrl = mrl
            self.send_set_reg(NetDev2FieldId.MRL, struct.pack(">H", mrl))
        if static_addr is not None:
            self.static_addr = static_addr
            self.send_set_reg(NetDev2FieldId.STATIC_ADDR, bytes([static_addr]))

    def send_set_reg(self, field_id: int | NetDev2FieldId, value_bytes: bytes) -> int:
        """Send a SET_REG frame: ``[0x01, field_id, value_bytes...]``."""
        frame = bytes([NetDev2MsgType.SET_REG, int(field_id)]) + value_bytes
        return self._send_raw(frame)

    def send_data(self, payload: bytes) -> int:
        """Send a DATA frame: ``[0x00, payload...]``."""
        frame = bytes([NetDev2MsgType.DATA]) + payload
        return self._send_raw(frame)

    def send_hot_join(self) -> int:
        """Send a HOT_JOIN frame: ``[0x02]``."""
        return self._send_raw(bytes([NetDev2MsgType.HOT_JOIN]))

    def send_hot_remove(self) -> int:
        """Send a HOT_REMOVE frame: ``[0x03]``."""
        return self._send_raw(bytes([NetDev2MsgType.HOT_REMOVE]))

    def send_ibi(self, mdb: int) -> int:
        """Send an IBI_REQ frame: ``[0x04, mdb]``."""
        return self._send_raw(bytes([NetDev2MsgType.IBI_REQ, mdb & 0xFF]))

    # ------------------------------------------------------------------
    # SuperSocket overrides
    # ------------------------------------------------------------------

    def send(self, x: Packet) -> int:
        """Send a Scapy packet; wraps with I3C PEC then into a DATA frame.

        The MCTP packet is wrapped in an :func:`I3CTransport` frame which
        appends a trailing CRC-8 PEC byte computed over
        ``(dynamic_addr << 1) | 1`` followed by the MCTP data bytes,
        matching the I3C private-read PEC convention expected by the Linux
        ``mctp-i3c`` driver.
        """
        sx = raw(I3CTransport(load=x, addr=self.dynamic_addr))
        with contextlib.suppress(AttributeError):
            x.sent_time = time.time()

        if self.dump_hex:
            print(f"{self.id_str}>TX> {linehexdump(sx, onlyhex=1, dump=True)}")
        if self.dump_packet:
            print(f"{self.id_str}>TX> {x.summary()}")

        return self.send_data(sx)

    def recv(self, x: int = MTU) -> Packet | None:
        """Receive a datagram from QEMU and dispatch on the type byte.

        Returns:
            A :class:`~pymctp.layers.mctp.TransportHdrPacket` for DATA frames,
            or ``None`` for control frames (CCC_NOTIFY, EVENT) and errors.
        """
        try:
            raw_bytes = self.ins.recv(x)
        except socket.error:
            return None

        if not raw_bytes:
            return None

        if self.dump_hex:
            print(f"{self.id_str}<RX< {linehexdump(raw_bytes, onlyhex=1, dump=True)}")

        msg_type = raw_bytes[0]
        payload = raw_bytes[1:]

        if msg_type == NetDev2MsgType.DATA:
            # Minimum: 4-byte MCTP transport header + 1-byte PEC
            if len(payload) < 5:
                logger.warning("%s: DATA frame too short (%d bytes)", self.id_str, len(payload))
                return None
            # Strip the trailing PEC byte before parsing MCTP
            mctp_bytes = I3CTransportPacket.strip_pec(payload)
            pkt = TransportHdrPacket(mctp_bytes)
            pkt.time = time.time()
            if pkt and self.dump_packet:
                print(f"{self.id_str}<RX< {pkt.summary()}")
            return pkt

        if msg_type == NetDev2MsgType.CCC_NOTIFY:
            if not payload:
                logger.warning("%s: CCC_NOTIFY frame missing CCC code", self.id_str)
                return None
            ccc = payload[0]
            data = payload[1:]
            self._handle_ccc_notify(ccc, data)
            return None

        if msg_type == NetDev2MsgType.EVENT:
            if payload:
                event_id = payload[0]
                event_name = (
                    NetDev2EventId(event_id).name
                    if event_id in NetDev2EventId._value2member_map_
                    else f"0x{event_id:02X}"
                )
                logger.info("%s: EVENT %s", self.id_str, event_name)
            else:
                logger.warning("%s: EVENT frame missing event ID", self.id_str)
            return None

        logger.warning("%s: unknown frame type 0x%02X (%d payload bytes)", self.id_str, msg_type, len(payload))
        return None

    @staticmethod
    def select(sockets: list[SuperSocket], remain: float | None = None) -> list[SuperSocket]:
        """Custom select that avoids blocking indefinitely on netdev2 sockets."""
        qemu_sockets = [sock for sock in sockets if isinstance(sock, QemuI3CNetDev2Socket)]
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_raw(self, frame: bytes) -> int:
        """Transmit a pre-built frame to the QEMU peer."""
        if not self.outs:
            return 0

        if self.out_port:
            try:
                result = self.outs.sendto(frame, (self.iface_out, self.out_port))
            except Exception as e:
                print(f"Failed sending data: {e}")
                raise
            return result
        else:
            return self.outs.send(frame)

    def _handle_ccc_notify(self, ccc: int, data: bytes) -> None:
        """Update local device state from an inbound CCC_NOTIFY payload.

        Args:
            ccc:  CCC code byte (first payload byte of the CCC_NOTIFY frame).
            data: Remaining payload bytes following the CCC code.
        """
        if ccc == NetDev2CccCode.ENTDAA:
            if data:
                self.dynamic_addr = data[0]
                logger.info("%s: ENTDAA — dynamic_addr=0x%02X", self.id_str, self.dynamic_addr)
        elif ccc == NetDev2CccCode.SETNEWDA:
            if data:
                self.dynamic_addr = data[0]
                logger.info("%s: SETNEWDA — dynamic_addr=0x%02X", self.id_str, self.dynamic_addr)
        elif ccc == NetDev2CccCode.SETMWL:
            if len(data) >= 2:
                self.mwl = (data[0] << 8) | data[1]
                logger.info("%s: SETMWL — mwl=%d", self.id_str, self.mwl)
        elif ccc == NetDev2CccCode.SETMRL:
            if len(data) >= 2:
                self.mrl = (data[0] << 8) | data[1]
                logger.info("%s: SETMRL — mrl=%d", self.id_str, self.mrl)
        elif ccc == NetDev2CccCode.RSTDAA:
            self.dynamic_addr = 0
            logger.info("%s: RSTDAA — dynamic_addr reset", self.id_str)
        elif ccc in (NetDev2CccCode.ENEC, NetDev2CccCode.ENEC_DIRECT):
            events = data[0] if data else 0
            if events & 0x01:  # ENINT (IBI enable)
                self.ibi_enabled = True
            logger.info("%s: ENEC — events_byte=0x%02X (ibi_enabled=%s)", self.id_str, events, self.ibi_enabled)
        elif ccc in (NetDev2CccCode.DISEC, NetDev2CccCode.DISEC_DIRECT):
            events = data[0] if data else 0
            if events & 0x01:  # ENINT (IBI enable)
                self.ibi_enabled = False
            logger.info("%s: DISEC — events_byte=0x%02X (ibi_enabled=%s)", self.id_str, events, self.ibi_enabled)
        else:
            logger.warning("%s: unhandled CCC_NOTIFY ccc=0x%02X data=%s", self.id_str, ccc, data.hex())
