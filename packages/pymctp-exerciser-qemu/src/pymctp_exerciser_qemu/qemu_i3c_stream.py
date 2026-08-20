# SPDX-FileCopyrightText: 2025 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""QEMU I3C "remote target" transport over a single bidirectional TCP stream.

This reuses the exact message semantics of :mod:`qemu_i3c_netdev2` — SET_REG,
HOT_JOIN, HOT_REMOVE, IBI_REQ, CCC_NOTIFY, EVENT, and PEC-wrapped DATA frames
— but instead of two UDP ports (``in_port``/``out_port``) the transport
connects as a TCP *client* to QEMU (QEMU listens as the TCP server) over a
single connection, and frames every message with a 4-byte big-endian length
prefix::

    [u32 length BE][u8 type][body...]

``length`` counts the bytes of ``type`` + ``body`` (i.e. ``1 + len(body)``).
There is no other header. See :mod:`stream_framing` for the codec.

On connect, a HELLO frame (type ``0x07``) carrying a 4-byte big-endian
protocol version is sent so both ends can verify they speak compatible
versions of the wire protocol.
"""

from __future__ import annotations

import collections
import contextlib
import logging
import select
import socket
import struct
import time
from enum import IntEnum

from scapy.compat import raw
from scapy.data import MTU
from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from scapy.utils import linehexdump

from pymctp.layers.mctp import I3CTransport, I3CTransportPacket, TransportHdrPacket

from .qemu_i3c_netdev2 import NetDev2CccCode, NetDev2EventId, NetDev2FieldId
from .stream_framing import FrameDecoder, encode_frame

logger = logging.getLogger(__name__)

# Wire protocol version sent/checked in HELLO frames: major=1, minor=0.
PROTO_VERSION = 0x00010000

# I3C ENEC/DISEC event-enable byte bits (see MIPI I3C ENEC/DISEC CCC).
I3C_EVENT_ENINT = 0x01  # target IBI (in-band interrupt) enable
I3C_EVENT_ENCR = 0x02  # controller-role request enable
I3C_EVENT_ENHJ = 0x08  # hot-join enable


class I3CStreamMsgType(IntEnum):
    """Frame type tags for the I3C TCP stream transport.

    Identical to :class:`~pymctp_exerciser_qemu.qemu_i3c_netdev2.NetDev2MsgType`
    with the addition of ``HELLO`` for the connection version handshake.
    """

    DATA = 0x00
    SET_REG = 0x01
    HOT_JOIN = 0x02
    HOT_REMOVE = 0x03
    IBI_REQ = 0x04
    CCC_NOTIFY = 0x05
    EVENT = 0x06
    HELLO = 0x07


class QemuI3CStreamSocket(SuperSocket):
    """SuperSocket backed by a QEMU I3C "remote target" TCP stream.

    QEMU invocation example (illustrative — the QEMU-side device is being
    built in parallel)::

        -device i3c-target-remote,bus=...,host=127.0.0.1,port=5560,address=0x08

    Corresponding socket creation::

        sock = QemuI3CStreamSocket(
            host="127.0.0.1", port=5560, id_str="i3c0",
            pid=0x000000000001, bcr=0x00, dcr=0xCC,
        )
    """

    desc = "read/write to a QEMU I3C remote-target TCP stream"

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        id_str: str = "",
        dump_hex: bool = True,
        dump_packet: bool = False,
        poll_period_ms: int = 10,
        connect_timeout: float = 5.0,
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
        self.host = host
        self.port = port

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

        self._decoder = FrameDecoder()
        self._pending_frames: collections.deque[tuple[int, bytes]] = collections.deque()

        fd = socket.create_connection((host, port), timeout=connect_timeout)
        fd.settimeout(None)
        assert fd != -1
        self.ins = self.outs = fd

        self._send_hello()

    # ------------------------------------------------------------------
    # High-level send helpers (mirrors QemuI3CNetDev2Socket)
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
        """Send a SET_REG frame: body ``[field_id, value_bytes...]``."""
        return self._send_raw(I3CStreamMsgType.SET_REG, bytes([int(field_id)]) + value_bytes)

    def send_data(self, payload: bytes) -> int:
        """Send a DATA frame: body is the raw private-transfer bytes."""
        return self._send_raw(I3CStreamMsgType.DATA, payload)

    def send_hot_join(self) -> int:
        """Send a HOT_JOIN frame (no body)."""
        return self._send_raw(I3CStreamMsgType.HOT_JOIN)

    def send_hot_remove(self) -> int:
        """Send a HOT_REMOVE frame (no body)."""
        return self._send_raw(I3CStreamMsgType.HOT_REMOVE)

    def send_ibi(self, mdb: int) -> int:
        """Send an IBI_REQ frame: body ``[mdb]``.

        The controller must have enabled IBIs for this device via ENEC(ENINT)
        first; if it has not, the IBI is likely to be NACKed. We still send it
        (some flows enable events out of band) but warn to aid debugging.
        """
        if not self.ibi_enabled:
            logger.warning("%s: sending IBI while IBIs are not enabled (no ENEC(ENINT) seen yet)", self.id_str)
        return self._send_raw(I3CStreamMsgType.IBI_REQ, bytes([mdb & 0xFF]))

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
        """Receive from the TCP stream and dispatch the next decoded frame.

        Handles partial reads and multiple frames arriving in a single TCP
        segment: newly received bytes are fed into the frame decoder, any
        fully decoded frames are queued, and one queued frame is dispatched
        per call (subsequent frames are drained on later calls, without a
        further ``recv()`` on the socket).

        Returns:
            A :class:`~pymctp.layers.mctp.TransportHdrPacket` for DATA frames,
            or ``None`` for control frames (HELLO, CCC_NOTIFY, EVENT) and
            errors.
        """
        if not self._pending_frames:
            try:
                raw_bytes = self.ins.recv(x)
            except socket.error:
                return None

            if not raw_bytes:
                logger.info("%s: peer closed the TCP connection", self.id_str)
                return None

            if self.dump_hex:
                print(f"{self.id_str}<RX< {linehexdump(raw_bytes, onlyhex=1, dump=True)}")

            self._pending_frames.extend(self._decoder.feed(raw_bytes))

        if not self._pending_frames:
            return None

        msg_type, payload = self._pending_frames.popleft()
        return self._dispatch(msg_type, payload)

    @staticmethod
    def select(sockets: list[SuperSocket], remain: float | None = None) -> list[SuperSocket]:
        """Custom select that avoids blocking indefinitely on stream sockets.

        Sockets with already-decoded frames queued (from a prior TCP segment
        that contained more than one frame) are always reported as ready,
        even if the underlying fd currently has no new data to read.
        """
        qemu_sockets = [sock for sock in sockets if isinstance(sock, QemuI3CStreamSocket)]
        if not qemu_sockets:
            return []

        ready = [sock for sock in qemu_sockets if sock._pending_frames]
        need_poll = [sock for sock in qemu_sockets if not sock._pending_frames]
        if not need_poll:
            return ready

        # A closed socket's fileno() is -1, which select() rejects with
        # ValueError rather than OSError. That happens routinely during
        # shutdown, when the socket is closed while the sniffer is still
        # polling, so drop closed sockets instead of tearing down the loop.
        need_poll = [sock for sock in need_poll if sock.ins is not None and sock.ins.fileno() >= 0]
        if not need_poll:
            return ready

        socket_fds = [sock.ins for sock in need_poll]
        poll_periods = [x._poll_period_ms for x in need_poll]
        timeout_ms = min(poll_periods + [(remain or 1) * 1000])
        timeout_s = timeout_ms / 1000.0

        try:
            ready_fds, _, _ = select.select(socket_fds, [], [], timeout_s)
        except (select.error, ValueError):
            return ready

        ready.extend(sock for sock in need_poll if sock.ins in ready_fds)
        return ready

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _dispatch(self, msg_type: int, payload: bytes) -> Packet | None:
        """Dispatch a single decoded ``(msg_type, payload)`` frame."""
        if msg_type == I3CStreamMsgType.DATA:
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

        if msg_type == I3CStreamMsgType.CCC_NOTIFY:
            if not payload:
                logger.warning("%s: CCC_NOTIFY frame missing CCC code", self.id_str)
                return None
            ccc = payload[0]
            data = payload[1:]
            self._handle_ccc_notify(ccc, data)
            return None

        if msg_type == I3CStreamMsgType.EVENT:
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

        if msg_type == I3CStreamMsgType.HELLO:
            self._handle_hello(payload)
            return None

        logger.warning("%s: unknown frame type 0x%02X (%d payload bytes)", self.id_str, msg_type, len(payload))
        return None

    def _send_raw(self, msg_type: int, body: bytes = b"") -> int:
        """Encode and transmit a frame to the QEMU peer over the TCP stream."""
        if not self.outs:
            return 0

        frame = encode_frame(int(msg_type), body)
        try:
            self.outs.sendall(frame)
        except Exception as e:
            print(f"Failed sending data: {e}")
            raise
        return len(frame)

    def _send_hello(self) -> int:
        """Send the initial HELLO frame carrying the wire protocol version."""
        return self._send_raw(I3CStreamMsgType.HELLO, struct.pack(">I", PROTO_VERSION))

    def _handle_hello(self, payload: bytes) -> None:
        """Validate a peer HELLO frame's protocol version, logging a warning on mismatch."""
        if len(payload) < 4:
            logger.warning("%s: HELLO frame too short (%d bytes)", self.id_str, len(payload))
            return
        (peer_version,) = struct.unpack(">I", payload[:4])
        if peer_version != PROTO_VERSION:
            logger.warning(
                "%s: HELLO protocol version mismatch: local=0x%08X peer=0x%08X",
                self.id_str,
                PROTO_VERSION,
                peer_version,
            )
        else:
            logger.info("%s: HELLO version check OK (0x%08X)", self.id_str, peer_version)

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
            # Enable Events: for each bit set, enable that event. Bit 0 (ENINT)
            # is the IBI enable — the controller is telling us we may raise IBIs.
            events = data[0] if data else 0
            if events & I3C_EVENT_ENINT:
                self.ibi_enabled = True
            logger.info("%s: ENEC — events_byte=0x%02X (ibi_enabled=%s)", self.id_str, events, self.ibi_enabled)
        elif ccc in (NetDev2CccCode.DISEC, NetDev2CccCode.DISEC_DIRECT):
            # Disable Events: for each bit set, disable that event.
            events = data[0] if data else 0
            if events & I3C_EVENT_ENINT:
                self.ibi_enabled = False
            logger.info("%s: DISEC — events_byte=0x%02X (ibi_enabled=%s)", self.id_str, events, self.ibi_enabled)
        else:
            logger.warning("%s: unhandled CCC_NOTIFY ccc=0x%02X data=%s", self.id_str, ccc, data.hex())
