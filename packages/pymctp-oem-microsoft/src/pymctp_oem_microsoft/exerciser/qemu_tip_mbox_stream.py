# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""QEMU NPCM8xx TIP shared-memory mailbox transport over TCP.

QEMU models the BMC-side Trusted I/O Platform (TIP) mailbox device and listens
as a TCP server; this transport connects as the TCP client and mocks the TIP
co-processor endpoint. Frames use the common stream framing codec::

    [u32 length BE][u8 type][body...]

Message types::

    0x00 DATA  — raw mailbox-window packet bytes, either starting at SMBus
                 command code 0x0F or including a leading destination address
                 byte followed by 0x0F.
    0x07 HELLO — body ``[u32 proto_version BE]``, sent once on connect.

The outbound TIP-to-BMC mailbox window omits the SMBus destination address
byte, but the trailing SMBus PEC is still computed over that destination byte
plus the visible window bytes. :meth:`send` therefore builds a normal addressed
SMBus/MCTP packet to the BMC, strips only the leading destination byte, and
sends the remainder in a DATA frame.
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

import crc8
from scapy.compat import raw
from scapy.data import MTU
from scapy.packet import Packet
from scapy.supersocket import SuperSocket
from scapy.utils import linehexdump

from pymctp.layers.mctp import SmbusTransport, SmbusTransportPacket

from .stream_framing import FrameDecoder, encode_frame

logger = logging.getLogger(__name__)

# Wire protocol version sent/checked in HELLO frames: major=1, minor=0.
PROTO_VERSION = 0x00010000

# Minimum window body: command_code, byte_count, src_addr, and PEC.
_MIN_MBOX_PAYLOAD_LEN = 4


class TipMboxStreamMsgType(IntEnum):
    """Frame type tags for the TIP mailbox TCP stream transport."""

    DATA = 0x00
    HELLO = 0x07


class QemuTipMboxStreamSocket(SuperSocket):
    """SuperSocket backed by a QEMU NPCM8xx TIP mailbox TCP stream.

    QEMU invocation example (illustrative)::

        -device npcm8xx-tip-mbox,port=5580,server=on

    Corresponding socket creation::

        sock = QemuTipMboxStreamSocket(host="127.0.0.1", port=5580, id_str="tip")
    """

    desc = "read/write to a QEMU NPCM8xx TIP mailbox TCP stream"

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        id_str: str = "",
        dump_hex: bool = True,
        dump_packet: bool = False,
        bmc_addr: int = 0x10,
        tip_addr: int = 0x41,
        rx_window_has_addr: bool | None = None,
        poll_period_ms: int = 10,
        connect_timeout: float = 5.0,
        **kwargs,
    ):
        self.id_str = id_str
        self.dump_hex = dump_hex
        self.dump_packet = dump_packet
        self.bmc_addr = bmc_addr
        self.tip_addr = tip_addr
        self.rx_window_has_addr = rx_window_has_addr
        self._poll_period_ms = poll_period_ms
        self.host = host
        self.port = port

        self._decoder = FrameDecoder()
        self._pending_frames: collections.deque[tuple[int, bytes]] = collections.deque()

        fd = socket.create_connection((host, port), timeout=connect_timeout)
        fd.settimeout(None)
        assert fd != -1
        self.ins = self.outs = fd

        self._send_hello()

    # ------------------------------------------------------------------
    # High-level send helpers
    # ------------------------------------------------------------------

    def send_data(self, payload: bytes) -> int:
        """Send a DATA frame whose body is the raw mailbox-window packet."""
        return self._send_raw(TipMboxStreamMsgType.DATA, payload)

    # ------------------------------------------------------------------
    # SuperSocket overrides
    # ------------------------------------------------------------------

    def send(self, x: Packet) -> int:
        """Send an MCTP packet to the BMC through the mailbox window.

        The session layer already wraps outgoing replies in an
        :class:`SmbusTransportPacket` (dst = the BMC's SMBus address, src = this
        TIP endpoint), with the PEC computed over that destination address.
        Re-wrapping such a packet would double-add the SMBus/MCTP header, so use
        it as-is; only a bare MCTP packet (e.g. from tests/tools) is wrapped
        here. QEMU's mailbox window starts at the SMBus command code 0x0F and
        the BMC's RX path prepends its own address for the PEC, so strip the
        leading destination address byte before sending.
        """
        if isinstance(x, SmbusTransportPacket):
            smbus_pkt = x
        else:
            smbus_pkt = SmbusTransport(
                dst_addr=(self.bmc_addr << 1) & 0xFF,
                src_addr=((self.tip_addr << 1) | 1) & 0xFF,
                load=x,
            )
        sx = raw(smbus_pkt)
        # Addressless window: drop the leading SMBus destination address byte
        # (a frame already starting at 0x0F has none to strip).
        body = sx[1:] if sx[:1] != b"\x0f" else sx
        with contextlib.suppress(AttributeError):
            x.sent_time = time.time()

        if self.dump_hex:
            print(f"{self.id_str}>TX> {linehexdump(body, onlyhex=1, dump=True)}")
        if self.dump_packet:
            print(f"{self.id_str}>TX> {x.summary()}")

        return self.send_data(body)

    def recv(self, x: int = MTU) -> Packet | None:
        """Receive and dispatch the next decoded frame from the TCP stream."""
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
        """Custom select that reports sockets with already-decoded frames ready."""
        qemu_sockets = [sock for sock in sockets if isinstance(sock, QemuTipMboxStreamSocket)]
        if not qemu_sockets:
            return []

        ready = [sock for sock in qemu_sockets if sock._pending_frames]
        need_poll = [sock for sock in qemu_sockets if not sock._pending_frames]
        if not need_poll:
            return ready

        socket_fds = [sock.ins for sock in need_poll]
        poll_periods = [x._poll_period_ms for x in need_poll]
        timeout_ms = min(poll_periods + [(remain or 1) * 1000])
        timeout_s = timeout_ms / 1000.0

        try:
            ready_fds, _, _ = select.select(socket_fds, [], [], timeout_s)
        except select.error:
            return ready

        ready.extend(sock for sock in need_poll if sock.ins in ready_fds)
        return ready

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _dispatch(self, msg_type: int, payload: bytes) -> Packet | None:
        """Dispatch a single decoded ``(msg_type, payload)`` frame."""
        if msg_type == TipMboxStreamMsgType.DATA:
            has_addr = self._rx_payload_has_addr(payload)
            if has_addr is None:
                return None
            self._check_rx_pec(payload, has_addr=has_addr)
            if has_addr:
                pkt = SmbusTransport(payload)
            else:
                # The window frame starts at the SMBus command code (0x0F), so
                # the destination address byte is absent and SmbusTransport would
                # leave dst_addr unset. This TIP endpoint is the destination, so
                # prepend our own SMBus write address (tip_addr << 1) before
                # parsing -- mirroring the BMC RX driver's
                # ``rx_scratch[0] = lladdr << 1`` -- so dst_addr is populated.
                # Otherwise downstream consumers that compute ``dst_addr >> 1``
                # raise "unsupported operand type(s) for >>: 'NoneType'". This
                # also matches the PEC the BMC computed over that address byte.
                pkt = SmbusTransport(bytes([(self.tip_addr << 1) & 0xFF]) + payload)
            pkt.time = time.time()
            if pkt and self.dump_packet:
                print(f"{self.id_str}<RX< {pkt.summary()}")
            return pkt

        if msg_type == TipMboxStreamMsgType.HELLO:
            self._handle_hello(payload)
            return None

        logger.warning("%s: unknown frame type 0x%02X (%d payload bytes)", self.id_str, msg_type, len(payload))
        return None

    def _rx_payload_has_addr(self, payload: bytes) -> bool | None:
        """Return whether an RX DATA body includes the leading SMBus address."""
        if len(payload) < _MIN_MBOX_PAYLOAD_LEN:
            logger.warning("%s: DATA frame too short (%d bytes)", self.id_str, len(payload))
            return None

        if self.rx_window_has_addr is False:
            if payload[0] == 0x0F:
                return False
            logger.warning("%s: DATA frame does not match addressless mailbox window format", self.id_str)
            return None

        if self.rx_window_has_addr is True:
            if len(payload) >= _MIN_MBOX_PAYLOAD_LEN + 1 and payload[1] == 0x0F:
                return True
            logger.warning("%s: DATA frame does not match address-prefixed mailbox window format", self.id_str)
            return None

        if payload[0] == 0x0F:
            return False
        if len(payload) < _MIN_MBOX_PAYLOAD_LEN + 1:
            logger.warning(
                "%s: DATA frame too short for address-prefixed mailbox window (%d bytes)", self.id_str, len(payload)
            )
            return None
        if payload[1] == 0x0F:
            return True

        logger.warning("%s: DATA frame matches neither mailbox window format", self.id_str)
        return None

    def _check_rx_pec(self, payload: bytes, *, has_addr: bool) -> None:
        """Warn if the mailbox DATA payload's PEC does not match the TIP address."""
        if len(payload) < 2:
            return
        if has_addr:
            expected_addr = (self.tip_addr << 1) & 0xFF
            if payload[0] != expected_addr:
                logger.debug(
                    "%s: DATA frame addressed to 0x%02X, expected TIP write address 0x%02X",
                    self.id_str,
                    payload[0],
                    expected_addr,
                )
            crc_input = payload[:-1]
        else:
            crc_input = bytes([(self.tip_addr << 1) & 0xFF]) + payload[:-1]
        crc = crc8.crc8()
        crc.update(crc_input)
        expected = crc.digest()[0]
        actual = payload[-1]
        if expected != actual:
            logger.warning(
                "%s: DATA PEC mismatch: expected=0x%02X actual=0x%02X",
                self.id_str,
                expected,
                actual,
            )

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
        return self._send_raw(TipMboxStreamMsgType.HELLO, struct.pack(">I", PROTO_VERSION))

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
