# SPDX-FileCopyrightText: 2025 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Loopback tests for the QEMU I2C TCP stream transport
(:mod:`pymctp_exerciser_qemu.qemu_i2c_stream`).

Mirrors ``test_qemu_i3c_stream.py``: a throwaway TCP server thread stands in
for QEMU, and test cases exchange raw frames with
:class:`QemuI2CStreamSocket` to exercise WRITE / READ_REQ / READ_RSP / HELLO
handling without needing a real QEMU instance.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from pymctp.layers.mctp import SmbusTransport, TransportHdrPacket, MsgTypes
from pymctp_exerciser_qemu.qemu_i2c_stream import (
    PROTO_VERSION,
    I2CStreamMsgType,
    QemuI2CStreamSocket,
)
from pymctp_exerciser_qemu.stream_framing import FrameDecoder, encode_frame


class FakeQemuServer:
    """Minimal single-connection TCP server standing in for QEMU."""

    def __init__(self):
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self.host, self.port = self._listener.getsockname()
        self.conn: socket.socket | None = None
        self._decoder = FrameDecoder()
        self._queued_frames: list[tuple[int, bytes]] = []
        self._accept_thread = threading.Thread(target=self._accept, daemon=True)
        self._accept_thread.start()

    def _accept(self):
        conn, _ = self._listener.accept()
        self.conn = conn

    def wait_for_connection(self, timeout=5.0):
        self._accept_thread.join(timeout)
        assert self.conn is not None, "client never connected"

    def recv_frame(self, timeout=5.0) -> tuple[int, bytes]:
        """Block until a single complete frame has been received.

        Frames beyond the first that arrive bundled in the same TCP segment
        are queued and returned by later calls before reading the socket
        again.
        """
        if self._queued_frames:
            return self._queued_frames.pop(0)

        self.conn.settimeout(timeout)
        while True:
            chunk = self.conn.recv(4096)
            if not chunk:
                raise ConnectionError("peer closed connection")
            frames = self._decoder.feed(chunk)
            if frames:
                self._queued_frames.extend(frames)
                return self._queued_frames.pop(0)

    def send_frame(self, msg_type: int, body: bytes = b"") -> None:
        self.conn.sendall(encode_frame(msg_type, body))

    def close(self):
        if self.conn:
            self.conn.close()
        self._listener.close()


@pytest.fixture
def fake_qemu():
    server = FakeQemuServer()
    yield server
    server.close()


class TestQemuI2CStreamConnectAndHello:
    def test_connect_sends_hello_frame(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I2CStreamMsgType.HELLO
            assert struct.unpack(">I", body)[0] == PROTO_VERSION
        finally:
            sock.close()

    def test_peer_hello_version_mismatch_logs_warning(self, fake_qemu, caplog):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain our outgoing HELLO

            fake_qemu.send_frame(I2CStreamMsgType.HELLO, struct.pack(">I", 0x00020000))
            with caplog.at_level("WARNING"):
                pkt = sock.recv()
            assert pkt is None
            assert any("version mismatch" in rec.message for rec in caplog.records)
        finally:
            sock.close()


class TestQemuI2CStreamWrite:
    def test_recv_write_frame_parses_smbus_packet(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            mctp_pkt = (
                TransportHdrPacket(
                    dst=0x10, src=0x08, som=1, eom=1, pkt_seq=0, to=0, tag=1, ic=0, msg_type=MsgTypes.CTRL.value
                )
                / b"\x01\x02\x03"
            )
            wire_pkt = SmbusTransport(dst_addr=0x10, src_addr=0x08, load=mctp_pkt)
            wire_bytes = bytes(wire_pkt)

            fake_qemu.send_frame(I2CStreamMsgType.WRITE, wire_bytes)

            pkt = sock.recv()
            assert pkt is not None
            assert bytes(pkt) == wire_bytes
        finally:
            sock.close()


class TestQemuI2CStreamReadRequestResponse:
    def test_send_queues_bytes_for_next_read_req(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            mctp_pkt = (
                TransportHdrPacket(
                    dst=0x08, src=0x10, som=1, eom=1, pkt_seq=0, to=0, tag=2, ic=0, msg_type=MsgTypes.CTRL.value
                )
                / b"\xde\xad\xbe\xef"
            )
            wire_pkt = SmbusTransport(dst_addr=0x08, src_addr=0x10, load=mctp_pkt)
            wire_bytes = bytes(wire_pkt)

            # Queue the response bytes (no network activity happens yet).
            n = sock.send(wire_pkt)
            assert n == len(wire_bytes)

            # QEMU master now issues a READ_REQ for the full length.
            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", len(wire_bytes)))
            assert sock.recv() is None  # READ_REQ handling is internal; recv() returns None

            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I2CStreamMsgType.READ_RSP
            assert body == wire_bytes
        finally:
            sock.close()

    def test_read_req_for_fewer_bytes_than_queued_leaves_remainder(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            sock._read_buffer.extend(b"0123456789")

            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", 4))
            assert sock.recv() is None
            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I2CStreamMsgType.READ_RSP
            assert body == b"0123"
            assert bytes(sock._read_buffer) == b"456789"
        finally:
            sock.close()

    def test_read_req_more_than_queued_returns_available_bytes_and_warns(self, fake_qemu, caplog):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            sock._read_buffer.extend(b"ab")
            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", 10))
            with caplog.at_level("WARNING"):
                assert sock.recv() is None
            assert any("only 2 bytes queued" in rec.message for rec in caplog.records)

            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I2CStreamMsgType.READ_RSP
            assert body == b"ab"
        finally:
            sock.close()


class TestQemuI2CStreamAlert:
    def test_send_alert_frame(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            sock.send_alert()
            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I2CStreamMsgType.ALERT
            assert body == b""
        finally:
            sock.close()


class TestQemuI2CStreamMultipleFramesInOneSegment:
    def test_multiple_queued_frames_drained_across_recv_calls(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            mctp_pkt = (
                TransportHdrPacket(
                    dst=0x10, src=0x08, som=1, eom=1, pkt_seq=0, to=0, tag=1, ic=0, msg_type=MsgTypes.CTRL.value
                )
                / b"\x01"
            )
            wire_bytes = bytes(SmbusTransport(dst_addr=0x10, src_addr=0x08, load=mctp_pkt))

            batch = encode_frame(I2CStreamMsgType.WRITE, wire_bytes) + encode_frame(I2CStreamMsgType.ALERT, b"")
            fake_qemu.conn.sendall(batch)

            pkt = sock.recv()
            assert pkt is not None
            assert bytes(pkt) == wire_bytes

            assert sock.recv() is None  # drains the queued ALERT frame
        finally:
            sock.close()
