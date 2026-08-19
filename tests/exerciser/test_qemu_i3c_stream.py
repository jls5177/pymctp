# SPDX-FileCopyrightText: 2025 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Loopback tests for the QEMU I3C TCP stream transport
(:mod:`pymctp_exerciser_qemu.qemu_i3c_stream`).

A throwaway TCP server thread stands in for QEMU: it accepts the single
client connection made by :class:`QemuI3CStreamSocket`, and test cases send
raw frames to it / read frames from it directly (bypassing QEMU-specific
semantics) to exercise the transport's framing, HELLO handshake, DATA, and
SET_REG handling without needing a real QEMU instance.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from pymctp.layers.mctp import I3CTransport, TransportHdrPacket, MsgTypes
from pymctp_exerciser_qemu.qemu_i3c_stream import (
    PROTO_VERSION,
    I3CStreamMsgType,
    QemuI3CStreamSocket,
)
from pymctp_exerciser_qemu.qemu_i3c_netdev2 import NetDev2FieldId
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


class TestQemuI3CStreamConnectAndHello:
    def test_connect_sends_hello_frame(self, fake_qemu):
        sock = QemuI3CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i3c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I3CStreamMsgType.HELLO
            assert struct.unpack(">I", body)[0] == PROTO_VERSION
        finally:
            sock.close()

    def test_peer_hello_version_mismatch_logs_warning(self, fake_qemu, caplog):
        sock = QemuI3CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i3c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain our outgoing HELLO

            fake_qemu.send_frame(I3CStreamMsgType.HELLO, struct.pack(">I", 0x00020000))
            with caplog.at_level("WARNING"):
                pkt = sock.recv()
            assert pkt is None
            assert any("version mismatch" in rec.message for rec in caplog.records)
        finally:
            sock.close()

    def test_peer_hello_matching_version_no_warning(self, fake_qemu, caplog):
        sock = QemuI3CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i3c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain our outgoing HELLO

            fake_qemu.send_frame(I3CStreamMsgType.HELLO, struct.pack(">I", PROTO_VERSION))
            with caplog.at_level("WARNING"):
                pkt = sock.recv()
            assert pkt is None
            assert not any("version mismatch" in rec.message for rec in caplog.records)
        finally:
            sock.close()


class TestQemuI3CStreamDataAndSetReg:
    def test_send_data_frames_mctp_packet_over_tcp(self, fake_qemu):
        sock = QemuI3CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i3c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            mctp_pkt = (
                TransportHdrPacket(
                    dst=0x10, src=0x08, som=1, eom=1, pkt_seq=0, to=0, tag=1, ic=0, msg_type=MsgTypes.CTRL.value
                )
                / b"\x01\x02\x03"
            )
            sock.send(mctp_pkt)

            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I3CStreamMsgType.DATA

            # The body is the raw I3CTransport-wrapped bytes (MCTP header + payload + PEC).
            expected = bytes(I3CTransport(load=mctp_pkt, addr=sock.dynamic_addr))
            assert body == expected
        finally:
            sock.close()

    def test_recv_data_frame_parses_mctp_packet(self, fake_qemu):
        sock = QemuI3CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i3c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            mctp_pkt = (
                TransportHdrPacket(
                    dst=0x08, src=0x10, som=1, eom=1, pkt_seq=0, to=0, tag=2, ic=0, msg_type=MsgTypes.CTRL.value
                )
                / b"\xaa\xbb"
            )
            wire_bytes = bytes(I3CTransport(load=mctp_pkt, addr=0x10))

            fake_qemu.send_frame(I3CStreamMsgType.DATA, wire_bytes)

            pkt = sock.recv()
            assert pkt is not None
            assert bytes(pkt) == bytes(mctp_pkt)
            assert pkt.dst == 0x08
            assert pkt.src == 0x10
        finally:
            sock.close()

    def test_send_set_reg_pid(self, fake_qemu):
        sock = QemuI3CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i3c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            sock.configure(pid=0x0102030405, bcr=0x40, dcr=0xCC)

            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I3CStreamMsgType.SET_REG
            assert body[0] == NetDev2FieldId.PID
            assert body[1:] == struct.pack(">Q", 0x0102030405)[2:]

            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I3CStreamMsgType.SET_REG
            assert body == bytes([NetDev2FieldId.BCR, 0x40])

            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I3CStreamMsgType.SET_REG
            assert body == bytes([NetDev2FieldId.DCR, 0xCC])
        finally:
            sock.close()

    def test_hot_join_and_hot_remove_frames(self, fake_qemu):
        sock = QemuI3CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i3c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            sock.send_hot_join()
            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I3CStreamMsgType.HOT_JOIN
            assert body == b""

            sock.send_hot_remove()
            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I3CStreamMsgType.HOT_REMOVE
            assert body == b""
        finally:
            sock.close()


class TestQemuI3CStreamMultipleFramesInOneSegment:
    def test_multiple_queued_frames_drained_across_recv_calls(self, fake_qemu):
        sock = QemuI3CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i3c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            # Send two CCC_NOTIFY frames and one EVENT frame back-to-back in
            # a single TCP write, simulating them arriving in one segment.
            batch = (
                encode_frame(I3CStreamMsgType.CCC_NOTIFY, bytes([0x07, 0x0A]))  # ENTDAA -> dynamic_addr=0x0A
                + encode_frame(I3CStreamMsgType.EVENT, bytes([0x00]))  # CONNECTED
                + encode_frame(I3CStreamMsgType.CCC_NOTIFY, bytes([0x88, 0x0B]))  # SETNEWDA -> dynamic_addr=0x0B
            )
            fake_qemu.conn.sendall(batch)

            # Three recv() calls should drain all three frames, updating
            # dynamic_addr along the way, without additional socket reads.
            assert sock.recv() is None
            assert sock.dynamic_addr == 0x0A
            assert sock.recv() is None
            assert sock.recv() is None
            assert sock.dynamic_addr == 0x0B
        finally:
            sock.close()
