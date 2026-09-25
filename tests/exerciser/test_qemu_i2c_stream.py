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
from concurrent.futures import ThreadPoolExecutor

import pytest

from pymctp.automaton.simple_endpoint import SimpleEndpointAM
from pymctp.automaton.role_endpoint import RoleBasedEndpointAM
from pymctp.layers.mctp import SmbusTransport, TransportHdrPacket, MsgTypes
from pymctp.layers.mctp.control import ControlHdr, ContrlCmdCodes, GetEndpointID, SetEndpointIDRequestPacket
from pymctp.layers.mctp.control.get_eid import GetEndpointIDRequestPacket
from pymctp.layers.mctp.types import EndpointContext, Smbus7bitAddress
from pymctp_exerciser_qemu.configs import I2CStreamSocketConfig
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


def response_packet(
    body: bytes, *, som: int = 1, eom: int = 1, pkt_seq: int = 0, tag: int = 2, src_addr: int = 0x10
):
    hdr = TransportHdrPacket(
        dst=0x08, src=0x10, som=som, eom=eom, pkt_seq=pkt_seq, to=0, tag=tag, msg_type=MsgTypes.CTRL.value
    )
    return SmbusTransport(dst_addr=0x08, src_addr=src_addr, load=hdr / body)


def control_request(address: int):
    return SmbusTransport(
        dst_addr=address << 1,
        src_addr=0x20,
        load=TransportHdrPacket(dst=8, src=9, to=1, som=1, eom=1) / ControlHdr(rq=True) / GetEndpointID(),
    )


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
    def test_slave_reply_stages_18_packets_without_pacing_then_flushes_on_read(self, fake_qemu, monkeypatch):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO
            packets = [
                response_packet(bytes([index]), som=int(index == 0), eom=int(index == 17), pkt_seq=index % 4)
                for index in range(18)
            ]
            sleeps = []
            monkeypatch.setattr("pymctp.automaton.simple_endpoint.time.sleep", sleeps.append)
            am = SimpleEndpointAM(socket=sock, context=EndpointContext())

            assert sock.stages_complete_replies
            assert am.inter_packet_delay_s == 0.005
            am.send_reply(packets)

            assert sleeps == []
            assert list(sock._pending_packets) == [bytes(packet) for packet in packets]
            assert not sock._staged_messages
            with pytest.raises(socket.timeout):
                fake_qemu.recv_frame(timeout=0.05)

            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", max(len(bytes(p)) for p in packets)))
            assert sock.recv() is None
            assert [fake_qemu.recv_frame() for _ in packets] == [
                (I2CStreamMsgType.READ_RSP, bytes(packet)) for packet in packets
            ]
            assert not sock._pending_packets
        finally:
            sock.close()

    def test_master_reply_still_paces_packets(self, fake_qemu, monkeypatch):
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host, port=fake_qemu.port, dump_hex=False, master=True, target_address=0x10
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO
            packets = [response_packet(b"first", som=1, eom=0), response_packet(b"last", som=0, eom=1, pkt_seq=1)]
            sleeps = []
            monkeypatch.setattr("pymctp.automaton.simple_endpoint.time.sleep", sleeps.append)
            am = SimpleEndpointAM(socket=sock, context=EndpointContext())

            assert not sock.stages_complete_replies
            am.send_reply(packets)

            assert sleeps == [0.005]
            assert [fake_qemu.recv_frame() for _ in packets] == [
                (I2CStreamMsgType.WRITE, bytes(packet)) for packet in packets
            ]
        finally:
            sock.close()

    def test_custom_sender_keeps_pacing_even_with_slave_socket(self, fake_qemu, monkeypatch):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, dump_hex=False)
        try:
            packets = [response_packet(b"first", som=1, eom=0), response_packet(b"last", som=0, eom=1, pkt_seq=1)]
            sent = []
            sleeps = []
            monkeypatch.setattr("pymctp.automaton.simple_endpoint.time.sleep", sleeps.append)
            am = SimpleEndpointAM(socket=sock, context=EndpointContext())

            am.send_reply(packets, send_function=sent.append)

            assert sent == packets
            assert sleeps == [0.005]
            assert not sock._pending_packets
        finally:
            sock.close()

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
            with pytest.raises(socket.timeout):
                fake_qemu.recv_frame(timeout=0.05)

            # QEMU master now issues a READ_REQ for the full length.
            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", len(wire_bytes)))
            assert sock.recv() is None  # READ_REQ handling is internal; recv() returns None

            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I2CStreamMsgType.READ_RSP
            assert body == wire_bytes
        finally:
            sock.close()

    def test_one_read_req_flushes_each_packet_in_order(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            packets = [response_packet(body, tag=tag) for tag, body in enumerate([b"first", b"second", b"third"])]
            for packet in packets:
                sock.send(packet)
            wire_bytes = [bytes(packet) for packet in packets]

            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", max(map(len, wire_bytes))))
            assert sock.recv() is None
            assert [fake_qemu.recv_frame() for _ in packets] == [
                (I2CStreamMsgType.READ_RSP, data) for data in wire_bytes
            ]
            assert not sock._pending_packets
            with pytest.raises(socket.timeout):
                fake_qemu.recv_frame(timeout=0.05)
        finally:
            sock.close()

    def test_empty_read_req_sends_no_response(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO
            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", 64))
            assert sock.recv() is None
            with pytest.raises(socket.timeout):
                fake_qemu.recv_frame(timeout=0.05)
        finally:
            sock.close()

    def test_small_read_req_retains_whole_packet_and_blocks_later_packets(self, fake_qemu, caplog):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO
            first = response_packet(b"0123456789")
            second = response_packet(b"a", tag=3)
            sock.send(first)
            sock.send(second)

            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", len(bytes(first)) - 1))
            with caplog.at_level("WARNING"):
                assert sock.recv() is None
            assert "retaining packet" in caplog.text
            assert list(sock._pending_packets) == [bytes(first), bytes(second)]
            with pytest.raises(socket.timeout):
                fake_qemu.recv_frame(timeout=0.05)

            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", len(bytes(first))))
            assert sock.recv() is None
            assert fake_qemu.recv_frame() == (I2CStreamMsgType.READ_RSP, bytes(first))
            assert fake_qemu.recv_frame() == (I2CStreamMsgType.READ_RSP, bytes(second))
        finally:
            sock.close()

    def test_read_req_more_than_queued_returns_available_packet_and_logs_debug(self, fake_qemu, caplog):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            packet = response_packet(b"ab")
            sock.send(packet)
            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", len(bytes(packet)) + 10))
            with caplog.at_level("DEBUG"):
                assert sock.recv() is None
            assert any("returned 1 queued packets" in rec.message for rec in caplog.records)
            assert not any(rec.levelname == "WARNING" for rec in caplog.records)

            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I2CStreamMsgType.READ_RSP
            assert body == bytes(packet)
        finally:
            sock.close()

    def test_paced_message_is_published_atomically_for_concurrent_pull(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        continue_reply = threading.Event()
        first_staged = threading.Event()
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO
            first = response_packet(b"first", som=1, eom=0)
            last = response_packet(b"last", som=0, eom=1, pkt_seq=1)

            def send_paced_reply():
                sock.send(first)
                first_staged.set()
                assert continue_reply.wait(timeout=2)
                sock.send(last)

            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(send_paced_reply)
                assert first_staged.wait(timeout=2)
                fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", 64))
                assert sock.recv() is None
                with pytest.raises(socket.timeout):
                    fake_qemu.recv_frame(timeout=0.05)
                assert not sock._pending_packets

                continue_reply.set()
                future.result(timeout=2)
                fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", 64))
                assert sock.recv() is None
                assert fake_qemu.recv_frame() == (I2CStreamMsgType.READ_RSP, bytes(first))
                assert fake_qemu.recv_frame() == (I2CStreamMsgType.READ_RSP, bytes(last))
        finally:
            continue_reply.set()
            sock.close()

    def test_invalid_read_requests_and_orphan_continuation_are_reported(self, fake_qemu, caplog):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO
            packet = response_packet(b"still pending")
            sock.send(packet)
            with pytest.raises(ValueError, match="continuation without SOM"):
                sock.send(response_packet(b"orphan", som=0, eom=1, pkt_seq=1))
            for invalid_body in [b"\x10", b"\x00\x40\x00", b"\x00\x00"]:
                fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, invalid_body)
                with caplog.at_level("WARNING"):
                    assert sock.recv() is None
            assert "malformed READ_REQ" in caplog.text
            assert "invalid READ_REQ length 0" in caplog.text
            assert list(sock._pending_packets) == [bytes(packet)]
            with pytest.raises(socket.timeout):
                fake_qemu.recv_frame(timeout=0.05)
        finally:
            sock.close()

    def test_new_som_discards_stale_fragment_and_recovers(self, fake_qemu, caplog):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            sock.send(response_packet(b"stale", som=1, eom=0))
            first = response_packet(b"new", som=1, eom=0)
            with caplog.at_level("WARNING"):
                sock.send(first)
            assert "discarding incomplete MCTP message" in caplog.text
            assert sock._staged_packet_count == 1
            assert not sock._pending_packets
            last = response_packet(b"last", som=0, eom=1, pkt_seq=1)
            sock.send(last)
            assert list(sock._pending_packets) == [bytes(first), bytes(last)]
            assert not sock._staged_messages
            assert sock._staged_packet_count == 0
        finally:
            sock.close()

    def test_failed_read_rsp_retains_packet_for_retry(self, fake_qemu, monkeypatch):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO
            packet = response_packet(b"retry")
            sock.send(packet)
            with monkeypatch.context() as patch:
                patch.setattr(sock, "send_read_rsp", lambda data: 0)
                fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", 64))
                assert sock.recv() is None
            assert list(sock._pending_packets) == [bytes(packet)]
            with pytest.raises(socket.timeout):
                fake_qemu.recv_frame(timeout=0.05)

            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", 64))
            assert sock.recv() is None
            assert fake_qemu.recv_frame() == (I2CStreamMsgType.READ_RSP, bytes(packet))
        finally:
            sock.close()

    def test_pending_cap_across_read_requests_and_recovers(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO
            packet = response_packet(b"cap")
            wire_bytes = bytes(packet)
            for _ in range(512):
                sock.send(packet)
            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", len(wire_bytes) - 1))
            assert sock.recv() is None
            with pytest.raises(OverflowError, match="pending packet limit 512"):
                sock.send(packet)
            assert len(sock._pending_packets) == 512
            with pytest.raises(socket.timeout):
                fake_qemu.recv_frame(timeout=0.05)

            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", len(wire_bytes)))
            assert sock.recv() is None
            assert [fake_qemu.recv_frame() for _ in range(512)] == [(I2CStreamMsgType.READ_RSP, wire_bytes)] * 512
            assert not sock._pending_packets

            for _ in range(512):
                sock.send(packet)
            with pytest.raises(OverflowError, match="pending packet limit 512"):
                sock.send(packet)
            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", len(wire_bytes)))
            assert sock.recv() is None
            assert [fake_qemu.recv_frame() for _ in range(512)] == [(I2CStreamMsgType.READ_RSP, wire_bytes)] * 512
            assert not sock._pending_packets
        finally:
            sock.close()

    def test_staged_fragments_count_toward_cap_and_overflow_discards_message(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO
            queued = response_packet(b"queued", tag=3)
            for _ in range(510):
                sock.send(queued)
            first = response_packet(b"first", som=1, eom=0)
            second = response_packet(b"second", som=0, eom=0, pkt_seq=1)
            sock.send(first)
            sock.send(second)
            assert len(sock._pending_packets) + sock._staged_packet_count == 512
            with pytest.raises(OverflowError, match="pending packet limit 512"):
                sock.send(response_packet(b"last", som=0, eom=1, pkt_seq=2))
            assert list(sock._pending_packets) == [bytes(queued)] * 510
            assert not sock._staged_messages
            assert sock._staged_packet_count == 0

            recovered = response_packet(b"recovered")
            sock.send(recovered)
            fake_qemu.send_frame(
                I2CStreamMsgType.READ_REQ, struct.pack(">H", max(len(bytes(queued)), len(bytes(recovered))))
            )
            assert sock.recv() is None
            assert [fake_qemu.recv_frame() for _ in range(510)] == [(I2CStreamMsgType.READ_RSP, bytes(queued))] * 510
            assert fake_qemu.recv_frame() == (I2CStreamMsgType.READ_RSP, bytes(recovered))
            assert not sock._pending_packets
        finally:
            sock.close()

    def test_staged_commit_at_exact_cap_rejects_other_admissions(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO
            queued = response_packet(b"queued", tag=3)
            for _ in range(510):
                sock.send(queued)
            first = response_packet(b"first", som=1, eom=0)
            last = response_packet(b"last", som=0, eom=1, pkt_seq=1)
            sock.send(first)
            sock.send(last)
            assert len(sock._pending_packets) == 512
            assert not sock._staged_messages
            assert sock._staged_packet_count == 0
            with pytest.raises(OverflowError, match="pending packet limit 512"):
                sock.send(SmbusTransport(dst_addr=0x08, src_addr=0x10, load=b"plain"))
            with pytest.raises(OverflowError, match="pending packet limit 512"):
                sock.send(response_packet(b"other", som=1, eom=0))
            assert len(sock._pending_packets) == 512
            assert not sock._staged_messages

            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", 64))
            assert sock.recv() is None
            assert [fake_qemu.recv_frame() for _ in range(510)] == [(I2CStreamMsgType.READ_RSP, bytes(queued))] * 510
            assert fake_qemu.recv_frame() == (I2CStreamMsgType.READ_RSP, bytes(first))
            assert fake_qemu.recv_frame() == (I2CStreamMsgType.READ_RSP, bytes(last))
            assert not sock._pending_packets
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


class TestQemuI2CStreamMasterModeConstruction:
    def test_master_without_target_address_raises(self, fake_qemu):
        with pytest.raises(ValueError, match="target_address"):
            QemuI2CStreamSocket(
                host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False, master=True
            )

    def test_slave_mode_default_does_not_require_target_address(self, fake_qemu):
        sock = QemuI2CStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-i2c", dump_hex=False)
        try:
            assert sock.master is False
            assert sock.target_address is None
        finally:
            sock.close()


class TestQemuI2CStreamMasterModeSend:
    def test_send_transmits_addressed_packet_unchanged(self, fake_qemu):
        """Master-mode send() should WRITE the SMBus packet immediately, with a
        single leading address byte (the packet's own SMBus dst_addr, over which
        its PEC is computed) — never a duplicate target_address prefix."""
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host,
            port=fake_qemu.port,
            id_str="test-i2c",
            dump_hex=False,
            master=True,
            target_address=0x12,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            mctp_pkt = (
                TransportHdrPacket(
                    dst=0x08, src=0x10, som=1, eom=1, pkt_seq=0, to=0, tag=2, ic=0, msg_type=MsgTypes.CTRL.value
                )
                / b"\xde\xad\xbe\xef"
            )
            # dst_addr is the on-wire SMBus destination byte (BMC 7-bit 0x12 << 1);
            # its PEC is computed over that byte, so the frame must be sent as-is.
            wire_pkt = SmbusTransport(dst_addr=(0x12 << 1), src_addr=0x10, load=mctp_pkt)
            wire_bytes = bytes(wire_pkt)

            n = sock.send(wire_pkt)
            assert n == len(wire_bytes)

            # No READ_REQ needed: the WRITE frame is on the wire immediately.
            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I2CStreamMsgType.WRITE
            assert body[0] == (0x12 << 1)  # single SMBus address byte, not duplicated
            assert body == wire_bytes  # transmitted unchanged (PEC stays valid)
        finally:
            sock.close()

    def test_send_prefixes_target_address_when_packet_unaddressed(self, fake_qemu):
        """When the packet carries no embedded SMBus address (first byte is the
        0x0F command code), send() prefixes the configured target_address so QEMU
        has an address to master the bus to."""
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host,
            port=fake_qemu.port,
            id_str="test-i2c",
            dump_hex=False,
            master=True,
            target_address=0x12,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            mctp_pkt = (
                TransportHdrPacket(
                    dst=0x08, src=0x10, som=1, eom=1, pkt_seq=0, to=0, tag=2, ic=0, msg_type=MsgTypes.CTRL.value
                )
                / b"\xde\xad\xbe\xef"
            )
            wire_pkt = SmbusTransport(src_addr=0x10, load=mctp_pkt)  # dst_addr unset
            wire_bytes = bytes(wire_pkt)
            assert wire_bytes[0] == 0x0F  # no embedded address byte

            sock.send(wire_pkt)

            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == I2CStreamMsgType.WRITE
            assert body[0] == (0x12 << 1)  # target_address prefixed
            assert body[1:] == wire_bytes
        finally:
            sock.close()


class TestQemuI2CStreamMasterModeRecv:
    def test_recv_parses_addressed_smbus_packet_with_dst_addr(self, fake_qemu):
        """Master-mode recv(): the BMC mastered the bus and wrote to us, so the
        WRITE frame body already leads with our SMBus address (the destination).
        recv() parses the whole frame as a SmbusTransportPacket with dst_addr
        populated — not stripped — so downstream `dst_addr >> 1` never sees None."""
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host,
            port=fake_qemu.port,
            id_str="test-i2c",
            dump_hex=False,
            master=True,
            target_address=0x12,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            mctp_pkt = (
                TransportHdrPacket(
                    dst=0x22, src=0x0F, som=1, eom=1, pkt_seq=0, to=0, tag=1, ic=0, msg_type=MsgTypes.CTRL.value
                )
                / b"\x01\x02\x03"
            )
            # On the wire the SMBus destination IS our own address (the BMC wrote
            # to us at 0x58). QEMU's WRITE body is exactly this frame, leading
            # with our address byte.
            our_addr = 0x58
            wire_pkt = SmbusTransport(dst_addr=(our_addr << 1), src_addr=0x25, load=mctp_pkt)
            wire_bytes = bytes(wire_pkt)
            assert wire_bytes[0] == (our_addr << 1)

            fake_qemu.send_frame(I2CStreamMsgType.WRITE, wire_bytes)

            pkt = sock.recv()
            assert pkt is not None
            assert bytes(pkt) == wire_bytes
            # dst_addr must be populated (was the crash: None >> 1).
            assert pkt.dst_addr == (our_addr << 1)
            assert pkt.dst_addr >> 1 == our_addr
        finally:
            sock.close()

    def test_recv_short_master_write_frame_warns_and_returns_none(self, fake_qemu, caplog):
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host,
            port=fake_qemu.port,
            id_str="test-i2c",
            dump_hex=False,
            master=True,
            target_address=0x12,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()  # drain HELLO

            # Only the address byte plus a couple of stray bytes: too short
            # to plausibly hold an SMBUS/MCTP transport header.
            fake_qemu.send_frame(I2CStreamMsgType.WRITE, bytes([0xB0, 0x01]))

            with caplog.at_level("WARNING"):
                pkt = sock.recv()
            assert pkt is None
            assert any("too short" in rec.message for rec in caplog.records)
        finally:
            sock.close()


class TestQemuI2CStreamSlaveOnlyAlias:
    @pytest.mark.parametrize("am_type", [SimpleEndpointAM, RoleBasedEndpointAM])
    def test_control_replies_use_request_address_and_correct_turnaround(self, fake_qemu, am_type):
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host, port=fake_qemu.port, dump_hex=False,
            master=True, target_address=0x10, slave_only_address=0x53,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()
            ctx = EndpointContext(physical_address=Smbus7bitAddress(0x54), assigned_eid=8)
            am = am_type(socket=sock, context=ctx)
            for address, expected_type in ((0x53, I2CStreamMsgType.READ_RSP), (0x54, I2CStreamMsgType.WRITE)):
                request = control_request(address)
                fake_qemu.send_frame(I2CStreamMsgType.WRITE, bytes(request))
                incoming = sock.recv()
                assert incoming.dst_addr == address << 1
                selected = am.get_context_for_endpoint(incoming)
                assert selected.physical_address == Smbus7bitAddress(address)
                if address == 0x53:
                    assert selected is not ctx
                else:
                    assert selected is ctx
                reply = list(am.make_reply(incoming))
                assert len(reply) == 1
                assert reply[0].src_addr == (address << 1 | 1)
                am.send_reply(reply)
                if address == 0x53:
                    with pytest.raises(socket.timeout):
                        fake_qemu.recv_frame(timeout=0.05)
                    fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", len(bytes(reply[0]))))
                    assert sock.recv() is None
                assert fake_qemu.recv_frame() == (expected_type, bytes(reply[0]))
                assert ctx.physical_address == Smbus7bitAddress(0x54)
        finally:
            sock.close()

    @pytest.mark.parametrize("am_type", [SimpleEndpointAM, RoleBasedEndpointAM])
    def test_legacy_set_eid_updates_shared_state_without_changing_primary_address(self, fake_qemu, am_type):
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host, port=fake_qemu.port, dump_hex=False,
            master=True, target_address=0x10, slave_only_address=0x53,
        )
        try:
            ctx = EndpointContext(physical_address=Smbus7bitAddress(0x54), assigned_eid=8)
            am = am_type(socket=sock, context=ctx)
            request = SmbusTransport(
                bytes(SmbusTransport(
                    dst_addr=0xA6,
                    src_addr=0x20,
                    load=TransportHdrPacket(dst=8, src=9, to=1, som=1, eom=1)
                    / ControlHdr(rq=True, cmd_code=ContrlCmdCodes.SetEndpointID)
                    / SetEndpointIDRequestPacket(op=0, eid=10),
                ))
            )
            reply = list(am.make_reply(request))
            assert reply[0].src_addr == 0xA7
            assert ctx.assigned_eid == 10
            assert ctx.discovered is True
            assert ctx.physical_address == Smbus7bitAddress(0x54)
            primary = control_request(0x54)
            primary.load.dst = 10
            assert list(am.make_reply(primary))[0].src_addr == 0xA9
        finally:
            sock.close()

    def test_fragmented_alias_reply_stages_all_18_without_pacing(self, fake_qemu, monkeypatch):
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host, port=fake_qemu.port, dump_hex=False,
            master=True, target_address=0x10, slave_only_address=0x53,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()
            fake_qemu.send_frame(I2CStreamMsgType.WRITE, bytes(control_request(0x53)))
            incoming = sock.recv()
            assert incoming.dst_addr == 0xA6
            large_payload = bytes(range(256)) + bytes(range(16))
            monkeypatch.setattr(
                GetEndpointIDRequestPacket, "make_ctrl_reply", lambda self, ctx: (0, large_payload)
            )
            sleeps = []
            monkeypatch.setattr("pymctp.automaton.simple_endpoint.time.sleep", sleeps.append)
            am = SimpleEndpointAM(
                socket=sock,
                context=EndpointContext(physical_address=Smbus7bitAddress(0x54), assigned_eid=8, mtu_size=16),
            )
            packets = list(am.make_reply(incoming))
            assert len(packets) == 18
            assert all(packet.src_addr == 0xA7 for packet in packets)
            assert not sock.stages_complete_replies
            assert sock.stages_reply_packets(packets)
            am.send_reply(packets)
            assert sleeps == []
            assert list(sock._pending_packets) == [bytes(packet) for packet in packets]
            assert not sock._staged_messages
            with pytest.raises(socket.timeout):
                fake_qemu.recv_frame(timeout=0.05)
            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", max(len(bytes(p)) for p in packets)))
            assert sock.recv() is None
            assert [fake_qemu.recv_frame() for _ in packets] == [
                (I2CStreamMsgType.READ_RSP, bytes(packet)) for packet in packets
            ]
        finally:
            sock.close()

    def test_primary_and_custom_sender_keep_pacing_and_master_write(self, fake_qemu, monkeypatch):
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host, port=fake_qemu.port, dump_hex=False,
            master=True, target_address=0x10, slave_only_address=0x53,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()
            packets = [
                response_packet(b"first", som=1, eom=0, src_addr=0xA9),
                response_packet(b"last", som=0, eom=1, pkt_seq=1, src_addr=0xA9),
            ]
            sleeps = []
            monkeypatch.setattr("pymctp.automaton.simple_endpoint.time.sleep", sleeps.append)
            am = SimpleEndpointAM(socket=sock, context=EndpointContext())
            assert not sock.stages_reply_packets(packets)
            am.send_reply(packets)
            assert sleeps == [0.005]
            assert [fake_qemu.recv_frame() for _ in packets] == [
                (I2CStreamMsgType.WRITE, bytes(packet)) for packet in packets
            ]
            sent = []
            am.send_reply(
                [response_packet(b"one", som=1, eom=0, src_addr=0xA7),
                 response_packet(b"two", som=0, eom=1, pkt_seq=1, src_addr=0xA7)],
                send_function=sent.append,
            )
            assert len(sent) == 2
            assert sleeps == [0.005, 0.005]
            assert not sock._pending_packets
        finally:
            sock.close()

    def test_alias_queued_and_staged_packets_share_512_limit(self, fake_qemu):
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host, port=fake_qemu.port, dump_hex=False,
            master=True, target_address=0x10, slave_only_address=0x53,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()
            queued = response_packet(b"queued", tag=3, src_addr=0xA7)
            for _ in range(510):
                sock.send(queued)
            first = response_packet(b"first", som=1, eom=0, src_addr=0xA7)
            second = response_packet(b"second", som=0, eom=0, pkt_seq=1, src_addr=0xA7)
            sock.send(first)
            sock.send(second)
            assert len(sock._pending_packets) + sock._staged_packet_count == 512
            with pytest.raises(OverflowError, match="pending packet limit 512"):
                sock.send(response_packet(b"last", som=0, eom=1, pkt_seq=2, src_addr=0xA7))
            assert len(sock._pending_packets) == 510
            assert not sock._staged_messages
            with pytest.raises(socket.timeout):
                fake_qemu.recv_frame(timeout=0.05)
            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", len(bytes(queued))))
            assert sock.recv() is None
            assert [fake_qemu.recv_frame() for _ in range(510)] == [
                (I2CStreamMsgType.READ_RSP, bytes(queued))
            ] * 510
            assert not sock._pending_packets
        finally:
            sock.close()

    def test_read_during_alias_fragmentation_cannot_see_partial_reply(self, fake_qemu):
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host, port=fake_qemu.port, dump_hex=False,
            master=True, target_address=0x10, slave_only_address=0x53,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()
            first = response_packet(b"first", som=1, eom=0, src_addr=0xA7)
            last = response_packet(b"last", som=0, eom=1, pkt_seq=1, src_addr=0xA7)
            sock.send(first)
            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", 64))
            assert sock.recv() is None
            with pytest.raises(socket.timeout):
                fake_qemu.recv_frame(timeout=0.05)
            sock.send(last)
            fake_qemu.send_frame(I2CStreamMsgType.READ_REQ, struct.pack(">H", 64))
            assert sock.recv() is None
            assert [fake_qemu.recv_frame() for _ in range(2)] == [
                (I2CStreamMsgType.READ_RSP, bytes(first)),
                (I2CStreamMsgType.READ_RSP, bytes(last)),
            ]
        finally:
            sock.close()

    def test_unconfigured_and_wrong_address_do_not_get_alias_context(self, fake_qemu):
        sock = QemuI2CStreamSocket(
            host=fake_qemu.host, port=fake_qemu.port, dump_hex=False, master=True, target_address=0x10
        )
        try:
            ctx = EndpointContext(physical_address=Smbus7bitAddress(0x54), assigned_eid=8)
            am = SimpleEndpointAM(socket=sock, context=ctx)
            request = control_request(0x53)
            assert am.get_context_for_endpoint(request) is ctx
            assert am.make_reply(request) is None
        finally:
            sock.close()

        other_qemu = FakeQemuServer()
        sock = QemuI2CStreamSocket(
            host=other_qemu.host, port=other_qemu.port, dump_hex=False,
            master=True, target_address=0x10, slave_only_address=0x53,
        )
        try:
            am = SimpleEndpointAM(socket=sock, context=ctx)
            assert am.get_context_for_endpoint(control_request(0x52)) is ctx
            assert am.make_reply(control_request(0x52)) is None
            downstream = EndpointContext(physical_address=Smbus7bitAddress(0x52), assigned_eid=9)
            bridged = SimpleEndpointAM(socket=sock, context=ctx, downstream_endpoints={9: downstream})
            request = control_request(0x53)
            request.load.dst = 9
            assert bridged.get_context_for_endpoint(request) is downstream
            assert bridged.make_reply(request) is None
            assert ctx.physical_address == Smbus7bitAddress(0x54)
        finally:
            sock.close()
            other_qemu.close()

    @pytest.mark.parametrize(
        ("master", "target", "alias"),
        [(False, None, 0x53), (True, 0x10, -1), (True, 0x10, 0x80),
         (True, 0x10, True), (True, 0x53, 0x53)],
    )
    def test_invalid_alias_rejected_before_connection(self, fake_qemu, master, target, alias):
        with pytest.raises(ValueError, match="slave_only_address"):
            QemuI2CStreamSocket(
                host=fake_qemu.host, port=fake_qemu.port, dump_hex=False,
                master=master, target_address=target, slave_only_address=alias,
            )

    def test_config_passes_alias_to_socket(self, fake_qemu):
        config = I2CStreamSocketConfig(
            host=fake_qemu.host, port=fake_qemu.port, name="omc", dump_hex=False,
            master=True, target_address=0x10, slave_only_address=0x53,
        )
        try:
            assert config.socket.slave_only_address == 0x53
            assert config.socket.master is True
        finally:
            config.close_socket()
