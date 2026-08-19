# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Loopback tests for the QEMU NPCM8xx TIP mailbox TCP stream transport."""

from __future__ import annotations

import socket
import struct
import threading

import crc8
import pytest

from pymctp.layers.mctp import MsgTypes, SmbusTransport, TransportHdrPacket
from pymctp_oem_microsoft.exerciser.qemu_tip_mbox_stream import (
    PROTO_VERSION,
    QemuTipMboxStreamSocket,
    TipMboxStreamMsgType,
)
from pymctp_oem_microsoft.exerciser.stream_framing import FrameDecoder, encode_frame


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


def smbus_pec(data: bytes) -> int:
    crc = crc8.crc8()
    crc.update(data)
    return crc.digest()[0]


def make_mctp_packet(dst: int = 0x10, src: int = 0x1C, payload: bytes = b"\x01\x02\x03"):
    return (
        TransportHdrPacket(
            dst=dst,
            src=src,
            som=1,
            eom=1,
            pkt_seq=0,
            to=0,
            tag=1,
            ic=0,
            msg_type=MsgTypes.CTRL.value,
        )
        / payload
    )


class TestQemuTipMboxStreamConnectAndHello:
    def test_connect_sends_hello_frame(self, fake_qemu):
        sock = QemuTipMboxStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-tip", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == TipMboxStreamMsgType.HELLO
            assert struct.unpack(">I", body)[0] == PROTO_VERSION
        finally:
            sock.close()

    def test_peer_hello_version_mismatch_logs_warning(self, fake_qemu, caplog):
        sock = QemuTipMboxStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-tip", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()

            fake_qemu.send_frame(TipMboxStreamMsgType.HELLO, struct.pack(">I", 0x00020000))
            with caplog.at_level("WARNING"):
                pkt = sock.recv()
            assert pkt is None
            assert any("version mismatch" in rec.message for rec in caplog.records)
        finally:
            sock.close()

    def test_peer_hello_matching_version_no_warning(self, fake_qemu, caplog):
        sock = QemuTipMboxStreamSocket(host=fake_qemu.host, port=fake_qemu.port, id_str="test-tip", dump_hex=False)
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()

            fake_qemu.send_frame(TipMboxStreamMsgType.HELLO, struct.pack(">I", PROTO_VERSION))
            with caplog.at_level("WARNING"):
                pkt = sock.recv()
            assert pkt is None
            assert not any("version mismatch" in rec.message for rec in caplog.records)
        finally:
            sock.close()


class TestQemuTipMboxStreamData:
    def test_send_produces_window_body_with_single_address_and_valid_pec(self, fake_qemu):
        bmc_addr = 0x10
        tip_addr = 0x41
        sock = QemuTipMboxStreamSocket(
            host=fake_qemu.host,
            port=fake_qemu.port,
            id_str="test-tip",
            dump_hex=False,
            bmc_addr=bmc_addr,
            tip_addr=tip_addr,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()

            mctp_pkt = make_mctp_packet(dst=0x10, src=0x1C, payload=b"\xde\xad\xbe\xef")
            expected_full = bytes(
                SmbusTransport(dst_addr=(bmc_addr << 1), src_addr=((tip_addr << 1) | 1), load=mctp_pkt)
            )

            sock.send(mctp_pkt)

            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == TipMboxStreamMsgType.DATA
            assert body == expected_full[1:]
            assert body[0] == 0x0F
            assert body[1] == len(mctp_pkt) + 1
            assert body[2] == ((tip_addr << 1) | 1)
            assert body[0] != (bmc_addr << 1)
            assert smbus_pec(bytes([(bmc_addr << 1)]) + body[:-1]) == body[-1]
            assert bytes(SmbusTransport(bytes([(bmc_addr << 1)]) + body)) == expected_full
        finally:
            sock.close()

    def test_send_does_not_double_wrap_already_smbus_wrapped_packet(self, fake_qemu):
        """The session layer wraps replies in an SmbusTransport before calling
        socket.send(); the transport must NOT wrap again (which would embed the
        SMBus/MCTP header inside the MCTP payload -- a double header)."""
        bmc_addr = 0x10
        tip_addr = 0x41
        sock = QemuTipMboxStreamSocket(
            host=fake_qemu.host,
            port=fake_qemu.port,
            id_str="test-tip",
            dump_hex=False,
            bmc_addr=bmc_addr,
            tip_addr=tip_addr,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()

            mctp_pkt = make_mctp_packet(dst=0x10, src=0x1C, payload=b"\xde\xad\xbe\xef")
            # Exactly what automaton/sessions.py builds before socket.send().
            wrapped = SmbusTransport(
                dst_addr=(bmc_addr << 1), src_addr=((tip_addr << 1) | 1), load=mctp_pkt
            )

            sock.send(wrapped)

            msg_type, body = fake_qemu.recv_frame()
            assert msg_type == TipMboxStreamMsgType.DATA
            # Single wrap: window starts at 0x0F, and the byte AFTER source_slave
            # is the MCTP transport header -- NOT another SMBus command code.
            assert body == bytes(wrapped)[1:]
            assert body[0] == 0x0F
            assert body[2] == ((tip_addr << 1) | 1)
            assert body[3] != 0x0F, "SMBus/MCTP header double-added into payload"
            # The load parses back to the original MCTP packet, and the PEC is
            # valid over the BMC-prepended destination address.
            reparsed = SmbusTransport(bytes([(bmc_addr << 1)]) + body)
            assert bytes(reparsed.load) == bytes(mctp_pkt)
            assert smbus_pec(bytes([(bmc_addr << 1)]) + body[:-1]) == body[-1]
        finally:
            sock.close()

    @pytest.mark.parametrize("address_present", [False, True])
    def test_tx_data_body_round_trips_through_rx_parse_path_for_both_window_layouts(
        self, fake_qemu, address_present
    ):
        bmc_addr = 0x10
        tip_addr = 0x41
        hidden_dst_addr = bmc_addr << 1
        sock = QemuTipMboxStreamSocket(
            host=fake_qemu.host,
            port=fake_qemu.port,
            id_str="test-tip",
            dump_hex=False,
            bmc_addr=bmc_addr,
            tip_addr=tip_addr,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()

            mctp_pkt = make_mctp_packet(dst=0x10, src=0x1C, payload=b"\xc0\xde")
            sock.send(mctp_pkt)

            msg_type, tx_body = fake_qemu.recv_frame()
            assert msg_type == TipMboxStreamMsgType.DATA
            assert tx_body[0] == 0x0F
            assert smbus_pec(bytes([hidden_dst_addr]) + tx_body[:-1]) == tx_body[-1]

            rx_body = bytes([hidden_dst_addr]) + tx_body if address_present else tx_body
            assert sock._rx_payload_has_addr(rx_body) is address_present
            if address_present:
                assert smbus_pec(rx_body[:-1]) == rx_body[-1]
            else:
                assert smbus_pec(bytes([hidden_dst_addr]) + rx_body[:-1]) == rx_body[-1]

            parsed = sock._dispatch(TipMboxStreamMsgType.DATA, rx_body)
            assert parsed is not None
            assert bytes(parsed.load) == bytes(mctp_pkt)
        finally:
            sock.close()

    def test_recv_data_frame_parses_mailbox_window_packet(self, fake_qemu):
        bmc_addr = 0x10
        tip_addr = 0x41
        sock = QemuTipMboxStreamSocket(
            host=fake_qemu.host,
            port=fake_qemu.port,
            id_str="test-tip",
            dump_hex=False,
            bmc_addr=bmc_addr,
            tip_addr=tip_addr,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()

            mctp_pkt = make_mctp_packet(dst=0x1C, src=0x10, payload=b"\xaa\xbb")
            wire_full = bytes(SmbusTransport(dst_addr=(tip_addr << 1), src_addr=((bmc_addr << 1) | 1), load=mctp_pkt))
            window_body = wire_full[1:]
            assert window_body[0] == 0x0F

            fake_qemu.send_frame(TipMboxStreamMsgType.DATA, window_body)

            pkt = sock.recv()
            assert pkt is not None
            # The addressless window has no destination byte, so the transport
            # prepends this TIP endpoint's own SMBus write address (tip_addr<<1)
            # to populate dst_addr -- otherwise downstream `dst_addr >> 1` in the
            # MCTP responder raises on a None field (regression test).
            assert pkt.dst_addr == (tip_addr << 1)
            assert pkt.dst_addr >> 1 == tip_addr
            assert bytes(pkt) == bytes([tip_addr << 1]) + window_body
            assert pkt.command_code == 0x0F
            assert pkt.src_addr == ((bmc_addr << 1) | 1)
            assert bytes(pkt.load) == bytes(mctp_pkt)
        finally:
            sock.close()

    def test_recv_data_frame_parses_address_prefixed_mailbox_window_packet(self, fake_qemu, caplog):
        bmc_addr = 0x10
        tip_addr = 0x41
        sock = QemuTipMboxStreamSocket(
            host=fake_qemu.host,
            port=fake_qemu.port,
            id_str="test-tip",
            dump_hex=False,
            bmc_addr=bmc_addr,
            tip_addr=tip_addr,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()

            mctp_pkt = make_mctp_packet(dst=0x1C, src=0x10, payload=b"\xaa\xbb")
            window_body = bytes(
                SmbusTransport(dst_addr=(tip_addr << 1), src_addr=((bmc_addr << 1) | 1), load=mctp_pkt)
            )
            assert window_body[0] == (tip_addr << 1)
            assert window_body[1] == 0x0F
            assert smbus_pec(window_body[:-1]) == window_body[-1]

            fake_qemu.send_frame(TipMboxStreamMsgType.DATA, window_body)

            with caplog.at_level("WARNING"):
                pkt = sock.recv()
            assert pkt is not None
            assert not any("PEC mismatch" in rec.message for rec in caplog.records)
            assert bytes(pkt) == window_body
            assert pkt.dst_addr == (tip_addr << 1)
            assert pkt.command_code == 0x0F
            assert pkt.src_addr == ((bmc_addr << 1) | 1)
            assert bytes(pkt.load) == bytes(mctp_pkt)
        finally:
            sock.close()

    def test_multiple_data_frames_in_one_segment_drain_across_recv_calls(self, fake_qemu):
        bmc_addr = 0x10
        tip_addr = 0x41
        sock = QemuTipMboxStreamSocket(
            host=fake_qemu.host,
            port=fake_qemu.port,
            id_str="test-tip",
            dump_hex=False,
            bmc_addr=bmc_addr,
            tip_addr=tip_addr,
        )
        try:
            fake_qemu.wait_for_connection()
            fake_qemu.recv_frame()

            pkt1 = make_mctp_packet(dst=0x1C, src=0x10, payload=b"\x01")
            pkt2 = make_mctp_packet(dst=0x1C, src=0x10, payload=b"\x02\x03")
            body1 = bytes(SmbusTransport(dst_addr=(tip_addr << 1), src_addr=((bmc_addr << 1) | 1), load=pkt1))[1:]
            body2 = bytes(SmbusTransport(dst_addr=(tip_addr << 1), src_addr=((bmc_addr << 1) | 1), load=pkt2))[1:]

            fake_qemu.conn.sendall(
                encode_frame(TipMboxStreamMsgType.DATA, body1) + encode_frame(TipMboxStreamMsgType.DATA, body2)
            )

            parsed1 = sock.recv()
            assert parsed1 is not None
            # Addressless windows get this TIP endpoint's own address prepended so
            # dst_addr is populated; the MCTP payload is what must round-trip.
            assert parsed1.dst_addr == (tip_addr << 1)
            assert bytes(parsed1) == bytes([tip_addr << 1]) + body1
            assert bytes(parsed1.load) == bytes(pkt1)

            parsed2 = sock.recv()
            assert parsed2 is not None
            assert parsed2.dst_addr == (tip_addr << 1)
            assert bytes(parsed2) == bytes([tip_addr << 1]) + body2
            assert bytes(parsed2.load) == bytes(pkt2)
        finally:
            sock.close()
