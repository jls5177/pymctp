# SPDX-FileCopyrightText: 2025 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the manager.py wiring of the new I3C/I2C TCP stream configs
(``ConfigTypes.I3CStream`` / ``ConfigTypes.I2CStream``).

Uses a throwaway local TCP listener in place of QEMU so config construction
(which eagerly connects the socket in ``__post_init__``) can be exercised
without a real QEMU instance.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from pymctp.automaton.manager import (
    ConfigTypes,
    I2CStreamSocketConfig,
    I3CStreamSocketConfig,
    deserialize_supersocket,
)


class FakeTcpTarget:
    """Accepts a single client connection and reads whatever it sends."""

    def __init__(self):
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self.host, self.port = self._listener.getsockname()
        self.conn: socket.socket | None = None
        self._accept_thread = threading.Thread(target=self._accept, daemon=True)
        self._accept_thread.start()

    def _accept(self):
        conn, _ = self._listener.accept()
        self.conn = conn

    def wait_for_connection(self, timeout=5.0):
        self._accept_thread.join(timeout)
        assert self.conn is not None, "client never connected"

    def recv_raw(self, nbytes: int, timeout=5.0) -> bytes:
        self.conn.settimeout(timeout)
        buf = bytearray()
        while len(buf) < nbytes:
            chunk = self.conn.recv(nbytes - len(buf))
            if not chunk:
                raise ConnectionError("peer closed connection")
            buf.extend(chunk)
        return bytes(buf)

    def close(self):
        if self.conn:
            self.conn.close()
        self._listener.close()


@pytest.fixture
def fake_target():
    target = FakeTcpTarget()
    yield target
    target.close()


class TestI3CStreamSocketConfig:
    def test_post_init_connects_and_sends_hello(self, fake_target):
        cfg = I3CStreamSocketConfig(host=fake_target.host, port=fake_target.port, name="i3c-under-test")
        try:
            fake_target.wait_for_connection()
            # [u32 length BE][u8 type=0x07 HELLO][u32 proto_version BE]
            header = fake_target.recv_raw(4)
            (length,) = struct.unpack(">I", header)
            assert length == 5  # 1 type byte + 4 version bytes
            body = fake_target.recv_raw(length)
            assert body[0] == 0x07  # HELLO
            assert struct.unpack(">I", body[1:])[0] == 0x00010000
        finally:
            cfg.close_socket()

    def test_config_type_and_deserialize_round_trip(self, fake_target):
        raw_config = {
            "type": ConfigTypes.I3CStream.value,
            "host": fake_target.host,
            "port": fake_target.port,
            "name": "i3c-under-test",
        }
        cfg = deserialize_supersocket(raw_config)
        try:
            fake_target.wait_for_connection()
            assert isinstance(cfg, I3CStreamSocketConfig)
            assert cfg.socket is not None
        finally:
            cfg.close_socket()

    def test_auto_configure_sends_set_reg_frames(self, fake_target):
        cfg = I3CStreamSocketConfig(
            host=fake_target.host,
            port=fake_target.port,
            name="i3c-under-test",
            pid=0x1234,
            bcr=0x40,
        )
        try:
            fake_target.wait_for_connection()
            # HELLO frame first.
            header = fake_target.recv_raw(4)
            (length,) = struct.unpack(">I", header)
            fake_target.recv_raw(length)

            # Then a SET_REG frame for pid, one for bcr, then HOT_JOIN.
            seen_types = []
            for _ in range(3):
                header = fake_target.recv_raw(4)
                (length,) = struct.unpack(">I", header)
                body = fake_target.recv_raw(length)
                seen_types.append(body[0])
            assert seen_types == [0x01, 0x01, 0x02]  # SET_REG, SET_REG, HOT_JOIN
        finally:
            cfg.close_socket()


class TestI2CStreamSocketConfig:
    def test_post_init_connects_and_sends_hello(self, fake_target):
        cfg = I2CStreamSocketConfig(host=fake_target.host, port=fake_target.port, name="i2c-under-test")
        try:
            fake_target.wait_for_connection()
            header = fake_target.recv_raw(4)
            (length,) = struct.unpack(">I", header)
            assert length == 5
            body = fake_target.recv_raw(length)
            assert body[0] == 0x07  # HELLO
            assert struct.unpack(">I", body[1:])[0] == 0x00010000
        finally:
            cfg.close_socket()

    def test_config_type_and_deserialize_round_trip(self, fake_target):
        raw_config = {
            "type": ConfigTypes.I2CStream.value,
            "host": fake_target.host,
            "port": fake_target.port,
            "name": "i2c-under-test",
        }
        cfg = deserialize_supersocket(raw_config)
        try:
            fake_target.wait_for_connection()
            assert isinstance(cfg, I2CStreamSocketConfig)
            assert cfg.socket is not None
        finally:
            cfg.close_socket()
