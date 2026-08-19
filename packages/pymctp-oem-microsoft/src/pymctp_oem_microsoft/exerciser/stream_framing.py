# SPDX-FileCopyrightText: 2025 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Length-prefixed frame codec shared by the QEMU TCP stream transports.

Both the I3C and I2C "remote target" stream transports talk to QEMU over a
single bidirectional TCP connection using the same simple framing::

    [u32 length BE][u8 type][body...]

``length`` counts the bytes of ``type`` + ``body`` (i.e. ``1 + len(body)``).
There is no other header.

:class:`FrameDecoder` accumulates raw bytes received from a TCP socket (which
may deliver partial frames or several frames in a single ``recv()``) and
yields fully decoded ``(msg_type, body)`` tuples as soon as they are
available.
"""

from __future__ import annotations

import struct

LENGTH_PREFIX_SIZE = 4
_LENGTH_STRUCT = struct.Struct(">I")


def encode_frame(msg_type: int, body: bytes = b"") -> bytes:
    """Encode a single frame: ``[u32 length BE][u8 type][body...]``."""
    payload = bytes([msg_type & 0xFF]) + bytes(body)
    return _LENGTH_STRUCT.pack(len(payload)) + payload


class FrameDecoder:
    """Incremental decoder for the length-prefixed stream framing.

    Feed it raw bytes as they arrive from the socket via :meth:`feed`; it
    returns the list of complete ``(msg_type, body)`` frames that became
    available, buffering any trailing partial frame for the next call.
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[tuple[int, bytes]]:
        """Feed newly received bytes and return any newly completed frames."""
        if data:
            self._buf.extend(data)

        frames: list[tuple[int, bytes]] = []
        while True:
            if len(self._buf) < LENGTH_PREFIX_SIZE:
                break
            (length,) = _LENGTH_STRUCT.unpack_from(self._buf, 0)
            total = LENGTH_PREFIX_SIZE + length
            if len(self._buf) < total:
                # Partial frame body; wait for more bytes.
                break

            frame_bytes = bytes(self._buf[LENGTH_PREFIX_SIZE:total])
            del self._buf[:total]

            if not frame_bytes:
                # Zero-length frame (no type byte) — malformed, drop it.
                continue

            msg_type = frame_bytes[0]
            body = frame_bytes[1:]
            frames.append((msg_type, body))

        return frames

    def reset(self) -> None:
        """Discard any buffered, not-yet-complete frame data."""
        self._buf.clear()

    def __len__(self) -> int:
        """Number of bytes currently buffered (including any partial frame)."""
        return len(self._buf)
