# SPDX-FileCopyrightText: 2025 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Unit tests for the length-prefixed frame codec used by the QEMU TCP
stream transports (:mod:`pymctp_exerciser_qemu.stream_framing`)."""

import struct

import pytest

from pymctp_exerciser_qemu.stream_framing import FrameDecoder, encode_frame


class TestEncodeFrame:
    def test_encode_frame_with_body(self):
        frame = encode_frame(0x01, b"\xaa\xbb\xcc")
        # length = 1 (type byte) + 3 (body) = 4
        assert frame == struct.pack(">I", 4) + b"\x01\xaa\xbb\xcc"

    def test_encode_frame_no_body(self):
        frame = encode_frame(0x02)
        assert frame == struct.pack(">I", 1) + b"\x02"

    def test_encode_frame_masks_type_to_byte(self):
        frame = encode_frame(0x1FF, b"")  # only the low byte should be kept
        assert frame == struct.pack(">I", 1) + b"\xff"


class TestFrameDecoderRoundTrip:
    def test_single_frame_round_trip(self):
        decoder = FrameDecoder()
        frame = encode_frame(0x07, struct.pack(">I", 0x00010000))
        frames = decoder.feed(frame)
        assert frames == [(0x07, struct.pack(">I", 0x00010000))]
        assert len(decoder) == 0

    def test_empty_body_round_trip(self):
        decoder = FrameDecoder()
        frame = encode_frame(0x02)  # HOT_JOIN, no body
        frames = decoder.feed(frame)
        assert frames == [(0x02, b"")]

    @pytest.mark.parametrize("msg_type,body", [(0x00, b"hello world"), (0x05, b"\x07\x01\x02"), (0x06, b"\x00")])
    def test_various_payloads_round_trip(self, msg_type, body):
        decoder = FrameDecoder()
        frame = encode_frame(msg_type, body)
        frames = decoder.feed(frame)
        assert frames == [(msg_type, body)]


class TestFrameDecoderPartialReads:
    def test_partial_length_prefix(self):
        decoder = FrameDecoder()
        frame = encode_frame(0x00, b"abc")
        # Feed only 2 of the 4 length-prefix bytes.
        assert decoder.feed(frame[:2]) == []
        assert len(decoder) == 2
        # Feed the rest.
        frames = decoder.feed(frame[2:])
        assert frames == [(0x00, b"abc")]

    def test_partial_body_split_across_multiple_feeds(self):
        decoder = FrameDecoder()
        frame = encode_frame(0x00, b"0123456789")
        assert decoder.feed(frame[:6]) == []  # 4-byte prefix + 2 body bytes
        assert decoder.feed(frame[6:10]) == []  # +4 more body bytes (still incomplete)
        frames = decoder.feed(frame[10:])  # remaining body bytes
        assert frames == [(0x00, b"0123456789")]

    def test_byte_at_a_time(self):
        decoder = FrameDecoder()
        frame = encode_frame(0x01, b"\x00\xaa\xbb")
        frames = []
        for i in range(len(frame)):
            frames.extend(decoder.feed(frame[i : i + 1]))
        assert frames == [(0x01, b"\x00\xaa\xbb")]


class TestFrameDecoderMultipleFrames:
    def test_multiple_frames_in_one_buffer(self):
        decoder = FrameDecoder()
        frame1 = encode_frame(0x00, b"first")
        frame2 = encode_frame(0x05, b"\x07\x01")
        frame3 = encode_frame(0x06, b"\x00")
        frames = decoder.feed(frame1 + frame2 + frame3)
        assert frames == [(0x00, b"first"), (0x05, b"\x07\x01"), (0x06, b"\x00")]
        assert len(decoder) == 0

    def test_multiple_frames_plus_trailing_partial_frame(self):
        decoder = FrameDecoder()
        frame1 = encode_frame(0x00, b"complete")
        frame2 = encode_frame(0x01, b"\x00" + b"x" * 20)
        buf = frame1 + frame2[:5]  # frame2 only partially arrived
        frames = decoder.feed(buf)
        assert frames == [(0x00, b"complete")]
        assert len(decoder) == 5

        # Feed the rest of frame2.
        frames = decoder.feed(frame2[5:])
        assert frames == [(0x01, b"\x00" + b"x" * 20)]

    def test_reset_discards_partial_buffer(self):
        decoder = FrameDecoder()
        frame = encode_frame(0x00, b"abcdef")
        decoder.feed(frame[:3])
        assert len(decoder) == 3
        decoder.reset()
        assert len(decoder) == 0
        # Feeding the remainder now decodes garbage/nothing meaningful since
        # the earlier bytes were discarded; feeding a fresh full frame works.
        frames = decoder.feed(encode_frame(0x02, b""))
        assert frames == [(0x02, b"")]
