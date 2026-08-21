# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for shared tcpdump text parsing."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytz
from scapy.compat import raw
from scapy.packet import Raw

from pymctp.cli.analyze_tcpdump import parse_line, parse_text_file, parse_timestamp
from pymctp.layers.mctp.transport import TransportHdr
from pymctp.layers.mctp.types import MsgTypes


def _packet_bytes(payload: bytes, *, src: int = 0x20, dst: int = 0x11) -> bytes:
    return raw(
        TransportHdr(
            msg_type=MsgTypes.PLDM,
            dst=dst,
            src=src,
            som=True,
            eom=True,
            to=True,
            tag=3,
        )
        / Raw(payload)
    )


def _tcpdump_text(packets: list[bytes], *, journal: bool = False) -> str:
    lines: list[str] = []
    for index, packet in enumerate(packets):
        timestamp = f"12:34:{index:02d}.123456"
        for offset in range(0, len(packet), 16):
            tcpdump = f"{timestamp if offset == 0 else '        '} 0x{offset:04x}:  {packet[offset : offset + 16].hex()}  text"
            if journal:
                lines.append(f"2026-01-01T00:00:{index:02d}.000000Z unit[{index}]: {tcpdump}\n")
            else:
                lines.append(f"{tcpdump}\n")
    return "".join(lines)


def _parsed_bytes(path: Path) -> list[bytes]:
    return [raw(packet) for _, packet in parse_text_file(path, timezone_str="UTC", is_dst=False, date_str="2026-02-03")]


def test_bare_tcpdump_text_parses_packet_bytes_unchanged(tmp_path: Path) -> None:
    packets = [_packet_bytes(b"\x81\x02\x51first"), _packet_bytes(b"\x81\x02\x51second", src=0x21)]
    capture = tmp_path / "bare.tcpdump.log"
    capture.write_text(_tcpdump_text(packets), encoding="utf-8")

    assert _parsed_bytes(capture) == packets


def test_journal_wrapped_tcpdump_text_parses_to_the_same_packet_bytes(tmp_path: Path) -> None:
    """Journal prefixes must not change the packet stream consumed by analyze-tcpdump or pldm-from-capture."""
    packets = [_packet_bytes(bytes(range(28))), _packet_bytes(b"\x81\x02\x51" + bytes(range(17)))]
    bare = tmp_path / "bare.tcpdump.log"
    journal = tmp_path / "journal.tcpdump.log"
    bare.write_text(_tcpdump_text(packets), encoding="utf-8")
    journal.write_text(_tcpdump_text(packets, journal=True), encoding="utf-8")

    assert _parsed_bytes(journal) == _parsed_bytes(bare) == packets


def test_journal_wrapped_hex_dump_line_is_not_a_packet_boundary(tmp_path: Path) -> None:
    """This pins the zero-packet regression: timestamp-looking journal text before 0x0010 is still dump data."""
    packet = _packet_bytes(bytes(range(40)))
    capture = tmp_path / "wrapped-continuation.tcpdump.log"
    text = _tcpdump_text([packet], journal=True)
    wrapped_continuation = next(line for line in text.splitlines() if "0x0010:" in line)

    offset, data = parse_line(wrapped_continuation)

    assert offset == 0x10
    assert data == packet[0x10:0x20]
    capture.write_text(text, encoding="utf-8")
    assert _parsed_bytes(capture) == [packet]


def test_tcpdump_timestamp_wins_over_journal_timestamp() -> None:
    line = "2026-01-01T00:00:00.000000Z unit[1]: 12:34:56.654321 0x0000:  010203"

    assert parse_timestamp(line, timezone_str="UTC", is_dst=False, date_str="2026-02-03") == pytz.utc.localize(
        datetime(2026, 2, 3, 12, 34, 56, 654321)
    )


def test_malformed_lines_are_skipped_without_raising(tmp_path: Path) -> None:
    capture = tmp_path / "garbage.tcpdump.log"
    capture.write_text(
        "\n"
        "not a packet\n"
        "2026-01-01T00:00:00.000000Z unit[1]: also not a packet\n"
        "0x0000:  not-hex-data\n",
        encoding="utf-8",
    )

    assert list(parse_text_file(capture, timezone_str="UTC", is_dst=False, date_str="2026-02-03")) == []
