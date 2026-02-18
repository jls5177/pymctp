# SPDX-FileCopyrightText: 2024 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Decoder for Cerberus attestation log (TCG-style) entries.

The attestation log uses a binary format with entry headers identified by a
magic byte in the 0xC0 range (0xCA, 0xCB, 0xCC, ...).  Each entry contains
a TCG event type, measurement type (PCR index + measurement index), a digest,
and the resulting measurement value after extension.

Binary layout reference: cerberus_utility_api.c cerberus_attestation_log_read_entries()
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# TCG hash algorithm IDs
TCG_SHA256_ALG_ID = 0x000B
TCG_SHA384_ALG_ID = 0x000C
TCG_SHA512_ALG_ID = 0x000D

DIGEST_SIZES = {
    TCG_SHA256_ALG_ID: 32,
    TCG_SHA384_ALG_ID: 48,
    TCG_SHA512_ALG_ID: 64,
}

ALG_NAMES = {
    TCG_SHA256_ALG_ID: "SHA256",
    TCG_SHA384_ALG_ID: "SHA384",
    TCG_SHA512_ALG_ID: "SHA512",
}


@dataclass
class TcgLogEntry:
    """A single decoded attestation log entry."""

    entry_id: int
    event_type: int
    measurement_type: int
    digest_algorithm_id: int
    digest: bytes
    measurement: bytes

    @property
    def pcr_index(self) -> int:
        return self.measurement_type & 0xFFFF

    @property
    def measurement_index(self) -> int:
        return (self.measurement_type >> 16) & 0xFFFF

    @property
    def alg_name(self) -> str:
        return ALG_NAMES.get(self.digest_algorithm_id, f"0x{self.digest_algorithm_id:04X}")

    def format_summary(self) -> str:
        """Single-line summary of this entry."""
        return (
            f"  entry={self.entry_id}: PCR[{self.pcr_index}].meas[{self.measurement_index}] "
            f"event=0x{self.event_type:08X} alg={self.alg_name} "
            f"digest={self.digest[:8].hex()}... "
            f"measurement={self.measurement[:8].hex()}..."
        )


def decode_attestation_log(data: bytes) -> list[TcgLogEntry]:
    """Decode a Cerberus attestation log binary blob into entries.

    Returns a list of TcgLogEntry on success.  Stops parsing on any
    format error and returns entries decoded so far.
    """
    entries: list[TcgLogEntry] = []
    pos = 0
    end = len(data)

    while pos < end:
        if pos >= end:
            break

        entry_type = data[pos]
        if (entry_type & 0xF0) != 0xC0:
            break

        if entry_type == 0xCA:
            # logging_tcg_entry_ca: magic(1) + entry_id(4) = 5 bytes
            if pos + 5 > end:
                break
            entry_id = struct.unpack_from("<I", data, pos + 1)[0]
            data_offset = 5
            # Fixed entry length: CA header + logging_tcg_entry - entry_id
            # = 5 + 86 - 4 = 87
            entry_length = 87

        elif entry_type == 0xCB:
            # logging_tcg_entry_cb: magic(1) + length(2) + entry_id(4) = 7 bytes
            if pos + 7 > end:
                break
            entry_length = struct.unpack_from("<H", data, pos + 1)[0]
            entry_id = struct.unpack_from("<I", data, pos + 3)[0]
            data_offset = 7

        else:
            # logging_tcg_entry_cc and beyond: magic(1) + length(2) + entry_id(4) + data_offset(1) = 8 bytes
            if pos + 8 > end:
                break
            entry_length = struct.unpack_from("<H", data, pos + 1)[0]
            entry_id = struct.unpack_from("<I", data, pos + 3)[0]
            data_offset = data[pos + 7]

        if pos + entry_length > end:
            break

        # attestation_log_entry_header: event_type(4) + measurement_type(4) + digest_count(4) + digest_algorithm_id(2) = 14
        hdr_offset = pos + data_offset
        if hdr_offset + 14 > end:
            break

        event_type, measurement_type, digest_count, digest_alg_id = struct.unpack_from(
            "<IIIH", data, hdr_offset
        )

        if digest_count != 1:
            break

        digest_size = DIGEST_SIZES.get(digest_alg_id)
        if digest_size is None:
            break

        digest_start = hdr_offset + 14
        if digest_start + digest_size > end:
            break
        digest = data[digest_start : digest_start + digest_size]

        # measurement_size(4) + measurement(digest_size)
        meas_size_offset = digest_start + digest_size
        if meas_size_offset + 4 > end:
            break
        meas_size = struct.unpack_from("<I", data, meas_size_offset)[0]
        if meas_size != digest_size:
            break

        meas_start = meas_size_offset + 4
        if meas_start + meas_size > end:
            break
        measurement = data[meas_start : meas_start + meas_size]

        entries.append(
            TcgLogEntry(
                entry_id=entry_id,
                event_type=event_type,
                measurement_type=measurement_type,
                digest_algorithm_id=digest_alg_id,
                digest=digest,
                measurement=measurement,
            )
        )

        pos += entry_length

    return entries


def format_tcg_log_summary(entries: list[TcgLogEntry]) -> str:
    """Format a list of TCG log entries as a multi-line summary."""
    if not entries:
        return "  (no entries)"
    return "\n".join(entry.format_summary() for entry in entries)
