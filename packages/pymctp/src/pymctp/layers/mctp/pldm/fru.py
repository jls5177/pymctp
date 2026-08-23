# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""PLDM FRU record table codecs."""

from __future__ import annotations

import binascii
import logging
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

logger = logging.getLogger(__name__)

FRU_RECORD_HEADER_LEN = 5
FRU_METADATA_LEN = 18
FRU_ENCODING_ASCII = 1
FRU_KNOWN_FIELD_TYPES = set(range(1, 24))

_FRU_RECORD_HEADER = struct.Struct("<HBBB")
_FRU_METADATA = struct.Struct("<BBIIHHI")


class PldmFruCmdCodes(IntEnum):
    Reserved = 0x00
    GetFRURecordTableMetadata = 0x01
    GetFRURecordTable = 0x02


@dataclass
class FruMetadata:
    major_version: int = 1
    minor_version: int = 0
    table_maximum_size: int = 0
    table_length: int = 0
    total_record_set_identifiers: int = 0
    total_records: int = 0
    integrity_checksum: int = 0

    def to_bytes(self) -> bytes:
        return _FRU_METADATA.pack(
            self.major_version & 0xFF,
            self.minor_version & 0xFF,
            self.table_maximum_size & 0xFFFFFFFF,
            self.table_length & 0xFFFFFFFF,
            self.total_record_set_identifiers & 0xFFFF,
            self.total_records & 0xFFFF,
            self.integrity_checksum & 0xFFFFFFFF,
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> FruMetadata:
        if len(raw) < FRU_METADATA_LEN:
            msg = f"FRU metadata requires {FRU_METADATA_LEN} bytes, got {len(raw)}"
            raise ValueError(msg)
        return cls(*_FRU_METADATA.unpack_from(raw))


@dataclass
class FruField:
    field_type: int
    value: str
    raw_value: bytes | None = None

    def to_bytes(self, encoding_type: int) -> bytes:
        value = _field_value_bytes(self.value, encoding_type, self.raw_value)
        return bytes([self.field_type & 0xFF, len(value) & 0xFF]) + value


@dataclass
class OpaqueFruField:
    field_type: int
    data: bytes

    def __post_init__(self) -> None:
        self.data = bytes(self.data)

    def to_bytes(self, encoding_type: int) -> bytes:
        return bytes([self.field_type & 0xFF, len(self.data) & 0xFF]) + self.data


@dataclass
class FruRecord:
    record_set_identifier: int
    record_type: int
    encoding_type: int
    fields: list[FruField | OpaqueFruField] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.record_set_identifier = int(self.record_set_identifier)
        self.record_type = int(self.record_type)
        self.encoding_type = int(self.encoding_type)
        self.fields = list(self.fields)

    def to_bytes(self) -> bytes:
        return _FRU_RECORD_HEADER.pack(
            self.record_set_identifier & 0xFFFF,
            self.record_type & 0xFF,
            len(self.fields) & 0xFF,
            self.encoding_type & 0xFF,
        ) + b"".join(field.to_bytes(self.encoding_type) for field in self.fields)


@dataclass
class OpaqueFruRecord:
    data: bytes

    def __post_init__(self) -> None:
        self.data = bytes(self.data)

    def to_bytes(self) -> bytes:
        return bytes(self.data)


@dataclass
class FruRepository:
    records: list[Any] = field(default_factory=list)
    table_padding: bytes = b""
    major_version: int = 1
    minor_version: int = 0
    table_maximum_size: int = 0
    reported_table_length: int | None = None
    reported_record_set_count: int | None = None
    reported_record_count: int | None = None
    reported_integrity_checksum: int | None = None

    def __post_init__(self) -> None:
        self.records = list(self.records)
        self.table_padding = bytes(self.table_padding)
        self.major_version = int(self.major_version)
        self.minor_version = int(self.minor_version)
        self.table_maximum_size = int(self.table_maximum_size)
        self.reported_table_length = _optional_int(self.reported_table_length)
        self.reported_record_set_count = _optional_int(self.reported_record_set_count)
        self.reported_record_count = _optional_int(self.reported_record_count)
        self.reported_integrity_checksum = _optional_int(self.reported_integrity_checksum)

    def encoded_table(self) -> bytes:
        return b"".join(encode_fru_record(record) for record in self.records)

    def response_table(self) -> bytes:
        return self.encoded_table() + self.table_padding

    @property
    def table_length(self) -> int:
        return self.reported_table_length if self.reported_table_length is not None else len(self.encoded_table())

    @property
    def record_count(self) -> int:
        return self.reported_record_count if self.reported_record_count is not None else len(self.records)

    @property
    def record_set_count(self) -> int:
        if self.reported_record_set_count is not None:
            return self.reported_record_set_count
        return len({record.record_set_identifier for record in self.records if hasattr(record, "record_set_identifier")})

    @property
    def integrity_checksum(self) -> int:
        if self.reported_integrity_checksum is not None:
            return self.reported_integrity_checksum
        return binascii.crc32(self.response_table()) & 0xFFFFFFFF

    def metadata(self) -> FruMetadata:
        return FruMetadata(
            major_version=self.major_version,
            minor_version=self.minor_version,
            table_maximum_size=self.table_maximum_size,
            table_length=self.table_length,
            total_record_set_identifiers=self.record_set_count,
            total_records=self.record_count,
            integrity_checksum=self.integrity_checksum,
        )


def decode_fru_record(raw: bytes) -> FruRecord | OpaqueFruRecord:
    """Decode one FRU record, falling back to opaque on any lossy structured decode."""
    raw = bytes(raw)
    try:
        record = _decode_fru_record(raw)
    except (UnicodeDecodeError, ValueError, struct.error) as exc:
        logger.warning("Failed to decode FRU record; keeping opaque: %s", exc)
        return OpaqueFruRecord(raw)

    encoded = encode_fru_record(record)
    if encoded != raw:
        logger.warning("Structured FRU record did not round-trip byte-for-byte; keeping opaque")
        return OpaqueFruRecord(raw)
    return record


def encode_fru_record(record: Any) -> bytes:
    if isinstance(record, (bytes, bytearray)):
        return bytes(record)
    to_bytes = getattr(record, "to_bytes", None)
    if callable(to_bytes):
        return bytes(to_bytes())
    msg = f"Unsupported FRU record type: {type(record).__name__}"
    raise TypeError(msg)


def decode_fru_table(raw: bytes) -> list[FruRecord | OpaqueFruRecord]:
    records: list[FruRecord | OpaqueFruRecord] = []
    offset = 0
    raw = bytes(raw)
    while offset < len(raw):
        next_offset = _next_record_offset(raw, offset)
        if next_offset is None:
            logger.warning("FRU table has %d undecodable trailing byte(s); keeping opaque", len(raw) - offset)
            records.append(OpaqueFruRecord(raw[offset:]))
            break
        records.append(decode_fru_record(raw[offset:next_offset]))
        offset = next_offset
    return records


def encode_fru_table(records: list[Any]) -> bytes:
    return b"".join(encode_fru_record(record) for record in records)


def fru_metadata_to_dict(metadata: FruMetadata) -> dict[str, int]:
    return {
        "major_version": metadata.major_version,
        "minor_version": metadata.minor_version,
        "table_maximum_size": metadata.table_maximum_size,
        "table_length": metadata.table_length,
        "total_record_set_identifiers": metadata.total_record_set_identifiers,
        "total_records": metadata.total_records,
        "integrity_checksum": metadata.integrity_checksum,
    }


def fru_metadata_from_dict(data: dict[str, Any]) -> FruMetadata:
    return FruMetadata(
        major_version=int(data.get("major_version", 1)),
        minor_version=int(data.get("minor_version", 0)),
        table_maximum_size=int(data.get("table_maximum_size", 0)),
        table_length=int(data.get("table_length", 0)),
        total_record_set_identifiers=int(data.get("total_record_set_identifiers", 0)),
        total_records=int(data.get("total_records", 0)),
        integrity_checksum=int(data.get("integrity_checksum", 0)),
    )


def fru_record_to_dict(record: FruRecord | OpaqueFruRecord) -> dict[str, Any]:
    if isinstance(record, OpaqueFruRecord):
        return {"record_set_identifier": 0, "record_type": -1, "data": record.data.hex()}
    return {
        "record_set_identifier": record.record_set_identifier,
        "record_type": record.record_type,
        "encoding_type": record.encoding_type,
        "fields": [_field_to_dict(field) for field in record.fields],
    }


def fru_record_from_dict(data: dict[str, Any]) -> FruRecord | OpaqueFruRecord:
    if "data" in data:
        return OpaqueFruRecord(bytes.fromhex(str(data.get("data", ""))))
    return FruRecord(
        record_set_identifier=int(data["record_set_identifier"]),
        record_type=int(data["record_type"]),
        encoding_type=int(data.get("encoding_type", FRU_ENCODING_ASCII)),
        fields=[_field_from_dict(field) for field in data.get("fields", [])],
    )


def _decode_fru_record(raw: bytes) -> FruRecord:
    if len(raw) < FRU_RECORD_HEADER_LEN:
        msg = f"FRU record header requires {FRU_RECORD_HEADER_LEN} bytes, got {len(raw)}"
        raise ValueError(msg)
    record_set_identifier, record_type, field_count, encoding_type = _FRU_RECORD_HEADER.unpack_from(raw)
    offset = FRU_RECORD_HEADER_LEN
    fields_: list[FruField | OpaqueFruField] = []
    for _ in range(field_count):
        if offset + 2 > len(raw):
            msg = "FRU field header is truncated"
            raise ValueError(msg)
        field_type = raw[offset]
        field_length = raw[offset + 1]
        offset += 2
        if offset + field_length > len(raw):
            msg = "FRU field value is truncated"
            raise ValueError(msg)
        field_data = raw[offset : offset + field_length]
        offset += field_length
        fields_.append(_decode_field(field_type, encoding_type, field_data))
    if offset != len(raw):
        msg = f"FRU record has {len(raw) - offset} trailing byte(s)"
        raise ValueError(msg)
    return FruRecord(record_set_identifier, record_type, encoding_type, fields_)


def _next_record_offset(raw: bytes, offset: int) -> int | None:
    if offset + FRU_RECORD_HEADER_LEN > len(raw):
        return None
    field_count = raw[offset + 3]
    cursor = offset + FRU_RECORD_HEADER_LEN
    for _ in range(field_count):
        if cursor + 2 > len(raw):
            return None
        field_length = raw[cursor + 1]
        cursor += 2 + field_length
        if cursor > len(raw):
            return None
    return cursor


def _decode_field(field_type: int, encoding_type: int, data: bytes) -> FruField | OpaqueFruField:
    if field_type not in FRU_KNOWN_FIELD_TYPES:
        return OpaqueFruField(field_type, data)
    try:
        return FruField(field_type, _decode_field_text(data, encoding_type), raw_value=data)
    except UnicodeDecodeError:
        return OpaqueFruField(field_type, data)


def _decode_field_text(data: bytes, encoding_type: int) -> str:
    return data.decode(_python_encoding(encoding_type))


def _field_value_bytes(value: str, encoding_type: int, raw_value: bytes | None) -> bytes:
    if raw_value is not None:
        try:
            if _decode_field_text(raw_value, encoding_type) == value:
                return bytes(raw_value)
        except UnicodeDecodeError:
            pass
    return value.encode(_python_encoding(encoding_type))


def _python_encoding(encoding_type: int) -> str:
    return {
        1: "ascii",
        2: "utf-8",
        3: "utf-16",
        4: "utf-16le",
        5: "utf-16be",
    }.get(int(encoding_type), "latin-1")


def _field_to_dict(field_: FruField | OpaqueFruField) -> dict[str, Any]:
    if isinstance(field_, OpaqueFruField):
        return {"field_type": field_.field_type, "data": field_.data.hex()}
    return {"field_type": field_.field_type, "value": field_.value, "raw_value": field_.raw_value.hex() if field_.raw_value is not None else None}


def _field_from_dict(data: dict[str, Any]) -> FruField | OpaqueFruField:
    field_type = int(data["field_type"])
    if "data" in data:
        return OpaqueFruField(field_type, bytes.fromhex(str(data.get("data", ""))))
    raw_value = data.get("raw_value")
    return FruField(
        field_type=field_type,
        value=str(data.get("value", "")),
        raw_value=bytes.fromhex(raw_value) if isinstance(raw_value, str) else None,
    )


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


__all__ = [
    "FRU_ENCODING_ASCII",
    "FRU_METADATA_LEN",
    "FRU_RECORD_HEADER_LEN",
    "FruField",
    "FruMetadata",
    "FruRecord",
    "FruRepository",
    "OpaqueFruField",
    "OpaqueFruRecord",
    "PldmFruCmdCodes",
    "decode_fru_record",
    "decode_fru_table",
    "encode_fru_record",
    "encode_fru_table",
    "fru_metadata_from_dict",
    "fru_metadata_to_dict",
    "fru_record_from_dict",
    "fru_record_to_dict",
]
