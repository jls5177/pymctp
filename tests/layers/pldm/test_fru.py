from __future__ import annotations

import binascii

from pymctp.layers.mctp.pldm.fru import (
    FruField,
    FruMetadata,
    FruRecord,
    FruRepository,
    OpaqueFruField,
    decode_fru_record,
    decode_fru_table,
    encode_fru_record,
    fru_metadata_from_dict,
    fru_metadata_to_dict,
    fru_record_from_dict,
    fru_record_to_dict,
)


def test_fru_metadata_round_trips_dict_and_bytes() -> None:
    metadata = FruMetadata(1, 0, 1024, 12, 1, 1, 0x12345678)

    assert FruMetadata.from_bytes(metadata.to_bytes()) == metadata
    assert fru_metadata_from_dict(fru_metadata_to_dict(metadata)) == metadata


def test_fru_record_decodes_and_reencodes_byte_identically_with_unknown_field() -> None:
    """Unknown FRU field types must remain opaque or a later response could corrupt vendor data."""
    raw = bytes.fromhex("3412fe02010105414c504841e003010203")
    record = decode_fru_record(raw)

    assert encode_fru_record(record) == raw
    assert fru_record_from_dict(fru_record_to_dict(record)).to_bytes() == raw
    assert isinstance(record.fields[0], FruField)
    assert isinstance(record.fields[1], OpaqueFruField)


def test_fru_table_decodes_multiple_records_and_repository_preserves_padding_checksum() -> None:
    first = FruRecord(1, 0xFE, 1, [FruField(1, "ALPHA")])
    second = FruRecord(2, 0xFE, 1, [OpaqueFruField(0xE0, b"\x01\x02")])
    padding = b"\x00\x00\x00"
    repository = FruRepository(records=[first, second], table_padding=padding)

    records = decode_fru_table(repository.encoded_table())

    assert [encode_fru_record(record) for record in records] == [first.to_bytes(), second.to_bytes()]
    assert repository.table_length == len(first.to_bytes()) + len(second.to_bytes())
    assert repository.response_table().endswith(padding)
    assert repository.integrity_checksum == binascii.crc32(repository.response_table()) & 0xFFFFFFFF
