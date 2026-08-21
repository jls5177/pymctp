# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the PLDM PDR codec."""

from __future__ import annotations

import json
import logging

from pymctp.automaton.behaviors.pldm_responder import NumericSensorPdr, StateSensorPdr
from pymctp.layers.mctp.pldm.pdr import (
    PDR_HEADER_LEN,
    PDR_TYPE_EFFECTER_AUXILIARY_NAMES,
    PDR_TYPE_ENTITY_AUXILIARY_NAMES,
    PDR_TYPE_NUMERIC_EFFECTER,
    PDR_TYPE_NUMERIC_SENSOR,
    PDR_TYPE_SENSOR_AUXILIARY_NAMES,
    PDR_TYPE_STATE_EFFECTER,
    PDR_TYPE_STATE_SENSOR,
    PDR_TYPE_TERMINUS_LOCATOR,
    EffecterAuxiliaryNamesEntry,
    EffecterAuxiliaryNamesPdr,
    EntityAuxiliaryNamesPdr,
    NumericEffecterPdr,
    OpaquePdr,
    PdrHeader,
    PdrNameString,
    SensorAuxiliaryNamesEntry,
    SensorAuxiliaryNamesPdr,
    StateEffecterPdr,
    TerminusLocatorPdr,
    decode_pdr,
    encode_pdr,
    pdr_from_dict,
    pdr_to_dict,
    split_pdr_records,
)
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import GetSensorReadingDataSizeEnum


# Representative DSP0248 Sensor Auxiliary Names PDR bytes with padding preserved after the string table.
_SENSOR_AUX_NAMES_RECORD = bytes.fromhex(
    "01000000010600004900000001100101656e0053004f0043005f0054004d0050005f004d004100580000"
    "00000000000000000000"
) + bytes(31)
_NUMERIC_SENSOR_UINT16_RANGE_RECORD = bytes.fromhex(
    "00000000010200004700000001101f0000000000000102ff0000000000000001020000803f000000000000000000"
    "00001f0000803f0000003fe80300000200fa0000000000000000000000000000000000"
)
_NUMERIC_SENSOR_UINT32_RANGE_RECORD = bytes.fromhex(
    "0f000000010200005f0000000200870000000000000100000000000000000001040000803f000000000000000000000000001f0000003f00000000102700000a0000000400640000000000000032000000e80300000000000000000000000000000000000000000000"
)
_STATE_SENSOR_COMPACT_RECORD = bytes.fromhex("0d0000000104000011000000010043000000000000010102000108")
_STATE_SENSOR_PADDED_RECORD = bytes.fromhex("1300000001040000130000000600870000000000000001080002010200")
_STATE_SENSOR_BIT_COUNT_RECORD = bytes.fromhex("44000000010400001100000044440000000000000000010e00030e")
_EFFECTER_AUX_NAMES_RECORD = bytes.fromhex("33000000010d00001100000001100101656e0000460041004e0000")


def _json_round_trip(record):
    encoded = encode_pdr(record)
    decoded = pdr_from_dict(json.loads(json.dumps(pdr_to_dict(record))))
    assert encode_pdr(decoded) == encoded
    return decoded


def test_header_encode_decode_round_trip() -> None:
    header = PdrHeader(
        record_handle=0x12345678,
        header_version=1,
        pdr_type=PDR_TYPE_NUMERIC_SENSOR,
        record_change_number=0x2345,
        data_length=0x3456,
    )

    raw = header.to_bytes()

    assert len(raw) == PDR_HEADER_LEN
    assert PdrHeader.from_bytes(raw) == header


def test_numeric_sensor_pdr_decodes_and_reencodes_identically() -> None:
    record = NumericSensorPdr(
        record_handle=0x11,
        record_change_number=0x22,
        sensor_id=0x33,
        data_size=GetSensorReadingDataSizeEnum.SINT16,
        terminus_handle=0x44,
        entity_type=0x55,
        entity_instance=0x66,
        container_id=0x77,
        unit_modifier=-2,
        resolution=0.5,
        offset=-1.25,
        hysteresis=2,
        max_readable=125,
        min_readable=-40,
        nominal_value=10,
        normal_max=70,
        normal_min=-10,
        warning_high=85,
        warning_low=-20,
        critical_high=95,
        critical_low=-30,
    )
    raw = record.to_bytes()

    decoded = decode_pdr(raw)

    assert isinstance(decoded, NumericSensorPdr)
    assert decoded.record_handle == 0x11
    assert decoded.sensor_id == 0x33
    assert decoded.data_size == GetSensorReadingDataSizeEnum.SINT16
    assert decoded.warning_high == 85
    assert encode_pdr(decoded) == raw


def test_state_sensor_pdr_decodes_and_reencodes_identically() -> None:
    record = StateSensorPdr(record_handle=0x21, sensor_id=0x43, possible_states={7: [1, 3, 9], 9: []})
    raw = record.to_bytes()

    decoded = decode_pdr(raw)

    assert isinstance(decoded, StateSensorPdr)
    assert decoded.record_handle == 0x21
    assert decoded.sensor_id == 0x43
    assert decoded.possible_states == {7: [1, 3, 9], 9: []}
    assert encode_pdr(decoded) == raw


def test_representative_numeric_sensor_pdr_uint16_range_fields_are_structured() -> None:
    decoded = decode_pdr(_NUMERIC_SENSOR_UINT16_RANGE_RECORD)

    assert isinstance(decoded, NumericSensorPdr)
    assert decoded.sensor_id == 0x1001
    assert decoded.data_size == GetSensorReadingDataSizeEnum.UINT16
    assert decoded.range_field_format == GetSensorReadingDataSizeEnum.UINT16
    assert decoded.nominal_value == 250
    assert encode_pdr(decoded) == _NUMERIC_SENSOR_UINT16_RANGE_RECORD


def test_representative_numeric_sensor_pdr_uint32_range_fields_are_structured() -> None:
    decoded = decode_pdr(_NUMERIC_SENSOR_UINT32_RANGE_RECORD)

    assert isinstance(decoded, NumericSensorPdr)
    assert decoded.sensor_id == 2
    assert decoded.data_size == GetSensorReadingDataSizeEnum.UINT32
    assert decoded.range_field_format == GetSensorReadingDataSizeEnum.UINT32
    assert decoded.warning_high == 1000
    assert decoded.supported_thresholds == 0
    assert encode_pdr(decoded) == _NUMERIC_SENSOR_UINT32_RANGE_RECORD


def test_representative_state_sensor_pdrs_are_structured_with_variable_bitfields() -> None:
    compact = decode_pdr(_STATE_SENSOR_COMPACT_RECORD)
    padded = decode_pdr(_STATE_SENSOR_PADDED_RECORD)

    assert isinstance(compact, StateSensorPdr)
    assert compact.possible_states == {2: [3]}
    assert encode_pdr(compact) == _STATE_SENSOR_COMPACT_RECORD
    assert isinstance(padded, StateSensorPdr)
    assert padded.possible_states == {8: [0, 9]}
    assert padded.trailing_data == b"\x00"
    assert encode_pdr(padded) == _STATE_SENSOR_PADDED_RECORD


def test_representative_state_sensor_pdr_round_trips_possible_states_size_as_bit_count() -> None:
    decoded = decode_pdr(_STATE_SENSOR_BIT_COUNT_RECORD)

    assert not isinstance(decoded, OpaquePdr)
    assert pdr_to_dict(decoded)["sensor_id"] == 0x4444
    assert pdr_to_dict(decoded)["possible_states"] == {"14": [1, 2, 3]}
    assert encode_pdr(decoded) == _STATE_SENSOR_BIT_COUNT_RECORD


def test_terminus_locator_pdr_decodes_mctp_eid() -> None:
    record = TerminusLocatorPdr(
        record_handle=0x31,
        pldm_terminus_handle=0x41,
        validity=1,
        tid=0x51,
        container_id=0x61,
        terminus_locator_type=0x00,
        terminus_locator_value=b"\x71",
    )
    raw = record.to_bytes()

    decoded = decode_pdr(raw)

    assert isinstance(decoded, TerminusLocatorPdr)
    assert decoded.eid == 0x71
    assert decoded.tid == 0x51
    assert encode_pdr(decoded) == raw


def test_sensor_auxiliary_names_pdr_exposes_readable_names_and_preserves_padding() -> None:
    """Names PDRs may contain padding bytes after strings; keeping it avoids lossy round-trips."""

    decoded = decode_pdr(_SENSOR_AUX_NAMES_RECORD)

    assert isinstance(decoded, SensorAuxiliaryNamesPdr)
    assert decoded.record_handle == 1
    assert decoded.sensor_id == 0x1001
    assert decoded.sensors[0].names[0].language_tag == "en"
    assert decoded.sensors[0].names[0].name == "SOC_TMP_MAX"
    assert len(decoded.trailing_data) == 40
    assert encode_pdr(decoded) == _SENSOR_AUX_NAMES_RECORD
    assert pdr_to_dict(decoded)["sensors"][0]["names"][0]["name"] == "SOC_TMP_MAX"


def test_numeric_effecter_pdr_decodes_and_reencodes_identically() -> None:
    # Representative DSP0248 numeric effecter PDR, real32 range fields.
    record = NumericEffecterPdr(
        record_handle=0x31,
        record_change_number=0x22,
        terminus_handle=0x44,
        effecter_id=0x1234,
        entity_type=0x55,
        entity_instance=0x66,
        container_id=0x77,
        effecter_semantic_id=0x88,
        effecter_init=1,
        effecter_auxiliary_names_pdr=1,
        base_unit=18,
        unit_modifier=-1,
        rate_unit=2,
        base_oem_unit_handle=3,
        aux_unit=4,
        aux_unit_modifier=-2,
        aux_rate_unit=5,
        aux_oem_unit_handle=6,
        is_linear=1,
        effecter_data_size=GetSensorReadingDataSizeEnum.SINT16,
        resolution=0.5,
        offset=-1.0,
        accuracy=10,
        plus_tolerance=2,
        minus_tolerance=3,
        state_transition_interval=1.25,
        transition_interval=2.5,
        max_settable=250,
        min_settable=-40,
        range_field_format=6,
        nominal_value=125.0,
        normal_max=200.0,
        normal_min=50.0,
        rated_max=225.0,
        rated_min=25.0,
    )
    raw = record.to_bytes()

    decoded = decode_pdr(raw)

    assert isinstance(decoded, NumericEffecterPdr)
    assert decoded.record_handle == 0x31
    assert decoded.effecter_id == 0x1234
    assert decoded.effecter_data_size == GetSensorReadingDataSizeEnum.SINT16
    assert decoded.range_field_format == 6
    assert decoded.rated_max == 225.0
    assert encode_pdr(decoded) == raw


def test_numeric_effecter_pdr_supports_variable_width_fields() -> None:
    # Representative DSP0248 numeric effecter PDR, uint32 effecter and sint16 range fields.
    raw = NumericEffecterPdr(
        record_handle=0x32,
        effecter_id=0x5678,
        effecter_data_size=GetSensorReadingDataSizeEnum.UINT32,
        max_settable=100000,
        min_settable=1000,
        range_field_format=GetSensorReadingDataSizeEnum.SINT16,
        nominal_value=500,
        normal_max=900,
        normal_min=100,
        rated_max=950,
        rated_min=50,
    ).to_bytes()

    decoded = decode_pdr(raw)

    assert isinstance(decoded, NumericEffecterPdr)
    assert decoded.effecter_data_size == GetSensorReadingDataSizeEnum.UINT32
    assert decoded.max_settable == 100000
    assert decoded.range_field_format == GetSensorReadingDataSizeEnum.SINT16
    assert decoded.rated_min == 50
    assert encode_pdr(decoded) == raw


def test_state_effecter_pdr_decodes_and_reencodes_identically() -> None:
    record = StateEffecterPdr(
        record_handle=0x41,
        terminus_handle=0x22,
        effecter_id=0x3456,
        entity_type=0x33,
        entity_instance=0x44,
        container_id=0x55,
        effecter_semantic_id=0x66,
        effecter_init=2,
        effecter_description_pdr=1,
        possible_states={7: [1, 3, 9], 9: []},
        possible_state_sizes={7: 2, 9: 0},
    )
    raw = record.to_bytes()

    decoded = decode_pdr(raw)

    assert isinstance(decoded, StateEffecterPdr)
    assert decoded.record_handle == 0x41
    assert decoded.effecter_id == 0x3456
    assert decoded.effecter_semantic_id == 0x66
    assert decoded.possible_states == {7: [1, 3, 9], 9: []}
    assert decoded.possible_state_sizes == {7: 2, 9: 0}
    assert encode_pdr(decoded) == raw


def test_state_effecter_pdr_supports_multiple_composite_effecters() -> None:
    raw = StateEffecterPdr(
        record_handle=0x42,
        effecter_id=0x789A,
        possible_states={2: [0, 8], 3: [2], 4: [15]},
        possible_state_sizes={2: 2, 3: 1, 4: 2},
        trailing_data=b"\x00",
    ).to_bytes()

    decoded = decode_pdr(raw)

    assert isinstance(decoded, StateEffecterPdr)
    assert decoded.possible_states == {2: [0, 8], 3: [2], 4: [15]}
    assert decoded.trailing_data == b"\x00"
    assert encode_pdr(decoded) == raw


def test_effecter_auxiliary_names_pdr_exposes_readable_names() -> None:
    decoded = decode_pdr(_EFFECTER_AUX_NAMES_RECORD)

    assert isinstance(decoded, EffecterAuxiliaryNamesPdr)
    assert decoded.record_handle == 0x33
    assert decoded.effecter_id == 0x1001
    assert decoded.effecters[0].names[0].language_tag == "en"
    assert decoded.effecters[0].names[0].name == "FAN"
    assert encode_pdr(decoded) == _EFFECTER_AUX_NAMES_RECORD
    assert pdr_to_dict(decoded)["effecters"][0]["names"][0]["name"] == "FAN"


def test_entity_auxiliary_names_pdr_uses_utf16be_names() -> None:
    record = EntityAuxiliaryNamesPdr(
        record_handle=0x41,
        entity_type=0x1234,
        entity_instance_number=2,
        entity_container_id=3,
        shared_name_count=1,
        names=[PdrNameString(language_tag="en", name="BOARD")],
    )
    raw = record.to_bytes()

    decoded = decode_pdr(raw)

    assert isinstance(decoded, EntityAuxiliaryNamesPdr)
    assert decoded.names[0].name == "BOARD"
    assert raw.endswith("BOARD".encode("utf-16-be") + b"\x00\x00")
    assert encode_pdr(decoded) == raw


def test_split_pdr_records_ignores_trailing_partial_record() -> None:
    first = TerminusLocatorPdr(1, 2, 1, 3, 4, 0, b"\x05").to_bytes()
    second = StateSensorPdr(6, 7).to_bytes()
    partial = NumericSensorPdr(8, 9).to_bytes()[: PDR_HEADER_LEN + 3]

    assert split_pdr_records(first + second + partial) == [first, second]


def test_unknown_pdr_type_is_opaque_and_round_trips() -> None:
    raw = PdrHeader(0x81, 1, 0xFE, 0x91, 3).to_bytes() + b"abc"

    decoded = decode_pdr(raw)

    assert isinstance(decoded, OpaquePdr)
    assert decoded.header.pdr_type == 0xFE
    assert decoded.data == b"abc"
    assert encode_pdr(decoded) == raw


def test_malformed_modelled_pdr_falls_back_to_opaque_and_logs(caplog) -> None:
    """A lossy or truncated modelled decode must never escape the round-trip guard."""

    raw = PdrHeader(0x91, 1, PDR_TYPE_NUMERIC_SENSOR, 0, 4).to_bytes() + b"tiny"

    with caplog.at_level(logging.WARNING, logger="pymctp.layers.mctp.pldm.pdr"):
        decoded = decode_pdr(raw)

    assert isinstance(decoded, OpaquePdr)
    assert encode_pdr(decoded) == raw
    assert "Failed to decode PDR type 2" in caplog.text


def test_malformed_effecter_pdrs_fall_back_to_opaque_and_log(caplog) -> None:
    """A lossy or truncated modelled decode must never escape the round-trip guard."""

    records = [
        PdrHeader(0xA1, 1, PDR_TYPE_NUMERIC_EFFECTER, 0, 4).to_bytes() + b"tiny",
        PdrHeader(0xA2, 1, PDR_TYPE_STATE_EFFECTER, 0, 4).to_bytes() + b"tiny",
        PdrHeader(0xA3, 1, PDR_TYPE_EFFECTER_AUXILIARY_NAMES, 0, 4).to_bytes() + b"tiny",
    ]

    with caplog.at_level(logging.WARNING, logger="pymctp.layers.mctp.pldm.pdr"):
        decoded = [decode_pdr(raw) for raw in records]

    assert all(isinstance(record, OpaquePdr) for record in decoded)
    assert [encode_pdr(record) for record in decoded] == records
    assert "Failed to decode PDR type 9" in caplog.text
    assert "Failed to decode PDR type 11" in caplog.text
    assert "Failed to decode PDR type 13" in caplog.text


def test_pdr_to_dict_and_from_dict_round_trip_through_json_for_every_type() -> None:
    records = [
        TerminusLocatorPdr(1, 2, 1, 3, 4, 0, b"\x05"),
        NumericSensorPdr(2, 3, data_size=GetSensorReadingDataSizeEnum.UINT16),
        StateSensorPdr(4, 5, possible_states={1: [0, 8]}),
        decode_pdr(_SENSOR_AUX_NAMES_RECORD),
        NumericEffecterPdr(5, 6, effecter_data_size=GetSensorReadingDataSizeEnum.SINT16, max_settable=10),
        StateEffecterPdr(6, 7, possible_states={1: [0, 8]}, possible_state_sizes={1: 2}),
        decode_pdr(_EFFECTER_AUX_NAMES_RECORD),
        EntityAuxiliaryNamesPdr(6, 7, 8, 9, 1, [PdrNameString("en", "ENTITY")]),
        OpaquePdr(PdrHeader(7, 1, 0xEE, 8, 2), b"xy"),
    ]

    for record in records:
        decoded = _json_round_trip(record)
        data = pdr_to_dict(decoded)
        assert "pdr_type" in data
        assert "record_handle" in data


def test_pdr_from_dict_dispatches_on_pdr_type() -> None:
    entity = pdr_from_dict(
        {
            "pdr_type": PDR_TYPE_ENTITY_AUXILIARY_NAMES,
            "record_handle": 1,
            "entity_type": 2,
            "entity_instance_number": 3,
            "entity_container_id": 4,
            "shared_name_count": 1,
            "names": [{"language_tag": "en", "name": "ENTITY"}],
        }
    )
    sensor = pdr_from_dict(
        {
            "pdr_type": PDR_TYPE_SENSOR_AUXILIARY_NAMES,
            "record_handle": 5,
            "pldm_terminus_handle": 6,
            "sensor_id": 7,
            "sensors": [{"names": [{"language_tag": "en", "name": "SENSOR"}]}],
        }
    )
    effecter = pdr_from_dict(
        {
            "pdr_type": PDR_TYPE_EFFECTER_AUXILIARY_NAMES,
            "record_handle": 15,
            "pldm_terminus_handle": 16,
            "effecter_id": 17,
            "effecters": [{"names": [{"language_tag": "en", "name": "EFFECTER"}]}],
        }
    )

    assert isinstance(entity, EntityAuxiliaryNamesPdr)
    assert isinstance(sensor, SensorAuxiliaryNamesPdr)
    assert isinstance(effecter, EffecterAuxiliaryNamesPdr)
    assert pdr_to_dict(entity)["pdr_type"] == PDR_TYPE_ENTITY_AUXILIARY_NAMES
    assert pdr_to_dict(sensor)["pdr_type"] == PDR_TYPE_SENSOR_AUXILIARY_NAMES
    assert pdr_to_dict(effecter)["pdr_type"] == PDR_TYPE_EFFECTER_AUXILIARY_NAMES
    assert pdr_to_dict(NumericSensorPdr(8, 9))["pdr_type"] == PDR_TYPE_NUMERIC_SENSOR
    assert pdr_to_dict(StateSensorPdr(10, 11))["pdr_type"] == PDR_TYPE_STATE_SENSOR
    assert pdr_to_dict(NumericEffecterPdr(12, 13))["pdr_type"] == PDR_TYPE_NUMERIC_EFFECTER
    assert pdr_to_dict(StateEffecterPdr(14, 15))["pdr_type"] == PDR_TYPE_STATE_EFFECTER
    assert pdr_to_dict(TerminusLocatorPdr(12, 13, 1, 14, 15, 0, b"\x10"))["pdr_type"] == PDR_TYPE_TERMINUS_LOCATOR
