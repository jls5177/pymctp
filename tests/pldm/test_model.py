# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the readable PLDM terminus model."""

from __future__ import annotations

import struct

import pytest
from scapy.packet import Raw
from scapy.plist import PacketList

from pymctp.automaton.behaviors.pldm_responder import (
    GetPDRTransferFlag,
    GetPDRTransferOperation,
    NumericSensorPdr,
    PldmSensorBehavior,
    StateSensorPdr,
)
from pymctp.layers.mctp.pldm import PldmHdr, PldmHdrPacket
from pymctp.layers.mctp.pldm.pdr import (
    PDR_TYPE_EFFECTER_AUXILIARY_NAMES,
    PDR_TYPE_NUMERIC_EFFECTER,
    PDR_TYPE_NUMERIC_SENSOR,
    PDR_TYPE_SENSOR_AUXILIARY_NAMES,
    PDR_TYPE_STATE_EFFECTER,
    PDR_TYPE_STATE_SENSOR,
    EffecterAuxiliaryNamesEntry,
    EffecterAuxiliaryNamesPdr,
    NumericEffecterPdr,
    PdrHeader,
    PdrNameString,
    SensorAuxiliaryNamesEntry,
    SensorAuxiliaryNamesPdr,
    StateEffecterPdr,
    decode_pdr,
    encode_pdr,
)
from pymctp.layers.mctp.pldm.fru import FruField, FruRecord, FruRepository, OpaqueFruField, fru_record_to_dict
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import (
    GetSensorReadingDataSizeEnum,
    PldmPlatformMonitoringCmdCodes,
)
from pymctp.layers.mctp.pldm.types import PldmTypeCodes
from pymctp.layers.mctp.transport import SmbusTransport, TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import EndpointContext, MsgTypes, Smbus7bitAddress
from pymctp.pldm.model import (
    FrequencySensor,
    CurrentSensor,
    FruRecordItem,
    NumericEffecter,
    NumericSensor,
    PowerSensor,
    StateEffecter,
    StateSensor,
    TemperatureSensor,
    Terminus,
    VerbatimFruRecord,
    VoltageSensor,
)
from pymctp.pldm.model.emitter import emit_python_module


def _ctx() -> EndpointContext:
    return EndpointContext(
        physical_address=Smbus7bitAddress(0x10),
        assigned_eid=0x10,
        supported_msg_types=[MsgTypes.CTRL, MsgTypes.PLDM],
    )


def _platform_request(cmd_code: int, payload=None):
    transport = TransportHdr(
        msg_type=MsgTypes.PLDM,
        dst=0x10,
        src=0x20,
        som=True,
        eom=True,
        to=True,
        tag=3,
    )
    pldm = PldmHdr(
        rq=True,
        instance_id=7,
        hdr_ver=0,
        pldm_type=PldmTypeCodes.PLATFORM_MONITORING,
        cmd_code=cmd_code,
    )
    pldm_payload = pldm / payload if payload is not None else pldm
    pkt = SmbusTransport(
        dst_addr=Smbus7bitAddress(0x10),
        src_addr=Smbus7bitAddress(0x20),
        load=transport / pldm_payload,
    )
    return SmbusTransport(bytes(pkt))


def _get_reply(behavior: PldmSensorBehavior, pkt, ctx: EndpointContext) -> PacketList:
    response = behavior.handle(pkt, ctx)
    assert response is not None
    assert response.stop_processing is True
    assert isinstance(response.reply, PacketList)
    return response.reply


def _single_pldm(reply: PacketList) -> PldmHdrPacket:
    assert len(reply) == 1
    pkt = SmbusTransport(bytes(reply[0]))
    pldm = pkt.getlayer(PldmHdrPacket)
    assert pldm is not None
    return pldm


def _pdr_request(record_handle: int, request_count: int = 512) -> bytes:
    return struct.pack("<IIBHH", record_handle, 0, int(GetPDRTransferOperation.GET_FIRST_PART), request_count, 0)


def _parse_pdr_response(pldm: PldmHdrPacket) -> tuple[int, int, int, bytes]:
    data = bytes(pldm.payload.load) if isinstance(pldm.payload, Raw) else bytes(pldm.payload)
    next_record_handle, next_transfer_handle, transfer_flag, response_count = struct.unpack_from("<IIBH", data)
    start = struct.calcsize("<IIBH")
    return next_record_handle, next_transfer_handle, transfer_flag, data[start : start + response_count]


def test_minimal_terminus_emits_numeric_sensor_and_names_with_sequential_handles() -> None:
    hcp = Terminus(eid=144, tid=3)
    sensor = hcp.add(NumericSensor(name="TEST_TEMP", sensor_id=0x1001, warning_high=85, critical_high=95))

    assert hcp["TEST_TEMP"] is sensor
    assert hcp[0x1001] is sensor
    records = hcp.build().pdr_repository.encoded_records()
    expected_sensor = NumericSensorPdr(
        record_handle=0,
        sensor_id=0x1001,
        data_size=GetSensorReadingDataSizeEnum.UINT32,
        entity_type=135,
        entity_instance=0,
        sensor_auxiliary_names_pdr=1,
        threshold_and_hysteresis_volatility=31,
        state_transition_interval=0.5,
        update_interval=1.0,
        range_field_support=8,
        warning_high=85,
        critical_high=95,
    )
    expected_names = SensorAuxiliaryNamesPdr(
        record_handle=1,
        pldm_terminus_handle=0,
        sensor_id=0x1001,
        sensors=[SensorAuxiliaryNamesEntry([PdrNameString("en", "TEST_TEMP")])],
    )

    assert records == [expected_sensor.to_bytes(), expected_names.to_bytes()]
    assert [PdrHeader.from_bytes(record).record_handle for record in records] == [0, 1]


def test_name_field_is_the_decoded_auxiliary_name() -> None:
    hcp = Terminus(eid=1, tid=1)
    hcp.add(NumericSensor(name="ALPHA_TEMP", sensor_id=1))

    names = decode_pdr(hcp.build().pdr_repository.encoded_records()[1])

    assert isinstance(names, SensorAuxiliaryNamesPdr)
    assert names.sensors[0].names[0].name == "ALPHA_TEMP"


def test_clone_deep_copies_mutable_state() -> None:
    original = StateSensor(name="STATE_A", sensor_id=1, possible_states={9: [1]})
    clone = original.clone(name="STATE_B", sensor_id=2)
    clone.possible_states[9].append(2)

    assert original.possible_states == {9: [1]}
    assert clone.possible_states == {9: [1, 2]}


def test_series_produces_independent_items() -> None:
    """Generated templates expand through series(), so members must not share editable mutable fields."""
    template = StateSensor(name="STATE_TEMPLATE", sensor_id=1, possible_states={9: [1]})
    first, second = template.series([("STATE_A", 0x1001), ("STATE_B", 0x1002)])
    first.possible_states[9].append(2)

    assert template.possible_states == {9: [1]}
    assert second.possible_states == {9: [1]}
    assert first.possible_states == {9: [1, 2]}


@pytest.mark.parametrize(
    ("template", "id_field"),
    [
        (NumericSensor(name="NUMERIC_SENSOR_TEMPLATE", sensor_id=1), "sensor_id"),
        (StateSensor(name="STATE_SENSOR_TEMPLATE", sensor_id=1), "sensor_id"),
        (NumericEffecter(name="NUMERIC_EFFECTER_TEMPLATE", effecter_id=1), "effecter_id"),
        (StateEffecter(name="STATE_EFFECTER_TEMPLATE", effecter_id=1), "effecter_id"),
    ],
)
def test_series_sets_the_item_type_id_field(template, id_field: str) -> None:
    first, second = template.series([("FIRST", 0x1001), ("SECOND", 0x1002)])

    assert [getattr(item, id_field) for item in (first, second)] == [0x1001, 0x1002]


def test_series_rejects_duplicate_ids() -> None:
    template = NumericSensor(name="SENSOR_TEMPLATE", sensor_id=1)

    with pytest.raises(ValueError, match="Duplicate sensor_id"):
        template.series([("FIRST", 0x1001), ("SECOND", 0x1001)])


def test_series_template_not_added_to_terminus_does_not_emit_record() -> None:
    """A template is a definition only; only expanded series members should become PDRs."""
    template = NumericSensor(name="SENSOR_TEMPLATE", sensor_id=0x2000)
    hcp = Terminus(eid=1, tid=1, items=template.series([("SENSOR_A", 0x2001), ("SENSOR_B", 0x2002)]))

    records = hcp.build().pdr_repository.encoded_records()

    assert [decode_pdr(records[index]).sensor_id for index in (0, 2)] == [0x2001, 0x2002]


def test_handles_remain_sequential_when_adding_clones() -> None:
    hcp = Terminus(eid=1, tid=1)
    seed = NumericSensor(name="SEED", sensor_id=0x2000)
    hcp.add(seed)
    hcp.add(seed.clone(name="COPY", sensor_id=0x2001))

    records = hcp.build().pdr_repository.encoded_records()

    assert [PdrHeader.from_bytes(record).record_handle for record in records] == [0, 1, 2, 3]
    assert [decode_pdr(records[index]).sensor_id for index in (0, 2)] == [0x2000, 0x2001]


@pytest.mark.parametrize(
    ("sensor_cls", "base_unit", "unit_modifier", "data_size", "range_field_format"),
    [
        (TemperatureSensor, 2, 0, GetSensorReadingDataSizeEnum.SINT32, GetSensorReadingDataSizeEnum.SINT32),
        (PowerSensor, 7, 0, GetSensorReadingDataSizeEnum.UINT32, GetSensorReadingDataSizeEnum.UINT32),
        (VoltageSensor, 5, -3, GetSensorReadingDataSizeEnum.UINT32, GetSensorReadingDataSizeEnum.UINT32),
        (CurrentSensor, 6, -3, GetSensorReadingDataSizeEnum.SINT32, GetSensorReadingDataSizeEnum.SINT32),
        (FrequencySensor, 20, 0, GetSensorReadingDataSizeEnum.UINT32, GetSensorReadingDataSizeEnum.UINT32),
    ],
)
def test_presets_set_captured_unit_modifier_and_width(sensor_cls, base_unit: int, unit_modifier: int, data_size, range_field_format) -> None:
    sensor = sensor_cls(name="PRESET", sensor_id=1)

    assert sensor.base_unit == base_unit
    assert sensor.unit_modifier == unit_modifier
    assert sensor.data_size == data_size
    assert sensor.range_field_format == range_field_format


def test_preset_range_format_defaults_to_overridden_data_size() -> None:
    sensor = TemperatureSensor(name="TEMP_UNSIGNED", sensor_id=1, data_size=GetSensorReadingDataSizeEnum.UINT32)

    assert sensor.data_size == GetSensorReadingDataSizeEnum.UINT32
    assert sensor.range_field_format == GetSensorReadingDataSizeEnum.UINT32


def test_verbatim_record_passes_through_byte_for_byte() -> None:
    raw = PdrHeader(record_handle=0x44, header_version=1, pdr_type=0x7F, record_change_number=0, data_length=3).to_bytes()
    raw += b"abc"
    hcp = Terminus(eid=1, tid=1)
    hcp.add_verbatim(raw)
    decoded = Terminus(eid=1, tid=1)
    decoded.add(decode_pdr(raw))

    assert hcp.build().pdr_repository.encoded_records() == [raw]
    assert decoded.build().pdr_repository.encoded_records() == [raw]


def test_build_output_drives_pldm_sensor_behavior_get_pdr() -> None:
    """GetPDR clients consume wire bytes, so build() must feed the existing responder directly."""
    hcp = Terminus(eid=1, tid=1)
    hcp.add(NumericSensor(name="WIRE_TEMP", sensor_id=0x2201))
    behavior = PldmSensorBehavior(profile=hcp.build())

    pldm = _single_pldm(
        _get_reply(
            behavior,
            _platform_request(PldmPlatformMonitoringCmdCodes.GetPDR, _pdr_request(0)),
            _ctx(),
        )
    )
    next_record_handle, transfer_handle, transfer_flag, record_data = _parse_pdr_response(pldm)

    assert next_record_handle == 1
    assert transfer_handle == 0
    assert transfer_flag == GetPDRTransferFlag.START_AND_END
    assert record_data == behavior.profile.pdr_repository.get_record(0)


def test_fru_record_model_builds_byte_identical_repository() -> None:
    record = FruRecord(0x1234, 0xFE, 1, [FruField(1, "ALPHA"), OpaqueFruField(0xE0, b"\x01")])
    hcp = Terminus(eid=1, tid=1, fru_records=[FruRecordItem("fru_alpha", 0x1234, 0xFE, record.fields)])

    assert hcp["fru_alpha"].record_set_identifier == 0x1234
    assert hcp.build().fru_repository.response_table() == record.to_bytes()


def test_fru_artifact_and_python_emission_rebuild_byte_identically() -> None:
    """Generated Python models must preserve FRU bytes or the responder cannot replay captured tables."""
    record = FruRecord(1, 0xFE, 1, [FruField(1, "ALPHA", b"ALPHA"), OpaqueFruField(0xE0, b"\x01\x02")])
    padding = b"\x00\x00\x00"
    repository = FruRepository(records=[record], table_padding=padding)
    artifact = {
        "eid": 1,
        "tid": 1,
        "fru": {
            "metadata": {
                "major_version": 1,
                "minor_version": 0,
                "table_maximum_size": 0,
                "table_length": len(record.to_bytes()),
                "total_record_set_identifiers": 1,
                "total_records": 1,
                "integrity_checksum": repository.integrity_checksum,
            },
            "table_padding": padding.hex(),
            "records": [{"name": "fru_alpha", **fru_record_to_dict(record)}],
        },
        "pdrs": [],
    }

    model = Terminus.from_artifact(artifact)
    namespace: dict[str, object] = {}
    exec(emit_python_module(artifact).code, namespace)
    emitted = namespace["terminus"]

    assert model.build().fru_repository.response_table() == record.to_bytes() + padding
    assert emitted.build().fru_repository.response_table() == record.to_bytes() + padding
    assert emitted.build().fru_repository.metadata().to_bytes() == repository.metadata().to_bytes()


def test_verbatim_fru_record_passes_through_byte_for_byte() -> None:
    raw = bytes.fromhex("0100fe0101e003010203")
    hcp = Terminus(eid=1, tid=1, fru_records=[VerbatimFruRecord(raw)])

    assert hcp.build().fru_repository.response_table() == raw


def test_state_sensors_and_effecters_build_structured_records_and_definitions() -> None:
    hcp = Terminus(eid=1, tid=1)
    hcp.add(StateSensor(name="STATE_SENSOR", sensor_id=0x3001, possible_states={1: [0, 2]}))
    hcp.add(NumericEffecter(name="NUMERIC_EFFECTER", effecter_id=0x4001, max_settable=10))
    hcp.add(StateEffecter(name="STATE_EFFECTER", effecter_id=0x4002, possible_states={2: [1, 3]}))

    profile = hcp.build()
    records = profile.pdr_repository.encoded_records()

    assert [PdrHeader.from_bytes(record).pdr_type for record in records] == [
        PDR_TYPE_STATE_SENSOR,
        PDR_TYPE_SENSOR_AUXILIARY_NAMES,
        PDR_TYPE_NUMERIC_EFFECTER,
        PDR_TYPE_EFFECTER_AUXILIARY_NAMES,
        PDR_TYPE_STATE_EFFECTER,
        PDR_TYPE_EFFECTER_AUXILIARY_NAMES,
    ]
    assert isinstance(decode_pdr(records[0]), StateSensorPdr)
    assert isinstance(decode_pdr(records[2]), NumericEffecterPdr)
    assert isinstance(decode_pdr(records[4]), StateEffecterPdr)
    assert 0x3001 in profile.sensors
    assert {0x4001, 0x4002}.issubset(profile.effecters)


def test_from_artifact_falls_back_to_verbatim_for_unexpressed_records() -> None:
    """Opaque records must survive conversion instead of being approximated by lossy defaults."""
    raw = PdrHeader(record_handle=0, header_version=1, pdr_type=PDR_TYPE_NUMERIC_EFFECTER, record_change_number=0, data_length=1)
    artifact = {"eid": 1, "tid": 1, "pdrs": [{"pdr_type": PDR_TYPE_NUMERIC_EFFECTER, "record_handle": 0, "data": "aa"}]}
    hcp = Terminus.from_artifact(artifact)

    assert hcp.verbatim_fallbacks == [
        {"index": 0, "record_handle": 0, "pdr_type": PDR_TYPE_NUMERIC_EFFECTER, "reason": "record is opaque in the artifact"}
    ]
    assert hcp.build().pdr_repository.encoded_records() == [raw.to_bytes() + b"\xaa"]


def test_from_artifact_converts_data_encoded_effecter_records() -> None:
    """Generated artifacts may store effecter PDRs as hex data; those should still become editable model objects."""
    effecter = NumericEffecterPdr(
        record_handle=0,
        effecter_id=0x6001,
        effecter_data_size=GetSensorReadingDataSizeEnum.SINT32,
        base_unit=6,
        unit_modifier=-3,
    )
    names = EffecterAuxiliaryNamesPdr(
        record_handle=1,
        pldm_terminus_handle=0,
        effecter_id=0x6001,
        effecters=[EffecterAuxiliaryNamesEntry([PdrNameString("en", "CURRENT_LIMIT")])],
    )
    artifact = {
        "eid": 1,
        "tid": 1,
        "pdrs": [
            _data_pdr_dict(effecter, PDR_TYPE_NUMERIC_EFFECTER),
            _data_pdr_dict(names, PDR_TYPE_EFFECTER_AUXILIARY_NAMES),
        ],
    }

    hcp = Terminus.from_artifact(artifact)

    assert hcp.verbatim_fallbacks == []
    assert hcp["CURRENT_LIMIT"].effecter_id == 0x6001
    assert hcp.build().pdr_repository.encoded_records() == [encode_pdr(effecter), encode_pdr(names)]


def test_from_artifact_rebuilds_structured_sensor_and_name_bytes() -> None:
    sensor = NumericSensorPdr(record_handle=0, sensor_id=0x5001)
    names = SensorAuxiliaryNamesPdr(
        record_handle=1,
        pldm_terminus_handle=0,
        sensor_id=0x5001,
        sensors=[SensorAuxiliaryNamesEntry([PdrNameString("en", "ROUND_TRIP")])],
    )
    artifact = {
        "eid": 1,
        "tid": 1,
        "pdrs": [
            {"pdr_type": PDR_TYPE_NUMERIC_SENSOR, **_pdr_dict(sensor)},
            {
                "pdr_type": PDR_TYPE_SENSOR_AUXILIARY_NAMES,
                "record_handle": 1,
                "header_version": 1,
                "record_change_number": 0,
                "pldm_terminus_handle": 0,
                "sensor_id": 0x5001,
                "sensor_count": 1,
                "sensors": [
                    {
                        "name_string_count": 1,
                        "names": [{"language_tag": "en", "name": "ROUND_TRIP"}],
                    }
                ],
                "trailing_data": "",
            },
        ],
    }

    assert Terminus.from_artifact(artifact).build().pdr_repository.encoded_records() == [
        encode_pdr(sensor),
        encode_pdr(names),
    ]


def _data_pdr_dict(record, pdr_type: int) -> dict[str, object]:
    raw = encode_pdr(record)
    header = PdrHeader.from_bytes(raw)
    return {
        "pdr_type": pdr_type,
        "record_handle": header.record_handle,
        "header_version": header.header_version,
        "record_change_number": header.record_change_number,
        "data_length": header.data_length,
        "data": raw[10:].hex(),
    }


def _pdr_dict(record: NumericSensorPdr) -> dict[str, object]:
    return {
        name: getattr(record, name)
        for name in (
            "record_handle",
            "record_change_number",
            "terminus_handle",
            "sensor_id",
            "entity_type",
            "entity_instance",
            "container_id",
            "sensor_init",
            "sensor_auxiliary_names_pdr",
            "base_unit",
            "unit_modifier",
            "rate_unit",
            "base_oem_unit_handle",
            "aux_unit",
            "aux_unit_modifier",
            "aux_rate_unit",
            "rel",
            "aux_oem_unit_handle",
            "is_linear",
            "data_size",
            "resolution",
            "offset",
            "accuracy",
            "plus_tolerance",
            "minus_tolerance",
            "hysteresis",
            "supported_thresholds",
            "threshold_and_hysteresis_volatility",
            "state_transition_interval",
            "update_interval",
            "max_readable",
            "min_readable",
            "range_field_format",
            "range_field_support",
            "nominal_value",
            "normal_max",
            "normal_min",
            "warning_high",
            "warning_low",
            "critical_high",
            "critical_low",
            "fatal_high",
            "fatal_low",
        )
    }
