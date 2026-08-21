# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the PLDM responder behaviors."""

from __future__ import annotations

import binascii
import logging
import struct
import time
import uuid

import pytest
from scapy.packet import Raw
from scapy.plist import PacketList

from pymctp.automaton.behaviors.pldm_responder import (
    GetPDRTransferFlag,
    GetPDRTransferOperation,
    NumericSensorPdr,
    PdrRepository,
    PldmBaseBehavior,
    PldmSensorBehavior,
    SensorDefinition,
    SensorSimulation,
    StateSensorPdr,
)
from pymctp.automaton.roles import get_behaviors_for_roles
from pymctp.layers.mctp.pldm import (
    GetPLDMCommandsPacket,
    GetPLDMTypesPacket,
    GetPLDMVersionPacket,
    GetSensorReadingPacket,
    GetTIDPacket,
    PldmHdr,
    PldmHdrPacket,
    SetTIDPacket,
)
from pymctp.layers.mctp.pldm.type1_base import GetPLDMVersionOperation, GetPLDMVersionTransferFlag
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import (
    GetSensorReadingDataSizeEnum,
    GetSensorReadingEventMsgEnableEnum,
    GetSensorReadingOperationalStateEnum,
    GetSensorReadingPresentEnum,
    PlatformEventMsgClasses,
    PollForPlatformEventMsgPacket,
    PollForPlatformEventOperation,
    PollForPlatformEventTransferFlag,
    PldmPlatformMonitoringCmdCodes,
)
from pymctp.layers.mctp.pldm.pdr import (
    OpaquePdr,
    PDR_TYPE_NUMERIC_EFFECTER,
    NumericEffecterPdr,
    PdrHeader,
    StateEffecterPdr,
    decode_pdr,
)
from pymctp.layers.mctp.pldm.types import CompletionCodes, PldmControlCmdCodes, PldmTypeCodes
from pymctp.layers.mctp.transport import SmbusTransport, TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import EndpointContext, MsgTypes, Smbus7bitAddress


def _ctx(*, supported_pldm: bool = True) -> EndpointContext:
    supported = [MsgTypes.CTRL, MsgTypes.PLDM] if supported_pldm else [MsgTypes.CTRL]
    return EndpointContext(
        physical_address=Smbus7bitAddress(0x10),
        assigned_eid=0x10,
        supported_msg_types=supported,
    )


def _request(
    pldm_type: int,
    cmd_code: int,
    payload=None,
    *,
    instance_id: int = 7,
    hdr_ver: int = 0,
    rq: bool = True,
    smbus: bool = True,
):
    transport = TransportHdr(
        msg_type=MsgTypes.PLDM,
        dst=0x10,
        src=0x20,
        som=True,
        eom=True,
        to=rq,
        tag=3,
    )
    pldm = PldmHdr(
        rq=rq,
        instance_id=instance_id,
        hdr_ver=hdr_ver,
        pldm_type=pldm_type,
        cmd_code=cmd_code,
        completion_code=0 if not rq else None,
    )
    pldm_payload = pldm / payload if payload is not None else pldm
    if not smbus:
        return TransportHdrPacket(bytes(transport / pldm_payload))

    pkt = SmbusTransport(
        dst_addr=Smbus7bitAddress(0x10),
        src_addr=Smbus7bitAddress(0x20),
        load=transport / pldm_payload,
    )
    return SmbusTransport(bytes(pkt))


def _get_reply(behavior: PldmBaseBehavior | PldmSensorBehavior, pkt, ctx: EndpointContext) -> PacketList:
    response = behavior.handle(pkt, ctx)
    assert response is not None
    assert response.stop_processing is True
    assert isinstance(response.reply, PacketList)
    return response.reply


def _single_pldm(reply: PacketList, *, smbus: bool = True) -> PldmHdrPacket:
    assert len(reply) == 1
    pkt = SmbusTransport(bytes(reply[0])) if smbus else TransportHdrPacket(bytes(reply[0]))
    pldm = pkt.getlayer(PldmHdrPacket)
    assert pldm is not None
    return pldm


def _base_request(cmd_code: int, payload=None, **kwargs):
    return _request(PldmTypeCodes.CONTROL, cmd_code, payload, **kwargs)


def _sensor_request(sensor_id: int = 1, **kwargs):
    return _request(
        PldmTypeCodes.PLATFORM_MONITORING,
        PldmPlatformMonitoringCmdCodes.GetSensorReading,
        GetSensorReadingPacket(sensorID=sensor_id, rearmEventState=0),
        **kwargs,
    )


def _set_numeric_sensor_enable_request(sensor_id: int, operational_state: int = 0, event_message_enable: int = 0):
    return _platform_request(
        PldmPlatformMonitoringCmdCodes.SetNumericSensorEnable,
        Raw(struct.pack("<HBB", sensor_id, operational_state, event_message_enable)),
    )


def _set_state_sensor_enables_request(sensor_id: int, payload: bytes | None = None):
    return _platform_request(
        PldmPlatformMonitoringCmdCodes.SetStateSensorEnables,
        Raw(payload if payload is not None else struct.pack("<HBBB", sensor_id, 1, 0, 0)),
    )


def _get_state_sensor_readings_request(sensor_id: int, payload: bytes | None = None):
    return _platform_request(
        PldmPlatformMonitoringCmdCodes.GetStateSensorReadings,
        Raw(payload if payload is not None else struct.pack("<HBB", sensor_id, 0, 0)),
    )


def _set_numeric_effecter_enable_request(effecter_id: int, operational_state: int = 0):
    return _platform_request(
        PldmPlatformMonitoringCmdCodes.SetNumericEffecterEnable,
        Raw(struct.pack("<HB", effecter_id, operational_state)),
    )


def _set_numeric_effecter_value_request(
    effecter_id: int,
    data_size: GetSensorReadingDataSizeEnum | int,
    value: int,
):
    return _platform_request(
        PldmPlatformMonitoringCmdCodes.SetNumericEffecterValue,
        Raw(struct.pack("<HB", effecter_id, int(data_size)) + _encode_test_value(data_size, value)),
    )


def _get_numeric_effecter_value_request(effecter_id: int, payload: bytes | None = None):
    return _platform_request(
        PldmPlatformMonitoringCmdCodes.GetNumericEffecterValue,
        Raw(payload if payload is not None else struct.pack("<H", effecter_id)),
    )


def _set_state_effecter_enables_request(effecter_id: int, payload: bytes | None = None):
    return _platform_request(
        PldmPlatformMonitoringCmdCodes.SetStateEffecterEnables,
        Raw(payload if payload is not None else struct.pack("<HBBB", effecter_id, 1, 0, 0)),
    )


def _set_state_effecter_states_request(effecter_id: int, payload: bytes | None = None):
    return _platform_request(
        PldmPlatformMonitoringCmdCodes.SetStateEffecterStates,
        Raw(payload if payload is not None else struct.pack("<HBBB", effecter_id, 1, 1, 0)),
    )


def _get_state_effecter_states_request(effecter_id: int, payload: bytes | None = None):
    return _platform_request(
        PldmPlatformMonitoringCmdCodes.GetStateEffecterStates,
        Raw(payload if payload is not None else struct.pack("<H", effecter_id)),
    )


def _encode_test_value(data_size: GetSensorReadingDataSizeEnum | int, value: int) -> bytes:
    formats = {
        GetSensorReadingDataSizeEnum.UINT8: "<B",
        GetSensorReadingDataSizeEnum.SINT8: "<b",
        GetSensorReadingDataSizeEnum.UINT16: "<H",
        GetSensorReadingDataSizeEnum.SINT16: "<h",
        GetSensorReadingDataSizeEnum.UINT32: "<I",
        GetSensorReadingDataSizeEnum.SINT32: "<i",
    }
    return struct.pack(formats[GetSensorReadingDataSizeEnum(data_size)], value)


def _platform_request(cmd_code: int, payload=None, **kwargs):
    return _request(PldmTypeCodes.PLATFORM_MONITORING, cmd_code, payload, **kwargs)


def _raw_payload(pldm: PldmHdrPacket) -> bytes:
    if isinstance(pldm.payload, Raw):
        return bytes(pldm.payload.load)
    return bytes(pldm.payload)


def _pdr_request(
    record_handle: int,
    data_transfer_handle: int,
    operation: GetPDRTransferOperation,
    request_count: int,
    record_change_number: int = 0,
) -> bytes:
    return struct.pack(
        "<IIBHH",
        record_handle,
        data_transfer_handle,
        int(operation),
        request_count,
        record_change_number,
    )


def _parse_pdr_response(pldm: PldmHdrPacket) -> tuple[int, int, int, bytes, bytes]:
    data = _raw_payload(pldm)
    next_record_handle, next_data_transfer_handle, transfer_flag, response_count = struct.unpack_from("<IIBH", data)
    start = struct.calcsize("<IIBH")
    end = start + response_count
    return next_record_handle, next_data_transfer_handle, transfer_flag, data[start:end], data[end:]


def _pdr_header(record: bytes) -> tuple[int, int, int, int, int]:
    return struct.unpack_from("<IBBHH", record)


def _pldm_from_reassembled(reply: PacketList) -> PldmHdrPacket:
    data = bytearray()
    for packet in reply:
        smbus = SmbusTransport(bytes(packet))
        transport = smbus.getlayer(TransportHdrPacket)
        assert transport is not None
        data.extend(bytes(transport.payload))
    return PldmHdrPacket(bytes(data))


def test_roles_resolve_pldm_base_and_sensor_in_order() -> None:
    base_behaviors = get_behaviors_for_roles(("pldm-base", {"tid": 9}))
    sensor_behaviors = get_behaviors_for_roles(
        ("pldm-sensor", {"base": {"tid": 6}, "sensors": {1: {"reading": 42}}})
    )

    assert len(base_behaviors) == 1
    assert isinstance(base_behaviors[0], PldmBaseBehavior)
    assert base_behaviors[0].profile.tid == 9
    assert [behavior.name for behavior in sensor_behaviors] == ["pldm-base", "pldm-sensor"]
    assert isinstance(sensor_behaviors[0], PldmBaseBehavior)
    assert isinstance(sensor_behaviors[1], PldmSensorBehavior)
    assert sensor_behaviors[0].profile.tid == 6


def test_can_handle_claims_only_supported_pldm_requests_for_own_type() -> None:
    base = PldmBaseBehavior()
    sensor = PldmSensorBehavior()
    base_request = _base_request(PldmControlCmdCodes.GetTID)
    sensor_request = _sensor_request()
    base_response = _base_request(PldmControlCmdCodes.GetTID, rq=False)

    assert base.can_handle(base_request, _ctx()) is True
    assert base.can_handle(sensor_request, _ctx()) is False
    assert base.can_handle(base_response, _ctx()) is False
    assert base.can_handle(base_request, _ctx(supported_pldm=False)) is False
    assert sensor.can_handle(sensor_request, _ctx()) is True
    assert sensor.can_handle(base_request, _ctx()) is False
    assert sensor.can_handle(sensor_request, _ctx(supported_pldm=False)) is False


def test_get_tid_and_set_tid_round_trip_through_delegated_payloads() -> None:
    behavior = PldmBaseBehavior(tid=3)
    ctx = _ctx()

    get_before = _single_pldm(_get_reply(behavior, _base_request(PldmControlCmdCodes.GetTID), ctx))
    set_tid = _single_pldm(
        _get_reply(behavior, _base_request(PldmControlCmdCodes.SetTID, SetTIDPacket(tid=0x22)), ctx)
    )
    get_after = _single_pldm(_get_reply(behavior, _base_request(PldmControlCmdCodes.GetTID), ctx))

    assert get_before.completion_code == CompletionCodes.SUCCESS
    assert get_before.getlayer(GetTIDPacket).tid == 3
    assert set_tid.completion_code == CompletionCodes.SUCCESS
    assert get_after.getlayer(GetTIDPacket).tid == 0x22
    assert ctx.msg_type_context[behavior.name]["tid"] == 0x22


def test_get_pldm_types_reports_profile_bitfield() -> None:
    behavior = PldmBaseBehavior(supported_types=[PldmTypeCodes.CONTROL, PldmTypeCodes.PLATFORM_MONITORING, 9])
    pldm = _single_pldm(_get_reply(behavior, _base_request(PldmControlCmdCodes.GetPLDMTypes), _ctx()))
    payload = pldm.getlayer(GetPLDMTypesPacket)

    assert pldm.completion_code == CompletionCodes.SUCCESS
    assert payload.PLDMTypes1 == 0b00000101
    assert payload.PLDMTypes2 == 0b00000010
    assert [payload.PLDMTypes3, payload.PLDMTypes4, payload.PLDMTypes5, payload.PLDMTypes6] == [0, 0, 0, 0]
    assert [payload.PLDMTypes7, payload.PLDMTypes8] == [0, 0]


def test_get_pldm_commands_reports_32_byte_command_bitfield() -> None:
    behavior = PldmBaseBehavior()
    pkt = _base_request(
        PldmControlCmdCodes.GetPLDMCommands,
        GetPLDMCommandsPacket(PLDMType=PldmTypeCodes.PLATFORM_MONITORING, Version=0xF1F0F000),
    )

    pldm = _single_pldm(_get_reply(behavior, pkt, _ctx()))
    payload = pldm.getlayer(GetPLDMCommandsPacket)

    assert pldm.completion_code == CompletionCodes.SUCCESS
    assert len(payload.cmds) == 32
    assert payload.cmds[0] == 0x18
    assert payload.cmds[4] == 0x03
    assert payload.cmds[6] == 0x07
    assert payload.cmds[7] == 0x07
    for command in (
        PldmPlatformMonitoringCmdCodes.GetTerminusUID,
        PldmPlatformMonitoringCmdCodes.SetEventReceiver,
        PldmPlatformMonitoringCmdCodes.PlatformEventMessage,
        PldmPlatformMonitoringCmdCodes.PollForPlatformEventMessage,
        PldmPlatformMonitoringCmdCodes.EventMessageSupported,
        PldmPlatformMonitoringCmdCodes.EventMessageBufferSize,
        PldmPlatformMonitoringCmdCodes.SetNumericSensorEnable,
        PldmPlatformMonitoringCmdCodes.GetSensorReading,
        PldmPlatformMonitoringCmdCodes.SetStateSensorEnables,
        PldmPlatformMonitoringCmdCodes.GetStateSensorReadings,
        PldmPlatformMonitoringCmdCodes.SetNumericEffecterEnable,
        PldmPlatformMonitoringCmdCodes.SetNumericEffecterValue,
        PldmPlatformMonitoringCmdCodes.GetNumericEffecterValue,
        PldmPlatformMonitoringCmdCodes.SetStateEffecterEnables,
        PldmPlatformMonitoringCmdCodes.SetStateEffecterStates,
        PldmPlatformMonitoringCmdCodes.GetStateEffecterStates,
        PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo,
        PldmPlatformMonitoringCmdCodes.GetPDR,
    ):
        assert payload.cmds[int(command) // 8] & (1 << (int(command) % 8))


def test_get_pldm_version_returns_single_part_version_bytes() -> None:
    behavior = PldmBaseBehavior(versions={PldmTypeCodes.CONTROL: ["1.0.0"]})
    pkt = _base_request(
        PldmControlCmdCodes.GetPLDMVersion,
        GetPLDMVersionPacket(
            DataTransferHandle=0,
            TransferOperationFlag=GetPLDMVersionOperation.GET_FIRST_PART,
            PLDMType=PldmTypeCodes.CONTROL,
        ),
    )

    pldm = _single_pldm(_get_reply(behavior, pkt, _ctx()))
    payload = pldm.getlayer(GetPLDMVersionPacket)

    assert pldm.completion_code == CompletionCodes.SUCCESS
    assert payload.NextDataTransferHandle == 0
    assert payload.TransferFlag == GetPLDMVersionTransferFlag.START_AND_END
    # Byte-for-byte what a real terminus answers for 1.0.0: the ver32 field in
    # major/minor/update/alpha order, then a CRC-32 over it.
    assert bytes(payload.payload) == bytes.fromhex("f1f0f000") + bytes.fromhex("b33ce6be")


@pytest.mark.parametrize(
    ("version", "blob"),
    [
        # Captured from a real PLDM terminus: ver32 followed by its CRC-32.
        ("1.1.0", "f1f1f000845624bf"),  # DSP0240 base
        ("1.3.0", "f1f3f000ea82a0bc"),  # DSP0248 platform monitoring
        ("1.0.1", "f1f0f100f20dfda7"),  # DSP0257 FRU
        ("1.0.0", "f1f0f000b33ce6be"),  # OEM
    ],
)
def test_get_pldm_version_matches_real_hardware_byte_for_byte(version: str, blob: str) -> None:
    """The ver32 field is transmitted major, minor, update, alpha.

    Encoding it the other way round produced ``00 F0 F0 F1`` for 1.0.0, whose
    leading byte is not even a valid BCD version component.
    """
    behavior = PldmBaseBehavior(versions={PldmTypeCodes.CONTROL: [version]})
    pkt = _base_request(
        PldmControlCmdCodes.GetPLDMVersion,
        GetPLDMVersionPacket(
            DataTransferHandle=0,
            TransferOperationFlag=GetPLDMVersionOperation.GET_FIRST_PART,
            PLDMType=PldmTypeCodes.CONTROL,
        ),
    )

    pldm = _single_pldm(_get_reply(behavior, pkt, _ctx()))

    assert bytes(pldm.getlayer(GetPLDMVersionPacket).payload) == bytes.fromhex(blob)


def test_get_pldm_version_appends_a_crc32_over_every_version() -> None:
    """openbmc's pldmd rejects a version response that omits the checksum.

    ``intel-pldmd`` (``src/base.cpp``) requires at least 8 bytes of version
    data ("Version response length is less than expected"), requires the
    remainder after stripping the trailing CRC to be a multiple of 4, and then
    verifies that CRC over the version bytes.
    """
    versions = ["1.0.0", "1.1.0"]
    behavior = PldmBaseBehavior(versions={PldmTypeCodes.CONTROL: versions})
    pkt = _base_request(
        PldmControlCmdCodes.GetPLDMVersion,
        GetPLDMVersionPacket(
            DataTransferHandle=0,
            TransferOperationFlag=GetPLDMVersionOperation.GET_FIRST_PART,
            PLDMType=PldmTypeCodes.CONTROL,
        ),
    )

    pldm = _single_pldm(_get_reply(behavior, pkt, _ctx()))
    version_data = bytes(pldm.getlayer(GetPLDMVersionPacket).payload)

    assert len(version_data) >= 8
    version_bytes, crc = version_data[:-4], version_data[-4:]
    assert len(version_bytes) == 4 * len(versions)
    assert len(version_bytes) % 4 == 0
    assert int.from_bytes(crc, "little") == binascii.crc32(version_bytes)


@pytest.mark.parametrize(
    ("data_size", "reading", "field_name", "encoded"),
    [
        (GetSensorReadingDataSizeEnum.UINT8, 0x12, "presentReading8", 0x12),
        (GetSensorReadingDataSizeEnum.SINT8, -2, "presentReading8", 0xFE),
        (GetSensorReadingDataSizeEnum.UINT16, 0x1234, "presentReading16", 0x1234),
        (GetSensorReadingDataSizeEnum.SINT16, -2, "presentReading16", 0xFFFE),
        (GetSensorReadingDataSizeEnum.UINT32, 0x12345678, "presentReading32", 0x12345678),
        (GetSensorReadingDataSizeEnum.SINT32, -2, "presentReading32", 0xFFFFFFFE),
    ],
)
def test_get_sensor_reading_encodes_each_data_size(
    data_size: GetSensorReadingDataSizeEnum,
    reading: int,
    field_name: str,
    encoded: int,
) -> None:
    behavior = PldmSensorBehavior(sensors={1: SensorDefinition(sensor_id=1, reading=reading, data_size=data_size)})
    pldm = _single_pldm(_get_reply(behavior, _sensor_request(1), _ctx()))
    payload = pldm.getlayer(GetSensorReadingPacket)

    assert pldm.completion_code == CompletionCodes.SUCCESS
    assert payload.sensorDataSize == data_size
    assert getattr(payload, field_name) == encoded


def test_dynamic_callable_sensor_reading_changes_between_polls() -> None:
    readings = iter([10, 11])

    def next_value() -> int:
        return next(readings)

    behavior = PldmSensorBehavior(sensors={1: SensorDefinition(sensor_id=1, reading=next_value)})
    ctx = _ctx()

    first = _single_pldm(_get_reply(behavior, _sensor_request(1), ctx)).getlayer(GetSensorReadingPacket)
    second = _single_pldm(_get_reply(behavior, _sensor_request(1), ctx)).getlayer(GetSensorReadingPacket)

    assert first.presentReading8 == 10
    assert second.presentReading8 == 11


def test_unknown_sensor_id_returns_invalid_data_completion_code() -> None:
    behavior = PldmSensorBehavior(sensors={1: SensorDefinition(sensor_id=1, reading=1)})
    pldm = _single_pldm(_get_reply(behavior, _sensor_request(2), _ctx()))

    assert pldm.completion_code == CompletionCodes.ERROR_INVALID_DATA
    assert isinstance(pldm.payload, GetSensorReadingPacket) is False


def test_unsupported_commands_return_unsupported_completion_code() -> None:
    base = PldmBaseBehavior()
    sensor = PldmSensorBehavior()
    base_error = _single_pldm(_get_reply(base, _base_request(PldmControlCmdCodes.SelectPLDMVersion), _ctx()))
    sensor_error = _single_pldm(
        _get_reply(
            sensor,
            _request(PldmTypeCodes.PLATFORM_MONITORING, PldmPlatformMonitoringCmdCodes.GetPLDMEventLogInfo),
            _ctx(),
        )
    )

    assert base_error.completion_code == CompletionCodes.ERROR_UNSUPPORTED_CMD
    assert sensor_error.completion_code == CompletionCodes.ERROR_UNSUPPORTED_CMD


def test_instance_id_and_hdr_ver_are_echoed_in_responses() -> None:
    behavior = PldmSensorBehavior(sensors={1: SensorDefinition(sensor_id=1, reading=1)})

    pldm = _single_pldm(_get_reply(behavior, _sensor_request(1, instance_id=0x1A, hdr_ver=2), _ctx()))

    assert pldm.instance_id == 0x1A
    assert pldm.hdr_ver == 2


def test_per_context_state_isolated_for_one_base_behavior_instance() -> None:
    behavior = PldmBaseBehavior(tid=1)
    ctx1 = _ctx()
    ctx2 = _ctx()

    _get_reply(behavior, _base_request(PldmControlCmdCodes.SetTID, SetTIDPacket(tid=0x31)), ctx1)
    ctx1_tid = _single_pldm(_get_reply(behavior, _base_request(PldmControlCmdCodes.GetTID), ctx1))
    ctx2_tid = _single_pldm(_get_reply(behavior, _base_request(PldmControlCmdCodes.GetTID), ctx2))

    assert ctx1_tid.getlayer(GetTIDPacket).tid == 0x31
    assert ctx2_tid.getlayer(GetTIDPacket).tid == 1


def test_point_to_point_request_without_smbus_layer_gets_transport_wrapped_reply() -> None:
    behavior = PldmSensorBehavior(sensors={1: SensorDefinition(sensor_id=1, reading=0x44)})
    pkt = _sensor_request(1, smbus=False)

    reply = _get_reply(behavior, pkt, _ctx())
    pldm = _single_pldm(reply, smbus=False)
    transport = TransportHdrPacket(bytes(reply[0]))
    payload = pldm.getlayer(GetSensorReadingPacket)

    assert transport.getlayer(PldmHdrPacket) is not None
    assert transport.dst == 0x20
    assert transport.src == 0x10
    assert pldm.completion_code == CompletionCodes.SUCCESS
    assert payload.presentReading8 == 0x44


def test_numeric_and_state_sensor_pdr_common_headers_round_trip() -> None:
    numeric = NumericSensorPdr(record_handle=0x11, sensor_id=0x22, data_size=GetSensorReadingDataSizeEnum.UINT16)
    state = StateSensorPdr(record_handle=0x33, sensor_id=0x44, possible_states={7: [1, 3, 9]})

    numeric_bytes = numeric.to_bytes()
    state_bytes = state.to_bytes()

    assert _pdr_header(numeric_bytes) == (0x11, 1, 2, 0, len(numeric_bytes) - 10)
    assert _pdr_header(state_bytes) == (0x33, 1, 4, 0, len(state_bytes) - 10)
    assert struct.unpack_from("<H", numeric_bytes, 12)[0] == 0x22
    assert struct.unpack_from("<H", state_bytes, 12)[0] == 0x44


def test_get_pdr_single_shot_small_record_returns_start_and_end() -> None:
    behavior = PldmSensorBehavior(sensors={1: SensorDefinition(sensor_id=1, reading=10)})
    request = _platform_request(
        PldmPlatformMonitoringCmdCodes.GetPDR,
        _pdr_request(0, 0, GetPDRTransferOperation.GET_FIRST_PART, 512),
    )

    pldm = _single_pldm(_get_reply(behavior, request, _ctx()))
    next_record, next_transfer, transfer_flag, record_data, crc = _parse_pdr_response(pldm)

    assert pldm.completion_code == CompletionCodes.SUCCESS
    assert next_record == 0
    assert next_transfer == 0
    assert transfer_flag == GetPDRTransferFlag.START_AND_END
    assert crc == b""
    assert record_data == behavior.profile.pdr_repository.get_record(0)


def test_get_pdr_multi_part_reassembles_record_and_walks_repository() -> None:
    behavior = PldmSensorBehavior(
        sensors={
            1: SensorDefinition(sensor_id=1, reading=10),
            2: SensorDefinition(sensor_id=2, reading=20),
        }
    )
    ctx = _ctx()

    pldm = _single_pldm(
        _get_reply(
            behavior,
            _platform_request(PldmPlatformMonitoringCmdCodes.GetPDR, _pdr_request(0, 0, GetPDRTransferOperation.GET_FIRST_PART, 20)),
            ctx,
        )
    )
    next_record, transfer_handle, transfer_flag, record_data, crc = _parse_pdr_response(pldm)
    assert transfer_flag == GetPDRTransferFlag.START
    assert transfer_handle == 1
    assert crc == b""

    while transfer_handle:
        pldm = _single_pldm(
            _get_reply(
                behavior,
                _platform_request(
                    PldmPlatformMonitoringCmdCodes.GetPDR,
                    _pdr_request(0, transfer_handle, GetPDRTransferOperation.GET_NEXT_PART, 20),
                ),
                ctx,
            )
        )
        next_record, transfer_handle, transfer_flag, chunk, crc = _parse_pdr_response(pldm)
        record_data += chunk
        if transfer_handle:
            assert transfer_flag == GetPDRTransferFlag.MIDDLE
        else:
            assert transfer_flag == GetPDRTransferFlag.END
            assert len(crc) == 4

    assert record_data == behavior.profile.pdr_repository.get_record(0)
    assert next_record == 2

    pldm = _single_pldm(
        _get_reply(
            behavior,
            _platform_request(
                PldmPlatformMonitoringCmdCodes.GetPDR,
                _pdr_request(next_record, 0, GetPDRTransferOperation.GET_FIRST_PART, 512),
            ),
            ctx,
        )
    )
    final_next_record, _, final_flag, final_record, _ = _parse_pdr_response(pldm)
    assert final_flag == GetPDRTransferFlag.START_AND_END
    assert final_record == behavior.profile.pdr_repository.get_record(2)
    assert final_next_record == 0


def test_get_pdr_invalid_record_and_transfer_handles_return_platform_codes() -> None:
    behavior = PldmSensorBehavior(sensors={1: SensorDefinition(sensor_id=1, reading=10)})
    invalid_record = _single_pldm(
        _get_reply(
            behavior,
            _platform_request(
                PldmPlatformMonitoringCmdCodes.GetPDR,
                _pdr_request(0x9999, 0, GetPDRTransferOperation.GET_FIRST_PART, 10),
            ),
            _ctx(),
        )
    )
    invalid_transfer = _single_pldm(
        _get_reply(
            behavior,
            _platform_request(
                PldmPlatformMonitoringCmdCodes.GetPDR,
                _pdr_request(0, 0x9999, GetPDRTransferOperation.GET_NEXT_PART, 10),
            ),
            _ctx(),
        )
    )

    assert invalid_record.completion_code == 0x82
    assert invalid_transfer.completion_code == 0x80


def test_get_pdr_transfer_state_is_isolated_per_endpoint_context() -> None:
    behavior = PldmSensorBehavior(sensors={1: SensorDefinition(sensor_id=1, reading=10)})
    ctx1 = _ctx()
    ctx2 = _ctx()
    request = _platform_request(
        PldmPlatformMonitoringCmdCodes.GetPDR,
        _pdr_request(0, 0, GetPDRTransferOperation.GET_FIRST_PART, 20),
    )

    first_1 = _parse_pdr_response(_single_pldm(_get_reply(behavior, request, ctx1)))
    first_2 = _parse_pdr_response(_single_pldm(_get_reply(behavior, request, ctx2)))
    assert first_1[1] == first_2[1] == 1

    next_request = _platform_request(
        PldmPlatformMonitoringCmdCodes.GetPDR,
        _pdr_request(0, 1, GetPDRTransferOperation.GET_NEXT_PART, 512),
    )
    next_2 = _parse_pdr_response(_single_pldm(_get_reply(behavior, next_request, ctx2)))
    next_1 = _parse_pdr_response(_single_pldm(_get_reply(behavior, next_request, ctx1)))

    assert first_1[3] + next_1[3] == behavior.profile.pdr_repository.get_record(0)
    assert first_2[3] + next_2[3] == behavior.profile.pdr_repository.get_record(0)


def test_pdrs_are_derived_from_configured_sensors_and_match_readings() -> None:
    behavior = PldmSensorBehavior(
        sensors={
            7: SensorDefinition(sensor_id=7, reading=0x55),
            8: SensorDefinition(sensor_id=8, reading=0x66),
        }
    )
    ctx = _ctx()

    pdr = _parse_pdr_response(
        _single_pldm(
            _get_reply(
                behavior,
                _platform_request(
                    PldmPlatformMonitoringCmdCodes.GetPDR,
                    _pdr_request(0, 0, GetPDRTransferOperation.GET_FIRST_PART, 512),
                ),
                ctx,
            )
        )
    )[3]
    reading = _single_pldm(_get_reply(behavior, _sensor_request(7), ctx)).getlayer(GetSensorReadingPacket)

    assert struct.unpack_from("<H", pdr, 12)[0] == 7
    assert reading.presentReading8 == 0x55


def test_numeric_sensor_pdr_without_sensor_definition_is_synthesized() -> None:
    """A requester enables sensors it discovered from GetPDR, so advertised IDs must be servable."""
    sensor_id = 0x2201
    record = NumericSensorPdr(
        record_handle=0x31,
        sensor_id=sensor_id,
        data_size=GetSensorReadingDataSizeEnum.UINT16,
        entity_type=0x1234,
        entity_instance=3,
        container_id=0x42,
        base_unit=5,
        max_readable=400,
        min_readable=100,
        range_field_support=0b01111111,
        nominal_value=250,
        normal_max=300,
        normal_min=200,
        warning_high=350,
        warning_low=150,
        critical_high=390,
        critical_low=110,
    )
    behavior = PldmSensorBehavior(pdr_repository=PdrRepository([record]))
    ctx = _ctx()

    sensor = behavior.profile.sensors[sensor_id]
    enable = _single_pldm(_get_reply(behavior, _set_numeric_sensor_enable_request(sensor_id), ctx))
    reading = _single_pldm(_get_reply(behavior, _sensor_request(sensor_id), ctx)).getlayer(GetSensorReadingPacket)

    assert sensor.data_size == GetSensorReadingDataSizeEnum.UINT16
    assert (sensor.entity_type, sensor.entity_instance, sensor.container_id, sensor.base_unit) == (0x1234, 3, 0x42, 5)
    assert (sensor.warning_high, sensor.warning_low, sensor.critical_high, sensor.critical_low) == (350, 150, 390, 110)
    assert enable.completion_code == CompletionCodes.SUCCESS
    assert reading.sensorDataSize == GetSensorReadingDataSizeEnum.UINT16
    assert reading.presentReading16 == 250


def test_synthesized_numeric_sensor_reading_uses_declared_range_without_nominal_value() -> None:
    record = NumericSensorPdr(
        record_handle=0x32,
        sensor_id=0x2202,
        data_size=GetSensorReadingDataSizeEnum.UINT16,
        min_readable=1000,
        max_readable=2000,
        range_field_support=0,
    )
    behavior = PldmSensorBehavior(pdr_repository=PdrRepository([record]))

    reading = _single_pldm(_get_reply(behavior, _sensor_request(0x2202), _ctx())).getlayer(GetSensorReadingPacket)

    assert 1000 <= reading.presentReading16 <= 2000


def test_explicit_sensor_definition_is_not_overridden_by_pdr_synthesis() -> None:
    """Captured models may patch selected sensor values; PDR synthesis must only fill gaps."""
    sensor_id = 0x2203
    record = NumericSensorPdr(
        record_handle=0x33,
        sensor_id=sensor_id,
        data_size=GetSensorReadingDataSizeEnum.UINT16,
        range_field_support=0b01001001,
        nominal_value=500,
        warning_high=600,
        critical_high=700,
    )
    explicit = SensorDefinition(
        sensor_id=sensor_id,
        reading=7,
        data_size=GetSensorReadingDataSizeEnum.UINT8,
        warning_high=9,
    )
    behavior = PldmSensorBehavior(sensors={sensor_id: explicit}, pdr_repository=PdrRepository([record]))
    sensor = behavior.profile.sensors[sensor_id]

    assert sensor.data_size == GetSensorReadingDataSizeEnum.UINT8
    assert sensor.warning_high == 9
    assert sensor.next_reading() == 7


def test_state_sensor_pdr_without_sensor_definition_is_synthesized() -> None:
    record = StateSensorPdr(
        record_handle=0x34,
        sensor_id=0x2204,
        entity_type=0x2222,
        entity_instance=4,
        container_id=0x44,
    )
    behavior = PldmSensorBehavior(pdr_repository=PdrRepository([record]))

    sensor = behavior.profile.sensors[0x2204]

    assert (sensor.entity_type, sensor.entity_instance, sensor.container_id) == (0x2222, 4, 0x44)


def test_set_state_sensor_enables_and_get_readings_match_wire_layouts() -> None:
    record = StateSensorPdr(record_handle=1, sensor_id=1, possible_states={0: [0x0A]})
    behavior = PldmSensorBehavior(pdr_repository=PdrRepository([record]))
    ctx = _ctx()
    enable_request = _set_state_sensor_enables_request(1)
    reading_request = _get_state_sensor_readings_request(1)

    assert _raw_payload(enable_request.getlayer(PldmHdrPacket)) == bytes.fromhex("0100010000")
    assert _raw_payload(reading_request.getlayer(PldmHdrPacket)) == bytes.fromhex("01000000")

    enable = _single_pldm(_get_reply(behavior, enable_request, ctx))
    reading = _single_pldm(_get_reply(behavior, reading_request, ctx))

    assert enable.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(enable) == b""
    assert reading.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(reading) == bytes.fromhex("01000a000a")


def test_composite_state_sensor_enables_are_retained_and_states_advance() -> None:
    """Composite counts and state values must come from the PDR, not a one-field shortcut."""
    record = StateSensorPdr(record_handle=1, sensor_id=1, possible_states={0: [1, 2], 1: [3, 4]})
    behavior = PldmSensorBehavior(pdr_repository=PdrRepository([record]))
    ctx = _ctx()
    request = _set_state_sensor_enables_request(
        1,
        struct.pack(
            "<HBBBBB",
            1,
            2,
            GetSensorReadingOperationalStateEnum.DISABLED,
            GetSensorReadingEventMsgEnableEnum.EVENTS_ENABLED,
            GetSensorReadingOperationalStateEnum.ENABLED,
            GetSensorReadingEventMsgEnableEnum.NO_EVENT_GENERATION,
        ),
    )

    enable = _single_pldm(_get_reply(behavior, request, ctx))
    first = _single_pldm(_get_reply(behavior, _get_state_sensor_readings_request(1), ctx))
    second = _single_pldm(_get_reply(behavior, _get_state_sensor_readings_request(1), ctx))
    state_sensor = behavior._state(ctx)["sensors"][1].state_sensor

    assert enable.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(first) == bytes([2, 1, 1, 0, 1, 0, 3, 0, 3])
    assert _raw_payload(second) == bytes([2, 1, 2, 1, 2, 0, 4, 3, 4])
    assert state_sensor is not None
    assert state_sensor.event_message_enables == [
        GetSensorReadingEventMsgEnableEnum.EVENTS_ENABLED,
        GetSensorReadingEventMsgEnableEnum.NO_EVENT_GENERATION,
    ]


@pytest.mark.parametrize(
    ("pkt", "completion_code"),
    [
        (_set_state_sensor_enables_request(99), 0x80),
        (_get_state_sensor_readings_request(99), 0x80),
        (_set_state_sensor_enables_request(1, b"\x01\x00"), CompletionCodes.ERROR_INVALID_LENGTH),
        (_get_state_sensor_readings_request(1, b"\x01\x00\x00"), CompletionCodes.ERROR_INVALID_LENGTH),
    ],
)
def test_state_sensor_commands_reject_unknown_ids_and_short_requests(pkt, completion_code: int) -> None:
    behavior = PldmSensorBehavior(pdr_repository=PdrRepository([StateSensorPdr(record_handle=1, sensor_id=1)]))

    pldm = _single_pldm(_get_reply(behavior, pkt, _ctx()))

    assert pldm.completion_code == completion_code


def test_numeric_effecter_enable_and_get_value_match_wire_layouts() -> None:
    behavior = PldmSensorBehavior(
        pdr_repository=PdrRepository(
            [
                NumericEffecterPdr(
                    record_handle=1,
                    effecter_id=0x1002,
                    effecter_data_size=GetSensorReadingDataSizeEnum.UINT32,
                )
            ]
        )
    )
    ctx = _ctx()
    enable_request = _set_numeric_effecter_enable_request(0x1002, operational_state=1)
    get_request = _get_numeric_effecter_value_request(0x1002)

    assert _raw_payload(enable_request.getlayer(PldmHdrPacket)) == bytes.fromhex("021001")
    assert _raw_payload(get_request.getlayer(PldmHdrPacket)) == bytes.fromhex("0210")

    enable = _single_pldm(_get_reply(behavior, enable_request, ctx))
    value = _single_pldm(_get_reply(behavior, get_request, ctx))

    assert enable.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(enable) == b""
    assert value.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(value) == bytes.fromhex("04010000000000000000")


def test_set_numeric_effecter_value_is_reported_by_get_value() -> None:
    """SetNumericEffecterValue is enough for requesters to observe their own write."""
    behavior = PldmSensorBehavior(
        pdr_repository=PdrRepository(
            [
                NumericEffecterPdr(
                    record_handle=1,
                    effecter_id=0x1002,
                    effecter_data_size=GetSensorReadingDataSizeEnum.UINT32,
                )
            ]
        )
    )
    ctx = _ctx()
    set_request = _set_numeric_effecter_value_request(0x1002, GetSensorReadingDataSizeEnum.UINT32, 0x12345678)

    assert _raw_payload(set_request.getlayer(PldmHdrPacket)) == bytes.fromhex("02100478563412")

    set_value = _single_pldm(_get_reply(behavior, set_request, ctx))
    value = _single_pldm(_get_reply(behavior, _get_numeric_effecter_value_request(0x1002), ctx))

    assert set_value.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(set_value) == b""
    assert value.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(value) == bytes.fromhex("04007856341278563412")


@pytest.mark.parametrize(
    ("data_size", "set_value", "expected"),
    [
        (GetSensorReadingDataSizeEnum.UINT8, 0xFE, bytes.fromhex("0000fefe")),
        (GetSensorReadingDataSizeEnum.UINT16, 0x1234, bytes.fromhex("020034123412")),
        (GetSensorReadingDataSizeEnum.SINT16, -7, bytes.fromhex("0300f9fff9ff")),
    ],
)
def test_numeric_effecter_data_size_widths_are_honored(
    data_size: GetSensorReadingDataSizeEnum,
    set_value: int,
    expected: bytes,
) -> None:
    behavior = PldmSensorBehavior(
        pdr_repository=PdrRepository([NumericEffecterPdr(record_handle=1, effecter_id=1, effecter_data_size=data_size)])
    )
    ctx = _ctx()

    set_reply = _single_pldm(_get_reply(behavior, _set_numeric_effecter_value_request(1, data_size, set_value), ctx))
    get_reply = _single_pldm(_get_reply(behavior, _get_numeric_effecter_value_request(1), ctx))

    assert set_reply.completion_code == CompletionCodes.SUCCESS
    assert get_reply.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(get_reply) == expected


def test_numeric_effecter_pdr_without_effecter_definition_is_synthesized() -> None:
    """Effecters advertised by a PDR repository must be servable even without explicit configuration."""
    effecter_id = 0x2201
    record = NumericEffecterPdr(
        record_handle=0x41,
        effecter_id=effecter_id,
        effecter_data_size=GetSensorReadingDataSizeEnum.UINT16,
        entity_type=0x1234,
        entity_instance=3,
        container_id=0x42,
        base_unit=5,
        max_settable=400,
        min_settable=100,
        range_field_support=0b00000001,
        nominal_value=250,
    )
    behavior = PldmSensorBehavior(pdr_repository=PdrRepository([record]))

    effecter = behavior.profile.effecters[effecter_id]
    value = _single_pldm(_get_reply(behavior, _get_numeric_effecter_value_request(effecter_id), _ctx()))

    assert effecter.data_size == GetSensorReadingDataSizeEnum.UINT16
    assert (effecter.entity_type, effecter.entity_instance, effecter.container_id, effecter.base_unit) == (
        0x1234,
        3,
        0x42,
        5,
    )
    assert (effecter.min_settable, effecter.max_settable) == (100, 400)
    assert value.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(value) == bytes.fromhex("0200fa00fa00")


def test_state_effecter_enables_and_get_states_match_wire_layouts() -> None:
    behavior = PldmSensorBehavior(
        pdr_repository=PdrRepository([StateEffecterPdr(record_handle=1, effecter_id=1, possible_states={0: [0]})])
    )
    ctx = _ctx()
    enable_request = _set_state_effecter_enables_request(1, bytes.fromhex("0100010101"))
    get_request = _get_state_effecter_states_request(1)

    assert _raw_payload(enable_request.getlayer(PldmHdrPacket)) == bytes.fromhex("0100010101")
    assert _raw_payload(get_request.getlayer(PldmHdrPacket)) == bytes.fromhex("0100")

    enable = _single_pldm(_get_reply(behavior, enable_request, ctx))
    states = _single_pldm(_get_reply(behavior, get_request, ctx))

    assert enable.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(enable) == b""
    assert states.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(states) == bytes.fromhex("01010000")


def test_set_state_effecter_states_is_reported_by_get_states() -> None:
    """State effecter writes complete synchronously, so pending and present states match."""
    behavior = PldmSensorBehavior(
        pdr_repository=PdrRepository([StateEffecterPdr(record_handle=1, effecter_id=1, possible_states={0: [0, 2]})])
    )
    ctx = _ctx()
    set_request = _set_state_effecter_states_request(1, bytes.fromhex("0100010102"))

    assert _raw_payload(set_request.getlayer(PldmHdrPacket)) == bytes.fromhex("0100010102")

    set_states = _single_pldm(_get_reply(behavior, set_request, ctx))
    states = _single_pldm(_get_reply(behavior, _get_state_effecter_states_request(1), ctx))

    assert set_states.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(set_states) == b""
    assert states.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(states) == bytes.fromhex("01000202")


def test_composite_state_effecter_states_round_trip() -> None:
    """Composite effecters must retain each field instead of reporting one shared state."""
    behavior = PldmSensorBehavior(
        pdr_repository=PdrRepository(
            [StateEffecterPdr(record_handle=1, effecter_id=1, possible_states={0: [1, 2], 1: [3, 4]})]
        )
    )
    ctx = _ctx()
    request = _set_state_effecter_states_request(1, bytes.fromhex("01000201020104"))

    set_states = _single_pldm(_get_reply(behavior, request, ctx))
    states = _single_pldm(_get_reply(behavior, _get_state_effecter_states_request(1), ctx))

    assert set_states.completion_code == CompletionCodes.SUCCESS
    assert states.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(states) == bytes([2, 0, 2, 2, 0, 4, 4])


def test_state_effecter_pdr_without_effecter_definition_is_synthesized() -> None:
    record = StateEffecterPdr(
        record_handle=0x42,
        effecter_id=0x2202,
        entity_type=0x2222,
        entity_instance=4,
        container_id=0x44,
        possible_states={0: [1, 2]},
    )
    behavior = PldmSensorBehavior(pdr_repository=PdrRepository([record]))

    effecter = behavior.profile.effecters[0x2202]
    states = _single_pldm(_get_reply(behavior, _get_state_effecter_states_request(0x2202), _ctx()))

    assert (effecter.entity_type, effecter.entity_instance, effecter.container_id) == (0x2222, 4, 0x44)
    assert states.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(states) == bytes([1, 0, 1, 1])


@pytest.mark.parametrize(
    ("pkt", "completion_code"),
    [
        (_set_numeric_effecter_enable_request(99), 0x80),
        (_set_numeric_effecter_value_request(99, GetSensorReadingDataSizeEnum.UINT8, 1), 0x80),
        (_get_numeric_effecter_value_request(99), 0x80),
        (_set_state_effecter_enables_request(99), 0x80),
        (_set_state_effecter_states_request(99), 0x80),
        (_get_state_effecter_states_request(99), 0x80),
        (
            _platform_request(PldmPlatformMonitoringCmdCodes.SetNumericEffecterEnable, Raw(b"\x01\x00")),
            CompletionCodes.ERROR_INVALID_LENGTH,
        ),
        (
            _platform_request(PldmPlatformMonitoringCmdCodes.SetNumericEffecterValue, Raw(b"\x01\x00")),
            CompletionCodes.ERROR_INVALID_LENGTH,
        ),
        (
            _platform_request(PldmPlatformMonitoringCmdCodes.GetNumericEffecterValue, Raw(b"\x01")),
            CompletionCodes.ERROR_INVALID_LENGTH,
        ),
        (
            _platform_request(PldmPlatformMonitoringCmdCodes.SetStateEffecterEnables, Raw(b"\x01\x00")),
            CompletionCodes.ERROR_INVALID_LENGTH,
        ),
        (
            _platform_request(PldmPlatformMonitoringCmdCodes.SetStateEffecterStates, Raw(b"\x01\x00")),
            CompletionCodes.ERROR_INVALID_LENGTH,
        ),
        (
            _platform_request(PldmPlatformMonitoringCmdCodes.GetStateEffecterStates, Raw(b"\x01")),
            CompletionCodes.ERROR_INVALID_LENGTH,
        ),
    ],
)
def test_effecter_commands_reject_unknown_ids_and_short_requests(pkt, completion_code: int) -> None:
    behavior = PldmSensorBehavior(
        pdr_repository=PdrRepository(
            [
                NumericEffecterPdr(record_handle=1, effecter_id=1),
                StateEffecterPdr(record_handle=2, effecter_id=2),
            ]
        )
    )

    pldm = _single_pldm(_get_reply(behavior, pkt, _ctx()))

    assert pldm.completion_code == completion_code


def test_opaque_effecter_pdr_is_skipped_without_error() -> None:
    behavior = PldmSensorBehavior(
        pdr_repository=PdrRepository([OpaquePdr(PdrHeader(1, 1, PDR_TYPE_NUMERIC_EFFECTER, 0, 0), b"")])
    )

    pldm = _single_pldm(_get_reply(behavior, _get_numeric_effecter_value_request(1), _ctx()))

    assert behavior.profile.effecters == {}
    assert pldm.completion_code == 0x80  # PLDM_PLATFORM_INVALID_EFFECTER_ID


def test_get_terminus_uid_returns_profile_uuid_and_matches_wire_layout() -> None:
    terminus_uid = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
    behavior = PldmSensorBehavior(terminus_uid=terminus_uid)
    request = _platform_request(PldmPlatformMonitoringCmdCodes.GetTerminusUID)

    assert _raw_payload(request.getlayer(PldmHdrPacket)) == b""

    pldm = _single_pldm(_get_reply(behavior, request, _ctx()))

    assert pldm.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(pldm) == terminus_uid.bytes


def test_get_terminus_uid_falls_back_to_zero_when_no_uuid_is_set() -> None:
    ctx = _ctx()
    ctx.endpoint_uuid = None

    pldm = _single_pldm(
        _get_reply(PldmSensorBehavior(), _platform_request(PldmPlatformMonitoringCmdCodes.GetTerminusUID), ctx)
    )

    assert pldm.completion_code == CompletionCodes.SUCCESS
    assert _raw_payload(pldm) == b"\x00" * 16


def test_opaque_pdr_is_skipped_by_sensor_synthesis() -> None:
    raw = struct.pack("<IBBHH", 0xABC, 1, 0x99, 0, 1) + b"\x00"
    opaque = decode_pdr(raw)

    behavior = PldmSensorBehavior(pdr_repository=PdrRepository([opaque]))

    assert behavior.profile.sensors == {}


def test_warning_fires_when_defined_sensor_has_no_pdr(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="pymctp.automaton.behaviors.pldm_responder")

    PldmSensorBehavior(sensors={0x2205: SensorDefinition(sensor_id=0x2205, reading=1)}, pdr_repository=PdrRepository())

    assert "PLDM sensor/PDR mismatch" in caplog.text
    assert "sensor definition(s) without PDRs: [8709]" in caplog.text


def test_sensor_derived_pdr_path_is_unchanged_and_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    """When no repository is supplied, sensors still generate their own PDR repository."""
    caplog.set_level(logging.WARNING, logger="pymctp.automaton.behaviors.pldm_responder")

    behavior = PldmSensorBehavior(sensors={7: SensorDefinition(sensor_id=7, reading=0x55)})
    pdr = behavior.profile.pdr_repository.get_record(0)

    assert pdr is not None
    assert struct.unpack_from("<H", pdr, 12)[0] == 7
    assert "PLDM sensor/PDR mismatch" not in caplog.text


def test_set_event_receiver_and_poll_for_platform_event_message() -> None:
    behavior = PldmSensorBehavior(sensors={1: SensorDefinition(sensor_id=1, reading=10)})
    ctx = _ctx()
    set_receiver = _platform_request(PldmPlatformMonitoringCmdCodes.SetEventReceiver, b"\x02\x00\x20\x00\x00")

    pldm = _single_pldm(_get_reply(behavior, set_receiver, ctx))
    queued = behavior.queue_event(PlatformEventMsgClasses.PLDM_SENSOR_EVENT, b"\x01\x02\x03", ctx=ctx)
    poll = _platform_request(
        PldmPlatformMonitoringCmdCodes.PollForPlatformEventMessage,
        PollForPlatformEventMsgPacket(
            formatVersion=1,
            TransferOperationFlag=PollForPlatformEventOperation.GET_FIRST_PART,
            DataTransferHandle=0,
            eventIDToAcknowledge=0,
        ),
    )

    event = _single_pldm(_get_reply(behavior, poll, ctx)).getlayer(PollForPlatformEventMsgPacket)
    drained = _single_pldm(_get_reply(behavior, poll, ctx)).getlayer(PollForPlatformEventMsgPacket)

    assert pldm.completion_code == CompletionCodes.SUCCESS
    assert ctx.msg_type_context[behavior.name]["event_receiver"]["eid"] == 0x20
    assert event.eventID == queued.event_id
    assert event.TransferFlag == PollForPlatformEventTransferFlag.START_AND_END
    assert event.eventData == [1, 2, 3]
    assert drained.eventID == 0


def test_ramping_sensor_threshold_crossing_queues_event() -> None:
    behavior = PldmSensorBehavior(
        sensors={
            1: SensorDefinition(
                sensor_id=1,
                simulation=SensorSimulation(minimum=0, maximum=20, step=10, warning_high=10),
            )
        }
    )
    ctx = _ctx()

    _get_reply(behavior, _sensor_request(1), ctx)
    _get_reply(behavior, _sensor_request(1), ctx)
    event = ctx.msg_type_context[behavior.name]["event_queue"][0]

    assert event.event_class == PlatformEventMsgClasses.PLDM_SENSOR_EVENT
    assert struct.unpack_from("<H", event.event_data)[0] == 1
    assert event.event_data[3] == GetSensorReadingPresentEnum.UPPERWARNING


class _FakeSession:
    def __init__(self) -> None:
        self.calls = []

    def sndrcv_mctp_msg(self, pkt, **kwargs):
        self.calls.append((pkt, kwargs))
        return None


class _FakeAM:
    def __init__(self) -> None:
        self.session = _FakeSession()


def test_platform_event_emission_is_off_by_default() -> None:
    behavior = PldmSensorBehavior()
    am = _FakeAM()
    ctx = _ctx()

    behavior.on_start(am, ctx)
    behavior.queue_event(PlatformEventMsgClasses.PLDM_SENSOR_EVENT, b"\x00", ctx=ctx)

    assert behavior.event_thread_running is False
    assert am.session.calls == []


def test_platform_event_emission_sends_after_receiver_is_set_when_enabled() -> None:
    behavior = PldmSensorBehavior(emit_events=True)
    am = _FakeAM()
    ctx = _ctx()
    behavior.on_start(am, ctx)
    _get_reply(behavior, _platform_request(PldmPlatformMonitoringCmdCodes.SetEventReceiver, b"\x01\x00\x20\x00\x00"), ctx)

    behavior.queue_event(PlatformEventMsgClasses.PLDM_SENSOR_EVENT, b"\x01\x02", ctx=ctx)
    deadline = time.monotonic() + 0.2
    while not am.session.calls and time.monotonic() < deadline:
        time.sleep(0.005)
    behavior.on_stop(am, ctx)

    assert behavior.event_thread_running is False
    assert len(am.session.calls) == 1
    _, kwargs = am.session.calls[0]
    assert kwargs["dst_eid"] == 0x20
    assert kwargs["msg_type"] == MsgTypes.PLDM
    assert kwargs["threaded"] is True


def test_large_pdr_response_is_fragmented_and_reassembles() -> None:
    large_pdr = StateSensorPdr(
        record_handle=1,
        sensor_id=1,
        possible_states={state_set: range(64) for state_set in range(80)},
    )
    behavior = PldmSensorBehavior(pdr_repository=PdrRepository([large_pdr]))
    reply = _get_reply(
        behavior,
        _platform_request(
            PldmPlatformMonitoringCmdCodes.GetPDR,
            _pdr_request(0, 0, GetPDRTransferOperation.GET_FIRST_PART, 4096),
        ),
        _ctx(),
    )

    assert len(reply) > 1
    pldm = _pldm_from_reassembled(reply)
    next_record, next_transfer, transfer_flag, record_data, _ = _parse_pdr_response(pldm)
    assert next_record == 0
    assert next_transfer == 0
    assert transfer_flag == GetPDRTransferFlag.START_AND_END
    assert record_data == large_pdr.to_bytes()


class TestSetNumericSensorEnable:
    """DSP0248 SetNumericSensorEnable (0x10).

    The requester enables every sensor before it starts polling. openbmc's
    pldmd aborts sensor discovery when this is refused ("SetNumericSensorEnable:
    Invalid completion code. CC: 5" then "Sensor Handler Init failed"), even
    though GetSensorReading on its own works fine.
    """

    @staticmethod
    def _enable(sensor_id: int, operational_state: int = 0, event_message_enable: int = 0):
        return _platform_request(
            PldmPlatformMonitoringCmdCodes.SetNumericSensorEnable,
            Raw(struct.pack("<HBB", sensor_id, operational_state, event_message_enable)),
        )

    def _behavior(self):
        return PldmSensorBehavior(
            sensors={
                1: SensorDefinition(sensor_id=1, reading=40),
                2: SensorDefinition(sensor_id=2, reading=41),
            }
        )

    @pytest.mark.parametrize("sensor_id", [1, 2])
    def test_enabling_a_known_sensor_succeeds(self, sensor_id: int) -> None:
        pldm = _single_pldm(_get_reply(self._behavior(), self._enable(sensor_id), _ctx()))

        assert pldm.completion_code == CompletionCodes.SUCCESS
        assert _raw_payload(pldm) == b""

    def test_it_is_advertised_by_get_pldm_commands(self) -> None:
        """An unadvertised command is never called, so discovery would still stall."""
        behavior = PldmBaseBehavior()
        pkt = _base_request(
            PldmControlCmdCodes.GetPLDMCommands,
            GetPLDMCommandsPacket(PLDMType=PldmTypeCodes.PLATFORM_MONITORING, Version=0xF1F0F000),
        )

        pldm = _single_pldm(_get_reply(behavior, pkt, _ctx()))
        payload = pldm.getlayer(GetPLDMCommandsPacket)

        command = int(PldmPlatformMonitoringCmdCodes.SetNumericSensorEnable)
        assert payload.cmds[command // 8] & (1 << (command % 8))

    def test_the_requested_state_is_retained(self) -> None:
        behavior = self._behavior()
        ctx = _ctx()

        reply = _single_pldm(_get_reply(behavior, self._enable(1, operational_state=1, event_message_enable=2), ctx))
        assert reply.completion_code == CompletionCodes.SUCCESS

        sensor = behavior._state(ctx)["sensors"][1]
        assert sensor.operational_state == GetSensorReadingOperationalStateEnum.DISABLED
        assert sensor.event_message_enable == GetSensorReadingEventMsgEnableEnum.EVENTS_ENABLED

    def test_unknown_sensor_id_is_rejected(self) -> None:
        pldm = _single_pldm(_get_reply(self._behavior(), self._enable(99), _ctx()))
        assert pldm.completion_code == 0x80  # PLDM_PLATFORM_INVALID_SENSOR_ID

    def test_short_request_is_rejected(self) -> None:
        request = _platform_request(
            PldmPlatformMonitoringCmdCodes.SetNumericSensorEnable, Raw(struct.pack("<H", 1))
        )
        pldm = _single_pldm(_get_reply(self._behavior(), request, _ctx()))
        assert pldm.completion_code == CompletionCodes.ERROR_INVALID_LENGTH

    def test_unsupported_event_generation_is_rejected(self) -> None:
        pldm = _single_pldm(_get_reply(self._behavior(), self._enable(1, event_message_enable=0x63), _ctx()))
        assert pldm.completion_code == 0x82  # PLDM_PLATFORM_EVENT_GENERATION_NOT_SUPPORTED

    def test_invalid_operational_state_is_rejected(self) -> None:
        pldm = _single_pldm(_get_reply(self._behavior(), self._enable(1, operational_state=0x63), _ctx()))
        assert pldm.completion_code == CompletionCodes.ERROR_INVALID_DATA
