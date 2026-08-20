# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the PLDM responder behaviors."""

from __future__ import annotations

import struct
import time

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
    GetSensorReadingPresentEnum,
    PlatformEventMsgClasses,
    PollForPlatformEventMsgPacket,
    PollForPlatformEventOperation,
    PollForPlatformEventTransferFlag,
    PldmPlatformMonitoringCmdCodes,
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
    for command in (
        PldmPlatformMonitoringCmdCodes.SetEventReceiver,
        PldmPlatformMonitoringCmdCodes.PlatformEventMessage,
        PldmPlatformMonitoringCmdCodes.PollForPlatformEventMessage,
        PldmPlatformMonitoringCmdCodes.EventMessageSupported,
        PldmPlatformMonitoringCmdCodes.EventMessageBufferSize,
        PldmPlatformMonitoringCmdCodes.GetSensorReading,
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
    assert bytes(payload.payload) == b"\x00\xf0\xf0\xf1"


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
