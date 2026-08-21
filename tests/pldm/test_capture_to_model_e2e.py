# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""End-to-end acceptance tests for capture-generated PLDM PDR models."""

from __future__ import annotations

import binascii
import json
import struct
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from click.testing import CliRunner
from scapy.compat import raw
from scapy.packet import Raw
from scapy.plist import PacketList

from pymctp.automaton.behaviors.pldm_responder import (
    GetPDRTransferFlag,
    GetPDRTransferOperation,
    NumericSensorPdr,
    PldmSensorBehavior,
    SensorSimulation,
)
from pymctp.automaton.roles import get_behaviors_for_roles
from pymctp.cli.main import cli
from pymctp.layers.mctp.pldm import GetSensorReadingPacket, PldmHdr, PldmHdrPacket
from pymctp.layers.mctp.pldm.pdr import (
    PDR_TYPE_NUMERIC_SENSOR,
    PDR_TYPE_SENSOR_AUXILIARY_NAMES,
    PdrNameString,
    SensorAuxiliaryNamesEntry,
    SensorAuxiliaryNamesPdr,
)
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import (
    GetSensorReadingDataSizeEnum,
    PldmPlatformMonitoringCmdCodes,
)
from pymctp.layers.mctp.pldm.types import CompletionCodes, PldmControlCmdCodes, PldmTypeCodes
from pymctp.layers.mctp.transport import SmbusTransport, TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import EndpointContext, MsgTypes, Smbus7bitAddress


REQUESTER_EID = 0x20
TERMINUS_EID = 0x11
REQUESTER_PHY = 0x20
TERMINUS_PHY = 0x10
TAG = 3

SENSOR_WITH_THRESHOLDS = 0x1001
SENSOR_WITHOUT_THRESHOLDS = 0x1002

PDR_TYPE_NUMERIC_EFFECTER = 9


def _ctx() -> EndpointContext:
    return EndpointContext(
        physical_address=Smbus7bitAddress(TERMINUS_PHY),
        assigned_eid=TERMINUS_EID,
        mtu_size=31,
        supported_msg_types=[MsgTypes.CTRL, MsgTypes.PLDM],
    )


def _write_capture(path: Path, packets: Iterable[object]) -> None:
    lines: list[str] = []
    for index, packet in enumerate(packets):
        transport = packet.getlayer(TransportHdrPacket)
        assert transport is not None
        packet_bytes = raw(transport)
        for offset in range(0, len(packet_bytes), 16):
            timestamp = f"12:00:{index % 60:02d}.{index:06d}" if offset == 0 else "        "
            lines.append(f"{timestamp} 0x{offset:04x}:  {packet_bytes[offset : offset + 16].hex()}  synthetic\n")
    path.write_text("".join(lines), encoding="utf-8")


def _wire_packet(
    *,
    src: int,
    dst: int,
    to: bool,
    payload: bytes,
    som: bool = True,
    eom: bool = True,
    pkt_seq: int = 0,
):
    transport = TransportHdr(
        msg_type=MsgTypes.PLDM,
        dst=dst,
        src=src,
        som=som,
        eom=eom,
        pkt_seq=pkt_seq,
        to=to,
        tag=TAG,
    ) / Raw(payload)
    smbus = SmbusTransport(
        dst_addr=Smbus7bitAddress(TERMINUS_PHY if to else REQUESTER_PHY),
        src_addr=Smbus7bitAddress(REQUESTER_PHY if to else TERMINUS_PHY),
        load=transport,
    )
    return SmbusTransport(bytes(smbus))


def _pldm_bytes(
    *,
    rq: bool,
    pldm_type: int,
    cmd_code: int,
    instance_id: int,
    completion_code: int = CompletionCodes.SUCCESS,
    payload: bytes = b"",
) -> bytes:
    pldm = PldmHdr(
        rq=rq,
        instance_id=instance_id,
        pldm_type=pldm_type,
        cmd_code=cmd_code,
        completion_code=None if rq else completion_code,
    )
    if payload:
        pldm /= Raw(payload)
    return raw(pldm)


def _request(
    payload: bytes,
    *,
    pldm_type: int = PldmTypeCodes.PLATFORM_MONITORING,
    cmd_code: int = PldmPlatformMonitoringCmdCodes.GetPDR,
    instance_id: int,
):
    return _wire_packet(
        src=REQUESTER_EID,
        dst=TERMINUS_EID,
        to=True,
        payload=_pldm_bytes(
            rq=True,
            pldm_type=pldm_type,
            cmd_code=cmd_code,
            instance_id=instance_id,
            payload=payload,
        ),
    )


def _response(
    payload: bytes,
    *,
    pldm_type: int = PldmTypeCodes.PLATFORM_MONITORING,
    cmd_code: int = PldmPlatformMonitoringCmdCodes.GetPDR,
    instance_id: int,
):
    return _wire_packet(
        src=TERMINUS_EID,
        dst=REQUESTER_EID,
        to=False,
        payload=_pldm_bytes(
            rq=False,
            pldm_type=pldm_type,
            cmd_code=cmd_code,
            instance_id=instance_id,
            payload=payload,
        ),
        pkt_seq=1,
    )


def _fragmented_response(payload: bytes, *, instance_id: int) -> list[object]:
    pldm = _pldm_bytes(
        rq=False,
        pldm_type=PldmTypeCodes.PLATFORM_MONITORING,
        cmd_code=PldmPlatformMonitoringCmdCodes.GetPDR,
        instance_id=instance_id,
        payload=payload,
    )
    chunks = [pldm[:5], pldm[5:28], pldm[28:]]
    return [
        _wire_packet(src=TERMINUS_EID, dst=REQUESTER_EID, to=False, payload=chunks[0], som=True, eom=False, pkt_seq=1),
        _wire_packet(src=TERMINUS_EID, dst=REQUESTER_EID, to=False, payload=chunks[1], som=False, eom=False, pkt_seq=2),
        _wire_packet(src=TERMINUS_EID, dst=REQUESTER_EID, to=False, payload=chunks[2], som=False, eom=True, pkt_seq=3),
    ]


def _get_pdr_request(
    record_handle: int,
    *,
    data_transfer_handle: int = 0,
    operation: GetPDRTransferOperation = GetPDRTransferOperation.GET_FIRST_PART,
    request_count: int = 0xFFFF,
) -> bytes:
    return struct.pack("<IIBHH", record_handle, data_transfer_handle, int(operation), request_count, 0)


def _get_pdr_response(
    record_data: bytes,
    *,
    next_record_handle: int,
    next_data_transfer_handle: int = 0,
    transfer_flag: GetPDRTransferFlag = GetPDRTransferFlag.START_AND_END,
    crc: bytes = b"",
) -> bytes:
    return (
        struct.pack("<IIBH", next_record_handle, next_data_transfer_handle, int(transfer_flag), len(record_data))
        + record_data
        + crc
    )


def _get_tid_exchange() -> list[object]:
    return [
        _request(b"", pldm_type=PldmTypeCodes.CONTROL, cmd_code=PldmControlCmdCodes.GetTID, instance_id=1),
        _response(b"\x01", pldm_type=PldmTypeCodes.CONTROL, cmd_code=PldmControlCmdCodes.GetTID, instance_id=1),
    ]


def _repository_info_exchange(records: list[bytes]) -> list[object]:
    payload = (
        bytes([0])
        + bytes(range(13))
        + bytes(range(13, 26))
        + struct.pack("<IIIB", len(records), sum(len(record) for record in records), max(map(len, records)), 0)
    )
    return [
        _request(b"", cmd_code=PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo, instance_id=2),
        _response(payload, cmd_code=PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo, instance_id=2),
    ]


def _single_pdr_exchange(record: bytes, *, requested_handle: int, next_handle: int, instance_id: int) -> list[object]:
    return [
        _request(_get_pdr_request(requested_handle), instance_id=instance_id),
        _response(_get_pdr_response(record, next_record_handle=next_handle), instance_id=instance_id),
    ]


def _multipart_fragmented_pdr_exchange(record: bytes, *, requested_handle: int, next_handle: int) -> list[object]:
    first, middle, end = record[:19], record[19:48], record[48:]
    return [
        _request(_get_pdr_request(requested_handle, request_count=len(first)), instance_id=5),
        _response(
            _get_pdr_response(
                first,
                next_record_handle=next_handle,
                next_data_transfer_handle=0xA0,
                transfer_flag=GetPDRTransferFlag.START,
            ),
            instance_id=5,
        ),
        _request(
            _get_pdr_request(
                requested_handle,
                data_transfer_handle=0xA0,
                operation=GetPDRTransferOperation.GET_NEXT_PART,
                request_count=len(middle),
            ),
            instance_id=6,
        ),
        *_fragmented_response(
            _get_pdr_response(
                middle,
                next_record_handle=next_handle,
                next_data_transfer_handle=0xA1,
                transfer_flag=GetPDRTransferFlag.MIDDLE,
            ),
            instance_id=6,
        ),
        _request(
            _get_pdr_request(
                requested_handle,
                data_transfer_handle=0xA1,
                operation=GetPDRTransferOperation.GET_NEXT_PART,
                request_count=len(end),
            ),
            instance_id=7,
        ),
        _response(
            _get_pdr_response(
                end,
                next_record_handle=next_handle,
                transfer_flag=GetPDRTransferFlag.END,
                crc=struct.pack("<I", binascii.crc32(record) & 0xFFFFFFFF),
            ),
            instance_id=7,
        ),
    ]


def _sensor_reading_exchange(
    sensor_id: int,
    reading: int,
    *,
    data_size: GetSensorReadingDataSizeEnum,
    instance_id: int,
) -> list[object]:
    formats = {
        GetSensorReadingDataSizeEnum.UINT8: "<B",
        GetSensorReadingDataSizeEnum.SINT8: "<b",
        GetSensorReadingDataSizeEnum.UINT16: "<H",
        GetSensorReadingDataSizeEnum.SINT16: "<h",
        GetSensorReadingDataSizeEnum.UINT32: "<I",
        GetSensorReadingDataSizeEnum.SINT32: "<i",
    }
    request = struct.pack("<HB", sensor_id, 0)
    response = bytes([int(data_size), 0, 0, 1, 1, 1]) + struct.pack(formats[data_size], reading)
    return [
        _request(request, cmd_code=PldmPlatformMonitoringCmdCodes.GetSensorReading, instance_id=instance_id),
        _response(response, cmd_code=PldmPlatformMonitoringCmdCodes.GetSensorReading, instance_id=instance_id),
    ]


def _records() -> list[bytes]:
    numeric_with_thresholds = NumericSensorPdr(
        record_handle=1,
        sensor_id=SENSOR_WITH_THRESHOLDS,
        data_size=GetSensorReadingDataSizeEnum.SINT16,
        warning_high=20,
        warning_low=-20,
        critical_high=30,
        critical_low=-30,
    ).to_bytes()
    aux_names = SensorAuxiliaryNamesPdr(
        record_handle=2,
        pldm_terminus_handle=0,
        sensor_id=SENSOR_WITH_THRESHOLDS,
        sensors=[SensorAuxiliaryNamesEntry(names=[PdrNameString(language_tag="en", name="THRESHOLD_SENSOR")])],
    ).to_bytes()
    opaque_body = b"numeric-effecter-body-" + bytes(range(64))
    opaque = struct.pack("<IBBHH", 3, 1, PDR_TYPE_NUMERIC_EFFECTER, 0, len(opaque_body)) + opaque_body
    numeric_without_thresholds = NumericSensorPdr(
        record_handle=4,
        sensor_id=SENSOR_WITHOUT_THRESHOLDS,
        data_size=GetSensorReadingDataSizeEnum.UINT8,
    ).to_bytes()
    return [numeric_with_thresholds, aux_names, opaque, numeric_without_thresholds]


def _synthetic_capture_packets(records: list[bytes]) -> list[object]:
    return [
        *_get_tid_exchange(),
        *_repository_info_exchange(records),
        *_single_pdr_exchange(records[0], requested_handle=0, next_handle=2, instance_id=3),
        *_single_pdr_exchange(records[1], requested_handle=2, next_handle=3, instance_id=4),
        *_multipart_fragmented_pdr_exchange(records[2], requested_handle=3, next_handle=4),
        *_single_pdr_exchange(records[3], requested_handle=4, next_handle=0, instance_id=8),
        *_sensor_reading_exchange(
            SENSOR_WITH_THRESHOLDS,
            -12,
            data_size=GetSensorReadingDataSizeEnum.SINT16,
            instance_id=9,
        ),
        *_sensor_reading_exchange(
            SENSOR_WITH_THRESHOLDS,
            -9,
            data_size=GetSensorReadingDataSizeEnum.SINT16,
            instance_id=10,
        ),
        *_sensor_reading_exchange(
            SENSOR_WITHOUT_THRESHOLDS,
            6,
            data_size=GetSensorReadingDataSizeEnum.UINT8,
            instance_id=11,
        ),
        *_sensor_reading_exchange(
            SENSOR_WITHOUT_THRESHOLDS,
            9,
            data_size=GetSensorReadingDataSizeEnum.UINT8,
            instance_id=12,
        ),
    ]


def _load_pldm_sensor_behavior(artifact: Path) -> PldmSensorBehavior:
    behaviors = get_behaviors_for_roles(("pldm-sensor", {"pdrs_from": str(artifact)}))
    behavior = behaviors[-1]
    assert isinstance(behavior, PldmSensorBehavior)
    return behavior


def _get_reply(behavior: PldmSensorBehavior, pkt, ctx: EndpointContext) -> PacketList:
    response = behavior.handle(pkt, ctx)
    assert response is not None
    assert response.stop_processing is True
    assert isinstance(response.reply, PacketList)
    return response.reply


def _pldm_from_reply(reply: PacketList) -> PldmHdrPacket:
    payload = bytearray()
    for packet in reply:
        smbus = SmbusTransport(bytes(packet))
        transport = smbus.getlayer(TransportHdrPacket)
        assert transport is not None
        payload.extend(raw(transport.payload))
    pldm = PldmHdrPacket(bytes(payload))
    assert pldm.completion_code == CompletionCodes.SUCCESS
    return pldm


def _raw_payload(pldm: PldmHdrPacket) -> bytes:
    return bytes(pldm.payload.load if isinstance(pldm.payload, Raw) else pldm.payload)


def _parse_get_pdr_response(pldm: PldmHdrPacket) -> tuple[int, int, int, bytes]:
    data = _raw_payload(pldm)
    next_record_handle, next_data_transfer_handle, transfer_flag, response_count = struct.unpack_from("<IIBH", data)
    start = struct.calcsize("<IIBH")
    return next_record_handle, next_data_transfer_handle, transfer_flag, data[start : start + response_count]


def _read_repository_over_wire(behavior: PldmSensorBehavior, expected_count: int) -> list[bytes]:
    ctx = _ctx()
    records: list[bytes] = []
    record_handle = 0
    while len(records) < expected_count:
        record, next_record_handle = _read_one_pdr_over_wire(behavior, ctx, record_handle)
        records.append(record)
        record_handle = next_record_handle
        if record_handle == 0:
            break
    return records


def _read_one_pdr_over_wire(
    behavior: PldmSensorBehavior,
    ctx: EndpointContext,
    record_handle: int,
) -> tuple[bytes, int]:
    packet = _request(
        _get_pdr_request(record_handle, request_count=23),
        cmd_code=PldmPlatformMonitoringCmdCodes.GetPDR,
        instance_id=13 + record_handle % 10,
    )
    next_record_handle, transfer_handle, transfer_flag, record_data = _parse_get_pdr_response(
        _pldm_from_reply(_get_reply(behavior, packet, ctx))
    )
    assert transfer_flag in (GetPDRTransferFlag.START, GetPDRTransferFlag.START_AND_END)
    while transfer_handle:
        packet = _request(
            _get_pdr_request(
                record_handle,
                data_transfer_handle=transfer_handle,
                operation=GetPDRTransferOperation.GET_NEXT_PART,
                request_count=23,
            ),
            cmd_code=PldmPlatformMonitoringCmdCodes.GetPDR,
            instance_id=13 + transfer_handle % 10,
        )
        next_record_handle, transfer_handle, transfer_flag, chunk = _parse_get_pdr_response(
            _pldm_from_reply(_get_reply(behavior, packet, ctx))
        )
        assert transfer_flag in (GetPDRTransferFlag.MIDDLE, GetPDRTransferFlag.END)
        record_data += chunk
    return record_data, next_record_handle


def _sensor_reading(behavior: PldmSensorBehavior, sensor_id: int, data_size: GetSensorReadingDataSizeEnum) -> int:
    pldm = _pldm_from_reply(
        _get_reply(
            behavior,
            _request(
                struct.pack("<HB", sensor_id, 0),
                cmd_code=PldmPlatformMonitoringCmdCodes.GetSensorReading,
                instance_id=25 + sensor_id % 10,
            ),
            _ctx(),
        )
    )
    reading = pldm.getlayer(GetSensorReadingPacket)
    assert reading is not None
    if data_size == GetSensorReadingDataSizeEnum.SINT16:
        value = int(reading.presentReading16)
        return value - 0x10000 if value & 0x8000 else value
    if data_size == GetSensorReadingDataSizeEnum.UINT8:
        return int(reading.presentReading8)
    msg = f"Unhandled test data size: {data_size}"
    raise AssertionError(msg)


def test_capture_cli_artifact_loaded_model_returns_byte_identical_pdrs(tmp_path: Path) -> None:
    """Acceptance criterion: capture-generated models must serve the exact PDR bytes originally captured."""
    records = _records()
    capture = tmp_path / "synthetic-pldm.tcpdump.log"
    output_dir = tmp_path / "out"
    _write_capture(capture, _synthetic_capture_packets(records))

    result = CliRunner().invoke(cli, ["pldm-from-capture", str(capture), "--output", str(output_dir), "--date", "2026-01-02"])

    assert result.exit_code == 0, result.output
    artifact_path = output_dir / f"pldm-terminus-{TERMINUS_EID}.json"
    artifact: dict[str, Any] = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert list(artifact) == ["eid", "tid", "source", "repository_info", "pdrs", "sensors", "warnings"]
    assert json.loads(json.dumps(artifact)) == artifact
    assert artifact["eid"] == TERMINUS_EID
    assert artifact["tid"] == 1
    assert artifact["repository_info"]["record_count"] == len(records)
    assert [pdr["record_handle"] for pdr in artifact["pdrs"]] == [1, 2, 3, 4]
    assert [pdr["pdr_type"] for pdr in artifact["pdrs"]] == [
        PDR_TYPE_NUMERIC_SENSOR,
        PDR_TYPE_SENSOR_AUXILIARY_NAMES,
        PDR_TYPE_NUMERIC_EFFECTER,
        PDR_TYPE_NUMERIC_SENSOR,
    ]
    assert "data" in artifact["pdrs"][2]

    thresholded = artifact["sensors"][str(SENSOR_WITH_THRESHOLDS)]
    unthresholded = artifact["sensors"][str(SENSOR_WITHOUT_THRESHOLDS)]
    assert SensorSimulation(**thresholded["simulation"])
    assert SensorSimulation(**unthresholded["simulation"])
    assert thresholded["data_size"] == int(GetSensorReadingDataSizeEnum.SINT16)
    assert thresholded["simulation"]["warning_high"] == 20
    assert thresholded["simulation"]["warning_low"] == -20
    assert thresholded["simulation"]["critical_high"] == 30
    assert thresholded["simulation"]["critical_low"] == -30
    assert unthresholded["simulation"]["warning_high"] is None
    assert unthresholded["simulation"]["warning_low"] is None
    assert unthresholded["simulation"]["critical_high"] is None
    assert unthresholded["simulation"]["critical_low"] is None

    behavior = _load_pldm_sensor_behavior(artifact_path)
    served_records = _read_repository_over_wire(behavior, expected_count=len(records))
    assert served_records == records

    signed_value = _sensor_reading(behavior, SENSOR_WITH_THRESHOLDS, GetSensorReadingDataSizeEnum.SINT16)
    unsigned_value = _sensor_reading(behavior, SENSOR_WITHOUT_THRESHOLDS, GetSensorReadingDataSizeEnum.UINT8)
    assert thresholded["simulation"]["minimum"] <= signed_value <= thresholded["simulation"]["maximum"]
    assert unthresholded["simulation"]["minimum"] <= unsigned_value <= unthresholded["simulation"]["maximum"]
