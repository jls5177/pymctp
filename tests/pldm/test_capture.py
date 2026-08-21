# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import struct
from collections.abc import Iterable
from pathlib import Path

from scapy.compat import raw
from scapy.packet import Raw

from pymctp.layers.mctp.pldm import PldmHdr
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import (
    GetSensorReadingDataSizeEnum,
    PldmPlatformMonitoringCmdCodes,
)
from pymctp.layers.mctp.pldm.types import CompletionCodes, PldmTypeCodes
from pymctp.layers.mctp.transport import SmbusTransport, TransportHdr
from pymctp.layers.mctp.types import MsgTypes
from pymctp.pldm.capture import TerminusCapture, extract_pldm, read_capture


REQUESTER_EID = 0x20
TERMINUS_EID = 0x10
TAG = 3

TRANSFER_START = 0x00
TRANSFER_MIDDLE = 0x01
TRANSFER_END = 0x04
TRANSFER_START_AND_END = 0x05


def _capture(*packets) -> Iterable[tuple[None, object]]:
    return [(None, packet) for packet in packets]


def _mctp_packet(
    *,
    src: int,
    dst: int,
    to: bool,
    payload: bytes,
    som: bool = True,
    eom: bool = True,
    pkt_seq: int = 0,
    tag: int = TAG,
):
    transport = TransportHdr(
        msg_type=MsgTypes.PLDM,
        dst=dst,
        src=src,
        som=som,
        eom=eom,
        to=to,
        tag=tag,
        pkt_seq=pkt_seq,
    ) / Raw(payload)
    smbus = SmbusTransport(dst_addr=dst, src_addr=src, load=transport)
    return SmbusTransport(bytes(smbus))


def _pldm_bytes(
    *,
    rq: bool,
    pldm_type: int = PldmTypeCodes.PLATFORM_MONITORING,
    cmd_code: int = PldmPlatformMonitoringCmdCodes.GetPDR,
    instance_id: int = 1,
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
    src: int = REQUESTER_EID,
    dst: int = TERMINUS_EID,
    pldm_type: int = PldmTypeCodes.PLATFORM_MONITORING,
    cmd_code: int = PldmPlatformMonitoringCmdCodes.GetPDR,
    instance_id: int = 1,
):
    return _mctp_packet(
        src=src,
        dst=dst,
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
    src: int = TERMINUS_EID,
    dst: int = REQUESTER_EID,
    pldm_type: int = PldmTypeCodes.PLATFORM_MONITORING,
    cmd_code: int = PldmPlatformMonitoringCmdCodes.GetPDR,
    instance_id: int = 1,
    completion_code: int = CompletionCodes.SUCCESS,
):
    return _mctp_packet(
        src=src,
        dst=dst,
        to=False,
        payload=_pldm_bytes(
            rq=False,
            pldm_type=pldm_type,
            cmd_code=cmd_code,
            instance_id=instance_id,
            completion_code=completion_code,
            payload=payload,
        ),
    )


def _get_pdr_request(
    *,
    record_handle: int,
    data_transfer_handle: int = 0,
    transfer_operation_flag: int = 0,
    request_count: int = 0xFFFF,
    record_change_number: int = 0,
) -> bytes:
    return struct.pack(
        "<IIBHH",
        record_handle,
        data_transfer_handle,
        transfer_operation_flag,
        request_count,
        record_change_number,
    )


def _get_pdr_response(
    record_data: bytes,
    *,
    next_record_handle: int = 0,
    next_data_transfer_handle: int = 0,
    transfer_flag: int = TRANSFER_START_AND_END,
    trailing_crc: bytes = b"",
) -> bytes:
    return (
        struct.pack("<IIBH", next_record_handle, next_data_transfer_handle, transfer_flag, len(record_data))
        + record_data
        + trailing_crc
    )


def _repository_info_response(*, record_count: int) -> bytes:
    return (
        bytes([0x01])
        + bytes(range(13))
        + bytes(range(13, 26))
        + struct.pack("<IIIB", record_count, 128, 64, 5)
    )


def _sensor_request(sensor_id: int) -> bytes:
    return struct.pack("<HB", sensor_id, 0)


def _sensor_response(sensor_data_size: int, reading: int) -> bytes:
    fmt = {
        GetSensorReadingDataSizeEnum.UINT8: "<B",
        GetSensorReadingDataSizeEnum.SINT8: "<b",
        GetSensorReadingDataSizeEnum.UINT16: "<H",
        GetSensorReadingDataSizeEnum.SINT16: "<h",
        GetSensorReadingDataSizeEnum.UINT32: "<I",
        GetSensorReadingDataSizeEnum.SINT32: "<i",
    }[GetSensorReadingDataSizeEnum(sensor_data_size)]
    return bytes([sensor_data_size, 0, 0, 1, 1, 1]) + struct.pack(fmt, reading)


def _terminus(result: dict[int, TerminusCapture], eid: int = TERMINUS_EID) -> TerminusCapture:
    assert eid in result
    return result[eid]


def test_single_start_and_end_get_pdr_record():
    record = b"pdr-record"

    result = extract_pldm(
        _capture(
            _request(_get_pdr_request(record_handle=1)),
            _response(_get_pdr_response(record, next_record_handle=2)),
        )
    )

    assert _terminus(result).pdr_records == [record]


def test_split_get_pdr_record_reassembles_original_bytes():
    """Large PDRs arrive over several GetPDR transfers and must remain one raw record."""
    record = b"start-middle-end"

    result = extract_pldm(
        _capture(
            _request(_get_pdr_request(record_handle=1, data_transfer_handle=0), instance_id=1),
            _response(
                _get_pdr_response(
                    record[:5],
                    next_data_transfer_handle=0xA0,
                    transfer_flag=TRANSFER_START,
                ),
                instance_id=1,
            ),
            _request(_get_pdr_request(record_handle=1, data_transfer_handle=0xA0), instance_id=2),
            _response(
                _get_pdr_response(
                    record[5:12],
                    next_data_transfer_handle=0xA1,
                    transfer_flag=TRANSFER_MIDDLE,
                ),
                instance_id=2,
            ),
            _request(_get_pdr_request(record_handle=1, data_transfer_handle=0xA1), instance_id=3),
            _response(
                _get_pdr_response(record[12:], transfer_flag=TRANSFER_END, trailing_crc=b"\x00"),
                instance_id=3,
            ),
        )
    )

    assert _terminus(result).pdr_records == [record]


def test_multi_packet_mctp_get_pdr_response_reassembles_before_decoding():
    """Transport-level fragmentation can split the PLDM header from the GetPDR payload."""
    record = b"fragmented-mctp-response"
    response_payload = _pldm_bytes(
        rq=False,
        cmd_code=PldmPlatformMonitoringCmdCodes.GetPDR,
        instance_id=1,
        payload=_get_pdr_response(record),
    )
    chunks = [response_payload[:2], response_payload[2:9], response_payload[9:]]

    result = extract_pldm(
        _capture(
            _request(_get_pdr_request(record_handle=1)),
            _mctp_packet(
                src=TERMINUS_EID,
                dst=REQUESTER_EID,
                to=False,
                payload=chunks[0],
                som=True,
                eom=False,
                pkt_seq=1,
            ),
            _mctp_packet(
                src=TERMINUS_EID,
                dst=REQUESTER_EID,
                to=False,
                payload=chunks[1],
                som=False,
                eom=False,
                pkt_seq=2,
            ),
            _mctp_packet(
                src=TERMINUS_EID,
                dst=REQUESTER_EID,
                to=False,
                payload=chunks[2],
                som=False,
                eom=True,
                pkt_seq=3,
            ),
        )
    )

    assert _terminus(result).pdr_records == [record]


def test_two_termini_are_keyed_by_responding_eid():
    result = extract_pldm(
        _capture(
            _request(_get_pdr_request(record_handle=1), dst=0x10, instance_id=1),
            _response(_get_pdr_response(b"term-10"), src=0x10, instance_id=1),
            _request(_get_pdr_request(record_handle=1), dst=0x11, instance_id=2),
            _response(_get_pdr_response(b"term-11"), src=0x11, instance_id=2),
        )
    )

    assert set(result) == {0x10, 0x11}
    assert result[0x10].pdr_records == [b"term-10"]
    assert result[0x11].pdr_records == [b"term-11"]


def test_repeated_repository_fetch_replaces_record_without_duplicate():
    result = extract_pldm(
        _capture(
            _request(_get_pdr_request(record_handle=7), instance_id=1),
            _response(_get_pdr_response(b"first"), instance_id=1),
            _request(_get_pdr_request(record_handle=7), instance_id=2),
            _response(_get_pdr_response(b"second"), instance_id=2),
        )
    )

    assert _terminus(result).pdr_records == [b"second"]


def test_non_zero_completion_code_is_skipped_and_warned():
    result = extract_pldm(
        _capture(
            _request(_get_pdr_request(record_handle=1)),
            _response(b"", completion_code=CompletionCodes.ERROR),
        )
    )

    capture = _terminus(result)
    assert capture.pdr_records == []
    assert any("non-zero PLDM completion code" in warning for warning in capture.warnings)


def test_sensor_readings_are_collected_in_order_for_multiple_widths():
    result = extract_pldm(
        _capture(
            _request(
                _sensor_request(1),
                cmd_code=PldmPlatformMonitoringCmdCodes.GetSensorReading,
                instance_id=1,
            ),
            _response(
                _sensor_response(GetSensorReadingDataSizeEnum.UINT8, 42),
                cmd_code=PldmPlatformMonitoringCmdCodes.GetSensorReading,
                instance_id=1,
            ),
            _request(
                _sensor_request(1),
                cmd_code=PldmPlatformMonitoringCmdCodes.GetSensorReading,
                instance_id=2,
            ),
            _response(
                _sensor_response(GetSensorReadingDataSizeEnum.UINT8, 43),
                cmd_code=PldmPlatformMonitoringCmdCodes.GetSensorReading,
                instance_id=2,
            ),
            _request(
                _sensor_request(2),
                cmd_code=PldmPlatformMonitoringCmdCodes.GetSensorReading,
                instance_id=3,
            ),
            _response(
                _sensor_response(GetSensorReadingDataSizeEnum.SINT16, -5),
                cmd_code=PldmPlatformMonitoringCmdCodes.GetSensorReading,
                instance_id=3,
            ),
        )
    )

    capture = _terminus(result)
    assert capture.sensor_readings == {1: [42.0, 43.0], 2: [-5.0]}
    assert capture.sensor_data_sizes == {
        1: GetSensorReadingDataSizeEnum.UINT8,
        2: GetSensorReadingDataSizeEnum.SINT16,
    }


def test_record_count_mismatch_warns_capture_may_be_truncated():
    result = extract_pldm(
        _capture(
            _request(
                b"",
                cmd_code=PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo,
                instance_id=1,
            ),
            _response(
                _repository_info_response(record_count=2),
                cmd_code=PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo,
                instance_id=1,
            ),
            _request(_get_pdr_request(record_handle=1), instance_id=2),
            _response(_get_pdr_response(b"only-record"), instance_id=2),
        )
    )

    capture = _terminus(result)
    assert capture.repository_info is not None
    assert capture.repository_info["record_count"] == 2
    assert "recovered 1 of 2 PDR records; capture may be truncated" in capture.warnings


def test_truncated_and_garbage_trailing_packets_do_not_raise():
    result = extract_pldm(
        _capture(
            _request(_get_pdr_request(record_handle=1)),
            _response(_get_pdr_response(b"valid")),
            Raw(b"garbage"),
            _mctp_packet(src=TERMINUS_EID, dst=REQUESTER_EID, to=False, payload=b"\x80", som=True, eom=True),
            _mctp_packet(src=TERMINUS_EID, dst=REQUESTER_EID, to=False, payload=b"orphan", som=False, eom=True),
        )
    )

    assert _terminus(result).pdr_records == [b"valid"]


def test_read_capture_parses_journal_wrapped_tcpdump_text():
    """Some service logs prefix every tcpdump line with a journal timestamp."""
    fixture = Path(__file__).parent / "fixtures" / "journal_wrapped_tcpdump.log"

    result = extract_pldm(read_capture(fixture, timezone="UTC", is_dst=False, date="2026-01-02"))

    assert _terminus(result).pdr_records == [b"journal-record"]
