# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pathlib
import struct
from collections import OrderedDict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, NamedTuple

from scapy.compat import raw
from scapy.packet import Packet

from pymctp.cli.analyze_tcpdump import parse_pcap_file, parse_text_file
from pymctp.layers.mctp.pldm.fru import FruMetadata, fru_metadata_to_dict
from pymctp.layers.mctp.pldm.fru import PldmFruCmdCodes
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import PldmPlatformMonitoringCmdCodes
from pymctp.layers.mctp.pldm.types import PldmControlCmdCodes, PldmTypeCodes
from pymctp.layers.mctp.transport import TransportHdrPacket
from pymctp.layers.mctp.types import MsgTypes


TRANSFER_FLAG_START = 0x00
TRANSFER_FLAG_MIDDLE = 0x01
TRANSFER_FLAG_END = 0x04
TRANSFER_FLAG_START_AND_END = 0x05


@dataclass
class TerminusCapture:
    eid: int
    tid: int | None = None
    supported_pldm_types: list[int] | None = None
    supported_pldm_commands: dict[int, list[int]] = field(default_factory=dict)
    repository_info: dict | None = None
    pdr_records: list[bytes] = field(default_factory=list)
    fru_metadata: dict[str, int] | None = None
    fru_record_table: bytes | None = None
    fru_record_table_padding: bytes = b""
    sensor_readings: dict[int, list[float]] = field(default_factory=dict)
    sensor_data_sizes: dict[int, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class _Message(NamedTuple):
    src: int
    dst: int
    tag: int
    to: int
    payload: bytes


class _PldmMessage(NamedTuple):
    rq: int
    instance_id: int
    pldm_type: int
    cmd_code: int
    completion_code: int | None
    payload: bytes


class _Request(NamedTuple):
    src: int
    dst: int
    tag: int
    payload: bytes


class _FragmentBuffer(NamedTuple):
    src: int
    dst: int
    tag: int
    to: int
    expected_seq: int
    payload: bytes


@dataclass
class _PdrTransfer:
    record_handle: int
    chunks: list[bytes]


@dataclass
class _FruTransfer:
    chunks: list[bytes]


def read_capture(
    path: str | pathlib.Path,
    *,
    timezone: str = "UTC",
    is_dst: bool = False,
    date: str | None = None,
) -> Iterator[tuple[datetime | None, Any]]:
    """Dispatch on suffix: .pcap/.dump use parse_pcap_file, anything else parse_text_file."""
    capture_path = pathlib.Path(path)
    if capture_path.suffix in {".pcap", ".dump"}:
        yield from parse_pcap_file(capture_path, timezone, is_dst)
        return

    date_str = date or datetime.now().strftime("%Y-%m-%d")
    yield from parse_text_file(capture_path, timezone, is_dst, date_str)


def extract_pldm(packets: Iterable[tuple[datetime | None, Any]]) -> dict[int, TerminusCapture]:
    """Recover every PLDM terminus in the capture, keyed by EID."""
    termini: dict[int, TerminusCapture] = {}
    outstanding: dict[tuple[int, int, int, int, int], _Request] = {}
    pdr_records_by_handle: dict[int, OrderedDict[int, bytes]] = {}
    pdr_transfers: dict[int, dict[int, _PdrTransfer]] = {}
    fru_transfers: dict[int, dict[int, _FruTransfer]] = {}
    fragment_buffers: dict[tuple[int, int, int, int], _FragmentBuffer] = {}

    def terminus(eid: int) -> TerminusCapture:
        if eid not in termini:
            termini[eid] = TerminusCapture(eid=eid)
        return termini[eid]

    def warn(eid: int, message: str) -> None:
        terminus(eid).warnings.append(message)

    def process_message(message: _Message) -> None:
        pldm = _parse_pldm_message(message.payload)
        if pldm is None:
            return

        if pldm.rq:
            key = (message.dst, message.src, pldm.instance_id, pldm.pldm_type, pldm.cmd_code)
            outstanding[key] = _Request(src=message.src, dst=message.dst, tag=message.tag, payload=pldm.payload)
            return

        key = (message.src, message.dst, pldm.instance_id, pldm.pldm_type, pldm.cmd_code)
        request = outstanding.pop(key, None)
        if pldm.completion_code:
            warn(
                message.src,
                f"non-zero PLDM completion code 0x{pldm.completion_code:02x} for type "
                f"0x{pldm.pldm_type:02x} cmd 0x{pldm.cmd_code:02x}; response skipped",
            )
            return
        if request is None:
            return

        if pldm.pldm_type == PldmTypeCodes.CONTROL:
            _process_control_response(terminus(message.src), pldm.cmd_code, request.payload, pldm.payload)
        elif pldm.pldm_type == PldmTypeCodes.PLATFORM_MONITORING:
            _process_platform_response(
                terminus(message.src),
                pldm.cmd_code,
                request.payload,
                pldm.payload,
                pdr_records_by_handle,
                pdr_transfers,
            )
        elif pldm.pldm_type == PldmTypeCodes.FRU:
            _process_fru_response(terminus(message.src), pldm.cmd_code, request.payload, pldm.payload, fru_transfers)

    for _, packet in packets:
        transport = _transport_layer(packet)
        if transport is None:
            continue

        try:
            src = int(transport.src)
            dst = int(transport.dst)
            tag = int(transport.tag)
            to = int(transport.to)
            som = int(transport.som)
            eom = int(transport.eom)
            pkt_seq = int(transport.pkt_seq)
        except Exception:
            continue

        key = (src, dst, tag, to)
        fragment_payload = _transport_payload(transport)

        if som:
            try:
                msg_type = int(transport.msg_type)
            except Exception:
                continue
            if msg_type != MsgTypes.PLDM:
                fragment_buffers.pop(key, None)
                continue
            if key in fragment_buffers:
                warn(_terminus_eid(src, dst, to), "dropped incomplete MCTP PLDM message before a new SOM fragment")
                fragment_buffers.pop(key, None)
            if eom:
                process_message(_Message(src=src, dst=dst, tag=tag, to=to, payload=fragment_payload))
            else:
                fragment_buffers[key] = _FragmentBuffer(
                    src=src,
                    dst=dst,
                    tag=tag,
                    to=to,
                    expected_seq=(pkt_seq + 1) & 0x03,
                    payload=fragment_payload,
                )
            continue

        buffer = fragment_buffers.get(key)
        if buffer is None:
            continue
        if pkt_seq != buffer.expected_seq:
            warn(
                _terminus_eid(src, dst, to),
                f"dropped MCTP PLDM message with packet sequence gap: expected {buffer.expected_seq}, got {pkt_seq}",
            )
            fragment_buffers.pop(key, None)
            continue
        payload = buffer.payload + fragment_payload
        if eom:
            fragment_buffers.pop(key, None)
            process_message(_Message(src=src, dst=dst, tag=tag, to=to, payload=payload))
        else:
            fragment_buffers[key] = _FragmentBuffer(
                src=src,
                dst=dst,
                tag=tag,
                to=to,
                expected_seq=(pkt_seq + 1) & 0x03,
                payload=payload,
            )

    for buffer in fragment_buffers.values():
        warn(_terminus_eid(buffer.src, buffer.dst, buffer.to), "dropped incomplete MCTP PLDM message at end of capture")

    for eid, transfers in fru_transfers.items():
        if transfers:
            termini[eid].warnings.append("dropped incomplete GetFRURecordTable transfer at end of capture")

    for eid, records in pdr_records_by_handle.items():
        termini[eid].pdr_records = list(records.values())

    for capture in termini.values():
        record_count = None
        if capture.repository_info is not None:
            record_count = capture.repository_info.get("record_count")
        if record_count is not None and record_count != len(capture.pdr_records):
            capture.warnings.append(
                f"recovered {len(capture.pdr_records)} of {record_count} PDR records; capture may be truncated"
            )

    return termini


def _transport_layer(packet: Any) -> TransportHdrPacket | None:
    if isinstance(packet, TransportHdrPacket):
        return packet
    if isinstance(packet, Packet) and packet.haslayer(TransportHdrPacket):
        layer = packet.getlayer(TransportHdrPacket)
        if isinstance(layer, TransportHdrPacket):
            return layer
    return None


def _transport_payload(packet: TransportHdrPacket) -> bytes:
    try:
        return raw(packet.payload)
    except Exception:
        return b""


def _parse_pldm_message(data: bytes) -> _PldmMessage | None:
    if len(data) < 3:
        return None
    rq = (data[0] >> 7) & 0x01
    instance_id = data[0] & 0x1F
    pldm_type = data[1] & 0x3F
    cmd_code = data[2]
    if rq:
        return _PldmMessage(
            rq=rq,
            instance_id=instance_id,
            pldm_type=pldm_type,
            cmd_code=cmd_code,
            completion_code=None,
            payload=data[3:],
        )
    if len(data) < 4:
        return None
    return _PldmMessage(
        rq=rq,
        instance_id=instance_id,
        pldm_type=pldm_type,
        cmd_code=cmd_code,
        completion_code=data[3],
        payload=data[4:],
    )


def _terminus_eid(src: int, dst: int, to: int) -> int:
    return dst if to else src


def _process_control_response(
    capture: TerminusCapture,
    cmd_code: int,
    request_payload: bytes,
    response_payload: bytes,
) -> None:
    if cmd_code == PldmControlCmdCodes.SetTID and request_payload:
        capture.tid = request_payload[0]
    elif cmd_code == PldmControlCmdCodes.GetTID and response_payload:
        capture.tid = response_payload[0]
    elif cmd_code == PldmControlCmdCodes.GetPLDMTypes and len(response_payload) >= 8:
        capture.supported_pldm_types = _decode_bitfield(response_payload[:8])
    elif cmd_code == PldmControlCmdCodes.GetPLDMCommands and len(request_payload) >= 1 and len(response_payload) >= 32:
        capture.supported_pldm_commands[int(request_payload[0])] = _decode_bitfield(response_payload[:32])


def _process_platform_response(
    capture: TerminusCapture,
    cmd_code: int,
    request_payload: bytes,
    response_payload: bytes,
    pdr_records_by_handle: dict[int, OrderedDict[int, bytes]],
    pdr_transfers: dict[int, dict[int, _PdrTransfer]],
) -> None:
    if cmd_code == PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo:
        repository_info = _parse_repository_info(response_payload)
        if repository_info is None:
            capture.warnings.append("malformed GetPDRRepositoryInfo response skipped")
        else:
            capture.repository_info = repository_info
    elif cmd_code == PldmPlatformMonitoringCmdCodes.GetPDR:
        _process_get_pdr_response(capture, request_payload, response_payload, pdr_records_by_handle, pdr_transfers)
    elif cmd_code == PldmPlatformMonitoringCmdCodes.GetSensorReading:
        _process_sensor_reading(capture, request_payload, response_payload)


def _process_fru_response(
    capture: TerminusCapture,
    cmd_code: int,
    request_payload: bytes,
    response_payload: bytes,
    fru_transfers: dict[int, dict[int, _FruTransfer]],
) -> None:
    if cmd_code == PldmFruCmdCodes.GetFRURecordTableMetadata:
        try:
            capture.fru_metadata = fru_metadata_to_dict(FruMetadata.from_bytes(response_payload))
        except ValueError:
            capture.warnings.append("malformed GetFRURecordTableMetadata response skipped")
    elif cmd_code == PldmFruCmdCodes.GetFRURecordTable:
        _process_get_fru_record_table_response(capture, request_payload, response_payload, fru_transfers)


def _parse_repository_info(response_payload: bytes) -> dict[str, int | str] | None:
    if len(response_payload) < 40:
        return None
    repository_state = response_payload[0]
    update_time = response_payload[1:14]
    oem_update_time = response_payload[14:27]
    record_count, repository_size, largest_record_size, timeout = struct.unpack_from("<IIIB", response_payload, 27)
    return {
        "repository_state": repository_state,
        "update_time": update_time.hex(),
        "oem_update_time": oem_update_time.hex(),
        "record_count": record_count,
        "repository_size": repository_size,
        "largest_record_size": largest_record_size,
        "data_transfer_handle_timeout": timeout,
    }


def _process_get_pdr_response(
    capture: TerminusCapture,
    request_payload: bytes,
    response_payload: bytes,
    pdr_records_by_handle: dict[int, OrderedDict[int, bytes]],
    pdr_transfers: dict[int, dict[int, _PdrTransfer]],
) -> None:
    request = _parse_get_pdr_request(request_payload)
    response = _parse_get_pdr_response(response_payload)
    if request is None or response is None:
        capture.warnings.append("malformed GetPDR transfer skipped")
        return

    record_handle, data_transfer_handle, *_ = request
    _, next_data_transfer_handle, transfer_flag, record_data = response
    records = pdr_records_by_handle.setdefault(capture.eid, OrderedDict())
    transfers = pdr_transfers.setdefault(capture.eid, {})

    if transfer_flag == TRANSFER_FLAG_START_AND_END:
        records[record_handle] = record_data
        return

    if transfer_flag == TRANSFER_FLAG_START:
        if next_data_transfer_handle in transfers:
            capture.warnings.append(
                f"replaced unfinished GetPDR transfer for handle 0x{next_data_transfer_handle:08x}"
            )
        transfers[next_data_transfer_handle] = _PdrTransfer(record_handle=record_handle, chunks=[record_data])
        return

    transfer = transfers.pop(data_transfer_handle, None)
    if transfer is None:
        capture.warnings.append(
            f"dropped GetPDR fragment for unknown transfer handle 0x{data_transfer_handle:08x}"
        )
        return

    transfer.chunks.append(record_data)
    if transfer_flag == TRANSFER_FLAG_MIDDLE:
        transfers[next_data_transfer_handle] = transfer
    elif transfer_flag == TRANSFER_FLAG_END:
        records[transfer.record_handle] = b"".join(transfer.chunks)
    else:
        capture.warnings.append(f"dropped GetPDR response with unknown transfer flag 0x{transfer_flag:02x}")


def _parse_get_pdr_request(payload: bytes) -> tuple[int, int, int, int, int] | None:
    if len(payload) < 13:
        return None
    return struct.unpack_from("<IIBHH", payload)


def _parse_get_pdr_response(payload: bytes) -> tuple[int, int, int, bytes] | None:
    if len(payload) < 11:
        return None
    next_record_handle, next_data_transfer_handle, transfer_flag, response_count = struct.unpack_from("<IIBH", payload)
    record_start = 11
    record_end = record_start + response_count
    if len(payload) < record_end:
        return None
    return next_record_handle, next_data_transfer_handle, transfer_flag, payload[record_start:record_end]


def _process_get_fru_record_table_response(
    capture: TerminusCapture,
    request_payload: bytes,
    response_payload: bytes,
    fru_transfers: dict[int, dict[int, _FruTransfer]],
) -> None:
    request = _parse_get_fru_record_table_request(request_payload)
    response = _parse_get_fru_record_table_response(response_payload)
    if request is None or response is None:
        capture.warnings.append("malformed GetFRURecordTable transfer skipped")
        return

    data_transfer_handle, _ = request
    next_data_transfer_handle, transfer_flag, table_data = response
    transfers = fru_transfers.setdefault(capture.eid, {})

    if transfer_flag == TRANSFER_FLAG_START_AND_END:
        _finish_fru_table(capture, table_data)
        return

    if transfer_flag == TRANSFER_FLAG_START:
        if next_data_transfer_handle in transfers:
            capture.warnings.append(
                f"replaced unfinished GetFRURecordTable transfer for handle 0x{next_data_transfer_handle:08x}"
            )
        transfers[next_data_transfer_handle] = _FruTransfer(chunks=[table_data])
        return

    transfer = transfers.pop(data_transfer_handle, None)
    if transfer is None:
        capture.warnings.append(
            f"dropped GetFRURecordTable fragment for unknown transfer handle 0x{data_transfer_handle:08x}"
        )
        return

    transfer.chunks.append(table_data)
    if transfer_flag == TRANSFER_FLAG_MIDDLE:
        transfers[next_data_transfer_handle] = transfer
    elif transfer_flag == TRANSFER_FLAG_END:
        _finish_fru_table(capture, b"".join(transfer.chunks))
    else:
        capture.warnings.append(f"dropped GetFRURecordTable response with unknown transfer flag 0x{transfer_flag:02x}")


def _parse_get_fru_record_table_request(payload: bytes) -> tuple[int, int] | None:
    if len(payload) < 5:
        return None
    return struct.unpack_from("<IB", payload)


def _parse_get_fru_record_table_response(payload: bytes) -> tuple[int, int, bytes] | None:
    if len(payload) < 5:
        return None
    next_data_transfer_handle, transfer_flag = struct.unpack_from("<IB", payload)
    return next_data_transfer_handle, transfer_flag, payload[5:]


def _finish_fru_table(capture: TerminusCapture, response_table: bytes) -> None:
    table_length = None if capture.fru_metadata is None else capture.fru_metadata.get("table_length")
    if table_length is None:
        capture.fru_record_table = bytes(response_table)
        capture.fru_record_table_padding = b""
        return

    table_length = int(table_length)
    if len(response_table) < table_length:
        capture.fru_record_table = bytes(response_table)
        capture.fru_record_table_padding = b""
        capture.warnings.append(
            f"GetFRURecordTable returned {len(response_table)} byte(s), shorter than metadata length {table_length}"
        )
        return

    capture.fru_record_table = bytes(response_table[:table_length])
    capture.fru_record_table_padding = bytes(response_table[table_length:])
    if capture.fru_record_table_padding and any(capture.fru_record_table_padding):
        capture.warnings.append(
            f"GetFRURecordTable returned {len(capture.fru_record_table_padding)} non-zero byte(s) after metadata length"
        )


def _process_sensor_reading(
    capture: TerminusCapture,
    request_payload: bytes,
    response_payload: bytes,
) -> None:
    if len(request_payload) < 2 or len(response_payload) < 7:
        capture.warnings.append("malformed GetSensorReading response skipped")
        return

    sensor_id = struct.unpack_from("<H", request_payload)[0]
    sensor_data_size = response_payload[0]
    reading_payload = response_payload[6:]
    reading = _decode_sensor_reading(sensor_data_size, reading_payload)
    if reading is None:
        capture.warnings.append(
            f"malformed GetSensorReading response for sensor 0x{sensor_id:04x} skipped"
        )
        return

    capture.sensor_data_sizes[sensor_id] = sensor_data_size
    capture.sensor_readings.setdefault(sensor_id, []).append(float(reading))


def _decode_sensor_reading(sensor_data_size: int, payload: bytes) -> int | None:
    formats = {
        0: ("<B", 1),
        1: ("<b", 1),
        2: ("<H", 2),
        3: ("<h", 2),
        4: ("<I", 4),
        5: ("<i", 4),
    }
    format_info = formats.get(sensor_data_size)
    if format_info is None:
        return None
    fmt, size = format_info
    if len(payload) < size:
        return None
    return int(struct.unpack_from(fmt, payload)[0])


def _decode_bitfield(data: bytes) -> list[int]:
    return [index * 8 + bit for index, value in enumerate(data) for bit in range(8) if value & (1 << bit)]
