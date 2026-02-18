# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import struct

from scapy.fields import ByteEnumField, StrField, XByteField, XLEIntField, XLEShortField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes, CerberusLogType, ComponentAttestStatus


# --- GET_LOG_INFO ---


class GetLogInfoRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetLogInfo-Req"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return self.name, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class LogInfoResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-LogInfo"
    fields_desc = [
        XLEIntField("debug_log_length", 0),
        XLEIntField("attestation_log_length", 0),
        XLEIntField("tamper_log_length", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"{self.name} (debug={self.debug_log_length}, "
            f"attest={self.attestation_log_length}, "
            f"tamper={self.tamper_log_length})"
        )
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class LogInfoCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 0:
            return GetLogInfoRequestPacket
        return LogInfoResponsePacket


bind_layers(
    VdPciHdrPacket,
    LogInfoCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_LOG_INFO,
)


# --- READ_LOG ---


class ReadLogRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-ReadLog-Req"
    fields_desc = [
        ByteEnumField("log_type", 0, CerberusLogType),
        XLEIntField("offset", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        try:
            type_name = CerberusLogType(self.log_type).name
        except ValueError:
            type_name = f"0x{self.log_type:02X}"
        summary = f"{self.name} (type={type_name}, offset=0x{self.offset:08X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ReadLogResponsePacket(AllowRawSummary, Packet):
    """Response contains variable-length log data as raw payload."""

    name = "Cerberus-ReadLog"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        data_len = len(bytes(self.payload)) if self.payload else 0
        summary = f"{self.name} (len={data_len})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ReadLogCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 5:
            return ReadLogRequestPacket
        return ReadLogResponsePacket


bind_layers(
    VdPciHdrPacket,
    ReadLogCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.READ_LOG,
)


# --- CLEAR_LOG ---


class ClearLogRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-ClearLog-Req"
    fields_desc = [ByteEnumField("log_type", 0, CerberusLogType)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        try:
            type_name = CerberusLogType(self.log_type).name
        except ValueError:
            type_name = f"0x{self.log_type:02X}"
        summary = f"{self.name} (type={type_name})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    ClearLogRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.CLEAR_LOG,
)


# --- GET_ATTESTATION_DATA ---


class GetAttestationDataRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetAttestData-Req"
    fields_desc = [
        XByteField("pmr_id", 0),
        XByteField("entry_id", 0),
        XLEIntField("offset", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (pmr={self.pmr_id}, entry={self.entry_id}, offset={self.offset})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


def _status_name(value: int) -> str:
    """Return a short name for a component attestation status byte."""
    try:
        return ComponentAttestStatus(value).name
    except ValueError:
        return f"0x{value:02X}"


def _decode_component_statuses_v2(
    data: bytes, component_maps: list[dict[int, str]],
) -> list[tuple[str, list[str]]]:
    """Decode version-2 component status data into (name, [status_str]) tuples."""
    entries: list[tuple[str, list[str]]] = []
    pos = 0
    while pos + 5 <= len(data):
        comp_id = struct.unpack_from("<I", data, pos)[0]
        comp_count = data[pos + 4]
        if pos + 5 + comp_count > len(data):
            break
        statuses = [_status_name(data[pos + 5 + i]) for i in range(comp_count)]
        # Resolve component name from maps
        comp_name: str | None = None
        for cmap in component_maps:
            comp_name = cmap.get(comp_id)
            if comp_name is not None:
                break
        if comp_name is None:
            comp_name = f"Component-{comp_id}"
        entries.append((comp_name, statuses))
        pos += 5 + comp_count
    return entries


def _decode_component_statuses_v2_raw(
    data: bytes, component_maps: list[dict[int, str]],
) -> list[tuple[str, list[int]]]:
    """Decode version-2 component status data into (name, [raw_status_byte]) tuples."""
    entries: list[tuple[str, list[int]]] = []
    pos = 0
    while pos + 5 <= len(data):
        comp_id = struct.unpack_from("<I", data, pos)[0]
        comp_count = data[pos + 4]
        if pos + 5 + comp_count > len(data):
            break
        statuses = [data[pos + 5 + i] for i in range(comp_count)]
        comp_name: str | None = None
        for cmap in component_maps:
            comp_name = cmap.get(comp_id)
            if comp_name is not None:
                break
        if comp_name is None:
            comp_name = f"Component-{comp_id}"
        entries.append((comp_name, statuses))
        pos += 5 + comp_count
    return entries


def _decode_component_statuses_v1(data: bytes) -> list[tuple[str, list[str]]]:
    """Decode version-1 flat status array (one byte per component)."""
    return [(f"Component-{i}", [_status_name(b)]) for i, b in enumerate(data)]


def _decode_component_statuses_v1_raw(data: bytes) -> list[tuple[str, list[int]]]:
    """Decode version-1 flat status array into (name, [raw_status_byte]) tuples."""
    return [(f"Component-{i}", [b]) for i, b in enumerate(data)]


class AttestationDataResponsePacket(AllowRawSummary, Packet):
    """Response for GET_ATTESTATION_DATA containing component attestation status.

    Binary format (first response, offset=0):
      - event_data:      4 bytes (LE uint32)
      - status_version:  1 byte  (1 or 2)
      - status_data:     variable-length component status entries

    Version 2 status_data: repeated {component_id(4 LE), count(1), status[count]}
    Version 1 status_data: flat array of status bytes (one per component)
    """

    name = "Cerberus-AttestData"
    fields_desc = [
        XLEIntField("event_data", 0),
        XByteField("status_version", 0),
        StrField("status_data", b""),
    ]

    # Component ID → name maps. Additional maps (e.g. for OEM components)
    # can be appended at runtime.
    component_maps: list[dict[int, str]] = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        raw = bytes(self.status_data) if self.status_data else b""
        version = self.status_version
        if version == 2 and raw:
            entries = _decode_component_statuses_v2(raw, self.component_maps)
        elif version == 1 and raw:
            entries = _decode_component_statuses_v1(raw)
        else:
            data_len = len(raw)
            summary = f"{self.name} (evt=0x{self.event_data:08X}, v{version}, {data_len}B)"
            return summary, [VdPciHdrPacket]

        parts = []
        for comp_name, statuses in entries:
            status_str = ",".join(statuses)
            parts.append(f"{comp_name}={status_str}")
        summary = (
            f"{self.name} (evt=0x{self.event_data:08X}, v{version}, "
            f"{len(entries)} comp): {', '.join(parts)}"
        )
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class AttestationDataCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 6:
            return GetAttestationDataRequestPacket
        return AttestationDataResponsePacket


bind_layers(
    VdPciHdrPacket,
    AttestationDataCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_ATTESTATION_DATA,
)
