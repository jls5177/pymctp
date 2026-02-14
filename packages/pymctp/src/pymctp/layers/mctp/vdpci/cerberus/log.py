# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import ByteEnumField, XByteField, XLEIntField, XLEShortField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes, CerberusLogType


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
        XLEShortField("offset", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (pmr={self.pmr_id}, entry={self.entry_id}, offset={self.offset})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class AttestationDataResponsePacket(AllowRawSummary, Packet):
    """Response contains variable-length attestation data as raw payload."""

    name = "Cerberus-AttestData"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        data_len = len(bytes(self.payload)) if self.payload else 0
        summary = f"{self.name} (len={data_len})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class AttestationDataCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 4:
            return GetAttestationDataRequestPacket
        return AttestationDataResponsePacket


bind_layers(
    VdPciHdrPacket,
    AttestationDataCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_ATTESTATION_DATA,
)
