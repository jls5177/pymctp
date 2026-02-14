# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import ByteEnumField, XByteField, XLEIntField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes, CerberusUpdateType


# --- INIT_FW_UPDATE ---


class InitFwUpdateRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-InitFwUpdate-Req"
    fields_desc = [XLEIntField("size", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (size={self.size})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    InitFwUpdateRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.INIT_FW_UPDATE,
)


# --- FW_UPDATE ---


class FwUpdateRequestPacket(AllowRawSummary, Packet):
    """Request to send FW update data. Payload follows as raw data."""

    name = "Cerberus-FwUpdate-Req"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        data_len = len(bytes(self.payload)) if self.payload else 0
        summary = f"{self.name} (len={data_len})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    FwUpdateRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.FW_UPDATE,
)


# --- COMPLETE_FW_UPDATE ---


class CompleteFwUpdateRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-CompleteFwUpdate-Req"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return self.name, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    CompleteFwUpdateRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.COMPLETE_FW_UPDATE,
)


# --- GET_UPDATE_STATUS ---


class GetUpdateStatusRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetUpdateStatus-Req"
    fields_desc = [
        ByteEnumField("update_type", 0, CerberusUpdateType),
        XByteField("port_id", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        try:
            type_name = CerberusUpdateType(self.update_type).name
        except ValueError:
            type_name = f"0x{self.update_type:02X}"
        summary = f"{self.name} (type={type_name}, port={self.port_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class UpdateStatusResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-UpdateStatus"
    fields_desc = [XLEIntField("status", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (status=0x{self.status:08X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class UpdateStatusCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 2:
            return GetUpdateStatusRequestPacket
        return UpdateStatusResponsePacket


bind_layers(
    VdPciHdrPacket,
    UpdateStatusCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_UPDATE_STATUS,
)


# --- GET_EXT_UPDATE_STATUS ---


class GetExtUpdateStatusRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetExtUpdateStatus-Req"
    fields_desc = [
        ByteEnumField("update_type", 0, CerberusUpdateType),
        XByteField("port_id", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        try:
            type_name = CerberusUpdateType(self.update_type).name
        except ValueError:
            type_name = f"0x{self.update_type:02X}"
        summary = f"{self.name} (type={type_name}, port={self.port_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ExtUpdateStatusResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-ExtUpdateStatus"
    fields_desc = [
        XLEIntField("status", 0),
        XLEIntField("remaining_bytes", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (status=0x{self.status:08X}, remaining={self.remaining_bytes})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ExtUpdateStatusCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 2:
            return GetExtUpdateStatusRequestPacket
        return ExtUpdateStatusResponsePacket


bind_layers(
    VdPciHdrPacket,
    ExtUpdateStatusCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_EXT_UPDATE_STATUS,
)
