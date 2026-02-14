# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import ByteEnumField, XByteField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes, CerberusResetConfig


# --- RESET_CONFIG ---


class ResetConfigRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-ResetConfig-Req"
    fields_desc = [ByteEnumField("reset_type", 0, CerberusResetConfig)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        try:
            type_name = CerberusResetConfig(self.reset_type).name
        except ValueError:
            type_name = f"0x{self.reset_type:02X}"
        summary = f"{self.name} (type={type_name})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    ResetConfigRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.RESET_CONFIG,
)


# --- GET_CONFIG_ID ---


class GetConfigIdRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetConfigId-Req"
    fields_desc = [XByteField("config_type", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (type={self.config_type})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ConfigIdResponsePacket(AllowRawSummary, Packet):
    """Response contains variable-length config ID data as raw payload."""

    name = "Cerberus-ConfigId"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        data_len = len(bytes(self.payload)) if self.payload else 0
        summary = f"{self.name} (len={data_len})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ConfigIdCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 1:
            return GetConfigIdRequestPacket
        return ConfigIdResponsePacket


bind_layers(
    VdPciHdrPacket,
    ConfigIdCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_CONFIG_ID,
)
