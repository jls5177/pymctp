# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import StrFixedLenField, XByteField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes


class FwVersionRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetFwVersion-Req"
    fields_desc = [XByteField("area_index", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (area={self.area_index})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class FwVersionResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-FwVersion"
    fields_desc = [StrFixedLenField("version", b"", 32)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        version_str = self.version.rstrip(b"\0").decode(errors="replace")
        summary = f"{self.name} (ver={version_str})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class FwVersionCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 1:
            return FwVersionRequestPacket
        return FwVersionResponsePacket


bind_layers(
    VdPciHdrPacket,
    FwVersionCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_FW_VERSION,
)
