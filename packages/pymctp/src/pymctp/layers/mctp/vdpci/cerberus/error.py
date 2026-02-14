# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import XByteEnumField, XByteField, XLEIntField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes, CerberusErrorCodes


class ErrorResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-Error"
    fields_desc = [
        XByteEnumField("code", 0, CerberusErrorCodes),
        XLEIntField("data", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        try:
            code_name = CerberusErrorCodes(self.code).name
        except ValueError:
            code_name = f"0x{self.code:02X}"
        summary = f"{self.name} (code={code_name}, data=0x{self.data:08X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


bind_layers(
    VdPciHdrPacket,
    ErrorResponsePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.ERROR,
)
