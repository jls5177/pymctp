# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import XByteField, XLEShortField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes


# --- UNSEAL_MESSAGE ---


class UnsealMessageRequestPacket(AllowRawSummary, Packet):
    """Start unsealing. Contains seed params then variable-length sealed data."""

    name = "Cerberus-Unseal-Req"
    fields_desc = [
        XByteField("seed_type", 0),
        XByteField("seed_params", 0),
        XLEShortField("seed_length", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"{self.name} (seed_type=0x{self.seed_type:02X}, "
            f"params=0x{self.seed_params:02X}, seed_len={self.seed_length})"
        )
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    UnsealMessageRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.UNSEAL_MESSAGE,
)


# --- UNSEAL_MESSAGE_RESULT ---


class UnsealMessageResultRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-UnsealResult-Req"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return self.name, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class UnsealMessageResultResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-UnsealResult"
    fields_desc = [
        XByteField("unseal_status", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (status=0x{self.unseal_status:02X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class UnsealMessageResultCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 0:
            return UnsealMessageResultRequestPacket
        return UnsealMessageResultResponsePacket


bind_layers(
    VdPciHdrPacket,
    UnsealMessageResultCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.UNSEAL_MESSAGE_RESULT,
)
