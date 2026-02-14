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


# --- EXCHANGE_KEYS ---


class ExchangeKeysRequestPacket(AllowRawSummary, Packet):
    """Key exchange request. Contains key type, then variable-length key data."""

    name = "Cerberus-ExchangeKeys-Req"
    fields_desc = [
        XByteField("key_type", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (type=0x{self.key_type:02X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ExchangeKeysResponsePacket(AllowRawSummary, Packet):
    """Key exchange response. Contains key type, then variable-length key data."""

    name = "Cerberus-ExchangeKeys"
    fields_desc = [
        XByteField("key_type", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (type=0x{self.key_type:02X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ExchangeKeysCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        # Both request and response start with key_type; use rq bit from VdPci header
        return cls


bind_layers(
    VdPciHdrPacket,
    ExchangeKeysCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.EXCHANGE_KEYS,
)


# --- SESSION_SYNC ---


class SessionSyncRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-SessionSync-Req"
    fields_desc = [XByteField("rn_req", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (rn=0x{self.rn_req:02X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class SessionSyncResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-SessionSync"
    fields_desc = [XByteField("rn_req", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (rn=0x{self.rn_req:02X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class SessionSyncCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        return cls


bind_layers(
    VdPciHdrPacket,
    SessionSyncCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.SESSION_SYNC,
)
