# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT
import doctest
from typing import Any

from scapy.fields import BitEnumField, BitField, FieldLenField, FieldListField, PacketListField, XByteField
from scapy.packet import Packet

from ...helpers import AllowRawSummary
from .. import EndpointContext
from ..types import AnyPacketType, EntryType, RoutingTableEntry
from .control import (
    AutobindControlMsg,
    ControlHdr,
    ControlHdrPacket,
    RqBit,
    set_control_fields,
)
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


class RoutingInfoUpdateEntry1BAddressPacket(AllowRawSummary, Packet):
    name = "RoutingInfoUpdateEntryPacket"

    fields_desc = [
        BitField("rsvd", 0, 4),
        BitEnumField("entry_type", 0, 4, EntryType),
        XByteField("entry_count", 0),
        XByteField("starting_eid", 0),
        XByteField("phy_address", 0),
    ]

    def extract_padding(self, p):
        """Required to ensure remaining bytes are properly transferred into next entry"""
        return b"", p

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        # eids = [eid for eid in range(self.starting_eid, self.starting_eid + self.entry_count)]
        summary = f"type={self.entry_type}["
        if self.entry_type == EntryType.SINGLE_ENDPOINT:
            summary += "EP"
        elif self.entry_type == EntryType.BRIDGE_AND_DOWNSTREAM_ENDPOINT:
            summary += "RNG"
        elif self.entry_type == EntryType.SINGLE_BRIDGE_ENDPOINT:
            summary += "BR"
        elif self.entry_type == EntryType.ADDITIONAL_BRIDGE_EID_RANGE:
            summary += "RNG+"
        summary += f"]phy_address=0x{self.phy_address:0X} "
        if self.entry_count == 1:
            summary += f"EID=0x{self.starting_eid:0X}"
        elif self.entry_count > 1:
            summary += f"EIDs=0x{self.starting_eid:0X}-{self.starting_eid + self.entry_count:0X}"
        return summary, [ControlHdrPacket, RoutingInfoUpdatePacket]


@AutobindControlMsg(ContrlCmdCodes.RoutingInformationUpdate)
class RoutingInfoUpdatePacket(AllowRawSummary, Packet):
    name = "RoutingInfoUpdate"

    fields_desc = set_control_fields(
        rq_fields=[
            FieldLenField("entry_count", None, fmt="B", count_of="entries"),
            PacketListField(
                "entries", [], RoutingInfoUpdateEntry1BAddressPacket, count_from=lambda pkt: pkt.entry_count
            ),
        ],
    )

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} [{self.entry_count}] ("
        if self.underlayer.getfieldval("rq") == RqBit.REQUEST.value:
            entries = [entry.mysummary()[0] for entry in self.entries]
            summary += "; ".join(entries)
        summary += ")"
        return summary, [ControlHdrPacket]


if __name__ == "__main__":
    pkt = ControlHdrPacket(bytes([0, 0x85, 0x9, 0x2, 0x03, 0x01, 0x80, 0x30]))
    print(f"Packet: {pkt.mysummary()}")
