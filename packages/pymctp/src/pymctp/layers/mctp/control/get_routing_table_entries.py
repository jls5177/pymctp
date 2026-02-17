# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

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
)
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


class RoutingTableEntryPacket(AllowRawSummary, Packet):
    name = "RoutingTableEntry"

    fields_desc = [
        XByteField("eid_range", 0),
        XByteField("starting_eid", 0),
        BitEnumField("entry_type", 0, 2, EntryType),
        BitField("static_eid", 0, 1),
        BitField("port_number", 0, 5),
        XByteField("phys_transport_binding_id", 0),
        XByteField("phy_media_type_id", 0),
        FieldLenField("phys_address_size", None, fmt="B", count_of="phy_address"),
        FieldListField("phy_address", [], XByteField("", 0), count_from=lambda pkt: pkt.phys_address_size),
    ]

    def extract_padding(self, p):
        """Required to ensure remaining bytes are properly transferred into next entry"""
        return b"", p

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (eid: 0x{self.starting_eid:02X}, range: {self.eid_range})"
        return summary, [ControlHdrPacket]

    def to_dict(self) -> dict[str, Any]:
        data = {}
        for f in self.fields_desc:
            value = getattr(self, f.name)
            if value is type(None):
                value = None
            data[f.name] = value
        return data


def NewRoutingTableEntry(entry: RoutingTableEntry) -> RoutingTableEntryPacket:
    return RoutingTableEntryPacket(**entry.to_dict())


@AutobindControlMsg(ContrlCmdCodes.GetRoutingTableEntries, is_request=True)
class GetRoutingTableEntriesRequestPacket(AllowRawSummary, Packet):
    name = "GetRoutingTableEntries"

    fields_desc = [
        XByteField("entry_handle", 0),
    ]

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        if not ctx.routing_table_ready:
            return CompletionCodes.ERROR_NOT_READY, None

        rt_entries = [NewRoutingTableEntry(e) for e in ctx.routing_table]
        return CompletionCodes.SUCCESS, GetRoutingTableEntriesResponse(next_entry_handle=0xFF, entries=rt_entries)

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} ("
        summary += f"hdl=0x{self.entry_handle:02X})"
        return summary, [ControlHdrPacket]


@AutobindControlMsg(ContrlCmdCodes.GetRoutingTableEntries, is_request=False)
class GetRoutingTableEntriesResponsePacket(AllowRawSummary, Packet):
    name = "GetRoutingTableEntries"

    fields_desc = [
        XByteField("next_entry_handle", 0),
        FieldLenField("entry_count", None, fmt="B", count_of="entries"),
        PacketListField("entries", [], RoutingTableEntryPacket, count_from=lambda pkt: pkt.entry_count),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} ("
        summary += f"next_hdl=0x{self.next_entry_handle:02X}, cnt={self.entry_count}) "
        for entry in self.entries:
            summary += f" [0x{entry.starting_eid:02X}:{entry.eid_range}]"
        return summary, [ControlHdrPacket]


# Keep backward compatibility alias
GetRoutingTableEntriesPacket = GetRoutingTableEntriesRequestPacket


def GetRoutingTableEntries(
    _pkt: bytes | bytearray = b"", /, *, entry_handle: int = 0
) -> GetRoutingTableEntriesRequestPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetRoutingTableEntries)
    if _pkt:
        return GetRoutingTableEntriesRequestPacket(_pkt, _underlayer=hdr)
    return GetRoutingTableEntriesRequestPacket(
        entry_handle=entry_handle,
        _underlayer=hdr,
    )


def GetRoutingTableEntriesResponse(
    _pkt: bytes | bytearray = b"", /, *, next_entry_handle: int, entries: list[int] | None = None
) -> GetRoutingTableEntriesResponsePacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.GetRoutingTableEntries)
    if _pkt:
        return GetRoutingTableEntriesResponsePacket(_pkt, _underlayer=hdr)
    return GetRoutingTableEntriesResponsePacket(
        next_entry_handle=next_entry_handle,
        entry_count=len(entries),
        entries=entries,
        _underlayer=hdr,
    )
