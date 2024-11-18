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
    RqBit,
    set_control_fields,
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


@AutobindControlMsg(ContrlCmdCodes.GetRoutingTableEntries)
class GetRoutingTableEntriesPacket(AllowRawSummary, Packet):
    name = "GetRoutingTableEntries"

    fields_desc = set_control_fields(
        # TODO: define response fields
        rq_fields=[
            XByteField("entry_handle", 0),
        ],
        rsp_fields=[
            XByteField("next_entry_handle", 0),
            FieldLenField("entry_count", None, fmt="B", count_of="entries"),
            # TODO: implement routing table entry field
            PacketListField("entries", [], RoutingTableEntryPacket, count_from=lambda pkt: pkt.entry_count),
        ],
    )

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        # if we made it hear then the msg_type is unsupported
        # 0x80: message type number not supported
        if not ctx.routing_table_ready:
            return CompletionCodes.ERROR_NOT_READY, None

        rt_entries = [NewRoutingTableEntry(e) for e in ctx.routing_table]
        return CompletionCodes.SUCCESS, GetRoutingTableEntriesResponse(next_entry_handle=0xFF, entries=rt_entries)

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} ("
        if self.underlayer.getfieldval("rq") == RqBit.REQUEST.value:
            summary += f"hdl=0x{self.entry_handle:02X})"
        else:
            summary += f"next_hdl=0x{self.next_entry_handle:02X}, cnt={self.entry_count}) "
            for entry in self.entries:
                summary += f" [0x{entry.starting_eid:02X}:{entry.eid_range}]"
        return summary, [ControlHdrPacket]


def GetRoutingTableEntries(_pkt: bytes | bytearray = b"", /, *, entry_handle: int = 0) -> GetRoutingTableEntriesPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetRoutingTableEntries)
    if _pkt:
        return GetRoutingTableEntriesPacket(_pkt, _underlayer=hdr)
    return GetRoutingTableEntriesPacket(
        entry_handle=entry_handle,
        _underlayer=hdr,
    )


def GetRoutingTableEntriesResponse(
    _pkt: bytes | bytearray = b"", /, *, next_entry_handle: int, entries: list[int] | None = None
) -> GetRoutingTableEntriesPacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.GetRoutingTableEntries)
    if _pkt:
        return GetRoutingTableEntriesPacket(_pkt, _underlayer=hdr)
    return GetRoutingTableEntriesPacket(
        next_entry_handle=next_entry_handle,
        entry_count=len(entries),
        entries=entries,
        # add a default underlayer to set the required "rq" field
        _underlayer=hdr,
    )
