# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import FieldLenField, FieldListField, XByteField
from scapy.packet import Packet

from .. import EndpointContext, TransportHdrPacket
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, ControlHdrPacket
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.ResolveEndpointID, is_request=True)
class ResolveEndpointIDRequestPacket(Packet):
    name = "ResolveEndpointID"
    fields_desc = [
        XByteField("target_eid", 0),
    ]

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        if not ctx.is_bus_owner:
            return CompletionCodes.ERROR_UNSUPPORTED_CMD, None

        # Search routing table for the target EID
        for entry in ctx.routing_table:
            if entry.starting_eid <= self.target_eid < entry.starting_eid + entry.eid_range:
                return CompletionCodes.SUCCESS, ResolveEndpointIDResponse(
                    bridge_eid=ctx.eid,
                    phys_address=list(entry.phy_address),
                )

        return CompletionCodes.ERROR_INVALID_DATA, None

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (target_eid: 0x{self.target_eid:02X})"
        return summary, [ControlHdrPacket, TransportHdrPacket]


@AutobindControlMsg(ContrlCmdCodes.ResolveEndpointID, is_request=False)
class ResolveEndpointIDResponsePacket(Packet):
    name = "ResolveEndpointID"
    fields_desc = [
        XByteField("bridge_eid", 0),
        FieldLenField("phys_address_size", None, fmt="B", count_of="phys_address"),
        FieldListField("phys_address", [], XByteField("", 0), count_from=lambda pkt: pkt.phys_address_size),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        addr = ":".join(f"{b:02X}" for b in self.phys_address) if self.phys_address else "none"
        summary = f"{self.name} (bridge_eid: 0x{self.bridge_eid:02X}, addr: {addr})"
        return summary, [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
ResolveEndpointIDPacket = ResolveEndpointIDRequestPacket


def ResolveEndpointID(_pkt: bytes | bytearray = b"", /, *, target_eid: int = 0) -> ResolveEndpointIDRequestPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.ResolveEndpointID)
    if _pkt:
        return ResolveEndpointIDRequestPacket(_pkt, _underlayer=hdr)
    return ResolveEndpointIDRequestPacket(
        target_eid=target_eid,
        _underlayer=hdr,
    )


def ResolveEndpointIDResponse(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    bridge_eid: int = 0,
    phys_address: list[int] | None = None,
) -> ResolveEndpointIDResponsePacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.ResolveEndpointID)
    if _pkt:
        return ResolveEndpointIDResponsePacket(_pkt, _underlayer=hdr)
    return ResolveEndpointIDResponsePacket(
        bridge_eid=bridge_eid,
        phys_address_size=len(phys_address) if phys_address else 0,
        phys_address=phys_address or [],
        _underlayer=hdr,
    )
