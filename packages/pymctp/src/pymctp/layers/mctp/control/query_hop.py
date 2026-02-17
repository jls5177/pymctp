# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import ShortField, XByteField
from scapy.packet import Packet

from .. import TransportHdrPacket
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, ControlHdrPacket
from .types import ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.QueryHop, is_request=True)
class QueryHopRequestPacket(Packet):
    name = "QueryHop"
    fields_desc = [
        XByteField("target_eid", 0),
        XByteField("mctp_ctrl_msg_type", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (target_eid: 0x{self.target_eid:02X}"
        summary += f", msg_type: 0x{self.mctp_ctrl_msg_type:02X})"
        return summary, [ControlHdrPacket, TransportHdrPacket]


@AutobindControlMsg(ContrlCmdCodes.QueryHop, is_request=False)
class QueryHopResponsePacket(Packet):
    name = "QueryHop"
    fields_desc = [
        XByteField("next_bridge_eid", 0),
        XByteField("mctp_ctrl_msg_type", 0),
        ShortField("max_incoming_unit_size", 64),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (next_bridge: 0x{self.next_bridge_eid:02X}"
        summary += f", msg_type: 0x{self.mctp_ctrl_msg_type:02X}"
        summary += f", max_unit: {self.max_incoming_unit_size})"
        return summary, [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
QueryHopPacket = QueryHopRequestPacket


def QueryHop(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    target_eid: int = 0,
    mctp_ctrl_msg_type: int = 0,
) -> QueryHopRequestPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.QueryHop)
    if _pkt:
        return QueryHopRequestPacket(_pkt, _underlayer=hdr)
    return QueryHopRequestPacket(
        target_eid=target_eid,
        mctp_ctrl_msg_type=mctp_ctrl_msg_type,
        _underlayer=hdr,
    )


def QueryHopResponse(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    next_bridge_eid: int = 0,
    mctp_ctrl_msg_type: int = 0,
    max_incoming_unit_size: int = 64,
) -> QueryHopResponsePacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.QueryHop)
    if _pkt:
        return QueryHopResponsePacket(_pkt, _underlayer=hdr)
    return QueryHopResponsePacket(
        next_bridge_eid=next_bridge_eid,
        mctp_ctrl_msg_type=mctp_ctrl_msg_type,
        max_incoming_unit_size=max_incoming_unit_size,
        _underlayer=hdr,
    )
