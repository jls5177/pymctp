# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.packet import Packet

from .. import TransportHdrPacket
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, ControlHdrPacket
from .types import ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.QueryRateLimit, is_request=True)
class QueryRateLimitRequestPacket(Packet):
    name = "QueryRateLimit"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]


@AutobindControlMsg(ContrlCmdCodes.QueryRateLimit, is_request=False)
class QueryRateLimitResponsePacket(Packet):
    name = "QueryRateLimit"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
QueryRateLimitPacket = QueryRateLimitRequestPacket


def QueryRateLimit(*args, **kwargs):
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.QueryRateLimit)
    if len(args):
        return QueryRateLimitRequestPacket(*args, _underlayer=hdr)
    return QueryRateLimitRequestPacket(
        _underlayer=hdr,
    )


def QueryRateLimitResponse(*args, **kwargs):
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.QueryRateLimit)
    if len(args) or len(kwargs):
        return QueryRateLimitResponsePacket(*args, _underlayer=hdr, **kwargs)
    return QueryRateLimitResponsePacket(
        _underlayer=hdr,
    )
