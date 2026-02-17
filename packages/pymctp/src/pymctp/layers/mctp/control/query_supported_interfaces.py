# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.packet import Packet

from .. import TransportHdrPacket
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, ControlHdrPacket
from .types import ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.QuerySupportedInterfaces, is_request=True)
class QuerySupportedInterfacesRequestPacket(Packet):
    name = "QuerySupportedInterfaces"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]


@AutobindControlMsg(ContrlCmdCodes.QuerySupportedInterfaces, is_request=False)
class QuerySupportedInterfacesResponsePacket(Packet):
    name = "QuerySupportedInterfaces"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
QuerySupportedInterfacesPacket = QuerySupportedInterfacesRequestPacket


def QuerySupportedInterfaces(*args, **kwargs):
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.QuerySupportedInterfaces)
    if len(args):
        return QuerySupportedInterfacesRequestPacket(*args, _underlayer=hdr)
    return QuerySupportedInterfacesRequestPacket(
        _underlayer=hdr,
    )


def QuerySupportedInterfacesResponse(*args, **kwargs):
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.QuerySupportedInterfaces)
    if len(args) or len(kwargs):
        return QuerySupportedInterfacesResponsePacket(*args, _underlayer=hdr, **kwargs)
    return QuerySupportedInterfacesResponsePacket(
        _underlayer=hdr,
    )
