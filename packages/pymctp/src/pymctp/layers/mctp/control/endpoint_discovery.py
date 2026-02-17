# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.packet import Packet

from .. import EndpointContext, TransportHdrPacket
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, ControlHdrPacket
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.EndpointDiscovery, is_request=True)
class EndpointDiscoveryRequestPacket(Packet):
    name = "EndpointDiscovery"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        return CompletionCodes.SUCCESS, EndpointDiscoveryResponse()


@AutobindControlMsg(ContrlCmdCodes.EndpointDiscovery, is_request=False)
class EndpointDiscoveryResponsePacket(Packet):
    name = "EndpointDiscovery"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
EndpointDiscoveryPacket = EndpointDiscoveryRequestPacket


def EndpointDiscovery(*args, **kwargs):
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.EndpointDiscovery)
    if len(args):
        return EndpointDiscoveryRequestPacket(*args, _underlayer=hdr)
    return EndpointDiscoveryRequestPacket(
        _underlayer=hdr,
    )


def EndpointDiscoveryResponse(*args, **kwargs):
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.EndpointDiscovery)
    if len(args) or len(kwargs):
        return EndpointDiscoveryResponsePacket(*args, _underlayer=hdr, **kwargs)
    return EndpointDiscoveryResponsePacket(
        _underlayer=hdr,
    )
