# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.packet import Packet

from .. import EndpointContext, TransportHdrPacket
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, ControlHdrPacket
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.PrepareForEndpointDiscovery, is_request=True)
class PrepareForEndpointDiscoveryRequestPacket(Packet):
    name = "PrepareForEndpointDiscovery"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        ctx.discovered = False
        return CompletionCodes.SUCCESS, PrepareForEndpointDiscoveryResponse()


@AutobindControlMsg(ContrlCmdCodes.PrepareForEndpointDiscovery, is_request=False)
class PrepareForEndpointDiscoveryResponsePacket(Packet):
    name = "PrepareForEndpointDiscovery"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
PrepareForEndpointDiscoveryPacket = PrepareForEndpointDiscoveryRequestPacket


def PrepareForEndpointDiscovery(*args, **kwargs):
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.PrepareForEndpointDiscovery)
    if len(args):
        return PrepareForEndpointDiscoveryRequestPacket(*args, _underlayer=hdr)
    return PrepareForEndpointDiscoveryRequestPacket(
        _underlayer=hdr,
    )


def PrepareForEndpointDiscoveryResponse(*args, **kwargs):
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.PrepareForEndpointDiscovery)
    if len(args) or len(kwargs):
        return PrepareForEndpointDiscoveryResponsePacket(*args, _underlayer=hdr, **kwargs)
    return PrepareForEndpointDiscoveryResponsePacket(
        _underlayer=hdr,
    )
