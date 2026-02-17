# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.packet import Packet

from .. import EndpointContext
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.DiscoveryNotify, is_request=True)
class DiscoveryNotifyRequestPacket(Packet):
    fields_desc = []

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        return CompletionCodes.SUCCESS, DiscoveryNotifyResponse()


@AutobindControlMsg(ContrlCmdCodes.DiscoveryNotify, is_request=False)
class DiscoveryNotifyResponsePacket(Packet):
    fields_desc = []


# Keep backward compatibility alias
DiscoveryNotifyPacket = DiscoveryNotifyRequestPacket


def DiscoveryNotify(*args, **kwargs):
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.DiscoveryNotify)
    if len(args):
        return DiscoveryNotifyRequestPacket(*args, _underlayer=hdr)
    return DiscoveryNotifyRequestPacket(
        _underlayer=hdr,
    )


def DiscoveryNotifyResponse(*args, **kwargs):
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.DiscoveryNotify)
    if len(args) or len(kwargs):
        return DiscoveryNotifyResponsePacket(*args, _underlayer=hdr, **kwargs)
    return DiscoveryNotifyResponsePacket(
        _underlayer=hdr,
    )
