from typing import Tuple

from scapy.packet import Packet

from .control import (
    AutobindControlMsg,
    ControlHdr
)
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes
from .. import EndpointContext
from ..types import AnyPacketType


@AutobindControlMsg(ContrlCmdCodes.DiscoveryNotify)
class DiscoveryNotifyPacket(Packet):
    fields_desc = []

    def make_ctrl_reply(self, ctx: EndpointContext) -> Tuple[CompletionCode, AnyPacketType]:
        return CompletionCodes.SUCCESS, DiscoveryNotifyResponse()


def DiscoveryNotify(*args, **kwargs):
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.DiscoveryNotify)
    if len(args):
        return DiscoveryNotifyPacket(*args, _underlayer=hdr)
    return DiscoveryNotifyPacket(
        _underlayer=hdr,
    )


def DiscoveryNotifyResponse(*args, **kwargs):
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.DiscoveryNotify)
    if len(args) or len(kwargs):
        return DiscoveryNotifyPacket(*args, _underlayer=hdr, **kwargs)
    return DiscoveryNotifyPacket(
        _underlayer=hdr,
    )
