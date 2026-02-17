# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.packet import Packet

from .. import TransportHdrPacket
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, ControlHdrPacket
from .types import ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.RequestTXRateLimit, is_request=True)
class RequestTXRateLimitRequestPacket(Packet):
    name = "RequestTXRateLimit"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]


@AutobindControlMsg(ContrlCmdCodes.RequestTXRateLimit, is_request=False)
class RequestTXRateLimitResponsePacket(Packet):
    name = "RequestTXRateLimit"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
RequestTXRateLimitPacket = RequestTXRateLimitRequestPacket


def RequestTXRateLimit(*args, **kwargs):
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.RequestTXRateLimit)
    if len(args):
        return RequestTXRateLimitRequestPacket(*args, _underlayer=hdr)
    return RequestTXRateLimitRequestPacket(
        _underlayer=hdr,
    )


def RequestTXRateLimitResponse(*args, **kwargs):
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.RequestTXRateLimit)
    if len(args) or len(kwargs):
        return RequestTXRateLimitResponsePacket(*args, _underlayer=hdr, **kwargs)
    return RequestTXRateLimitResponsePacket(
        _underlayer=hdr,
    )
