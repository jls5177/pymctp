# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.packet import Packet

from .. import TransportHdrPacket
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, ControlHdrPacket
from .types import ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.UpdateRateLimit, is_request=True)
class UpdateRateLimitRequestPacket(Packet):
    name = "UpdateRateLimit"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]


@AutobindControlMsg(ContrlCmdCodes.UpdateRateLimit, is_request=False)
class UpdateRateLimitResponsePacket(Packet):
    name = "UpdateRateLimit"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
UpdateRateLimitPacket = UpdateRateLimitRequestPacket


def UpdateRateLimit(*args, **kwargs):
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.UpdateRateLimit)
    if len(args):
        return UpdateRateLimitRequestPacket(*args, _underlayer=hdr)
    return UpdateRateLimitRequestPacket(
        _underlayer=hdr,
    )


def UpdateRateLimitResponse(*args, **kwargs):
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.UpdateRateLimit)
    if len(args) or len(kwargs):
        return UpdateRateLimitResponsePacket(*args, _underlayer=hdr, **kwargs)
    return UpdateRateLimitResponsePacket(
        _underlayer=hdr,
    )
