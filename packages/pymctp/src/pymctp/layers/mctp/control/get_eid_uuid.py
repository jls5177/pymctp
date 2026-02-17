# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import uuid

from scapy.fields import UUIDField
from scapy.packet import Packet

from .. import EndpointContext, TransportHdrPacket
from ..types import AnyPacketType
from .control import (
    AutobindControlMsg,
    ControlHdr,
    ControlHdrPacket,
)
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.GetEndpointUUID, is_request=True)
class GetEndpointUUIDRequestPacket(Packet):
    name = "GetEndpointUUID"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        if not ctx.endpoint_uuid:
            return CompletionCodes.ERROR_UNSUPPORTED_CMD, None
        return CompletionCodes.SUCCESS, GetEndpointUUIDResponse(uuid=ctx.endpoint_uuid)


@AutobindControlMsg(ContrlCmdCodes.GetEndpointUUID, is_request=False)
class GetEndpointUUIDResponsePacket(Packet):
    name = "GetEndpointUUID"
    fields_desc = [UUIDField("uuid", None, uuid_fmt=UUIDField.FORMAT_BE)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (uuid: {self.uuid})"
        return summary, [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
GetEndpointUUIDPacket = GetEndpointUUIDRequestPacket


def GetEndpointUUID(*args) -> GetEndpointUUIDRequestPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetEndpointUUID)
    if len(args):
        return GetEndpointUUIDRequestPacket(*args, _underlayer=hdr)
    return GetEndpointUUIDRequestPacket(_underlayer=hdr)


def GetEndpointUUIDResponse(*args, uuid: uuid.UUID | None = None) -> GetEndpointUUIDResponsePacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.GetEndpointUUID)
    if len(args):
        return GetEndpointUUIDResponsePacket(*args, _underlayer=hdr)
    return GetEndpointUUIDResponsePacket(
        uuid=uuid,
        _underlayer=hdr,
    )
