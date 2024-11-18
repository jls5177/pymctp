# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import uuid

from scapy.fields import UUIDField
from scapy.packet import Packet

from .. import EndpointContext
from ..types import AnyPacketType
from .control import (
    AutobindControlMsg,
    ControlHdr,
    set_control_fields,
)
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.GetEndpointUUID)
class GetEndpointUUIDPacket(Packet):
    name = "GetEndpointUUID"

    # No request fields
    fields_desc = set_control_fields(rsp_fields=[UUIDField("uuid", None, uuid_fmt=UUIDField.FORMAT_BE)])

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        if not ctx.endpoint_uuid:
            return CompletionCodes.ERROR_UNSUPPORTED_CMD, None
        return CompletionCodes.SUCCESS, GetEndpointUUIDResponse(uuid=ctx.endpoint_uuid)


def GetEndpointUUID(*args) -> GetEndpointUUIDPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetEndpointUUID)
    if len(args):
        return GetEndpointUUIDPacket(*args, _underlayer=hdr)
    return GetEndpointUUIDPacket(_underlayer=hdr)


def GetEndpointUUIDResponse(*args, uuid: uuid.UUID | None = None) -> GetEndpointUUIDPacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.GetEndpointUUID)
    if len(args):
        return GetEndpointUUIDPacket(*args, _underlayer=hdr)
    return GetEndpointUUIDPacket(
        uuid=uuid,
        # add a default underlayer to set the required "rq" field
        _underlayer=hdr,
    )
