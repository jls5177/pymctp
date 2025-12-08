# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import ByteField, FieldLenField, FieldListField
from scapy.packet import Packet

from .. import EndpointContext
from ..types import AnyPacketType
from .control import (
    AutobindControlMsg,
    ControlHdr,
    set_control_fields,
)
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.GetMessageTypeSupport)
class GetMessageTypeSupportPacket(Packet):
    name = "GetMessageTypeSupport"

    fields_desc = set_control_fields(
        rsp_fields=[
            FieldLenField("msg_type_cnt", None, fmt="!B", count_of="msg_type_list"),
            FieldListField("msg_type_list", [], ByteField("", 0), length_from=lambda pkt: pkt.msg_type_cnt),
        ]
    )

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        if not ctx.supported_msg_types:
            return CompletionCodes.ERROR_UNSUPPORTED_CMD, None
        # filter out the Control msg types
        msg_types = ctx.supported_msg_types
        # msg_types = [t for t in ctx.supported_msg_types if t != MsgTypes.MctpControl]
        return CompletionCodes.SUCCESS, GetMessageTypeSupportResponse(
            msg_types=msg_types,
        )


def GetMessageTypeSupport(_pkt: bytes | bytearray = b"", /, *args) -> GetMessageTypeSupportPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetMessageTypeSupport)
    if _pkt:
        return GetMessageTypeSupportPacket(_pkt, _underlayer=hdr)
    return GetMessageTypeSupportPacket(_underlayer=hdr)


def GetMessageTypeSupportResponse(
    _pkt: bytes | bytearray = b"", /, *, msg_types: list[int] | None = None
) -> GetMessageTypeSupportPacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.GetMessageTypeSupport)
    if _pkt:
        return GetMessageTypeSupportPacket(_pkt, _underlayer=hdr)
    return GetMessageTypeSupportPacket(
        msg_type_cnt=len(msg_types),
        msg_type_list=msg_types,
        # add a default underlayer to set the required "rq" field
        _underlayer=hdr,
    )
