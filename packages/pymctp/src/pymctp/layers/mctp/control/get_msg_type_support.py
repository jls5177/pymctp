# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import ByteField, FieldLenField, FieldListField
from scapy.packet import Packet

from .. import EndpointContext, TransportHdrPacket
from ..types import AnyPacketType
from .control import (
    AutobindControlMsg,
    ControlHdr,
    ControlHdrPacket,
)
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.GetMessageTypeSupport, is_request=True)
class GetMessageTypeSupportRequestPacket(Packet):
    name = "GetMessageTypeSupport"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        if not ctx.supported_msg_types:
            return CompletionCodes.ERROR_UNSUPPORTED_CMD, None
        msg_types = ctx.supported_msg_types
        return CompletionCodes.SUCCESS, GetMessageTypeSupportResponse(
            msg_types=msg_types,
        )


@AutobindControlMsg(ContrlCmdCodes.GetMessageTypeSupport, is_request=False)
class GetMessageTypeSupportResponsePacket(Packet):
    name = "GetMessageTypeSupport"
    fields_desc = [
        FieldLenField("msg_type_cnt", None, fmt="!B", count_of="msg_type_list"),
        FieldListField("msg_type_list", [], ByteField("", 0), length_from=lambda pkt: pkt.msg_type_cnt),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        types = ", ".join(f"0x{t:02X}" for t in self.msg_type_list)
        summary = f"{self.name} (cnt: {self.msg_type_cnt}, types: [{types}])"
        return summary, [ControlHdrPacket]


# Keep backward compatibility alias
GetMessageTypeSupportPacket = GetMessageTypeSupportRequestPacket


def GetMessageTypeSupport(_pkt: bytes | bytearray = b"", /, *args) -> GetMessageTypeSupportRequestPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetMessageTypeSupport)
    if _pkt:
        return GetMessageTypeSupportRequestPacket(_pkt, _underlayer=hdr)
    return GetMessageTypeSupportRequestPacket(_underlayer=hdr)


def GetMessageTypeSupportResponse(
    _pkt: bytes | bytearray = b"", /, *, msg_types: list[int] | None = None
) -> GetMessageTypeSupportResponsePacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.GetMessageTypeSupport)
    if _pkt:
        return GetMessageTypeSupportResponsePacket(_pkt, _underlayer=hdr)
    return GetMessageTypeSupportResponsePacket(
        msg_type_cnt=len(msg_types),
        msg_type_list=msg_types,
        _underlayer=hdr,
    )
