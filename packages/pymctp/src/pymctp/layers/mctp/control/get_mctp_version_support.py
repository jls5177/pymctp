# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import FieldLenField, FieldListField, XByteField, XLEIntField
from scapy.packet import Packet

from .. import EndpointContext, TransportHdrPacket
from ..types import AnyPacketType
from .control import (
    AutobindControlMsg,
    ControlHdr,
    ControlHdrPacket,
)
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes
from ...helpers import AllowRawSummary

MCTP_BASE_SPEC_VERSION_1_3_1 = 0xF1F3F100
MCTP_CONTROL_VERSION_1_3_1 = 0xF1F3F100


@AutobindControlMsg(ContrlCmdCodes.GetMCTPVersionSupport, is_request=True)
class GetMctpVersionSupportRequestPacket(AllowRawSummary, Packet):
    name = "GetMctpVersionSupport"

    fields_desc = [
        XByteField("msg_type_number", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} ("
        summary += f"msg_type_number: {self.msg_type_number}"
        summary += ")"
        return summary, [ControlHdrPacket, TransportHdrPacket]

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        msg_type_number = self.msg_type_number

        version_numbers = []
        if msg_type_number == 0:
            version_numbers += [MCTP_CONTROL_VERSION_1_3_1]
        elif msg_type_number == 0xFF:
            version_numbers += [MCTP_BASE_SPEC_VERSION_1_3_1]

        if version_numbers:
            return CompletionCodes.SUCCESS, GetMctpVersionSupportResponse(
                version_number_list=version_numbers,
            )

        # if we made it hear then the msg_type is unsupported
        # 0x80: message type number not supported
        return 0x80, None


@AutobindControlMsg(ContrlCmdCodes.GetMCTPVersionSupport, is_request=False)
class GetMctpVersionSupportResponsePacket(AllowRawSummary, Packet):
    name = "GetMctpVersionSupport"

    fields_desc = [
        FieldLenField("version_number_entry_count", None, fmt="!B", count_of="version_number_list"),
        FieldListField(
            "version_number_list", [], XLEIntField("", 0), count_from=lambda pkt: pkt.version_number_entry_count
        ),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} ("
        if self.version_number_entry_count != 0:
            summary += ", ".join(f"0x{x:08X}" for x in self.version_number_list)
        summary += ")"
        return summary, [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
GetMctpVersionSupportPacket = GetMctpVersionSupportRequestPacket


def GetMctpVersionSupport(
    _pkt: bytes | bytearray = b"", /, *, msg_type_number: int = 0
) -> GetMctpVersionSupportRequestPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetMCTPVersionSupport)
    if _pkt:
        return GetMctpVersionSupportRequestPacket(_pkt, _underlayer=hdr)
    return GetMctpVersionSupportRequestPacket(
        msg_type_number=msg_type_number,
        _underlayer=hdr,
    )


def GetMctpVersionSupportResponse(
    _pkt: bytes | bytearray = b"", /, *, version_number_list: list[int] | None = None
) -> GetMctpVersionSupportResponsePacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.GetMCTPVersionSupport)
    if _pkt:
        return GetMctpVersionSupportResponsePacket(_pkt, _underlayer=hdr)
    return GetMctpVersionSupportResponsePacket(
        version_number_list=version_number_list,
        _underlayer=hdr,
    )
