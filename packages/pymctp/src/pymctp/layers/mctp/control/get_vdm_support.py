# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import ByteEnumField, MultipleTypeField, XByteField, XIntField, XShortField
from scapy.packet import Packet

from ...helpers import AllowRawSummary
from .. import EndpointContext
from ..types import AnyPacketType, VendorCapabilitySet, VendorIdFormat
from .control import (
    AutobindControlMsg,
    ControlHdr,
    ControlHdrPacket,
)
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes

NO_MORE_CAPABILITY_SETS = 0xFF


@AutobindControlMsg(ContrlCmdCodes.GetVendorDefinedMessageSupport, is_request=True)
class GetVendorDefinedMessageSupportRequestPacket(AllowRawSummary, Packet):
    fields_desc = [
        XByteField("vendor_id_set_selector", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = "GetVendorDefinedMessageSupport ("
        summary += f"sel={self.vendor_id_set_selector}"
        summary += ")"
        return summary, [ControlHdrPacket]

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        if not ctx.supported_vdm_msg_types or self.vendor_id_set_selector >= len(ctx.supported_vdm_msg_types):
            return CompletionCodes.ERROR_INVALID_DATA, None

        cap_set: VendorCapabilitySet = ctx.supported_vdm_msg_types[self.vendor_id_set_selector]

        next_set_selector = self.vendor_id_set_selector + 1
        if next_set_selector >= len(ctx.supported_vdm_msg_types):
            next_set_selector = NO_MORE_CAPABILITY_SETS

        return CompletionCodes.SUCCESS, GetVendorDefinedMessageSupportResponse(
            set_selector=next_set_selector,
            vendor_id_fmt=cap_set.id_format,
            vendor_id=cap_set.vendor_id,
            command_set_type=cap_set.command_set_type,
        )


@AutobindControlMsg(ContrlCmdCodes.GetVendorDefinedMessageSupport, is_request=False)
class GetVendorDefinedMessageSupportResponsePacket(AllowRawSummary, Packet):
    fields_desc = [
        XByteField("next_vendor_id_set_selector", 0),
        ByteEnumField("vendor_id_format", 0, VendorIdFormat),
        MultipleTypeField(
            [
                (XIntField("vendor_id", 0), lambda pkt: pkt.vendor_id_format == VendorIdFormat.IANA_ENT_NUMBER),
            ],
            XShortField("vendor_id", 0),
        ),
        XShortField("command_set_type", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = "GetVendorDefinedMessageSupport ("
        summary += f"next_sel={self.next_vendor_id_set_selector}"
        summary += f", vendor_id={self.vendor_id:04X}, cmd_set_type={self.command_set_type:04X}"
        summary += ")"
        return summary, [GetVendorDefinedMessageSupportResponsePacket, ControlHdrPacket]


# Keep backward compatibility alias
GetVendorDefinedMessageSupportPacket = GetVendorDefinedMessageSupportRequestPacket


def GetVendorDefinedMessageSupport(_pkt: bytes | bytearray = b"", /, *, set_selector: int = 0):
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetVendorDefinedMessageSupport)
    if _pkt:
        return GetVendorDefinedMessageSupportRequestPacket(_pkt, _underlayer=hdr)
    return GetVendorDefinedMessageSupportRequestPacket(
        vendor_id_set_selector=set_selector,
        _underlayer=hdr,
    )


def GetVendorDefinedMessageSupportResponse(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    set_selector: int = 0,
    vendor_id_fmt: VendorIdFormat = VendorIdFormat.PCI_VENDOR_ID,
    vendor_id: int = 0,
    command_set_type: int = 0,
):
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.GetVendorDefinedMessageSupport)
    if _pkt:
        return GetVendorDefinedMessageSupportResponsePacket(_pkt, _underlayer=hdr)
    return GetVendorDefinedMessageSupportResponsePacket(
        next_vendor_id_set_selector=set_selector,
        vendor_id_format=vendor_id_fmt,
        vendor_id=vendor_id,
        command_set_type=command_set_type,
        _underlayer=hdr,
    )
