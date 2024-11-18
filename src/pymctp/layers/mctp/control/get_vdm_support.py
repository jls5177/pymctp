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
    set_control_fields,
)
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes

NO_MORE_CAPABILITY_SETS = 0xFF


@AutobindControlMsg(ContrlCmdCodes.GetVendorDefinedMessageSupport)
class GetVendorDefinedMessageSupportPacket(AllowRawSummary, Packet):
    fields_desc = set_control_fields(
        rq_fields=[
            XByteField("vendor_id_set_selector", 0),
        ],
        rsp_fields=[
            XByteField("next_vendor_id_set_selector", 0),
            ByteEnumField("vendor_id_format", 0, VendorIdFormat),
            MultipleTypeField(
                [
                    (XIntField("vendor_id", 0), lambda pkt: pkt.vendor_id_format == VendorIdFormat.IANA_ENT_NUMBER),
                ],
                XShortField("vendor_id", 0),
            ),
            XShortField("command_set_type", 0),
        ],
    )

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        if not ctx.supported_vdm_msg_types or self.vendor_id_set_selector >= len(ctx.supported_vdm_msg_types):
            # invalid request
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


def GetVendorDefinedMessageSupport(_pkt: bytes | bytearray = b"", /, *, set_selector: int = 0):
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetVendorDefinedMessageSupport)
    if _pkt:
        return GetVendorDefinedMessageSupportPacket(_pkt, _underlayer=hdr)
    return GetVendorDefinedMessageSupportPacket(
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
        return GetVendorDefinedMessageSupportPacket(_pkt, _underlayer=hdr)
    return GetVendorDefinedMessageSupportPacket(
        next_vendor_id_set_selector=set_selector,
        vendor_id_format=vendor_id_fmt,
        vendor_id=vendor_id,
        command_set_type=command_set_type,
        _underlayer=hdr,
    )
