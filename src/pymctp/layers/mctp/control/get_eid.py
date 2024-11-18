# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from enum import IntEnum

from scapy.fields import BitEnumField, BitField, XByteField
from scapy.packet import Packet

from .. import EndpointContext, TransportHdrPacket
from ..types import AnyPacketType
from .control import (
    AutobindControlMsg,
    ControlHdr,
    ControlHdrPacket,
    set_control_fields,
)
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


class EndpointType(IntEnum):
    SIMPLE = 0
    """Simple Endpoint"""

    BUS_OWNER = 1
    """Bus Owner and/or Bridge"""


class EndpointIDType(IntEnum):
    DYNAMIC = 0
    """The endpoint uses a dynamic EID only"""

    STATIC_EID_SUPPORTED = 1
    """The EID returned by this command reflects the present setting and may or
    may not match the static EID value."""

    STATIC_EID_MATCH = 2
    """The endpoint has been configured with a static EID. The present value is
    the same as the static value."""

    STATIC_EID_MISMATCH = 3
    """ Endpoint has been configured with a static EID. The present value is
    different than the static value"""


@AutobindControlMsg(ContrlCmdCodes.GetEndpointID)
class GetEndpointIDPacket(Packet):
    name = "GetEndpointID"

    fields_desc = set_control_fields(
        rsp_fields=[
            XByteField("eid", 0),
            BitField("unused", 0, 2),
            BitEnumField("endpoint_type", 0, 2, EndpointType),
            BitField("unused2", 0, 2),
            BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
            XByteField("medium_specific", 0),
        ],
    )

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name}"
        if self.underlayer.getfieldval("rq") == 0:
            summary += f" (eid: {self.eid:02X}, type: "
            summary += "simple, " if self.endpoint_type == 0 else "busowner, "
            if self.endpoint_id_type == EndpointIDType.DYNAMIC.value:
                summary += "eid_type: dynamic"
            elif self.endpoint_id_type == EndpointIDType.STATIC_EID_SUPPORTED.value:
                summary += "eid_type: static_eid_supported"
            elif self.endpoint_id_type == EndpointIDType.STATIC_EID_MATCH.value:
                summary += "eid_type: static_eid_match"
            elif self.endpoint_id_type == EndpointIDType.STATIC_EID_MISMATCH.value:
                summary += "eid_type: static_eid_mismatch"
            summary += ")"
        return summary, [ControlHdrPacket, TransportHdrPacket]

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        cmplt_code = CompletionCodes.SUCCESS
        endp_type = EndpointIDType.DYNAMIC
        if ctx.static_eid:
            endp_type = EndpointIDType.STATIC_EID_SUPPORTED
            if ctx.assigned_eid:
                if ctx.assigned_eid == ctx.static_eid:
                    endp_type = EndpointIDType.STATIC_EID_MATCH
                else:
                    endp_type = EndpointIDType.STATIC_EID_MISMATCH
        return cmplt_code, GetEndpointIDResponse(
            eid=ctx.eid,
            endpoint_type=EndpointType.BUS_OWNER if ctx.is_bus_owner else EndpointType.SIMPLE,
            endpoint_id_type=endp_type,
        )


def GetEndpointID(*args) -> GetEndpointIDPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetEndpointID)
    if len(args):
        return GetEndpointIDPacket(*args, _underlayer=hdr)
    return GetEndpointIDPacket(_underlayer=hdr)


def GetEndpointIDResponse(
    *args,
    eid: int = 0,
    endpoint_type: EndpointType = EndpointType.SIMPLE,
    endpoint_id_type: EndpointIDType = EndpointIDType.DYNAMIC,
    medium_specific: int = 0,
) -> GetEndpointIDPacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.GetEndpointID)
    if len(args):
        return GetEndpointIDPacket(*args, _underlayer=hdr)
    return GetEndpointIDPacket(
        eid=eid,
        endpoint_type=endpoint_type,
        endpoint_id_type=endpoint_id_type,
        medium_specific=medium_specific,
        # add a default underlayer to set the required "rq" field
        _underlayer=hdr,
    )
