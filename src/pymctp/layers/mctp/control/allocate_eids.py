# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from enum import IntEnum

from scapy.fields import XByteEnumField, XByteField
from scapy.packet import Packet

from .. import EndpointContext
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, set_control_fields
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


class AllocateEIDOperation(IntEnum):
    ALLOCATE_EIDS = 0
    FORCE_ALLOCATION = 1
    GET_ALLOCATION_INFO = 2


class AllocateEIDAllocationStatus(IntEnum):
    ACCEPTED = 0
    REJECTED = 1


@AutobindControlMsg(ContrlCmdCodes.AllocateEndpointIDs)
class AllocateEndpointIDsPacket(Packet):
    fields_desc = set_control_fields(
        rq_fields=[
            XByteEnumField("op", 0, AllocateEIDOperation),
            XByteField("allocated_pool_size", 0),
            XByteField("starting_eid", 0),
        ],
        rsp_fields=[
            XByteEnumField("status", 0, AllocateEIDAllocationStatus),
            XByteField("eid_pool_size", 0),
            XByteField("first_eid", 0),
        ],
    )

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        if not ctx.is_bus_owner:
            return CompletionCodes.ERROR_UNSUPPORTED_CMD, None

        status = AllocateEIDAllocationStatus.ACCEPTED
        eid_pool_size = ctx.pool_size if ctx.allocated_pool else 0
        first_eid = ctx.allocated_pool[0] if ctx.allocated_pool else 0

        if self.op != AllocateEIDOperation.GET_ALLOCATION_INFO:
            if self.op == AllocateEIDOperation.ALLOCATE_EIDS and ctx.allocated_pool:
                status = AllocateEIDAllocationStatus.REJECTED
            elif self.allocated_pool_size != 0:
                ctx.allocated_pool = list(range(self.starting_eid, self.starting_eid + self.allocated_pool_size))
                first_eid = ctx.allocated_pool[0]
            elif self.op == AllocateEIDOperation.FORCE_ALLOCATION:
                # Asking us to clear our EID allocation pool
                # TODO: signal to runtime that the routing table needs to be rebuilt
                ctx.allocated_pool = None
                first_eid = 0
        return CompletionCodes.SUCCESS, AllocateEndpointIDsResponse(
            status=status,
            eid_pool_size=eid_pool_size,
            first_eid=first_eid,
        )


def AllocateEndpointIDs(
    _pkt: bytes | bytearray = b"", /, *, op: AllocateEIDOperation, allocated_pool_size: int, starting_eid: int
) -> AllocateEndpointIDsPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.AllocateEndpointIDs)
    if _pkt:
        return AllocateEndpointIDsPacket(_pkt, _underlayer=hdr)
    return AllocateEndpointIDsPacket(
        op=op,
        allocated_pool_size=allocated_pool_size,
        starting_eid=starting_eid,
        _underlayer=hdr,
    )


def AllocateEndpointIDsResponse(
    _pkt: bytes | bytearray = b"", /, *, status: AllocateEIDAllocationStatus, eid_pool_size: int, first_eid: int
):
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.AllocateEndpointIDs)
    if _pkt:
        return AllocateEndpointIDsPacket(_pkt, _underlayer=hdr)
    return AllocateEndpointIDsPacket(
        status=status,
        eid_pool_size=eid_pool_size,
        first_eid=first_eid,
        _underlayer=hdr,
    )
