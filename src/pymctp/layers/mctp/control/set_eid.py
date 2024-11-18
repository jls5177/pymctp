# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from enum import IntEnum

from scapy.fields import BitEnumField, BitField, XByteField
from scapy.packet import Packet

from .. import EndpointContext, TransportHdrPacket
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, ControlHdrPacket, set_control_fields
from .types import CompletionCode, CompletionCodes, ContrlCmdCodes


class SetEndpointIDOperation(IntEnum):
    SetEID = 0
    """Submit an EID for assignment. The given EID will be accepted conditional upon which bus the device received
    the EID from (see preceding text). A device where the endpoint is only reached through one bus shall always
    accept this operation (provided the EID value is legal)."""

    ForceEID = 1
    """Force EID assignment. The given EID will be accepted regardless of whether the EID was already assigned
    through another bus. Note that if the endpoint is forcing, the EID assignment changes which bus is being tracked
    as the originator of the Set Endpoint ID command. A device where the endpoint is only reached through one bus
    shall always accept this operation (provided the EID value is legal), in which case the Set EID and Force EID
    operations are equivalent."""

    ResetEID = 2
    """This option only applies to endpoints that support static EIDs. If static EIDs are supported, the endpoint
    shall restore the EID to the statically configured EID value. The EID value in byte 2 shall be ignored. An
    ERROR_INVALID_DATA completion code shall be returned if this operation is not supported."""

    SetDiscoveredFlag = 3
    """Set Discovered flag to the “discovered” state only. Do not change present EID setting. The EID value in byte 2
    shall be ignored.

    Note that Discovered flag is only used for some physical transport bindings. An
    ERROR_INVALID_DATA completion code shall be returned if this operation is selected and the particular transport
    binding does not support a Discovered flag."""


class SetEndpointIDAssignmentStatus(IntEnum):
    ACCEPTED = 0
    REJECTED = 1


class SetEndpointIDAllocationStatus(IntEnum):
    NO_EID_POOL_REQUIRED = 0
    EID_POOL_REQUIRED = 1
    EID_POOL_ALREADY_ASSIGNED = 2


@AutobindControlMsg(ContrlCmdCodes.SetEndpointID)
class SetEndpointIDPacket(Packet):
    fields_desc = set_control_fields(
        rq_fields=[
            BitField("reserved1", 0, 6),
            BitEnumField("op", 0, 2, SetEndpointIDOperation),
            XByteField("eid", 0),
        ],
        rsp_fields=[
            BitField("reserved2", 0, 2),
            BitEnumField("eid_assignment_status", 0, 2, SetEndpointIDAssignmentStatus),
            BitField("reserved3", 0, 2),
            BitEnumField("eid_allocation_status", 0, 2, SetEndpointIDAllocationStatus),
            XByteField("eid_setting", 0),
            XByteField("eid_pool_size", 0),
        ],
    )

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} ("
        if self.underlayer.getfieldval("rq") == 0:
            summary += "assign_status: "
            summary += "accepted, " if self.eid_assignment_status == 0 else "rejected, "

            summary += "eid_alloc_status: "
            if self.eid_allocation_status == SetEndpointIDAllocationStatus.NO_EID_POOL_REQUIRED.value:
                summary += "no_pool, "
            elif self.eid_allocation_status == SetEndpointIDAllocationStatus.EID_POOL_REQUIRED.value:
                summary += "pool_required, "
            elif self.eid_allocation_status == SetEndpointIDAllocationStatus.EID_POOL_ALREADY_ASSIGNED.value:
                summary += "pool_assigned, "

            summary += f"eid_setting: 0x{self.eid_setting:02X}, eid_pool_size: {self.eid_pool_size}"
        else:
            summary += f"eid: 0x{self.eid:02X}, op: "
            if self.op == SetEndpointIDOperation.SetEID.value:
                summary += "set"
            elif self.op == SetEndpointIDOperation.ForceEID.value:
                summary += "force"
            elif self.op == SetEndpointIDOperation.ResetEID.value:
                summary += "reset"
            elif self.op == SetEndpointIDOperation.SetDiscoveredFlag.value:
                summary += "set_disc"
        summary += ")"
        return summary, [ControlHdrPacket, TransportHdrPacket]

    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        cmplt_code = CompletionCodes.SUCCESS
        op: SetEndpointIDOperation = self.op
        eid: int = self.eid

        assignment_status = SetEndpointIDAssignmentStatus.REJECTED
        if op in (SetEndpointIDOperation.SetEID, SetEndpointIDOperation.ForceEID):
            ctx.assigned_eid = eid
            ctx.discovered = True
            assignment_status = SetEndpointIDAssignmentStatus.ACCEPTED
        elif op == SetEndpointIDOperation.SetDiscoveredFlag:
            ctx.discovered = True
        elif op == SetEndpointIDOperation.ResetEID:
            ctx.assigned_eid = ctx.static_eid
        else:
            return CompletionCodes.ERROR_INVALID_DATA, None

        alloc_status = SetEndpointIDAllocationStatus.NO_EID_POOL_REQUIRED
        if ctx.pool_size:
            if ctx.allocated_pool:
                alloc_status = SetEndpointIDAllocationStatus.EID_POOL_ALREADY_ASSIGNED
            else:
                alloc_status = SetEndpointIDAllocationStatus.EID_POOL_REQUIRED

        return cmplt_code, SetEndpointIDResponse(
            eid_allocation_status=alloc_status,
            eid_pool_size=ctx.pool_size,
            eid_assignment_status=assignment_status,
            eid_setting=ctx.assigned_eid,
        )


def SetEndpointID(*args, op: SetEndpointIDOperation, eid: int) -> Packet:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.SetEndpointID)
    if len(args):
        return SetEndpointIDPacket(*args, _underlayer=hdr)
    return SetEndpointIDPacket(
        op=op,
        eid=eid,
        _underlayer=hdr,
    )


def SetEndpointIDResponse(
    *args,
    eid_assignment_status: SetEndpointIDAssignmentStatus,
    eid_allocation_status: SetEndpointIDAllocationStatus,
    eid_setting: int,
    eid_pool_size: int,
) -> Packet:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.SetEndpointID)
    if len(args):
        return SetEndpointIDPacket(*args, _underlayer=hdr)
    return SetEndpointIDPacket(
        eid_assignment_status=eid_assignment_status,
        eid_allocation_status=eid_allocation_status,
        eid_setting=eid_setting,
        eid_pool_size=eid_pool_size,
        # add a default underlayer to set the required "rq" field
        _underlayer=hdr,
    )
