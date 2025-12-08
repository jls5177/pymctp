# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""
This module defines the ControlHdrPacket class and related enums and functions
for handling MCTP control header packets.
"""

from collections.abc import Callable
from enum import IntEnum
from typing import Any

from scapy.config import conf
from scapy.fields import (
    AnyField,
    BitEnumField,
    BitField,
    ByteEnumField,
    ConditionalField,
    Emph,
    Field,
    XBitField,
    XByteField,
)
from scapy.packet import Packet, bind_layers

from ...helpers import AllowRawSummary
from ...interfaces import ICanSetMySummaryClasses
from .. import EndpointContext
from ..transport import AutobindMessageType, MsgTypes, SmbusTransportPacket, TransportHdrPacket
from ..types import AnyPacketType
from . import ContrlCmdCodes, IControlMsgCanReply


class RqBit(IntEnum):
    RESPONSE = 0
    REQUEST = 1


@AutobindMessageType(MsgTypes.CTRL)
class ControlHdrPacket(AllowRawSummary, Packet):
    name = "MCTP-Control"
    fields_desc = [
        Emph(BitEnumField("rq", 0, 1, RqBit)),
        BitField("d", 0, 1),
        BitField("unused", 0, 1),
        XBitField("instance_id", 0, 5),
        Emph(ByteEnumField("cmd_code", 0, ContrlCmdCodes)),
        ConditionalField(XByteField("completion_code", 0), lambda pkt: pkt.rq == RqBit.RESPONSE.value),
    ]

    def do_dissect_payload(self, s: bytes) -> None:
        cls = self.guess_payload_class(s)
        try:
            p = cls(s, _internal=1, _underlayer=self)
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector and cls is not None:
                raise
            p = conf.raw_layer(s, _internal=1, _underlayer=self)
        self.add_payload(p)
        if isinstance(p, ICanSetMySummaryClasses):
            p.set_mysummary_classes([self.__class__, self.underlayer.__class__])

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        rqType = "REQ" if self.rq == RqBit.REQUEST.value else "RSP"
        summary = f"CONTROL {rqType} (instance_id: {self.instance_id}, cmd_code={self.cmd_code}"
        if self.rq == RqBit.RESPONSE.value:
            summary += f", completion_code={self.completion_code})"
        else:
            summary += ")"
        return summary, [TransportHdrPacket, SmbusTransportPacket]

    def answers(self, other: Packet) -> int:
        if not other.haslayer(ControlHdrPacket):
            return 0
        if self.rq != 0 or other.rq != 1:
            return 0
        if self.cmd_code != other.cmd_code:
            return 0
        if self.instance_id != other.instance_id:
            return 0
        return self.payload.answers(other.payload)

    def is_request(self, check_payload: bool = True) -> bool:
        return self.rq == 1

    def make_reply(self, ctx: EndpointContext) -> AnyPacketType:
        if not self.is_request():
            return None
        if self.cmd_code not in list(ContrlCmdCodes):
            return None

        completion_code = 0
        payload_resp = None
        if self.payload and isinstance(self.payload, IControlMsgCanReply):
            completion_code, payload_resp = self.payload.make_ctrl_reply(ctx)

        rsp = ControlHdr(
            rq=False,
            instance_id=self.instance_id,
            cmd_code=self.cmd_code,
            completion_code=completion_code,
        )
        return (rsp / payload_resp) if payload_resp else rsp


def ControlHdr(
    *args,
    rq: bool | RqBit = RqBit.RESPONSE,
    d: bool = False,
    instance_id: int = 0,
    cmd_code: ContrlCmdCodes = ContrlCmdCodes.GetEndpointID,
    completion_code: int | None = 0,
) -> ControlHdrPacket:
    if len(args):
        return ControlHdrPacket(*args)
    return ControlHdrPacket(
        rq=0 if not rq or rq in [False, RqBit.RESPONSE, 0] else 1,
        d=1 if d else 0,
        instance_id=instance_id,
        cmd_code=cmd_code,
        completion_code=completion_code,
    )


class AutobindControlMsg:
    def __init__(self, cmd_code: ContrlCmdCodes):
        self.cmd_code = cmd_code

    def __call__(self, cls: type[Packet]):
        cmd_code = self.cmd_code
        # print(f"Binding cls {cls} to cmd_code {cmd_code}:{self.is_request}")
        bind_layers(ControlHdrPacket, cls, cmd_code=cmd_code.value if type(cmd_code) == ContrlCmdCodes else cmd_code)
        if not hasattr(cls, "name") or cls.name is None:
            cls.name = cls.__name__
        if not hasattr(cls, "cmd_code") or cls.cmd_code is None:
            cls.cmd_code = self.cmd_code
        return cls


def set_control_fields(
    rq_fields: list[AnyField] | None = None, rsp_fields: list[AnyField] | None = None
) -> list[AnyField]:
    rq_fields = rq_fields or []
    rsp_fields = rsp_fields or []

    def gen_conditional_field(fld: AnyField, cond: Callable[[Packet], bool]):
        def default_cond(pkt):
            return False

        if isinstance(fld, ConditionalField):
            # unwrap the conditional field
            default_cond = fld.cond
            fld = fld.fld
        return ConditionalField(fld=fld, cond=lambda pkt: any([cond(pkt), default_cond(pkt)]))

    def is_request(pkt: Packet) -> bool:
        return pkt.underlayer.getfieldval("rq") == RqBit.REQUEST.value

    def is_response(pkt: Packet) -> bool:
        return pkt.underlayer.getfieldval("rq") == RqBit.RESPONSE.value

    fields = [gen_conditional_field(fld, is_request) for fld in rq_fields]
    fields += [gen_conditional_field(fld, is_response) for fld in rsp_fields]

    return fields


def response_fields(fields: list[AnyField]) -> list[AnyField]:
    """Wraps the list of Fields in a ConditionalField that checks if 'rq==0'"""
    return [ResponseField(fld) for fld in fields]


class ResponseField(ConditionalField):
    """Wraps the field within a ConditionalField that checks if 'rq==0'"""

    def __init__(self, fld: Field[Any, Any]) -> None:
        ConditionalField.__init__(self, fld, cond=lambda pkt: pkt.underlayer.getfieldval("rq") == 0)
