# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import time
from collections.abc import Callable
from enum import IntEnum

from scapy.config import conf
from scapy.fields import AnyField, BitEnumField, BitField, ConditionalField, XBitField, XByteField
from scapy.packet import Packet, Raw, bind_layers

from ...interfaces import ICanSetMySummaryClasses
from .. import EndpointContext
from ..transport import AutobindMessageType, MsgTypes, SmbusTransportPacket, TransportHdrPacket
from ..types import AnyPacketType
from .types import CompletionCodes, PldmTypeCodes


class RqBit(IntEnum):
    RESPONSE = 0
    REQUEST = 1


DEFAULT_HDR_VERSION = 0


@AutobindMessageType(MsgTypes.PLDM)
class PldmHdrPacket(Packet):
    name = "PLDM"
    fields_desc = [
        BitEnumField("rq", 0, 1, RqBit),
        BitField("d", 0, 1),
        BitField("unused", 0, 1),
        XBitField("instance_id", 0, 5),
        BitField("hdr_ver", DEFAULT_HDR_VERSION, 2),
        BitEnumField("pldm_type", 0, 6, PldmTypeCodes),
        XByteField("cmd_code", 0),
        ConditionalField(XByteField("completion_code", 0), lambda pkt: pkt.rq == RqBit.RESPONSE.value),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        rqType = "REQ" if self.rq == RqBit.REQUEST.value else "RSP"
        summary = (
            f"PLDM {rqType} (inst_id=0x{self.instance_id:02X}, type=0x{self.pldm_type:02X}, cmd=0x{self.cmd_code:02X}"
        )
        if self.rq == RqBit.RESPONSE.value:
            summary += f", cc={self.completion_code})"
        else:
            summary += ")"
        return summary, [TransportHdrPacket, SmbusTransportPacket]

    def do_dissect_payload(self, s: bytes) -> None:
        if not s:
            return
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
            p.set_mysummary_classes([PldmHdrPacket, TransportHdrPacket])

    def answers(self, other: Packet) -> int:
        if not other.haslayer(PldmHdrPacket):
            return 0
        if self.rq != 0 or other.rq != 1:
            return 0
        if self.pldm_type != other.pldm_type:
            return 0
        if self.cmd_code != other.cmd_code:
            return 0
        if self.hdr_ver != DEFAULT_HDR_VERSION:
            print(f"WARN: Mismatched header versions: {self.hdr_ver} != {DEFAULT_HDR_VERSION}")
        return self.payload.answers(other.payload)

    def is_request(self, check_payload: bool = True) -> bool:
        return self.rq == 1

    def make_reply(self, ctx: EndpointContext) -> AnyPacketType:
        if not self.is_request():
            return None
        if self.pldm_type not in list(PldmTypeCodes):
            return None
        # only make a reply if we are a supported msg type (allows context to control which packets generate responses)
        if MsgTypes.PLDM not in ctx.supported_msg_types:
            return None

        completion_code = CompletionCodes.ERROR_UNSUPPORTED_CMD
        payload_resp = None

        # Check if we have a premade response
        if ctx.mctp_responses:
            pldm_hdr: PldmHdrPacket = self.getlayer(PldmHdrPacket)
            data = bytes(pldm_hdr)
            rqDInstanceID, req_data = data[0], data[1:]
            resp_info = ctx.get_response(MsgTypes.PLDM, req_data)
            if resp_info:
                print(f"***> PLDM Request  ({len(resp_info.data)} bytes): {resp_info.description}")
                resp_data = Raw(resp_info.data)

                delay = resp_info.processing_delay
                if delay:
                    time.sleep(delay / 1000.0)
                return Raw(bytes([rqDInstanceID & 0x7F])) / resp_data
        # TODO: add support to auto-respond to pldm msgs

        rsp = PldmHdr(
            rq=False,
            instance_id=self.instance_id,
            pldm_type=self.pldm_type,
            hdr_ver=self.hdr_ver,
            cmd_code=self.cmd_code,
            completion_code=completion_code,
        )
        return (rsp / payload_resp) if payload_resp else rsp


def PldmHdr(
    *args,
    rq: bool | RqBit = RqBit.RESPONSE,
    d: bool = False,
    instance_id: int = 0,
    hdr_ver: int = DEFAULT_HDR_VERSION,
    pldm_type: PldmTypeCodes = PldmTypeCodes.CONTROL,
    cmd_code: int = 0,
    completion_code: int | None = 0,
) -> PldmHdrPacket:
    if len(args):
        return PldmHdrPacket(*args)
    return PldmHdrPacket(
        rq=0 if not rq or rq in [False, RqBit.RESPONSE, 0] else 1,
        d=1 if d else 0,
        instance_id=instance_id,
        hdr_ver=hdr_ver,
        pldm_type=pldm_type,
        cmd_code=cmd_code,
        completion_code=completion_code,
    )


class AutobindPLDMMsg:
    def __init__(self, pldm_type: PldmTypeCodes, cmd_code: int):
        self.pldm_type = pldm_type
        self.cmd_code = cmd_code

    def __call__(self, cls: type[Packet]):
        pldm_type = self.pldm_type
        cmd_code = self.cmd_code
        # print(f"Binding cls {cls} to cmd_code {cmd_code}:{self.is_request}")
        bind_layers(
            PldmHdrPacket,
            cls,
            pldm_type=pldm_type.value if type(pldm_type) == PldmTypeCodes else pldm_type,
            cmd_code=cmd_code.value if hasattr(cmd_code, "value") else cmd_code,
        )
        if not hasattr(cls, "name") or cls.name is None:
            cls.name = cls.__name__
        if not hasattr(cls, "pldm_type") or cls.pldm_type is None:
            cls.pldm_type = self.pldm_type
        if not hasattr(cls, "cmd_code") or cls.cmd_code is None:
            cls.cmd_code = self.cmd_code
        return cls


def set_pldm_fields(
    rq_fields: list[AnyField] | None = None, rsp_fields: list[AnyField] | None = None
) -> list[AnyField]:
    rq_fields = rq_fields or []
    rsp_fields = rsp_fields or []

    def gen_conditional_field(fld: AnyField, cond: Callable[[Packet], bool]):
        def default_cond(pkt):
            return True

        if isinstance(fld, ConditionalField):
            # unwrap the conditional field
            default_cond = fld.cond
            fld = fld.fld
        return ConditionalField(fld=fld, cond=lambda pkt: all([cond(pkt), default_cond(pkt)]))

    def is_request(pkt: Packet) -> bool:
        return pkt.underlayer.getfieldval("rq") == RqBit.REQUEST.value

    def is_response(pkt: Packet) -> bool:
        return pkt.underlayer.getfieldval("rq") == RqBit.RESPONSE.value

    fields = [gen_conditional_field(fld, is_request) for fld in rq_fields]
    fields += [gen_conditional_field(fld, is_response) for fld in rsp_fields]

    return fields
