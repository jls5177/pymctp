# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from collections.abc import Callable

from scapy.config import conf
from scapy.fields import AnyField, ByteEnumField, ConditionalField, XByteField
from scapy.packet import Packet, bind_layers

from ...helpers import AllowRawSummary
from ...interfaces import ICanSetMySummaryClasses
from ..transport import AutobindMessageType, MsgTypes, SmbusTransportPacket, TransportHdrPacket
from ..types import AnyPacketType
from .types import SPDM_REQUEST_RESPONSE_MAP, SpdmMessageCode, SpdmRequestCode, SpdmResponseCode


def _is_request_code(code: int) -> bool:
    """Check if the SPDM message code is a request."""
    try:
        SpdmRequestCode(code)
        return True
    except ValueError:
        return False


@AutobindMessageType(MsgTypes.SPDM)
class SpdmHdrPacket(AllowRawSummary, Packet):
    name = "SPDM"
    fields_desc = [
        XByteField("spdm_version", 0x10),
        ByteEnumField("request_response_code", 0, SpdmMessageCode),
        XByteField("param1", 0),
        XByteField("param2", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        ver_major = (self.spdm_version >> 4) & 0xF
        ver_minor = self.spdm_version & 0xF
        code = self.request_response_code
        rq = "REQ" if _is_request_code(code) else "RSP"
        summary = f"{rq} ({ver_major}.{ver_minor}, 0x{code:02X})"
        return summary, [TransportHdrPacket, SmbusTransportPacket]

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
        if s or cls is not conf.raw_layer:
            self.add_payload(p)
        if isinstance(p, ICanSetMySummaryClasses):
            p.set_mysummary_classes([self.__class__, self.underlayer.__class__])

    def answers(self, other: Packet) -> int:
        if not other.haslayer(SpdmHdrPacket):
            return 0
        # self should be response, other should be request
        if not _is_request_code(other.request_response_code):
            return 0
        if _is_request_code(self.request_response_code):
            return 0
        # Check request/response code mapping
        try:
            req_code = SpdmRequestCode(other.request_response_code)
            expected_rsp = SPDM_REQUEST_RESPONSE_MAP.get(req_code)
            if expected_rsp is not None and self.request_response_code != expected_rsp.value:
                # Allow ERROR responses to match any request
                if self.request_response_code != SpdmResponseCode.ERROR.value:
                    return 0
        except ValueError:
            return 0
        return self.payload.answers(other.payload)

    def is_request(self, check_payload: bool = True) -> bool:
        return _is_request_code(self.request_response_code)


def SpdmHdr(
    *args,
    spdm_version: int = 0x10,
    request_response_code: int = 0,
    param1: int = 0,
    param2: int = 0,
) -> SpdmHdrPacket:
    if len(args):
        return SpdmHdrPacket(*args)
    return SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=request_response_code,
        param1=param1,
        param2=param2,
    )


class AutobindSPDMMsg:
    def __init__(self, request_response_code: int):
        self.request_response_code = request_response_code

    def __call__(self, cls: type[Packet]):
        code = self.request_response_code
        bind_layers(
            SpdmHdrPacket,
            cls,
            request_response_code=code.value if hasattr(code, "value") else code,
        )
        if not hasattr(cls, "name") or cls.name is None:
            cls.name = cls.__name__
        if not hasattr(cls, "request_response_code") or cls.request_response_code is None:
            cls.request_response_code = self.request_response_code
        return cls


def set_spdm_fields(
    rq_fields: list[AnyField] | None = None, rsp_fields: list[AnyField] | None = None
) -> list[AnyField]:
    rq_fields = rq_fields or []
    rsp_fields = rsp_fields or []

    def gen_conditional_field(fld: AnyField, cond: Callable[[Packet], bool]):
        def default_cond(pkt):
            return True

        if isinstance(fld, ConditionalField):
            default_cond = fld.cond
            fld = fld.fld
        return ConditionalField(fld=fld, cond=lambda pkt: all([cond(pkt), default_cond(pkt)]))

    def is_request(pkt: Packet) -> bool:
        return _is_request_code(pkt.underlayer.getfieldval("request_response_code"))

    def is_response(pkt: Packet) -> bool:
        return not _is_request_code(pkt.underlayer.getfieldval("request_response_code"))

    fields = [gen_conditional_field(fld, is_request) for fld in rq_fields]
    fields += [gen_conditional_field(fld, is_response) for fld in rsp_fields]

    return fields
