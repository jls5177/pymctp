# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import time
from enum import IntEnum

from scapy.config import conf
from scapy.fields import BitEnumField, BitField, ShortEnumField, XByteField
from scapy.packet import Packet, Raw, bind_layers

from ...interfaces import ICanVerifyIfRequest
from .. import EndpointContext
from ..transport import (
    AutobindMessageType,
    MsgTypes,
    SmbusTransportPacket,
    TransportHdrPacket,
    TrimmedSmbusTransportPacket,
)
from ..types import AnyPacketType
from ...interfaces import ICanSetMySummaryClasses
from .types import VdPCIVendorIds


class RqBit(IntEnum):
    RESPONSE = 0
    REQUEST = 1


DEFAULT_HDR_VERSION = 0


class ShortVdPciPacket(Packet):
    """Fallback for VDPCI payloads shorter than the standard 4-byte header.

    Some non-standard vendors (e.g. 0xFFFF for in-kernel target reads) send
    only a 2-byte vendor ID with no rq/cmd_code fields.
    """

    name = "VDM-PCI-Short"
    expects_response = False
    fields_desc = [
        ShortEnumField("vendor_id", 0, VdPCIVendorIds),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"Short ({self.vendor_id:04X})"
        return summary, [TransportHdrPacket, SmbusTransportPacket, TrimmedSmbusTransportPacket]

    def do_dissect_payload(self, s: bytes) -> None:
        cls = self.guess_payload_class(s)
        if cls is not None and cls is not conf.raw_layer:
            self.add_payload(cls(s, _internal=1, _underlayer=self))
        elif s:
            self.add_payload(conf.raw_layer(s, _internal=1, _underlayer=self))

    def is_request(self, check_payload: bool = True) -> bool:
        return True


@AutobindMessageType(MsgTypes.VDPCI)
class VdPciHdrPacket(Packet):
    name = "VDM-PCI"
    fields_desc = [
        ShortEnumField("vendor_id", 0, VdPCIVendorIds),
        BitEnumField("rq", 0, 1, RqBit),
        BitField("rsv", 0, 2),
        BitField("unused", 0, 5),
        XByteField("vdm_cmd_code", 0),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is not None and len(_pkt) < 4:
            return ShortVdPciPacket
        return cls

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        rqType = "REQ" if self.is_request() else "RSP"
        summary = f"{rqType} ({self.vendor_id:04X}:0x{self.vdm_cmd_code:02X})"
        return summary, [TransportHdrPacket, SmbusTransportPacket, TrimmedSmbusTransportPacket]

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
            p.set_mysummary_classes([VdPciHdrPacket, TransportHdrPacket])

    def answers(self, other: Packet) -> int:
        # if self.rq != 0 or other.rq != 1:
        #     return 0
        if self.vendor_id != other.vendor_id:
            return 0
        if self.vdm_cmd_code != other.vdm_cmd_code:
            return 0
        return self.payload.answers(other.payload)

    def is_request(self, check_payload: bool = True) -> bool:
        # The MCTP TO (tag owner) bit is authoritative whenever the transport
        # header is present: it is set on requests and clear on responses.
        #
        # Checking the VDPCI ``rq`` bit alone is not safe, because vendor
        # protocols disagree about it. Microsoft's VDM leaves ``rq`` SET on its
        # responses, so an ``rq``-based test classified a response as a request
        # and the endpoint dutifully answered it with an empty reply. The
        # Cerberus Utility does the opposite, leaving ``rq`` CLEAR on requests.
        # Only the TO bit is consistent across both.
        transport = self.underlayer
        if transport is not None and isinstance(transport, ICanVerifyIfRequest):
            return bool(transport.is_request(check_payload=False))
        return any(
            [
                self.rq == RqBit.REQUEST.value,
                self.payload and isinstance(self.payload, ICanVerifyIfRequest) and self.payload.is_request(),
            ]
        )

    def make_reply(self, ctx: EndpointContext) -> AnyPacketType:
        if not self.is_request():
            return None
        if self.vendor_id not in list(VdPCIVendorIds):
            return None
        # only make a reply if we are a supported msg type (allows context to control which packets generate responses)
        if MsgTypes.VDPCI not in ctx.supported_msg_types:
            return None

        payload_resp = None

        # TODO: fill in reading from the file
        if ctx.mctp_responses:
            vdpci_hdr: VdPciHdrPacket = self.getlayer(VdPciHdrPacket)
            hdr_data = bytes(vdpci_hdr)
            data = bytes(vdpci_hdr.payload)
            vendor_id = self.vendor_id_enum
            resp_info = ctx.get_response(MsgTypes.VDPCI, data, vendor_id.name, str(self.vdm_cmd_code))
            if resp_info:
                print(f"***> VDPCI Request Matched: {resp_info.description}")
                resp_data = Raw(resp_info.data)
                delay = resp_info.processing_delay
                if delay:
                    time.sleep(delay / 1000.0)
                return Raw(bytes([hdr_data[0], hdr_data[1], 0, hdr_data[3]])) / resp_data

        rsp = VdPciHdr(
            rq=False,
            vendor_id=self.vendor_id,
            vdm_cmd_code=self.vdm_cmd_code,
        )
        return (rsp / payload_resp) if payload_resp else rsp

    @property
    def vendor_id_enum(self) -> VdPCIVendorIds:
        return VdPCIVendorIds(self.vendor_id)


def VdPciHdr(*args, rq: bool | RqBit = RqBit.RESPONSE, vendor_id: int = 0, vdm_cmd_code: int = 0) -> VdPciHdrPacket:
    if len(args):
        return VdPciHdrPacket(*args)
    return VdPciHdrPacket(
        rq=0 if not rq or rq in [False, RqBit.RESPONSE, 0] else 1, vendor_id=vendor_id, vdm_cmd_code=vdm_cmd_code
    )


class AutobindVDMMsg:
    def __init__(self, vid: VdPCIVendorIds, vdm_cmd_code):
        self.vdm_cmd_code = vdm_cmd_code
        self.vid = vid

    def __call__(self, cls: type[Packet]):
        vid = self.vid
        cmd_code = self.vdm_cmd_code
        bind_layers(
            VdPciHdrPacket,
            cls,
            vid=vid.value if isinstance(vid, VdPCIVendorIds) else vid,
            vdm_cmd_code=cmd_code.value if hasattr(cmd_code, "value") else cmd_code,
        )
        if not hasattr(cls, "name") or cls.name is None:
            cls.name = cls.__name__
        if not hasattr(cls, "vid") or cls.vid is None:
            cls.vid = self.vid
        if not hasattr(cls, "vdm_cmd_code") or cls.vdm_cmd_code is None:
            cls.vdm_cmd_code = self.vdm_cmd_code
        return cls
