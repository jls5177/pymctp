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

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        rqType = "REQ" if self.is_request() else "RSP"
        summary = (
            f"{self.name} {rqType} (VID: {self.vendor_id:04X}, cmd_code: 0x{self.vdm_cmd_code:02X}, rq: {self.rq})"
        )
        return summary, [TransportHdrPacket, SmbusTransportPacket, TrimmedSmbusTransportPacket]

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
            p.set_mysummary_classes([VdPciHdrPacket, TransportHdrPacket])

    def answers(self, other: Packet) -> int:
        if self.rq != 0 or other.rq != 1:
            return 0
        if self.vendor_id != other.vendor_id:
            return 0
        if self.vdm_cmd_code != other.vdm_cmd_code:
            return 0
        return self.payload.answers(other.payload)

    def is_request(self, check_payload: bool = True) -> bool:
        return any(
            [
                self.rq == RqBit.REQUEST.value,
                self.payload and isinstance(self.payload, ICanVerifyIfRequest) and self.payload.is_request(),
                self.underlayer
                and isinstance(self.underlayer, ICanVerifyIfRequest)
                and self.underlayer.is_request(check_payload=False),
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
            vendor_id = self.vendor_id
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
            vid=vid.value if type(vid) == VdPCIVendorIds else vid,
            vdm_cmd_code=cmd_code.value if hasattr(cmd_code, "value") else cmd_code,
        )
        if not hasattr(cls, "name") or cls.name is None:
            cls.name = cls.__name__
        if not hasattr(cls, "vid") or cls.vid is None:
            cls.vid = self.vid
        if not hasattr(cls, "vdm_cmd_code") or cls.vdm_cmd_code is None:
            cls.vdm_cmd_code = self.vdm_cmd_code
        return cls
