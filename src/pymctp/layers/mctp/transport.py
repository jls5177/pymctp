# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import crc8
from scapy.compat import raw
from scapy.config import conf
from scapy.fields import BitEnumField, BitField, ConditionalField, LenField, PacketLenField, XByteField
from scapy.layers.l2 import CookedLinux, CookedLinuxV2
from scapy.packet import Packet, bind_layers
from scapy.plist import PacketList

from ..helpers import AllowRawSummary, AnyPacketType
from ..interfaces import ICanSetMySummaryClasses, ICanVerifyIfRequest
from .types import EndpointContext, ICanReply, MsgTypes, Smbus7bitAddress


class TransportHdrPacket(AllowRawSummary, Packet):
    name = "MCTP-Transport"
    # match_subclass = True
    fields_desc = [
        BitField("rsvd", 0, 4),
        BitField("version", 0b0001, 4),
        XByteField("dst", 0),
        XByteField("src", 0),
        BitField("som", 0, 1),
        BitField("eom", 0, 1),
        BitField("pkt_seq", 0, 2),
        BitField("to", 0, 1),
        BitField("tag", 0, 3),
        # These are technically part of the msg, but are needed to properly bind the layers
        ConditionalField(BitEnumField("ic", 0, 1, {0: "no", 1: "yes"}), lambda pkt: pkt.som == 1),
        ConditionalField(BitEnumField("msg_type", MsgTypes.CTRL.value, 7, MsgTypes), lambda pkt: pkt.som == 1),
    ]

    def mysummary(self):  # type: () -> str
        summary = ""
        if self.underlayer and isinstance(self.underlayer, CookedLinux):
            summary += f"[{len(self.original):3}] / "
        summary += f"MCTP {self.pkt_seq}:{self.tag} ({self.dst:02X} <-- {self.src:02X}) ("
        flags = []
        msg_type = None
        if self.som == 1:
            flags += ["S"]
            msg_type = self.msg_type
        if self.eom == 1:
            flags += ["E"]
        if self.to == 1:
            flags += ["TO"]
        if flags:
            summary += ":".join(flags)
        summary += ")"
        # allow unknown message types to be passed in
        if msg_type is not None:
            msg_type_name = getattr(MsgTypes(msg_type), "name", f"{msg_type:02X}")
            summary += f" {msg_type_name}"
        return summary, [SmbusTransportPacket, TrimmedSmbusTransportPacket]

    def do_dissect_payload(self, s: bytes) -> None:
        if not s:
            return
        # Message Type is only present within the first fragment, just assume a raw payload
        cls = conf.raw_layer if self.som == 0 else self.guess_payload_class(s)
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
            p.set_mysummary_classes([SmbusTransportPacket, TransportHdrPacket, TrimmedSmbusTransportPacket])

    def answers(self, rq_pkt: Packet) -> int:
        # the endpoint EID should match
        if rq_pkt.dst not in (self.src, 0):
            print(f"mismatched eid: {rq_pkt.dst} != {self.src}")
            return 0
        # the tags should be the same
        if self.tag != rq_pkt.tag:
            print(f"mismatched tags: {rq_pkt.tag} != {self.tag}")
            return 0
        # the request should be the tag owner
        if self.to == 0 and rq_pkt.to == 1:
            return self.payload.answers(rq_pkt.payload)
        print(f"mismatched to: {rq_pkt.to} != {self.to}")
        return 0

    def is_request(self, check_payload: bool = True) -> bool:
        # check next layer
        if check_payload and self.payload and isinstance(self.payload, ICanVerifyIfRequest):
            return self.payload.is_request()
        # check previous layer
        if self.underlayer and isinstance(self.underlayer, ICanVerifyIfRequest):
            return self.underlayer.is_request()
        # Fallback to checking the TO bit
        return self.to == 1

    def make_reply(self, ctx: EndpointContext) -> AnyPacketType:
        payload_resp = None
        if self.payload and isinstance(self.payload, ICanReply):
            payload_resp = self.payload.make_reply(ctx)
            if not payload_resp:
                return None

        if isinstance(payload_resp, PacketList | list):
            # TODO: Implement multiple payloads from upper layers
            msg = "multiple payloads are not yet supported"
            raise TypeError(msg)

        if not payload_resp:
            # TODO: should this just return None?
            return TransportHdr(
                msg_type=self.msg_type,
                to=False,
                tag=self.tag,
                src=ctx.assigned_eid or self.dst,
                dst=self.src,
                som=True,
                eom=True,
                pkt_seq=self.pkt_seq + 1,
            )

        # Split the response payload into packets (if needed)
        resps = PacketList()
        buf = raw(payload_resp)
        buf_size = msg_size = len(buf)
        buf_offset = 0
        pkt_seq = self.pkt_seq + 1
        while buf_size > 0:
            packet_size = min(ctx.mtu_size, buf_size)
            packet = payload_resp if msg_size <= ctx.mtu_size else buf[buf_offset : buf_offset + packet_size]
            som = bool(not buf_offset)
            eom = (buf_offset + packet_size) >= msg_size

            resp = TransportHdr(
                msg_type=self.msg_type,
                to=False,
                tag=self.tag,
                src=ctx.assigned_eid or self.dst,
                dst=self.src,
                som=som,
                eom=eom,
                pkt_seq=pkt_seq,
            )
            resps.append(resp / packet)

            buf_offset += packet_size
            buf_size -= packet_size
            pkt_seq += 1

        return resps


def TransportHdr(
    *args,
    dst: int = 0,
    src: int = 0,
    som: bool | int = True,
    eom: bool | int = True,
    pkt_seq: int = 0,
    to: bool | int = True,
    tag: int = 0,
    ic: bool | int = False,
    msg_type: MsgTypes = MsgTypes.CTRL,
    version: bytes = 0b0001,
) -> TransportHdrPacket:
    if len(args):
        return TransportHdrPacket(*args)
    return TransportHdrPacket(
        dst=dst,
        src=src,
        som=1 if som else 0,
        eom=1 if eom else 0,
        pkt_seq=pkt_seq,
        to=1 if to else 0,
        tag=tag,
        ic=1 if ic else 0,
        msg_type=msg_type,
        version=version,
    )


class ExtendedConditionalField(ConditionalField):
    """
    A FCS field that gets appended at the end of the *packet* (not layer).
    """

    __slots__ = ["fld", "cond"]

    def __init__(
        self,
        fld,  # type: Field[Any, Any]
        cond,  # type: Callable[[Packet, bytes], bool]
    ):
        # type: (...) -> None
        self.fld = fld
        self.cond = cond

    def _evalcond(self, pkt, s=None):
        # type: (Packet, bytes) -> bool
        return bool(self.cond(pkt, s or pkt.original))

    def i2h(self, pkt, val):
        # type: (Optional[Packet], Any) -> Any
        if pkt and not self._evalcond(pkt, pkt.original or [val]):
            return None
        return self.fld.i2h(pkt, val)

    def getfield(self, pkt, s):
        # type: (Packet, bytes) -> Tuple[bytes, Any]
        if self._evalcond(pkt, s):
            return self.fld.getfield(pkt, s)
        return s, None

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Any) -> bytes
        if self._evalcond(pkt, s):
            return self.fld.addfield(pkt, s, val)
        return s


class SmbusTransportPacket(AllowRawSummary, Packet):
    name = "SMBUS/I2C"

    fields_desc = [
        ExtendedConditionalField(
            XByteField("dst_addr", 0), lambda pkt, s: (s[0] != 0x0F) if s else pkt.getfieldval("dst_addr")
        ),
        XByteField("command_code", 0x0F),
        LenField("byte_count", None, fmt="B", adjust=lambda x: 0 if not x else (x + 1)),
        XByteField("src_addr", 0),
        PacketLenField("load", None, TransportHdrPacket, length_from=lambda x: x.byte_count - 1),
        ExtendedConditionalField(
            XByteField("pec", None), lambda pkt, s: len(s) == 1 or len(s) >= pkt.getfieldval("byte_count")
        ),
    ]

    def mysummary(self):  # type: () -> str
        summary = "SMBUS ("
        if "dst_addr" in self.fields:
            summary += f"dst=0x{self.dst_addr:02X}, "
        summary += f"src=0x{self.src_addr:02X}, byte_count={self.byte_count}"
        if "pec" in self.fields:
            summary += f", pec=0x{self.pec:02X}"
        summary += ")"
        return summary, [SmbusTransportPacket]

    def post_build(self, p, pay):
        # hexdump(p)
        # hexdump(pay)
        p += pay
        if self.pec is None:
            crc = crc8.crc8()
            crc.update(p[:-1])
            val = crc.digest()
            self.pec = int.from_bytes(val, byteorder="little")
            p = p[:-1] + val
        elif pay and self.pec != pay[-1]:
            p = p[:-1] + int.to_bytes(self.pec, byteorder="little", length=1)
        return p

    def answers(self, other: Packet) -> int:
        if self.src_addr >> 1 != other.dst_addr >> 1:
            return 0
        if self.command_code != other.command_code:
            return 0
        if self.payload:
            return self.payload.answers(other.payload)
        if self.load:
            return self.load.answers(other.load)
        return None

    def src_addr_7bit(self) -> Smbus7bitAddress:
        return Smbus7bitAddress(self.src_addr >> 1)

    def dst_addr_7bit(self) -> Smbus7bitAddress:
        return Smbus7bitAddress(self.dst_addr >> 1)

    def is_request(self, check_payload: bool = True) -> bool:
        if check_payload and self.payload and isinstance(self.payload, ICanReply):
            return self.payload.is_request()
        if check_payload and self.load and isinstance(self.load, ICanReply):
            return self.load.is_request()
        return False

    def make_reply(self, ctx: EndpointContext) -> AnyPacketType:
        # Validate the smbus address (if set in context)
        if ctx.physical_address:
            if not isinstance(ctx.physical_address, Smbus7bitAddress):
                return None
            if ctx.physical_address != self.dst_addr_7bit():
                print(
                    f"Warning: received incorrectly addressed packet: {self.dst_addr_7bit()} != {ctx.physical_address}"
                )
                return None

        payload_resp = None
        if self.payload and isinstance(self.payload, ICanReply):
            payload_resp = self.payload.make_reply(ctx)
            if not payload_resp:
                return None
        if self.load and isinstance(self.load, ICanReply):
            payload_resp = self.load.make_reply(ctx)
            if not payload_resp:
                return None

        dst = self.dst_addr_7bit()
        src = self.src_addr_7bit()

        if not isinstance(payload_resp, PacketList | list):
            payload_resp = [payload_resp]

        # wrap each packet with the SMBUS transport header
        packets = PacketList()
        for packet in payload_resp:
            resp_hdr = SmbusTransport(
                dst_addr=src.write(),
                src_addr=dst.read(),
                byte_count=len(packet),
                load=packet,
            )

            packets.extend(resp_hdr)

        return packets


class TrimmedSmbusTransportPacket(SmbusTransportPacket):
    name = "SMBUS/I2C"

    fields_desc = [
        XByteField("command_code", 0x0F),
        LenField("byte_count", None, fmt="B", adjust=lambda x: 0 if not x else (x + 1)),
        XByteField("src_addr", 0),
        PacketLenField("load", None, TransportHdrPacket, length_from=lambda x: x.byte_count - 1),
        ExtendedConditionalField(XByteField("pec", None), lambda pkt, s: len(s) == 1 or len(s) >= pkt.byte_count),
    ]


def SmbusTransport(
    *args,
    dst_addr: int | Smbus7bitAddress = 0,
    src_addr: int | Smbus7bitAddress = 1,
    byte_count: int | None = None,
    command_code: int = 0x0F,
    load: AnyPacketType = None,
    pec: int | None = None,
) -> SmbusTransportPacket:
    if len(args):
        return SmbusTransportPacket(*args)
    if isinstance(dst_addr, Smbus7bitAddress):
        dst_addr = dst_addr.write()
    if isinstance(src_addr, Smbus7bitAddress):
        src_addr = src_addr.read()
    if not byte_count:
        byte_count = len(load) if load else 0
    byte_count += 1
    if not pec:
        crc = crc8.crc8()
        crc.update(bytes([dst_addr, command_code, byte_count, src_addr]))
        crc.update(raw(load))
        val = crc.digest()
        pec = int.from_bytes(val, byteorder="little")
    return SmbusTransportPacket(
        dst_addr=dst_addr, src_addr=src_addr, command_code=command_code, byte_count=byte_count, load=load, pec=pec
    )


class AutobindMessageType:
    def __init__(self, msg_type: MsgTypes):
        self.msg_type = msg_type

    def __call__(self, cls: type[Packet]):
        # print(f"Binding cls {cls} to msg_type {self.msg_type}")
        bind_layers(TransportHdrPacket, cls, msg_type=self.msg_type.value)
        if not hasattr(cls, "name") or cls.name is None:
            cls.name = cls.__name__
        return cls


# Add the MCTP Transport (ETH_P_MCTP = 0xFA) as a valid L2 protocol
bind_layers(CookedLinux, TransportHdrPacket, proto=0xFA)
bind_layers(CookedLinuxV2, TransportHdrPacket, proto=0xFA)

# Add the MCTP Transport as a valid SMBUS command protocol
bind_layers(SmbusTransportPacket, TransportHdrPacket, command_code=0x0F)
