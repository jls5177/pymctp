# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from enum import IntEnum

import crc8
from scapy.compat import raw
from scapy.config import conf
from scapy.fields import BitEnumField, BitField, PacketField, XByteField, LenField, PacketLenField
from scapy.packet import Packet, bind_layers

from ..helpers import AllowRawSummary
from ..interfaces import ICanSetMySummaryClasses
from ..mctp import TrimmedSmbusTransportPacket
from ..mctp.transport import ExtendedConditionalField
from ..mctp.types import AnyPacketType, Smbus7bitAddress


class TransportHdrPacket(AllowRawSummary, Packet):
    name = "IPMI-Transport"
    # match_subclass = True
    fields_desc = [
        BitField("net_fn", 0, 6),
        BitField("lun", 0, 2),
        XByteField("cmd", 0),
    ]

    def is_request(self):
        return self.net_fn % 2 == 0

    def netfn_name(self):
        netfn_names = {
            0: "CHASSIS REQ",
            1: "CHASSIS RSP",
            2: "BRIDGE REQ",
            3: "BRIDGE RSP",
            4: "SENSOR REQ",
            5: "SENSOR RSP",
            6: "APP REQ",
            7: "APP RSP",
            8: "FW REQ",
            9: "FW RSP",
            10: "STORAGE REQ",
            11: "STORAGE RSP",
            12: "TRANSPORT REQ",
            13: "TRANSPORT RSP",
            0x2C: "GROUP REQ",
            0x2D: "GROUP RSP",
            0x2E: "OEM REQ",
            0x2F: "OEM RSP",
            0x30: "OEM1 REQ",
            0x31: "OEM1 RSP",
            0x32: "OEM2 REQ",
            0x33: "OEM2 RSP",
            0x34: "OEM3 REQ",
            0x35: "OEM3 RSP",
            0x36: "OEM4 REQ",
            0x37: "OEM4 RSP",
            0x38: "OEM5 REQ",
            0x39: "OEM5 RSP",
        }
        return netfn_names.get(self.net_fn, "")

    def mysummary(self):  # type: () -> str
        netfn_name = self.netfn_name()
        # summary = f"IPMI {netfn_name} (netFn={self.net_fn:02x}, cmd={self.cmd:02X}"
        payload_len = len(self.payload.original) if self.payload else 0
        summary = f"IPMI {self.net_fn:02x}:{self.cmd:02X}"
        if self.lun:
            summary += f" (lun={self.lun})"
        if not self.payload or isinstance(self.payload, conf.raw_layer):
            summary += f" {netfn_name}"
        summary += f" / [{payload_len:3}]"
        return summary

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
        # skip adding empty RAW payloads
        if s or not isinstance(cls, conf.raw_layer):
            self.add_payload(p)
        if isinstance(p, ICanSetMySummaryClasses):
            p.set_mysummary_classes([self.__class__, self.underlayer.__class__])


class SSIFTransportPacket(AllowRawSummary, Packet):
    name = "SSIF/I2C"

    fields_desc = [
        XByteField("dst_addr", 0),
        XByteField("command_code", 0x0F),
        LenField("byte_count", None, fmt="B", adjust=lambda x: 0 if not x else (x + 1)),
        PacketLenField("load", None, TransportHdrPacket, length_from=lambda x: x.byte_count - 1),
        XByteField("pec", None),
    ]

    def mysummary(self):  # type: () -> str
        summary = "SMBUS ("
        if "dst_addr" in self.fields:
            summary += f"dst=0x{self.dst_addr:02X}, "
        summary += f"byte_count={self.byte_count}"
        if "pec" in self.fields:
            summary += f", pec=0x{self.pec:02X}"
        summary += ")"
        return summary, [SSIFTransportPacket]

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

    def dst_addr_7bit(self) -> Smbus7bitAddress:
        return Smbus7bitAddress(self.dst_addr >> 1)


def SsifTransport(
    *args,
    dst_addr: int | Smbus7bitAddress = 0,
    byte_count: int | None = None,
    command_code: int = 0x0F,
    load: AnyPacketType = None,
    pec: int | None = None,
) -> SSIFTransportPacket:
    if len(args):
        return SSIFTransportPacket(*args)
    if isinstance(dst_addr, Smbus7bitAddress):
        dst_addr = dst_addr.write()
    if not byte_count:
        byte_count = len(load) if load else 0
    byte_count += 1
    if not pec:
        crc = crc8.crc8()
        crc.update(bytes([dst_addr, command_code, byte_count]))
        crc.update(raw(load))
        val = crc.digest()
        pec = int.from_bytes(val, byteorder="little")
    return SSIFTransportPacket(dst_addr=dst_addr, command_code=command_code, byte_count=byte_count, load=load, pec=pec)


class MasterWriteReadBusType(IntEnum):
    PUBLIC = 0
    PRIVATE = 1


class MasterWriteReadRequestPacket(AllowRawSummary, Packet):
    name = "MasterWriteRead REQ"
    # match_subclass = True
    fields_desc = [
        BitField("channel", 0, 4),
        BitField("bus", 0, 3),
        BitEnumField("bus_type", 0, 1, MasterWriteReadBusType),
        XByteField("phy_address", 0),
        XByteField("read_count", 0),
        PacketField("load", None, TrimmedSmbusTransportPacket),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        bus_type_str = "PUB" if self.bus_type == MasterWriteReadBusType.PUBLIC.value else "PRV"
        summary = (
            f"{self.name} (ch: {self.channel}, bus: {self.bus}, type: {bus_type_str}, "
            f"phys_addr: 0x{self.phy_address:02X}, rd_cnt: {self.read_count})"
        )
        return summary, [TransportHdrPacket]


class MasterWriteReadResponsePacket(AllowRawSummary, Packet):
    name = "MasterWriteRead RSP"
    # match_subclass = True
    fields_desc = [
        XByteField("completion_code", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (cc: {self.completion_code:02X})"
        return summary, [TransportHdrPacket]


bind_layers(TransportHdrPacket, MasterWriteReadRequestPacket, net_fn=0x06, cmd=0x52)
bind_layers(TransportHdrPacket, MasterWriteReadResponsePacket, net_fn=0x07, cmd=0x52)
