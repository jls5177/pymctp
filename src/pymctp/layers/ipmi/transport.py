from enum import IntEnum
from typing import Union, Tuple, List

from scapy.config import conf
from scapy.fields import BitField, XByteField, ByteEnumField, BitEnumField, PacketField
from scapy.packet import Packet, bind_layers

from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.mctp import TrimmedSmbusTransportPacket
from pymctp.layers.mctp.types import AnyPacketType


class TransportHdrPacket(AllowRawSummary, Packet):
    name = "IPMI-Transport"
    # match_subclass = True
    fields_desc = [
        BitField("net_fn", 0, 6),
        BitField("lun", 0, 2),
        XByteField("cmd", 0),
    ]

    def is_request(self):
        return self.net_fn % 2 == 1

    def netfn_name(self):
        if self.net_fn == 0:
            return "CHASSIS REQ"
        if self.net_fn == 1:
            return "CHASSIS RSP"
        if self.net_fn == 2:
            return "BRIDGE REQ"
        if self.net_fn == 3:
            return "BRIDGE RSP"
        if self.net_fn == 4:
            return "SENSOR REQ"
        if self.net_fn == 5:
            return "SENSOR RSP"
        if self.net_fn == 6:
            return "APP REQ"
        if self.net_fn == 7:
            return "APP RSP"
        if self.net_fn == 8:
            return "FW REQ"
        if self.net_fn == 9:
            return "FW RSP"
        if self.net_fn == 10:
            return "STORAGE REQ"
        if self.net_fn == 11:
            return "STORAGE RSP"
        if self.net_fn == 12:
            return "TRANSPORT REQ"
        if self.net_fn == 13:
            return "TRANSPORT RSP"
        if self.net_fn == 0x2C:
            return "GROUP REQ"
        if self.net_fn == 0x2D:
            return "GROUP RSP"
        if self.net_fn == 0x2E:
            return "OEM REQ"
        if self.net_fn == 0x2F:
            return "OEM RSP"
        if self.net_fn == 0x30:
            return "OEM1 REQ"
        if self.net_fn == 0x31:
            return "OEM1 RSP"
        if self.net_fn == 0x32:
            return "OEM2 REQ"
        if self.net_fn == 0x33:
            return "OEM2 RSP"
        if self.net_fn == 0x34:
            return "OEM3 REQ"
        if self.net_fn == 0x35:
            return "OEM3 RSP"
        if self.net_fn == 0x36:
            return "OEM4 REQ"
        if self.net_fn == 0x37:
            return "OEM4 RSP"
        if self.net_fn == 0x38:
            return "OEM5 REQ"
        if self.net_fn == 0x39:
            return "OEM5 RSP"
        return ""

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

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        bus_type_str = f"PUB" if self.bus_type == MasterWriteReadBusType.PUBLIC.value else f"PRV"
        summary = (f"{self.name} (ch: {self.channel}, bus: {self.bus}, type: {bus_type_str}, "
                   f"phys_addr: 0x{self.phy_address:02X}, rd_cnt: {self.read_count})")
        return summary, [TransportHdrPacket]


class MasterWriteReadResponsePacket(AllowRawSummary, Packet):
    name = "MasterWriteRead RSP"
    # match_subclass = True
    fields_desc = [
        XByteField("completion_code", 0),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (cc: {self.completion_code:02X})"
        return summary, [TransportHdrPacket]


bind_layers(TransportHdrPacket, MasterWriteReadRequestPacket, net_fn=0x06, cmd=0x52)
bind_layers(TransportHdrPacket, MasterWriteReadResponsePacket, net_fn=0x07, cmd=0x52)
