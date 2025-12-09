from typing import Union, Tuple, List

from scapy.config import conf
from scapy.fields import XByteField, PacketField, ConditionalField
from scapy.packet import Packet, bind_layers

from pymctp.layers import ipmi
from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.interfaces import ICanSetMySummaryClasses
from pymctp.layers.mctp import TrimmedSmbusTransportPacket
from pymctp.layers.mctp.types import AnyPacketType


class MasterMuxWriteReadRequestPacket(AllowRawSummary, Packet):
    name = "MasterMuxWriteRead REQ"
    # match_subclass = True
    fields_desc = [
        XByteField("bus", 0),
        XByteField("muxAddr1", 0),
        XByteField("channel1", 0),
        XByteField("muxAddr2", 1),
        XByteField("channel2", 0),
        XByteField("phy_address", 0),
        XByteField("read_count", 0),
        ConditionalField(PacketField("load", None, TrimmedSmbusTransportPacket), lambda pkt: pkt.read_count == 0),
        # PacketField("load", None, TrimmedSmbusTransportPacket),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (bus: {self.bus}, addr: 0x{self.phy_address:02X}, rd_cnt: {self.read_count}"
        if self.channel1 or self.muxAddr1 != 0xFF:
            summary += f", mux1: {self.channel1}@0x{self.muxAddr1:02X}"
        if self.channel2 or self.muxAddr2 != 0xFF:
            summary += f", mux2: {self.channel2}@0x{self.muxAddr2:02X}"
        summary += ")"
        return summary, [ipmi.TransportHdrPacket]


class MasterMuxWriteReadResponsePacket(AllowRawSummary, Packet):
    name = "MasterMuxWriteRead RSP"
    # match_subclass = True
    fields_desc = [
        XByteField("completion_code", 0),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (cc: {self.completion_code:02X})"
        return summary, [ipmi.TransportHdrPacket]

    def do_dissect_payload(self, s: bytes) -> None:
        if s:
            cls = TrimmedSmbusTransportPacket
            try:
                p = cls(s, _internal=1, _underlayer=self)
            except KeyboardInterrupt:
                raise
            except Exception:
                if conf.debug_dissector and cls is not None:
                    raise
                p = conf.raw_layer(s, _internal=1, _underlayer=self)
            # skip adding empty RAW payloads
            if s or cls != conf.raw_layer:
                self.add_payload(p)
            if isinstance(p, ICanSetMySummaryClasses):
                p.set_mysummary_classes([self.__class__, self.underlayer.__class__])


bind_layers(ipmi.TransportHdrPacket, MasterMuxWriteReadRequestPacket, net_fn=0x38, cmd=0x53)
bind_layers(ipmi.TransportHdrPacket, MasterMuxWriteReadResponsePacket, net_fn=0x39, cmd=0x53)
