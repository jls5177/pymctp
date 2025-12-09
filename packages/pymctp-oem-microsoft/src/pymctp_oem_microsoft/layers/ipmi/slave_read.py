from enum import IntEnum
from typing import Union, Tuple, List

from scapy.fields import XByteField, ByteEnumField, PacketField
from scapy.packet import Packet, bind_layers

from pymctp.layers import ipmi
from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.mctp import TrimmedSmbusTransportPacket
from pymctp.layers.mctp.types import AnyPacketType


class SlaveReadRequestOperation(IntEnum):
    READ = 0
    CLEAR = 1


class SlaveReadRequestPacket(AllowRawSummary, Packet):
    name = "Slave-Read REQ"
    # match_subclass = True
    fields_desc = [
        ByteEnumField("operation", 0, SlaveReadRequestOperation),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (op: "
        if self.operation == SlaveReadRequestOperation.READ.value:
            summary += "READ)"
        else:
            summary += "CLEAR)"
        return summary, [ipmi.TransportHdrPacket]


class SlaveReadResponsePacket(AllowRawSummary, Packet):
    name = "Slave-Read RSP"
    # match_subclass = True
    fields_desc = [
        XByteField("completion_code", 0),
        PacketField("load", None, TrimmedSmbusTransportPacket),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (cc: {self.completion_code:02X})"
        return summary, [ipmi.TransportHdrPacket]


bind_layers(ipmi.TransportHdrPacket, SlaveReadRequestPacket, net_fn=0x36, cmd=0xF9)
bind_layers(ipmi.TransportHdrPacket, SlaveReadResponsePacket, net_fn=0x37, cmd=0xF9)
