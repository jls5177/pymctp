from typing import Union, Tuple, List

from scapy.fields import XByteField, PacketField, ConditionalField
from scapy.packet import Packet, bind_layers

from pymctp.layers import ipmi
from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.mctp import TrimmedSmbusTransportPacket
from pymctp.layers.mctp.types import AnyPacketType


class GetOvlSocPowerControlRequestPacket(AllowRawSummary, Packet):
    name = "Get-OVL-Soc-Power-Control"
    fields_desc = []

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name}"
        return summary, [ipmi.TransportHdrPacket]


class GetOvlSocPowerControlResponsePacket(AllowRawSummary, Packet):
    name = "Get-OVL-Soc-Power-Control RSP"
    fields_desc = [
        XByteField("completion_code", 0),
        XByteField("pwr_status", 0),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (cc: {self.completion_code:02X}, pwr_status: {self.pwr_status:02X})"
        return summary, [ipmi.TransportHdrPacket]


class GetOvlSocTemperatureRequestPacket(AllowRawSummary, Packet):
    name = "Get-OVL-Soc-Temperature"
    fields_desc = [
        XByteField("core_temp", 0),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (core: {self.core_temp})"
        return summary, [ipmi.TransportHdrPacket]


class GetOvlSocTemperatureResponsePacket(AllowRawSummary, Packet):
    name = "Get-OVL-Soc-Temperature RSP"
    fields_desc = [
        XByteField("completion_code", 0),
        XByteField("temp_src", 0),
        XByteField("temp", 0),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (cc: {self.completion_code:02X}, src: {self.temp_src:02X}, temp: {self.temp:02X})"
        return summary, [ipmi.TransportHdrPacket]


bind_layers(ipmi.TransportHdrPacket, GetOvlSocPowerControlRequestPacket, net_fn=0x30, cmd=0xA3)
bind_layers(ipmi.TransportHdrPacket, GetOvlSocPowerControlResponsePacket, net_fn=0x31, cmd=0xA3)
bind_layers(ipmi.TransportHdrPacket, GetOvlSocTemperatureRequestPacket, net_fn=0x30, cmd=0xA6)
bind_layers(ipmi.TransportHdrPacket, GetOvlSocTemperatureResponsePacket, net_fn=0x31, cmd=0xA6)
