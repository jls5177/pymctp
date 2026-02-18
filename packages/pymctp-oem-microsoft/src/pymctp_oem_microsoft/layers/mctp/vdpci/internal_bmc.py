from scapy.packet import Packet, bind_layers

from pymctp.layers.mctp.vdpci import ShortVdPciPacket
from pymctp.layers.mctp.types import AnyPacketType


class InKernelTargetReadRequestPacket(Packet):
    """Internal BMC-to-BMC target read request using a non-standard vendor ID (0xFFFF)."""

    name = "InKernel-TargetRead"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return "InKernel-TargetRead ()", []


bind_layers(ShortVdPciPacket, InKernelTargetReadRequestPacket, vendor_id=0xFFFF)
