from scapy.fields import XByteField
from scapy.packet import Packet, bind_layers

from pymctp.layers.mctp import VdPciHdrPacket


class InKernelTargetReadRequestPacket(Packet):
    """Internal BMC-to-BMC target read request using a non-standard vendor ID (0xFFFF)."""

    name = "InKernel-TargetRead"
    fields_desc = [
        XByteField("d1", 0xFF),
        XByteField("d2", 0xFF),
    ]


bind_layers(VdPciHdrPacket, InKernelTargetReadRequestPacket, vendor_id=0xFFFF)
