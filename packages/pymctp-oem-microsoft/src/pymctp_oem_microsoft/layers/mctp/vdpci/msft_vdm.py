from enum import IntEnum
from typing import Tuple, Union, List

from scapy.compat import raw
from scapy.config import conf
from scapy.fields import (
    XByteEnumField,
    XByteField,
    XLEIntField,
    XLEShortField,
    FieldLenField,
    FieldListField,
    ConditionalField,
    PacketField,
)
from scapy.packet import Packet, bind_layers, Raw

from pymctp.layers.interfaces import ICanSetMySummaryClasses
from pymctp.layers.mctp import VdPciHdrPacket, TransportHdrPacket
from pymctp.layers.mctp.types import AnyPacketType
from pymctp.layers.mctp.vdpci import VdPCIVendorIds


class InKernelTargetReadRequestPacket(Packet):
    name = "TARGET RD"
    fields_desc = [
        XByteField("d1", 0xFF),
        XByteField("d2", 0xFF),
    ]


class MsftVdmProtocolPacket(Packet):
    name = "MSFT-VDM"
    fields_desc = [XByteField("cmd_set", 0), XLEShortField("protocol_version", 0), XByteField("cmd", 0)]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"MSFT (cmd_set: {self.cmd_set}, cmd: {self.cmd}, proto_ver: {self.protocol_version})"
        return summary, [VdPciHdrPacket, TransportHdrPacket]

    def do_dissect_payload(self, s: bytes) -> None:
        if not s:
            return
        cls = self.guess_payload_class(s)
        try:
            p = cls(s, _internal=1, _underlayer=self)
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector:
                if cls is not None:
                    raise
            p = conf.raw_layer(s, _internal=1, _underlayer=self)
        self.add_payload(p)
        if isinstance(p, ICanSetMySummaryClasses):
            p.set_mysummary_classes([VdPciHdrPacket, TransportHdrPacket, MsftVdmProtocolPacket])


bind_layers(
    VdPciHdrPacket, MsftVdmProtocolPacket, vendor_id=VdPCIVendorIds.Msft, rq=1, rsv=0, unused=0, vdm_cmd_code=0xFF
)
bind_layers(VdPciHdrPacket, InKernelTargetReadRequestPacket, vendor_id=0xFFFF)
