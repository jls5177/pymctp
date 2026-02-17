from pymctp.layers.helpers import AllowRawSummary
from scapy.config import conf
from scapy.fields import ConditionalField, XByteField, XLEShortField
from scapy.packet import Packet, bind_layers

from pymctp.layers.interfaces import ICanSetMySummaryClasses
from pymctp.layers.mctp import VdPciHdrPacket, TransportHdrPacket
from pymctp.layers.mctp.types import AnyPacketType
from pymctp.layers.mctp.vdpci import VdPCIVendorIds
from ..types import CompletionCodes, MsftVdmCommandSets


def _is_response(pkt: Packet) -> bool:
    """Check if this is a response by reading the TO bit from TransportHdrPacket.

    TO=1 means request (tag owner), TO=0 means response.
    Walk up: MsftVdmProtocolPacket -> VdPciHdrPacket -> TransportHdrPacket
    """
    try:
        return pkt.underlayer.underlayer.getfieldval("to") == 0
    except (AttributeError, KeyError):
        return False


class MsftVdmProtocolPacket(AllowRawSummary, Packet):
    name = "MSFT-VDM"
    fields_desc = [
        XByteField("cmd_set", 0),
        XLEShortField("protocol_version", 0),
        XByteField("cmd", 0),
        ConditionalField(XByteField("completion_code", 0), _is_response),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        try:
            set_name = f"{self.cmd_set}({MsftVdmCommandSets(self.cmd_set).name})"
        except ValueError:
            set_name = f"0x{self.cmd_set:02X}"
        summary = f"MSFT-VDM (set={set_name}, cmd=0x{self.cmd:02X}, ver={self.protocol_version}"
        if _is_response(self):
            try:
                cc_name = f"0x{self.completion_code:02X}({CompletionCodes(self.completion_code).name})"
            except ValueError:
                cc_name = f"0x{self.completion_code:02X}"
            summary += f", cc={cc_name}"
        summary += ")"
        return summary, [VdPciHdrPacket, TransportHdrPacket]

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
        if s or cls is not conf.raw_layer:
            self.add_payload(p)
        if isinstance(p, ICanSetMySummaryClasses):
            p.set_mysummary_classes([VdPciHdrPacket, TransportHdrPacket, MsftVdmProtocolPacket])


bind_layers(
    VdPciHdrPacket,
    MsftVdmProtocolPacket,
    vendor_id=VdPCIVendorIds.Msft,
    rq=1,
    vdm_cmd_code=0xFF,
)
