from scapy.fields import ConditionalField, XByteField, XLEIntField
from scapy.packet import Packet, bind_layers

from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.mctp import VdPciHdrPacket
from pymctp.layers.mctp.types import AnyPacketType
from pymctp.layers.mctp.vdpci import VdPCIVendorIds
from pymctp.layers.mctp.vdpci.cerberus import FwVersionCmdPacket
from .types import OverlakeCmdCodes


# Bind SOC FW version to the same upstream FwVersionCmdPacket
bind_layers(
    VdPciHdrPacket,
    FwVersionCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=OverlakeCmdCodes.GET_SOC_FWVERSION,
)


def _get_update_type_name(cmd_code: int) -> str:
    if cmd_code in (OverlakeCmdCodes.SOC_INIT_FW_UPDATE, OverlakeCmdCodes.SOC_UPDATE_FW):
        return "SOC"
    return "Unknown"


# --- SOC_INIT_FW_UPDATE ---

class SocInitFwUpdateRequestPacket(AllowRawSummary, Packet):
    name = "Overlake-SocInitFwUpdate-Req"
    fields_desc = [XLEIntField("size", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (size={self.size})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    SocInitFwUpdateRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=OverlakeCmdCodes.SOC_INIT_FW_UPDATE,
)


# --- SOC_UPDATE_FW ---

class SocUpdateFwRequestPacket(AllowRawSummary, Packet):
    """Request to send SoC FW update data. Payload follows as raw data."""

    name = "Overlake-SocUpdateFw-Req"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        data_len = len(bytes(self.payload)) if self.payload else 0
        summary = f"{self.name} (len={data_len})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    SocUpdateFwRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=OverlakeCmdCodes.SOC_UPDATE_FW,
)
