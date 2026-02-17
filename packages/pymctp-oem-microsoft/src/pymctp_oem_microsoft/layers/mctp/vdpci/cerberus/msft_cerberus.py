from scapy.fields import FieldLenField, PacketListField, XByteField, XLEIntField
from scapy.packet import Packet, bind_layers

from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.mctp import VdPciHdrPacket
from pymctp.layers.mctp.types import AnyPacketType
from pymctp.layers.mctp.vdpci import VdPCIVendorIds
from .types import PrivateCerberusCmdCodes


# Component ID to name mapping
COMPONENT_MAP: dict[int, str] = {
    1: "Agilex",
    2: "HGX-FPG",
    3: "HGX-GPU",
    4: "HGX-HMC",
    5: "HGX-NVS",
    6: "HGX-PSW",
    7: "HGX-GPU-PCIE",
    8: "V710",
    9: "CX7",
    10: "MA35D",
    11: "MI300X",
    12: "H200-FPG",
    13: "H200-GPU",
    14: "H200-HMC",
    15: "H200-NVS",
    16: "H200-PSW",
    17: "MANTICORE",
    18: "INTEL-CPU-GNR",
    19: "B100-FPG",
    20: "B100-GPU",
    21: "B100-HMC",
    22: "B100-NVS",
    23: "B100-PSW",
    24: "MSFT-CAP-CMC",
    25: "MSFT-CAP-OMC",
    26: "PNR-HSP-OVL1",
    27: "AMD-CPU-TURIN",
    28: "MI300X-HF",
    29: "B200-B200",
    30: "B200-FPG",
    31: "B200-HMC",
    32: "B200-NVS",
    33: "B200-NVB",
    34: "PNR-HSP-OVL2",
    35: "GB200-HMC",
    36: "GB200-CPU-EROT",
    37: "GB200-GPU-IROT",
    38: "GB200-FPG-EROT",
    39: "GB200-CX7",
    40: "BMC-TIP",
    41: "AMD-CPU-MI300C",
    42: "FUNGIBLE-DPU",
    43: "INTEL-CPU-GNR-NL",
    44: "HPC-CX7",
    45: "GB200F-M2-SSD",
    46: "GB200F-E1.s-SSD",
    47: "CXL",
    48: "C200-CPU",
    49: "M200-AMC1-TIP",
    50: "M200-AMC2-TIP",
    51: "GB200F-HMC",
    52: "GB200F-CPU-EROT",
    53: "GB200F-GPU-IROT",
    54: "GB200F-FPG-EROT",
    55: "RTX-PRO-6000-GPU",
    56: "RTX-PRO-6000-MCU",
    57: "BRAGA-HSP",
    58: "GB200F-CX8",
    59: "GB200F-MCU",
    60: "HBA-9602W-16E",
    61: "HBA-9600-16E",
    62: "HBA-9600-16I",
    63: "HBA-9600-8I8E",
    64: "HBA-9600W-16E",
    65: "HBA-SAS4016",
    66: "HPC-CX8",
    67: "GB300-HMC",
    68: "GB300-CPU-EROT",
    69: "GB300-GPU-IROT",
    70: "GB300-FPG-EROT",
    71: "GB300-CX8",
    72: "GB300-MCU",
    73: "SAMSUNG-M2-SSD",
    74: "SAMSUNG-E1.s-SSD",
}


def _component_name(component_id: int) -> str:
    """Return the component name for a given ID, or 'Unknown(0xNN)' if not found."""
    name = COMPONENT_MAP.get(component_id)
    if name is not None:
        return name
    return f"Unknown(0x{component_id:08X})"


# --- FORCE_ATTESTATION ---


class ForceAttestationRequestPacket(AllowRawSummary, Packet):
    """Request to force attestation for a specific component instance.

    Fields:
        mode: 1-byte attestation mode
        component_id: 32-bit component identifier
        instance_id: 1-byte instance identifier
    """

    name = "ForceAttest"
    fields_desc = [
        XByteField("mode", 0),
        XLEIntField("component_id", 0),
        XByteField("instance_id", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        comp_name = _component_name(self.component_id)
        summary = f"ForceAttest (mode={self.mode}, {comp_name}, inst={self.instance_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ForceAttestationResponsePacket(AllowRawSummary, Packet):
    """Response to force attestation request (empty payload)."""

    name = "ForceAttest"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return "ForceAttest ()", [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ForceAttestationCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 0:
            return ForceAttestationResponsePacket
        return ForceAttestationRequestPacket


bind_layers(
    VdPciHdrPacket,
    ForceAttestationCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=PrivateCerberusCmdCodes.FORCE_ATTESTATION,
)


# --- GET_PCD_COMPONENT_INSTANCE_INFO ---


class GetComponentInstanceInfoRequestPacket(AllowRawSummary, Packet):
    """Request to get instance info for a PCD component.

    Fields:
        component_id: 32-bit component identifier
    """

    name = "GetComponentInstanceInfo"
    fields_desc = [XLEIntField("component_id", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        comp_name = _component_name(self.component_id)
        summary = f"GetCompInstInfo ({comp_name})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ComponentInstanceEntry(Packet):
    """A single (instance_id, eid) tuple in the instance info response."""

    name = "ComponentInstanceEntry"
    fields_desc = [
        XByteField("instance_id", 0),
        XByteField("eid", 0),
    ]

    def extract_padding(self, s: bytes) -> tuple[bytes, bytes]:
        return b"", s


class ComponentInstanceInfoResponsePacket(AllowRawSummary, Packet):
    """Response containing a list of (instance_id, EID) tuples.

    Fields:
        count: number of instance entries
        entries: list of ComponentInstanceEntry packets
    """

    name = "ComponentInstanceInfo"
    fields_desc = [
        FieldLenField("count", None, count_of="entries", fmt="B"),
        PacketListField("entries", [], ComponentInstanceEntry, count_from=lambda pkt: pkt.count),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        entries_str = ", ".join(f"{e.instance_id}:0x{e.eid:02X}" for e in self.entries)
        summary = f"CompInstInfo [{entries_str}]"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ComponentInstanceInfoCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 4:
            return GetComponentInstanceInfoRequestPacket
        return ComponentInstanceInfoResponsePacket


bind_layers(
    VdPciHdrPacket,
    ComponentInstanceInfoCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=PrivateCerberusCmdCodes.GET_PCD_COMPONENT_INSTANCE_INFO,
)
