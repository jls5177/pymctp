# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import ByteEnumField, ConditionalField, XByteField, XLEIntField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes, CerberusUpdateType


_MANIFEST_INIT_CODES = {
    CerberusCmdCodes.INIT_PFM_UPDATE,
    CerberusCmdCodes.INIT_CFM_UPDATE,
    CerberusCmdCodes.INIT_PCD_UPDATE,
}

_MANIFEST_UPDATE_CODES = {
    CerberusCmdCodes.PFM_UPDATE,
    CerberusCmdCodes.CFM_UPDATE,
    CerberusCmdCodes.PCD_UPDATE,
}

_MANIFEST_COMPLETE_CODES = {
    CerberusCmdCodes.COMPLETE_PFM_UPDATE,
    CerberusCmdCodes.COMPLETE_CFM_UPDATE,
    CerberusCmdCodes.COMPLETE_PCD_UPDATE,
}

_PFM_CODES = {
    CerberusCmdCodes.GET_PFM_ID,
    CerberusCmdCodes.GET_PFM_SUPPORTED_FW,
    CerberusCmdCodes.INIT_PFM_UPDATE,
    CerberusCmdCodes.PFM_UPDATE,
    CerberusCmdCodes.COMPLETE_PFM_UPDATE,
}


def _get_manifest_type_name(cmd_code: int) -> str:
    if CerberusCmdCodes.GET_PFM_ID <= cmd_code <= CerberusCmdCodes.COMPLETE_PFM_UPDATE:
        return "PFM"
    if CerberusCmdCodes.GET_CFM_ID <= cmd_code <= CerberusCmdCodes.COMPLETE_CFM_UPDATE:
        return "CFM"
    if CerberusCmdCodes.GET_PCD_ID <= cmd_code <= CerberusCmdCodes.COMPLETE_PCD_UPDATE:
        return "PCD"
    return "Unknown"


def _is_pfm_cmd(pkt: Packet) -> bool:
    return pkt.underlayer.getfieldval("vdm_cmd_code") in {c.value for c in _PFM_CODES}


# --- GET_xxx_ID (PFM/CFM/PCD) ---


class GetManifestIdRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetManifestId-Req"
    fields_desc = [
        ConditionalField(XByteField("port_id", 0), _is_pfm_cmd),
        XByteField("id_type", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        mtype = _get_manifest_type_name(self.underlayer.getfieldval("vdm_cmd_code"))
        parts = [f"type={self.id_type}"]
        if _is_pfm_cmd(self):
            parts.insert(0, f"port={self.port_id}")
        summary = f"Cerberus-Get{mtype}Id-Req ({', '.join(parts)})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ManifestIdResponsePacket(AllowRawSummary, Packet):
    """Response contains the manifest version ID as raw payload."""

    name = "Cerberus-ManifestId"
    fields_desc = [XByteField("valid", 0), XLEIntField("manifest_id", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        mtype = _get_manifest_type_name(self.underlayer.getfieldval("vdm_cmd_code"))
        summary = f"Cerberus-{mtype}Id (valid={self.valid}, id=0x{self.manifest_id:08X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ManifestIdCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) <= 2:
            return GetManifestIdRequestPacket
        return ManifestIdResponsePacket


for _code in (CerberusCmdCodes.GET_PFM_ID, CerberusCmdCodes.GET_CFM_ID, CerberusCmdCodes.GET_PCD_ID):
    bind_layers(VdPciHdrPacket, ManifestIdCmdPacket, vendor_id=VdPCIVendorIds.Msft, vdm_cmd_code=_code)


# --- GET_PFM_SUPPORTED_FW ---


class GetPfmSupportedFwRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetPfmSupportedFw-Req"
    fields_desc = [
        XByteField("port_id", 0),
        XLEIntField("offset", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (port={self.port_id}, offset=0x{self.offset:08X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class PfmSupportedFwResponsePacket(AllowRawSummary, Packet):
    """Response contains variable-length FW version list as raw payload."""

    name = "Cerberus-PfmSupportedFw"
    fields_desc = [XByteField("valid", 0), XLEIntField("pfm_id", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (valid={self.valid}, pfm_id=0x{self.pfm_id:08X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class PfmSupportedFwCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 5:
            return GetPfmSupportedFwRequestPacket
        return PfmSupportedFwResponsePacket


bind_layers(
    VdPciHdrPacket,
    PfmSupportedFwCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_PFM_SUPPORTED_FW,
)


# --- INIT_xxx_UPDATE (PFM/CFM/PCD) ---


class InitManifestUpdateRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-InitManifestUpdate-Req"
    fields_desc = [
        ConditionalField(XByteField("port_id", 0), _is_pfm_cmd),
        XLEIntField("size", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        mtype = _get_manifest_type_name(self.underlayer.getfieldval("vdm_cmd_code"))
        parts = [f"size={self.size}"]
        if _is_pfm_cmd(self):
            parts.insert(0, f"port={self.port_id}")
        summary = f"Cerberus-Init{mtype}Update-Req ({', '.join(parts)})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


for _code in _MANIFEST_INIT_CODES:
    bind_layers(
        VdPciHdrPacket,
        InitManifestUpdateRequestPacket,
        vendor_id=VdPCIVendorIds.Msft,
        vdm_cmd_code=_code,
    )


# --- xxx_UPDATE (PFM/CFM/PCD) ---


class ManifestUpdateRequestPacket(AllowRawSummary, Packet):
    """Request to send manifest update data. Payload follows as raw data."""

    name = "Cerberus-ManifestUpdate-Req"
    fields_desc = [
        ConditionalField(XByteField("port_id", 0), _is_pfm_cmd),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        mtype = _get_manifest_type_name(self.underlayer.getfieldval("vdm_cmd_code"))
        parts = []
        if _is_pfm_cmd(self):
            parts.append(f"port={self.port_id}")
        data_len = len(bytes(self.payload)) if self.payload else 0
        parts.append(f"len={data_len}")
        summary = f"Cerberus-{mtype}Update-Req ({', '.join(parts)})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


for _code in _MANIFEST_UPDATE_CODES:
    bind_layers(
        VdPciHdrPacket,
        ManifestUpdateRequestPacket,
        vendor_id=VdPCIVendorIds.Msft,
        vdm_cmd_code=_code,
    )


# --- COMPLETE_xxx_UPDATE (PFM/CFM/PCD) ---


class CompleteManifestUpdateRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-CompleteManifestUpdate-Req"
    fields_desc = [
        ConditionalField(XByteField("port_id", 0), _is_pfm_cmd),
        ConditionalField(
            XByteField("activation", 0),
            lambda pkt: pkt.underlayer.getfieldval("vdm_cmd_code")
            in {CerberusCmdCodes.COMPLETE_PFM_UPDATE.value, CerberusCmdCodes.COMPLETE_CFM_UPDATE.value},
        ),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        mtype = _get_manifest_type_name(self.underlayer.getfieldval("vdm_cmd_code"))
        parts = []
        if _is_pfm_cmd(self):
            parts.append(f"port={self.port_id}")
        cmd = self.underlayer.getfieldval("vdm_cmd_code")
        if cmd in (CerberusCmdCodes.COMPLETE_PFM_UPDATE.value, CerberusCmdCodes.COMPLETE_CFM_UPDATE.value):
            parts.append(f"activation={self.activation}")
        summary = (
            f"Cerberus-Complete{mtype}Update-Req ({', '.join(parts)})"
            if parts
            else f"Cerberus-Complete{mtype}Update-Req"
        )
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


for _code in _MANIFEST_COMPLETE_CODES:
    bind_layers(
        VdPciHdrPacket,
        CompleteManifestUpdateRequestPacket,
        vendor_id=VdPCIVendorIds.Msft,
        vdm_cmd_code=_code,
    )


# --- GET_CFM_SUPPORTED_COMPONENT_IDS / GET_PCD_SUPPORTED_COMPONENT_IDS ---


class GetComponentIdsRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetComponentIds-Req"
    fields_desc = [XLEIntField("offset", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        cmd = self.underlayer.getfieldval("vdm_cmd_code")
        prefix = "CFM" if cmd == CerberusCmdCodes.GET_CFM_SUPPORTED_COMPONENT_IDS.value else "PCD"
        summary = f"Cerberus-Get{prefix}ComponentIds-Req (offset=0x{self.offset:08X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ComponentIdsResponsePacket(AllowRawSummary, Packet):
    """Response contains variable-length component ID list as raw payload."""

    name = "Cerberus-ComponentIds"
    fields_desc = [XByteField("valid", 0), XLEIntField("manifest_id", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        cmd = self.underlayer.getfieldval("vdm_cmd_code")
        prefix = "CFM" if cmd == CerberusCmdCodes.GET_CFM_SUPPORTED_COMPONENT_IDS.value else "PCD"
        summary = f"Cerberus-{prefix}ComponentIds (valid={self.valid}, id=0x{self.manifest_id:08X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ComponentIdsCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 4:
            return GetComponentIdsRequestPacket
        return ComponentIdsResponsePacket


for _code in (CerberusCmdCodes.GET_CFM_SUPPORTED_COMPONENT_IDS, CerberusCmdCodes.GET_PCD_SUPPORTED_COMPONENT_IDS):
    bind_layers(VdPciHdrPacket, ComponentIdsCmdPacket, vendor_id=VdPCIVendorIds.Msft, vdm_cmd_code=_code)
