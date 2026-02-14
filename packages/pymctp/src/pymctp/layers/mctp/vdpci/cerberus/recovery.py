# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import XByteField, XLEIntField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes


# --- TRIGGER_FW_RECOVERY ---


class TriggerFwRecoveryRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-TriggerFwRecovery-Req"
    fields_desc = [XByteField("port_id", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (port={self.port_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    TriggerFwRecoveryRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.TRIGGER_FW_RECOVERY,
)


# --- PREPARE_RECOVERY_IMAGE ---


class PrepareRecoveryImageRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-PrepareRecoveryImage-Req"
    fields_desc = [
        XByteField("port_id", 0),
        XLEIntField("size", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (port={self.port_id}, size={self.size})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    PrepareRecoveryImageRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.PREPARE_RECOVERY_IMAGE,
)


# --- UPDATE_RECOVERY_IMAGE ---


class UpdateRecoveryImageRequestPacket(AllowRawSummary, Packet):
    """Request to send recovery image data. Payload follows as raw data."""

    name = "Cerberus-UpdateRecoveryImage-Req"
    fields_desc = [XByteField("port_id", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        data_len = len(bytes(self.payload)) if self.payload else 0
        summary = f"{self.name} (port={self.port_id}, len={data_len})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    UpdateRecoveryImageRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.UPDATE_RECOVERY_IMAGE,
)


# --- ACTIVATE_RECOVERY_IMAGE ---


class ActivateRecoveryImageRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-ActivateRecoveryImage-Req"
    fields_desc = [XByteField("port_id", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (port={self.port_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    ActivateRecoveryImageRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.ACTIVATE_RECOVERY_IMAGE,
)


# --- GET_RECOVERY_IMAGE_VERSION ---


class GetRecoveryImageVersionRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetRecoveryImageVer-Req"
    fields_desc = [XByteField("port_id", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (port={self.port_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class RecoveryImageVersionResponsePacket(AllowRawSummary, Packet):
    """Response contains the recovery image version string as raw payload."""

    name = "Cerberus-RecoveryImageVer"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        ver = bytes(self.payload).rstrip(b"\0").decode(errors="replace") if self.payload else ""
        summary = f"{self.name} (ver={ver})" if ver else self.name
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class RecoveryImageVersionCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 1:
            return GetRecoveryImageVersionRequestPacket
        return RecoveryImageVersionResponsePacket


bind_layers(
    VdPciHdrPacket,
    RecoveryImageVersionCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_RECOVERY_IMAGE_VERSION,
)
