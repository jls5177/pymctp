# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import XByteField, XLEShortField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes


# --- EXPORT_CSR ---


class ExportCsrRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-ExportCSR-Req"
    fields_desc = [XByteField("csr_index", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (index={self.csr_index})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ExportCsrResponsePacket(AllowRawSummary, Packet):
    """Response contains the variable-length CSR as raw payload."""

    name = "Cerberus-CSR"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        csr_len = len(bytes(self.payload)) if self.payload else 0
        summary = f"{self.name} (len={csr_len})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ExportCsrCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 1:
            return ExportCsrRequestPacket
        return ExportCsrResponsePacket


bind_layers(
    VdPciHdrPacket,
    ExportCsrCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.EXPORT_CSR,
)


# --- IMPORT_CA_SIGNED_CERT ---


class ImportCertRequestPacket(AllowRawSummary, Packet):
    """Request to import a CA-signed certificate. Cert index followed by cert data."""

    name = "Cerberus-ImportCert-Req"
    fields_desc = [
        XByteField("cert_index", 0),
        XLEShortField("cert_length", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (index={self.cert_index}, len={self.cert_length})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    ImportCertRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.IMPORT_CA_SIGNED_CERT,
)


# --- GET_SIGNED_CERT_STATE ---


class GetSignedCertStateRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetCertState-Req"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return self.name, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class SignedCertStateResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-CertState"
    fields_desc = [XByteField("cert_state", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (state={self.cert_state})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class SignedCertStateCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 0:
            return GetSignedCertStateRequestPacket
        return SignedCertStateResponsePacket


bind_layers(
    VdPciHdrPacket,
    SignedCertStateCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_SIGNED_CERT_STATE,
)
