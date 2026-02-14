# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import StrFixedLenField, XByteField, XLEShortField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes


# --- GET_PMR ---


class GetPmrRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetPMR-Req"
    fields_desc = [XByteField("pmr_id", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (pmr={self.pmr_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class PmrResponsePacket(AllowRawSummary, Packet):
    """Response contains the variable-length PMR value as raw payload."""

    name = "Cerberus-PMR"
    fields_desc = [XByteField("pmr_length", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (len={self.pmr_length})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class PmrCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 1:
            return GetPmrRequestPacket
        return PmrResponsePacket


bind_layers(
    VdPciHdrPacket,
    PmrCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_PMR,
)


# --- GET_DIGEST ---


class GetDigestRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetDigest-Req"
    fields_desc = [
        XByteField("slot_num", 0),
        XByteField("key_algorithm", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (slot={self.slot_num}, algo=0x{self.key_algorithm:02X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class DigestResponsePacket(AllowRawSummary, Packet):
    """Response contains the certificate chain digest(s) as raw payload."""

    name = "Cerberus-Digest"
    fields_desc = [XByteField("num_digests", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (count={self.num_digests})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class DigestCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 2:
            return GetDigestRequestPacket
        return DigestResponsePacket


bind_layers(
    VdPciHdrPacket,
    DigestCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_DIGEST,
)


# --- GET_CERTIFICATE ---


class GetCertificateRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetCertificate-Req"
    fields_desc = [
        XByteField("slot_num", 0),
        XByteField("cert_num", 0),
        XLEShortField("offset", 0),
        XLEShortField("length", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (slot={self.slot_num}, cert={self.cert_num}, offset={self.offset}, len={self.length})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class CertificateResponsePacket(AllowRawSummary, Packet):
    """Response contains the variable-length certificate data as raw payload."""

    name = "Cerberus-Certificate"
    fields_desc = [
        XByteField("slot_num", 0),
        XByteField("cert_num", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        data_len = len(bytes(self.payload)) if self.payload else 0
        summary = f"{self.name} (slot={self.slot_num}, cert={self.cert_num}, len={data_len})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class CertificateCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 6:
            return GetCertificateRequestPacket
        return CertificateResponsePacket


bind_layers(
    VdPciHdrPacket,
    CertificateCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_CERTIFICATE,
)


# --- ATTESTATION_CHALLENGE ---


class AttestationChallengeRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-Challenge-Req"
    fields_desc = [
        XByteField("slot_num", 0),
        XByteField("reserved", 0),
        StrFixedLenField("nonce", b"\x00" * 32, 32),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (slot={self.slot_num})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class AttestationChallengeResponsePacket(AllowRawSummary, Packet):
    """Response contains slot_num, slot_mask, min_protocol_version, max_protocol_version,
    nonce (32 bytes), then variable-length measurement data and signature."""

    name = "Cerberus-Challenge"
    fields_desc = [
        XByteField("slot_num", 0),
        XByteField("slot_mask", 0),
        XByteField("min_protocol_version", 0),
        XByteField("max_protocol_version", 0),
        StrFixedLenField("nonce", b"\x00" * 32, 32),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"{self.name} (slot={self.slot_num}, mask=0x{self.slot_mask:02X}, "
            f"proto={self.min_protocol_version}-{self.max_protocol_version})"
        )
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class AttestationChallengeCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 34:
            return AttestationChallengeRequestPacket
        return AttestationChallengeResponsePacket


bind_layers(
    VdPciHdrPacket,
    AttestationChallengeCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.ATTESTATION_CHALLENGE,
)
