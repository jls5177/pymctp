# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""
SPDM GET_CERTIFICATE / CERTIFICATE message packets (DSP0274).

GET_CERTIFICATE request carries offset and length of the requested portion.
The slot_id is in the SPDM header param1 (bits [3:0]).

CERTIFICATE response carries portion_length and remainder_length.  The actual
certificate chain data follows as variable-length payload.

spdm-dump style output:
  SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0x0000, Length=0x0400)
  SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x0400, RemLen=0x0000)
"""

from scapy.fields import LEShortField
from scapy.packet import Packet

from ..transport import TransportHdrPacket
from ..types import AnyPacketType
from .spdm import AutobindSPDMMsg, SpdmHdrPacket
from .types import SpdmRequestCode, SpdmResponseCode

SPDM_GET_CERTIFICATE_REQUEST_SLOT_ID_MASK = 0x0F


@AutobindSPDMMsg(SpdmRequestCode.GET_CERTIFICATE)
class GetCertificatePacket(Packet):
    name = "SPDM_GET_CERTIFICATE"
    fields_desc = [
        LEShortField("offset", 0),
        LEShortField("length", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        slot_id = 0
        if self.underlayer is not None:
            slot_id = self.underlayer.getfieldval("param1") & SPDM_GET_CERTIFICATE_REQUEST_SLOT_ID_MASK
        summary = (
            f"SPDM_GET_CERTIFICATE (SlotID=0x{slot_id:02X}, Offset=0x{self.offset:04X}, Length=0x{self.length:04X})"
        )
        return summary, [SpdmHdrPacket, TransportHdrPacket]


@AutobindSPDMMsg(SpdmResponseCode.CERTIFICATE)
class CertificatePacket(Packet):
    name = "SPDM_CERTIFICATE"
    fields_desc = [
        LEShortField("portion_length", 0),
        LEShortField("remainder_length", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        slot_id = 0
        if self.underlayer is not None:
            slot_id = self.underlayer.getfieldval("param1") & SPDM_GET_CERTIFICATE_REQUEST_SLOT_ID_MASK
        summary = (
            f"SPDM_CERTIFICATE ("
            f"SlotID=0x{slot_id:02X}"
            f", PortLen=0x{self.portion_length:04X}"
            f", RemLen=0x{self.remainder_length:04X})"
        )
        return summary, [SpdmHdrPacket, TransportHdrPacket]


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------
def GetCertificate(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    spdm_version: int = 0x10,
    slot_id: int = 0,
    offset: int = 0,
    length: int = 0x0400,
) -> GetCertificatePacket:
    """Create a GET_CERTIFICATE request packet."""
    hdr = SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=SpdmRequestCode.GET_CERTIFICATE,
        param1=slot_id & SPDM_GET_CERTIFICATE_REQUEST_SLOT_ID_MASK,
        param2=0,
    )
    if _pkt:
        return GetCertificatePacket(_pkt, _underlayer=hdr)
    return GetCertificatePacket(offset=offset, length=length, _underlayer=hdr)


def CertificateResponse(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    spdm_version: int = 0x10,
    slot_id: int = 0,
    portion_length: int = 0,
    remainder_length: int = 0,
) -> CertificatePacket:
    """Create a CERTIFICATE response packet."""
    hdr = SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=SpdmResponseCode.CERTIFICATE,
        param1=slot_id & SPDM_GET_CERTIFICATE_REQUEST_SLOT_ID_MASK,
        param2=0,
    )
    if _pkt:
        return CertificatePacket(_pkt, _underlayer=hdr)
    return CertificatePacket(
        portion_length=portion_length,
        remainder_length=remainder_length,
        _underlayer=hdr,
    )
