# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""
SPDM GET_CAPABILITIES / CAPABILITIES message packets (DSP0274).

The wire format varies by negotiated SPDM version. The version is taken from
the SPDM header (spdm_version field in the underlayer).

v1.0 request:  no payload beyond the SPDM header.
v1.0 response: reserved(1) + ct_exponent(1) + reserved2(2) + flags(4 LE)

v1.1 adds the same body to the *request*.

v1.2 appends:  data_transfer_size(4 LE) + max_spdm_msg_size(4 LE)

spdm-dump style output:
  SPDM_GET_CAPABILITIES ()                                           # v1.0
  SPDM_GET_CAPABILITIES (Flags=0x000000FE, CTExponent=0x00)          # v1.1
  SPDM_CAPABILITIES (Flags=0x0000FFFE, CTExponent=0x0C,
                      DataTransSize=0x00001000, MaxSpdmMsgSize=0x00001000)  # v1.2
"""

from enum import IntFlag

from scapy.fields import ConditionalField, XByteField, XLEIntField, XLEShortField
from scapy.packet import Packet

from ..transport import TransportHdrPacket
from ..types import AnyPacketType
from .spdm import AutobindSPDMMsg, SpdmHdrPacket
from .types import SpdmRequestCode, SpdmResponseCode

SPDM_VERSION_10 = 0x10
SPDM_VERSION_11 = 0x11
SPDM_VERSION_12 = 0x12


def _spdm_version(pkt: Packet) -> int:
    """Return the SPDM version byte from the underlayer header."""
    if pkt.underlayer is not None:
        return pkt.underlayer.getfieldval("spdm_version")
    return SPDM_VERSION_10


# ---------------------------------------------------------------------------
# Requester capability flags  (DSP0274 Table 24 – GET_CAPABILITIES request)
# ---------------------------------------------------------------------------
class RequesterCapabilityFlags(IntFlag):
    """SPDM requester capability flags (DSP0274)."""

    # v1.1
    CERT_CAP = 0x0000_0002
    CHAL_CAP = 0x0000_0004
    ENCRYPT_CAP = 0x0000_0040
    MAC_CAP = 0x0000_0080
    MUT_AUTH_CAP = 0x0000_0100
    KEY_EX_CAP = 0x0000_0200
    PSK_CAP = 0x0000_0400
    ENCAP_CAP = 0x0000_1000
    HBEAT_CAP = 0x0000_2000
    KEY_UPD_CAP = 0x0000_4000
    HANDSHAKE_IN_THE_CLEAR_CAP = 0x0000_8000
    PUB_KEY_ID_CAP = 0x0001_0000
    # v1.2
    CHUNK_CAP = 0x0002_0000
    # v1.3
    EP_INFO_CAP_NO_SIG = 0x0040_0000
    EP_INFO_CAP_SIG = 0x0080_0000
    EVENT_CAP = 0x0200_0000
    MULTI_KEY_CAP_ONLY = 0x0400_0000
    MULTI_KEY_CAP_NEG = 0x0800_0000
    # v1.4
    LARGE_RESP_CAP = 0x8000_0000


# ---------------------------------------------------------------------------
# Responder capability flags  (DSP0274 Table 25 – CAPABILITIES response)
# ---------------------------------------------------------------------------
class ResponderCapabilityFlags(IntFlag):
    """SPDM responder capability flags (DSP0274)."""

    # v1.0
    CACHE_CAP = 0x0000_0001
    CERT_CAP = 0x0000_0002
    CHAL_CAP = 0x0000_0004
    MEAS_CAP_NO_SIG = 0x0000_0008
    MEAS_CAP_SIG = 0x0000_0010
    MEAS_FRESH_CAP = 0x0000_0020
    # v1.1
    ENCRYPT_CAP = 0x0000_0040
    MAC_CAP = 0x0000_0080
    MUT_AUTH_CAP = 0x0000_0100
    KEY_EX_CAP = 0x0000_0200
    PSK_CAP = 0x0000_0400
    PSK_CAP_WITH_CONTEXT = 0x0000_0800
    ENCAP_CAP = 0x0000_1000
    HBEAT_CAP = 0x0000_2000
    KEY_UPD_CAP = 0x0000_4000
    HANDSHAKE_IN_THE_CLEAR_CAP = 0x0000_8000
    PUB_KEY_ID_CAP = 0x0001_0000
    # v1.2
    CHUNK_CAP = 0x0002_0000
    ALIAS_CERT_CAP = 0x0004_0000
    SET_CERT_CAP = 0x0008_0000
    CSR_CAP = 0x0010_0000
    CERT_INSTALL_RESET_CAP = 0x0020_0000
    # v1.3
    EP_INFO_CAP_NO_SIG = 0x0040_0000
    EP_INFO_CAP_SIG = 0x0080_0000
    MEL_CAP = 0x0100_0000
    EVENT_CAP = 0x0200_0000
    MULTI_KEY_CAP_ONLY = 0x0400_0000
    MULTI_KEY_CAP_NEG = 0x0800_0000
    GET_KEY_PAIR_INFO_CAP = 0x1000_0000
    SET_KEY_PAIR_INFO_CAP = 0x2000_0000
    # v1.4
    SET_KEY_PAIR_RESET_CAP = 0x4000_0000
    LARGE_RESP_CAP = 0x8000_0000


# ---------------------------------------------------------------------------
# Helper to pretty-print a flags bitmask
# ---------------------------------------------------------------------------
def _format_flags(flags: int, flag_enum: type[IntFlag]) -> str:
    """Format capability flags as a comma-separated string of flag names."""
    names = [member.name for member in flag_enum if flags & member.value]
    return ", ".join(names) if names else ""


# ---------------------------------------------------------------------------
# Capabilities summary builder (shared between request and response)
# ---------------------------------------------------------------------------
def _capabilities_summary(pkt: Packet, label: str) -> str:
    ver = _spdm_version(pkt)
    if ver < SPDM_VERSION_11 and label == "SPDM_GET_CAPABILITIES":
        return f"{label} ()"
    summary = f"{label} (Flags=0x{pkt.flags:08X}, CTExponent=0x{pkt.ct_exponent:02X}"
    if ver >= SPDM_VERSION_12:
        summary += f", DataTransSize=0x{pkt.data_transfer_size:08X}, MaxSpdmMsgSize=0x{pkt.max_spdm_msg_size:08X}"
    summary += ")"
    return summary


# ---------------------------------------------------------------------------
# GET_CAPABILITIES request packet
# ---------------------------------------------------------------------------
@AutobindSPDMMsg(SpdmRequestCode.GET_CAPABILITIES)
class GetCapabilitiesPacket(Packet):
    name = "SPDM_GET_CAPABILITIES"
    fields_desc = [
        # v1.1+ fields
        ConditionalField(XByteField("reserved", 0), lambda pkt: _spdm_version(pkt) >= SPDM_VERSION_11),
        ConditionalField(XByteField("ct_exponent", 0), lambda pkt: _spdm_version(pkt) >= SPDM_VERSION_11),
        ConditionalField(XLEShortField("reserved2", 0), lambda pkt: _spdm_version(pkt) >= SPDM_VERSION_11),
        ConditionalField(XLEIntField("flags", 0), lambda pkt: _spdm_version(pkt) >= SPDM_VERSION_11),
        # v1.2+ fields
        ConditionalField(XLEIntField("data_transfer_size", 0), lambda pkt: _spdm_version(pkt) >= SPDM_VERSION_12),
        ConditionalField(XLEIntField("max_spdm_msg_size", 0), lambda pkt: _spdm_version(pkt) >= SPDM_VERSION_12),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return _capabilities_summary(self, "SPDM_GET_CAPABILITIES"), [SpdmHdrPacket, TransportHdrPacket]


# ---------------------------------------------------------------------------
# CAPABILITIES response packet
# ---------------------------------------------------------------------------
@AutobindSPDMMsg(SpdmResponseCode.CAPABILITIES)
class CapabilitiesPacket(Packet):
    name = "SPDM_CAPABILITIES"
    fields_desc = [
        XByteField("reserved", 0),
        XByteField("ct_exponent", 0),
        XLEShortField("reserved2", 0),
        XLEIntField("flags", 0),
        # v1.2+ fields
        ConditionalField(XLEIntField("data_transfer_size", 0), lambda pkt: _spdm_version(pkt) >= SPDM_VERSION_12),
        ConditionalField(XLEIntField("max_spdm_msg_size", 0), lambda pkt: _spdm_version(pkt) >= SPDM_VERSION_12),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return _capabilities_summary(self, "SPDM_CAPABILITIES"), [SpdmHdrPacket, TransportHdrPacket]


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------
def GetCapabilities(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    spdm_version: int = SPDM_VERSION_11,
    ct_exponent: int = 0,
    flags: int = 0,
    data_transfer_size: int | None = None,
    max_spdm_msg_size: int | None = None,
) -> GetCapabilitiesPacket:
    """Create a GET_CAPABILITIES request packet."""
    hdr = SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=SpdmRequestCode.GET_CAPABILITIES,
        param1=0,
        param2=0,
    )
    if _pkt:
        return GetCapabilitiesPacket(_pkt, _underlayer=hdr)
    kwargs: dict = {}
    if spdm_version >= SPDM_VERSION_11:
        kwargs.update(ct_exponent=ct_exponent, flags=flags)
    if spdm_version >= SPDM_VERSION_12:
        kwargs.update(
            data_transfer_size=data_transfer_size or 0,
            max_spdm_msg_size=max_spdm_msg_size or 0,
        )
    return GetCapabilitiesPacket(_underlayer=hdr, **kwargs)


def CapabilitiesResponse(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    spdm_version: int = SPDM_VERSION_11,
    ct_exponent: int = 0,
    flags: int = 0,
    data_transfer_size: int | None = None,
    max_spdm_msg_size: int | None = None,
) -> CapabilitiesPacket:
    """Create a CAPABILITIES response packet."""
    hdr = SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=SpdmResponseCode.CAPABILITIES,
        param1=0,
        param2=0,
    )
    if _pkt:
        return CapabilitiesPacket(_pkt, _underlayer=hdr)
    kwargs: dict = dict(ct_exponent=ct_exponent, flags=flags)
    if spdm_version >= SPDM_VERSION_12:
        kwargs.update(
            data_transfer_size=data_transfer_size or 0,
            max_spdm_msg_size=max_spdm_msg_size or 0,
        )
    return CapabilitiesPacket(_underlayer=hdr, **kwargs)
