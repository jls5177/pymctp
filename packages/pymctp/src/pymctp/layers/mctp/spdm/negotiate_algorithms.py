# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""
SPDM NEGOTIATE_ALGORITHMS / ALGORITHMS message packets (DSP0274).

The request carries the requester's supported algorithms. The response carries
the responder's selected algorithms.  Both include a fixed header followed by
optional extended algorithm entries and (v1.1+) algorithm structure tables.

spdm-dump style output:
  SPDM_NEGOTIATE_ALGORITHMS (MeasSpec=0x01(DMTF), Hash=0x00000001(SHA_256),
      Asym=0x00000010(ECDSA_P256))
  SPDM_ALGORITHMS (MeasSpec=0x01(DMTF), MeasHash=0x00000002(SHA_256),
      Hash=0x00000001(SHA_256), Asym=0x00000010(ECDSA_P256))
"""

from enum import IntFlag

from scapy.fields import (
    ConditionalField,
    FieldLenField,
    LEShortField,
    StrLenField,
    XByteField,
    XLEIntField,
    XLEShortField,
)
from scapy.packet import Packet

from ..transport import TransportHdrPacket
from ..types import AnyPacketType
from .spdm import AutobindSPDMMsg, SpdmHdrPacket
from .types import SpdmRequestCode, SpdmResponseCode

SPDM_VERSION_11 = 0x11


# ---------------------------------------------------------------------------
# Algorithm bitmask enums
# ---------------------------------------------------------------------------
class BaseAsymAlgo(IntFlag):
    RSASSA_2048 = 0x0000_0001
    RSAPSS_2048 = 0x0000_0002
    RSASSA_3072 = 0x0000_0004
    RSAPSS_3072 = 0x0000_0008
    ECDSA_P256 = 0x0000_0010
    RSASSA_4096 = 0x0000_0020
    RSAPSS_4096 = 0x0000_0040
    ECDSA_P384 = 0x0000_0080
    ECDSA_P521 = 0x0000_0100
    # v1.2
    SM2_P256 = 0x0000_0200
    EDDSA_25519 = 0x0000_0400
    EDDSA_448 = 0x0000_0800


class BaseHashAlgo(IntFlag):
    SHA_256 = 0x0000_0001
    SHA_384 = 0x0000_0002
    SHA_512 = 0x0000_0004
    SHA3_256 = 0x0000_0008
    SHA3_384 = 0x0000_0010
    SHA3_512 = 0x0000_0020
    # v1.2
    SM3_256 = 0x0000_0040


class MeasurementHashAlgo(IntFlag):
    RAW_BIT_STREAM = 0x0000_0001
    SHA_256 = 0x0000_0002
    SHA_384 = 0x0000_0004
    SHA_512 = 0x0000_0008
    SHA3_256 = 0x0000_0010
    SHA3_384 = 0x0000_0020
    SHA3_512 = 0x0000_0040
    # v1.2
    SM3_256 = 0x0000_0080


class MeasurementSpecification(IntFlag):
    DMTF = 0x01


def _format_flags(flags: int, flag_enum: type[IntFlag]) -> str:
    names = [m.name for m in flag_enum if flags & m.value]
    return "|".join(names) if names else "0"


# ---------------------------------------------------------------------------
# NEGOTIATE_ALGORITHMS request
# ---------------------------------------------------------------------------
@AutobindSPDMMsg(SpdmRequestCode.NEGOTIATE_ALGORITHMS)
class NegotiateAlgorithmsPacket(Packet):
    name = "SPDM_NEGOTIATE_ALGORITHMS"
    fields_desc = [
        LEShortField("length", 0),
        XByteField("measurement_specification", 0),
        XByteField("other_params_support", 0),
        XLEIntField("base_asym_algo", 0),
        XLEIntField("base_hash_algo", 0),
        # pqc_asym_algo added in v1.4 — always present in the struct but reserved before 1.4
        XLEIntField("pqc_asym_algo", 0),
        StrLenField("reserved2", b"\x00" * 8, length_from=lambda pkt: 8),
        XByteField("ext_asym_count", 0),
        XByteField("ext_hash_count", 0),
        XByteField("reserved3", 0),
        XByteField("mel_specification", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"SPDM_NEGOTIATE_ALGORITHMS ("
            f"MeasSpec=0x{self.measurement_specification:02X}"
            f"({_format_flags(self.measurement_specification, MeasurementSpecification)})"
            f", Hash=0x{self.base_hash_algo:08X}"
            f"({_format_flags(self.base_hash_algo, BaseHashAlgo)})"
            f", Asym=0x{self.base_asym_algo:08X}"
            f"({_format_flags(self.base_asym_algo, BaseAsymAlgo)})"
            f")"
        )
        return summary, [SpdmHdrPacket, TransportHdrPacket]


# ---------------------------------------------------------------------------
# ALGORITHMS response
# ---------------------------------------------------------------------------
@AutobindSPDMMsg(SpdmResponseCode.ALGORITHMS)
class AlgorithmsPacket(Packet):
    name = "SPDM_ALGORITHMS"
    fields_desc = [
        LEShortField("length", 0),
        XByteField("measurement_specification_sel", 0),
        XByteField("other_params_selection", 0),
        XLEIntField("measurement_hash_algo", 0),
        XLEIntField("base_asym_sel", 0),
        XLEIntField("base_hash_sel", 0),
        # pqc_asym_sel added in v1.4
        XLEIntField("pqc_asym_sel", 0),
        StrLenField("reserved2", b"\x00" * 7, length_from=lambda pkt: 7),
        XByteField("mel_specification_sel", 0),
        XByteField("ext_asym_sel_count", 0),
        XByteField("ext_hash_sel_count", 0),
        XLEShortField("reserved3", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"SPDM_ALGORITHMS ("
            f"MeasSpec=0x{self.measurement_specification_sel:02X}"
            f"({_format_flags(self.measurement_specification_sel, MeasurementSpecification)})"
            f", MeasHash=0x{self.measurement_hash_algo:08X}"
            f"({_format_flags(self.measurement_hash_algo, MeasurementHashAlgo)})"
            f", Hash=0x{self.base_hash_sel:08X}"
            f"({_format_flags(self.base_hash_sel, BaseHashAlgo)})"
            f", Asym=0x{self.base_asym_sel:08X}"
            f"({_format_flags(self.base_asym_sel, BaseAsymAlgo)})"
            f")"
        )
        return summary, [SpdmHdrPacket, TransportHdrPacket]


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------
def NegotiateAlgorithms(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    spdm_version: int = SPDM_VERSION_11,
    measurement_specification: int = MeasurementSpecification.DMTF,
    base_asym_algo: int = 0,
    base_hash_algo: int = 0,
    other_params_support: int = 0,
) -> NegotiateAlgorithmsPacket:
    """Create a NEGOTIATE_ALGORITHMS request packet."""
    hdr = SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=SpdmRequestCode.NEGOTIATE_ALGORITHMS,
        param1=0,
        param2=0,
    )
    if _pkt:
        return NegotiateAlgorithmsPacket(_pkt, _underlayer=hdr)
    return NegotiateAlgorithmsPacket(
        measurement_specification=measurement_specification,
        base_asym_algo=base_asym_algo,
        base_hash_algo=base_hash_algo,
        other_params_support=other_params_support,
        _underlayer=hdr,
    )


def AlgorithmsResponse(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    spdm_version: int = SPDM_VERSION_11,
    measurement_specification_sel: int = MeasurementSpecification.DMTF,
    measurement_hash_algo: int = 0,
    base_asym_sel: int = 0,
    base_hash_sel: int = 0,
    other_params_selection: int = 0,
) -> AlgorithmsPacket:
    """Create an ALGORITHMS response packet."""
    hdr = SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=SpdmResponseCode.ALGORITHMS,
        param1=0,
        param2=0,
    )
    if _pkt:
        return AlgorithmsPacket(_pkt, _underlayer=hdr)
    return AlgorithmsPacket(
        measurement_specification_sel=measurement_specification_sel,
        measurement_hash_algo=measurement_hash_algo,
        base_asym_sel=base_asym_sel,
        base_hash_sel=base_hash_sel,
        other_params_selection=other_params_selection,
        _underlayer=hdr,
    )
