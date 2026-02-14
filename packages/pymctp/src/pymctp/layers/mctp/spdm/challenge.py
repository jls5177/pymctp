# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""
SPDM CHALLENGE / CHALLENGE_AUTH message packets (DSP0274).

CHALLENGE request: 32-byte nonce.  slot_id in header param1, hash_type in
header param2.

CHALLENGE_AUTH response: variable-length payload (cert_chain_hash, nonce,
measurement_summary_hash, opaque data, signature) that depends on negotiated
algorithms.  The fixed summary is built from header fields.

spdm-dump style output:
  SPDM_CHALLENGE (SlotID=0x00, HashType=0x00(NoHash))
  SPDM_CHALLENGE_AUTH (SlotID=0x00, SlotMask=0x01)
"""

from enum import IntEnum

from scapy.fields import StrFixedLenField
from scapy.packet import Packet

from ..transport import TransportHdrPacket
from ..types import AnyPacketType
from .spdm import AutobindSPDMMsg, SpdmHdrPacket
from .types import SpdmRequestCode, SpdmResponseCode

SPDM_NONCE_SIZE = 32


class MeasurementSummaryHashType(IntEnum):
    NO_HASH = 0x00
    TCB_HASH = 0x01
    ALL_HASH = 0xFF


_HASH_TYPE_NAMES = {
    MeasurementSummaryHashType.NO_HASH: "NoHash",
    MeasurementSummaryHashType.TCB_HASH: "TcbHash",
    MeasurementSummaryHashType.ALL_HASH: "AllHash",
}


@AutobindSPDMMsg(SpdmRequestCode.CHALLENGE)
class ChallengePacket(Packet):
    name = "SPDM_CHALLENGE"
    fields_desc = [
        StrFixedLenField("nonce", b"\x00" * SPDM_NONCE_SIZE, length=SPDM_NONCE_SIZE),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        slot_id = 0
        hash_type = 0
        if self.underlayer is not None:
            slot_id = self.underlayer.getfieldval("param1")
            hash_type = self.underlayer.getfieldval("param2")

        ht_name = _HASH_TYPE_NAMES.get(hash_type, f"0x{hash_type:02X}")
        summary = f"SPDM_CHALLENGE (SlotID=0x{slot_id:02X}, HashType=0x{hash_type:02X}({ht_name}))"
        return summary, [SpdmHdrPacket, TransportHdrPacket]


@AutobindSPDMMsg(SpdmResponseCode.CHALLENGE_AUTH)
class ChallengeAuthPacket(Packet):
    name = "SPDM_CHALLENGE_AUTH"
    # The response is entirely variable-length (cert_chain_hash, nonce,
    # measurement_summary_hash, opaque data, signature).  We expose only the
    # header-level fields in the summary and leave the body as raw payload.
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        slot_id = 0
        slot_mask = 0
        if self.underlayer is not None:
            slot_id = self.underlayer.getfieldval("param1") & 0x0F
            slot_mask = self.underlayer.getfieldval("param2")

        summary = f"SPDM_CHALLENGE_AUTH (SlotID=0x{slot_id:02X}, SlotMask=0x{slot_mask:02X})"
        return summary, [SpdmHdrPacket, TransportHdrPacket]


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------
def Challenge(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    spdm_version: int = 0x10,
    slot_id: int = 0,
    hash_type: int = MeasurementSummaryHashType.NO_HASH,
    nonce: bytes = b"\x00" * SPDM_NONCE_SIZE,
) -> ChallengePacket:
    """Create a CHALLENGE request packet."""
    hdr = SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=SpdmRequestCode.CHALLENGE,
        param1=slot_id,
        param2=hash_type,
    )
    if _pkt:
        return ChallengePacket(_pkt, _underlayer=hdr)
    return ChallengePacket(nonce=nonce, _underlayer=hdr)


def ChallengeAuthResponse(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    spdm_version: int = 0x10,
    slot_id: int = 0,
    slot_mask: int = 0x01,
) -> ChallengeAuthPacket:
    """Create a CHALLENGE_AUTH response packet."""
    hdr = SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=SpdmResponseCode.CHALLENGE_AUTH,
        param1=slot_id,
        param2=slot_mask,
    )
    if _pkt:
        return ChallengeAuthPacket(_pkt, _underlayer=hdr)
    return ChallengeAuthPacket(_underlayer=hdr)
