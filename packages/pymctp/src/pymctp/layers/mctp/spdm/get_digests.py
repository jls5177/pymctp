# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""
SPDM GET_DIGESTS / DIGESTS message packets (DSP0274).

GET_DIGESTS has no payload beyond the SPDM header.
DIGESTS response uses param1 (supported_slot_mask in v1.3+) and param2
(provisioned_slot_mask / slot_mask).  The actual digest data follows as
variable-length payload depending on the negotiated hash algorithm.

spdm-dump style output:
  SPDM_GET_DIGESTS ()
  SPDM_DIGESTS (ProvisionedSlotMask=0x01)
"""

from scapy.packet import Packet

from ..transport import TransportHdrPacket
from ..types import AnyPacketType
from .spdm import AutobindSPDMMsg, SpdmHdrPacket
from .types import SpdmRequestCode, SpdmResponseCode


@AutobindSPDMMsg(SpdmRequestCode.GET_DIGESTS)
class GetDigestsPacket(Packet):
    name = "SPDM_GET_DIGESTS"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return "SPDM_GET_DIGESTS ()", [SpdmHdrPacket, TransportHdrPacket]


@AutobindSPDMMsg(SpdmResponseCode.DIGESTS)
class DigestsPacket(Packet):
    name = "SPDM_DIGESTS"
    # The digest data is variable-length (hash_size * slot_count) and follows
    # as raw payload.  The slot_mask lives in the SPDM header param2.
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        slot_mask = 0
        supported_slot_mask = 0
        ver = 0x10
        if self.underlayer is not None:
            slot_mask = self.underlayer.getfieldval("param2")
            supported_slot_mask = self.underlayer.getfieldval("param1")
            ver = self.underlayer.getfieldval("spdm_version")

        summary = "SPDM_DIGESTS ("
        if ver >= 0x13:
            summary += f"SupportedSlotMask=0x{supported_slot_mask:02X}, "
        summary += f"ProvisionedSlotMask=0x{slot_mask:02X})"
        return summary, [SpdmHdrPacket, TransportHdrPacket]


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------
def GetDigests() -> GetDigestsPacket:
    """Create a GET_DIGESTS request packet."""
    hdr = SpdmHdrPacket(
        spdm_version=0x10,
        request_response_code=SpdmRequestCode.GET_DIGESTS,
    )
    return GetDigestsPacket(_underlayer=hdr)


def DigestsResponse(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    spdm_version: int = 0x10,
    slot_mask: int = 0x01,
    supported_slot_mask: int = 0x00,
) -> DigestsPacket:
    """Create a DIGESTS response packet."""
    hdr = SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=SpdmResponseCode.DIGESTS,
        param1=supported_slot_mask,
        param2=slot_mask,
    )
    if _pkt:
        return DigestsPacket(_pkt, _underlayer=hdr)
    return DigestsPacket(_underlayer=hdr)
