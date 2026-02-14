# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""
SPDM GET_VERSION / VERSION message packets (DSP0274).

GET_VERSION request has no payload beyond the header (param1=param2=0).

VERSION response format:
  - reserved (1 byte)
  - version_number_entry_count (1 byte)
  - version_number_entries (2 bytes each): major.minor.update.alpha
    encoded as [major:4][minor:4][update:4][alpha:4] in a 16-bit LE field.

spdm-dump style output:
  SPDM_GET_VERSION ()
  SPDM_VERSION (1.0.0.0, 1.1.0.0, 1.2.0.0)
"""

from scapy.fields import (
    FieldLenField,
    FieldListField,
    XByteField,
    XLEShortField,
)
from scapy.packet import Packet

from ..transport import TransportHdrPacket
from ..types import AnyPacketType
from .spdm import AutobindSPDMMsg, SpdmHdrPacket
from .types import SpdmRequestCode, SpdmResponseCode


def _format_spdm_version_number(ver: int) -> str:
    """Format a 16-bit SPDM version number as major.minor.update.alpha."""
    major = (ver >> 12) & 0xF
    minor = (ver >> 8) & 0xF
    update = (ver >> 4) & 0xF
    alpha = ver & 0xF
    return f"{major}.{minor}.{update}.{alpha}"


@AutobindSPDMMsg(SpdmRequestCode.GET_VERSION)
class GetVersionPacket(Packet):
    name = "SPDM_GET_VERSION"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return "SPDM_GET_VERSION ()", [SpdmHdrPacket, TransportHdrPacket]


@AutobindSPDMMsg(SpdmResponseCode.VERSION)
class VersionPacket(Packet):
    name = "SPDM_VERSION"
    fields_desc = [
        XByteField("reserved", 0),
        FieldLenField("version_number_entry_count", None, fmt="B", count_of="version_number_list"),
        FieldListField(
            "version_number_list",
            [],
            XLEShortField("", 0),
            count_from=lambda pkt: pkt.version_number_entry_count,
        ),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        if self.version_number_list:
            versions = ", ".join(_format_spdm_version_number(v) for v in self.version_number_list)
            summary = f"SPDM_VERSION ({versions})"
        else:
            summary = "SPDM_VERSION ()"
        return summary, [SpdmHdrPacket, TransportHdrPacket]


def GetVersion() -> GetVersionPacket:
    """Create a GET_VERSION request packet."""
    hdr = SpdmHdrPacket(
        spdm_version=0x10,
        request_response_code=SpdmRequestCode.GET_VERSION,
        param1=0,
        param2=0,
    )
    return GetVersionPacket(_underlayer=hdr)


def VersionResponse(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    version_number_list: list[int] | None = None,
) -> VersionPacket:
    """Create a VERSION response packet."""
    hdr = SpdmHdrPacket(
        spdm_version=0x10,
        request_response_code=SpdmResponseCode.VERSION,
        param1=0,
        param2=0,
    )
    if _pkt:
        return VersionPacket(_pkt, _underlayer=hdr)
    version_number_list = version_number_list or []
    return VersionPacket(
        version_number_list=version_number_list,
        _underlayer=hdr,
    )
