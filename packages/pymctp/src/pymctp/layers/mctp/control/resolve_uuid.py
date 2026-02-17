# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import uuid

from scapy.fields import UUIDField, XByteField
from scapy.packet import Packet

from .. import TransportHdrPacket
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, ControlHdrPacket
from .types import ContrlCmdCodes


@AutobindControlMsg(ContrlCmdCodes.ResolveUUID, is_request=True)
class ResolveUUIDRequestPacket(Packet):
    name = "ResolveUUID"
    fields_desc = [
        UUIDField("uuid", None, uuid_fmt=UUIDField.FORMAT_BE),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (uuid: {self.uuid})"
        return summary, [ControlHdrPacket, TransportHdrPacket]


@AutobindControlMsg(ContrlCmdCodes.ResolveUUID, is_request=False)
class ResolveUUIDResponsePacket(Packet):
    name = "ResolveUUID"
    fields_desc = [
        XByteField("eid", 0),
        XByteField("bridge_eid", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (eid: 0x{self.eid:02X}, bridge_eid: 0x{self.bridge_eid:02X})"
        return summary, [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
ResolveUUIDPacket = ResolveUUIDRequestPacket


def ResolveUUID(_pkt: bytes | bytearray = b"", /, *, target_uuid: uuid.UUID | None = None) -> ResolveUUIDRequestPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.ResolveUUID)
    if _pkt:
        return ResolveUUIDRequestPacket(_pkt, _underlayer=hdr)
    return ResolveUUIDRequestPacket(
        uuid=target_uuid,
        _underlayer=hdr,
    )


def ResolveUUIDResponse(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    eid: int = 0,
    bridge_eid: int = 0,
) -> ResolveUUIDResponsePacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.ResolveUUID)
    if _pkt:
        return ResolveUUIDResponsePacket(_pkt, _underlayer=hdr)
    return ResolveUUIDResponsePacket(
        eid=eid,
        bridge_eid=bridge_eid,
        _underlayer=hdr,
    )
