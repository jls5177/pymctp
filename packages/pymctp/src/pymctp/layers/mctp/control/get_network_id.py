# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import UUIDField
from scapy.packet import Packet

from .. import TransportHdrPacket
from ..types import AnyPacketType
from .control import AutobindControlMsg, ControlHdr, ControlHdrPacket
from .types import ContrlCmdCodes

import uuid


@AutobindControlMsg(ContrlCmdCodes.GetNetworkID, is_request=True)
class GetNetworkIDRequestPacket(Packet):
    name = "GetNetworkID"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [ControlHdrPacket, TransportHdrPacket]


@AutobindControlMsg(ContrlCmdCodes.GetNetworkID, is_request=False)
class GetNetworkIDResponsePacket(Packet):
    name = "GetNetworkID"
    fields_desc = [
        UUIDField("network_id", None, uuid_fmt=UUIDField.FORMAT_BE),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (network_id: {self.network_id})"
        return summary, [ControlHdrPacket, TransportHdrPacket]


# Keep backward compatibility alias
GetNetworkIDPacket = GetNetworkIDRequestPacket


def GetNetworkID(_pkt: bytes | bytearray = b"", /, *args) -> GetNetworkIDRequestPacket:
    hdr = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetNetworkID)
    if _pkt:
        return GetNetworkIDRequestPacket(_pkt, _underlayer=hdr)
    return GetNetworkIDRequestPacket(_underlayer=hdr)


def GetNetworkIDResponse(
    _pkt: bytes | bytearray = b"", /, *, network_id: uuid.UUID | None = None
) -> GetNetworkIDResponsePacket:
    hdr = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.GetNetworkID)
    if _pkt:
        return GetNetworkIDResponsePacket(_pkt, _underlayer=hdr)
    return GetNetworkIDResponsePacket(
        network_id=network_id,
        _underlayer=hdr,
    )
