# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import XByteField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes


class GetDeviceInfoRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetDeviceInfo-Req"
    fields_desc = [XByteField("info_index", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (index={self.info_index})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class DeviceInfoResponsePacket(AllowRawSummary, Packet):
    """Response contains a variable-length info string as raw payload."""

    name = "Cerberus-DeviceInfo"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        info = bytes(self.payload).rstrip(b"\0").decode(errors="replace") if self.payload else ""
        summary = f"{self.name} (info={info})" if info else self.name
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class DeviceInfoCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 1:
            return GetDeviceInfoRequestPacket
        return DeviceInfoResponsePacket


bind_layers(
    VdPciHdrPacket,
    DeviceInfoCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_DEVICE_INFO,
)
