# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import XByteField, XLEShortField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes


class GetDeviceIdRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetDeviceId-Req"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return self.name, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class DeviceIdResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-DeviceId"
    fields_desc = [
        XLEShortField("vendor_id", 0),
        XLEShortField("device_id", 0),
        XLEShortField("subsystem_vid", 0),
        XLEShortField("subsystem_id", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"{self.name} (vid=0x{self.vendor_id:04X}, did=0x{self.device_id:04X}, "
            f"svid=0x{self.subsystem_vid:04X}, sid=0x{self.subsystem_id:04X})"
        )
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class DeviceIdCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 0:
            return GetDeviceIdRequestPacket
        return DeviceIdResponsePacket


bind_layers(
    VdPciHdrPacket,
    DeviceIdCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_DEVICE_ID,
)
