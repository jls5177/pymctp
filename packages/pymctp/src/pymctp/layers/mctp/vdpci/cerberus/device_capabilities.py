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


class DeviceCapsRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetDevCaps-Req"
    fields_desc = [
        XLEShortField("max_message", 0),
        XLEShortField("max_packet", 0),
        XByteField("device_info", 0),
        XByteField("features", 0),
        XByteField("pk_key_strength", 0),
        XByteField("enc_key_strength", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"{self.name} (max_msg={self.max_message}, max_pkt={self.max_packet}, "
            f"info=0x{self.device_info:02X}, ft=0x{self.features:02X}, "
            f"pk=0x{self.pk_key_strength:02X}, enc=0x{self.enc_key_strength:02X})"
        )
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class DeviceCapsResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-DevCaps"
    fields_desc = [
        XLEShortField("max_message", 0),
        XLEShortField("max_packet", 0),
        XByteField("device_info", 0),
        XByteField("features", 0),
        XByteField("pk_key_strength", 0),
        XByteField("enc_key_strength", 0),
        XByteField("message_timeout", 0),
        XByteField("crypto_timeout", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"{self.name} (max_msg={self.max_message}, max_pkt={self.max_packet}, "
            f"info=0x{self.device_info:02X}, ft=0x{self.features:02X}, "
            f"pk=0x{self.pk_key_strength:02X}, enc=0x{self.enc_key_strength:02X}, "
            f"msg_to={self.message_timeout}, crypto_to={self.crypto_timeout})"
        )
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class DeviceCapsCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 8:
            return DeviceCapsRequestPacket
        return DeviceCapsResponsePacket


bind_layers(
    VdPciHdrPacket,
    DeviceCapsCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_DEVICE_CAPABILITIES,
)
