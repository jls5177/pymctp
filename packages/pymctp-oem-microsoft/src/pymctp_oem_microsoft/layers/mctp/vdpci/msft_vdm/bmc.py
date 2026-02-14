from scapy.fields import (
    ByteField,
    FieldLenField,
    FieldListField,
    XByteField,
    XLEShortField,
)
from scapy.packet import Packet, bind_layers

from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.mctp.types import AnyPacketType
from .msft_vdm import MsftVdmProtocolPacket
from .types import MsftVdmBmcCmdCodes


# --- GET_SYSTEM_DEVICES (0x13) ---

class GetSystemDevicesRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-GetSystemDevices-Req"
    fields_desc = [
        XLEShortField("start_index", 0),
        XLEShortField("max_entry_count", 0),
        XLEShortField("filter_properties", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"{self.name} (start={self.start_index}, max={self.max_entry_count}, "
            f"filter=0x{self.filter_properties:04X})"
        )
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class GetSystemDevicesResponsePacket(AllowRawSummary, Packet):
    name = "MsftVdm-SystemDevices"
    fields_desc = [
        XLEShortField("start_index", 0),
        XLEShortField("entry_count", 0),
        XLEShortField("remaining_count", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"{self.name} (start={self.start_index}, count={self.entry_count}, "
            f"remaining={self.remaining_count})"
        )
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class GetSystemDevicesCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        # Both request and response are 6 bytes; use TO bit from TransportHdrPacket
        # Walk: _underlayer (MsftVdmProtocolPacket) -> underlayer (VdPciHdrPacket) -> underlayer (TransportHdrPacket)
        underlayer = kargs.get("_underlayer")
        if underlayer is not None:
            try:
                to = underlayer.underlayer.underlayer.getfieldval("to")
                if to == 0:
                    return GetSystemDevicesResponsePacket
            except (AttributeError, KeyError):
                pass
        return GetSystemDevicesRequestPacket


bind_layers(
    MsftVdmProtocolPacket, GetSystemDevicesCmdPacket,
    cmd=MsftVdmBmcCmdCodes.BMC_GET_SYSTEM_DEVICES,
)


# --- GET_DEVICE_STRING (0x14) ---

class GetDeviceStringRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-GetDeviceString-Req"
    fields_desc = [
        XLEShortField("vendor_id", 0),
        XLEShortField("device_id", 0),
        XLEShortField("subsystem_vendor_id", 0),
        XLEShortField("subsystem_device_id", 0),
        XByteField("instance", 0),
        XByteField("string_type", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        type_name = "instance" if self.string_type == 0 else "type"
        summary = (
            f"{self.name} (vid=0x{self.vendor_id:04X}, did=0x{self.device_id:04X}, "
            f"inst={self.instance}, str_type={type_name})"
        )
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class GetDeviceStringResponsePacket(AllowRawSummary, Packet):
    name = "MsftVdm-DeviceString"
    fields_desc = [
        XLEShortField("string_length", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        s = bytes(self.payload).rstrip(b"\0").decode(errors="replace") if self.payload else ""
        summary = f'{self.name} (str="{s}")' if s else f"{self.name} (len={self.string_length})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class GetDeviceStringCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 10:
            return GetDeviceStringRequestPacket
        return GetDeviceStringResponsePacket


bind_layers(
    MsftVdmProtocolPacket, GetDeviceStringCmdPacket,
    cmd=MsftVdmBmcCmdCodes.BMC_GET_DEVICE_STRING,
)


# --- GET_DEVICE_EID (0x15) ---

class GetDeviceEidRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-GetDeviceEid-Req"
    fields_desc = [
        XLEShortField("vendor_id", 0),
        XLEShortField("device_id", 0),
        XLEShortField("subsystem_vendor_id", 0),
        XLEShortField("subsystem_device_id", 0),
        XByteField("instance", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"{self.name} (vid=0x{self.vendor_id:04X}, did=0x{self.device_id:04X}, "
            f"inst={self.instance})"
        )
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class GetDeviceEidResponsePacket(AllowRawSummary, Packet):
    name = "MsftVdm-DeviceEid"
    fields_desc = [
        ByteField("eid_count", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (count={self.eid_count})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class GetDeviceEidCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 9:
            return GetDeviceEidRequestPacket
        return GetDeviceEidResponsePacket


bind_layers(
    MsftVdmProtocolPacket, GetDeviceEidCmdPacket,
    cmd=MsftVdmBmcCmdCodes.BMC_GET_DEVICE_EID,
)
