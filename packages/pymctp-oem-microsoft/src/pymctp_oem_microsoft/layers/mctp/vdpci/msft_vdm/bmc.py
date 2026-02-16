from enum import IntEnum

from scapy.fields import (
    ByteEnumField,
    ByteField,
    FieldLenField,
    FieldListField,
    PacketListField,
    XByteField,
    XLEShortField,
)
from scapy.packet import Packet, bind_layers

from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.mctp.types import AnyPacketType
from ..types import MsftVdmCommandSets
from .msft_vdm import MsftVdmProtocolPacket
from .types import MsftVdmBmcCmdCodes


class TransportType(IntEnum):
    SMBUS = 1
    PCIE_VDM = 2
    USB = 3
    KCS = 4
    SERIAL = 5
    I3C = 6
    MMBI = 7
    PCC = 8
    UCIE = 9
    VENDOR_DEFINED = 0xFF


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
            f"{self.name} (start={self.start_index}, max={self.max_entry_count}, filter=0x{self.filter_properties:04X})"
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
        summary = f"{self.name} (start={self.start_index}, count={self.entry_count}, remaining={self.remaining_count})"
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
    MsftVdmProtocolPacket,
    GetSystemDevicesCmdPacket,
    cmd_set=MsftVdmCommandSets.BMC,
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
    MsftVdmProtocolPacket,
    GetDeviceStringCmdPacket,
    cmd_set=MsftVdmCommandSets.BMC,
    cmd=MsftVdmBmcCmdCodes.BMC_GET_DEVICE_STRING,
)


# --- GET_DEVICE_EID (0x15) ---


class EidEntryPacket(Packet):
    name = "EidEntry"
    fields_desc = [
        ByteField("eid", 0),
        ByteEnumField("transport_type", 0, TransportType),
    ]

    def extract_padding(self, s):
        return b"", s

    def mysummary(self):
        try:
            transport = TransportType(self.transport_type).name
        except ValueError:
            transport = f"0x{self.transport_type:02X}"
        return f"{self.eid}({transport})"


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
        summary = f"{self.name} (vid=0x{self.vendor_id:04X}, did=0x{self.device_id:04X}, inst={self.instance})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class GetDeviceEidResponsePacket(AllowRawSummary, Packet):
    name = "MsftVdm-DeviceEid"
    fields_desc = [
        FieldLenField("eid_count", None, count_of="entries", fmt="B"),
        PacketListField("entries", [], EidEntryPacket, count_from=lambda pkt: pkt.eid_count),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        entry_strs = [e.mysummary() for e in self.entries] if self.entries else []
        entries_str = ", ".join(entry_strs)
        summary = f"{self.name} (eids=[{entries_str}])"
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
    MsftVdmProtocolPacket,
    GetDeviceEidCmdPacket,
    cmd_set=MsftVdmCommandSets.BMC,
    cmd=MsftVdmBmcCmdCodes.BMC_GET_DEVICE_EID,
)
