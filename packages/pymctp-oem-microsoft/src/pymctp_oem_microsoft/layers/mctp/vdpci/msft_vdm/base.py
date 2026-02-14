from scapy.fields import (
    ByteEnumField,
    ByteField,
    FieldLenField,
    FieldListField,
    PacketListField,
    XByteField,
    XLEIntField,
    XLEShortField,
)
from scapy.packet import Packet, bind_layers

from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.mctp.types import AnyPacketType
from ..types import MsftVdmCommandSets
from .msft_vdm import MsftVdmProtocolPacket
from .types import MsftVdmBaseCmdCodes


# --- STATUS (0x00) - response only ---


class StatusResponsePacket(AllowRawSummary, Packet):
    name = "MsftVdm-Status"
    fields_desc = [
        XLEIntField("error_code", 0),
        XLEShortField("error_data_length", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (err=0x{self.error_code:08X}, data_len={self.error_data_length})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


bind_layers(
    MsftVdmProtocolPacket,
    StatusResponsePacket,
    cmd_set=MsftVdmCommandSets.BASE,
    cmd=MsftVdmBaseCmdCodes.STATUS,
)


# --- CMD_SET_SUPPORT (0x01) ---


class CmdSetSupportRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-CmdSetSupport-Req"
    fields_desc = [XByteField("list_entry_start", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (start={self.list_entry_start})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ProtocolVersionPacket(Packet):
    name = "ProtocolVersion"
    fields_desc = [
        ByteField("major", 0),
        ByteField("minor", 0),
    ]

    def extract_padding(self, s):
        return b"", s

    def mysummary(self):
        return f"{self.major}.{self.minor}"


class CmdSetEntryPacket(Packet):
    name = "CmdSetEntry"
    fields_desc = [
        ByteEnumField("cmd_set_id", 0, MsftVdmCommandSets),
        FieldLenField("version_count", None, count_of="versions", fmt="B"),
        PacketListField("versions", [], ProtocolVersionPacket, count_from=lambda pkt: pkt.version_count),
    ]

    def extract_padding(self, s):
        return b"", s

    def mysummary(self):
        try:
            name = MsftVdmCommandSets(self.cmd_set_id).name
        except ValueError:
            name = f"0x{self.cmd_set_id:02X}"
        ver_count = self.version_count if self.version_count is not None else len(self.versions)
        vers = ",".join(f"{v.major}.{v.minor}" for v in self.versions) if self.versions else ""
        return f"{name}(v=[{vers}])" if vers else f"{name}(count={ver_count})"


class CmdSetSupportResponsePacket(AllowRawSummary, Packet):
    name = "MsftVdm-CmdSetSupport"
    fields_desc = [
        XByteField("next_list_entry", 0),
        FieldLenField("entry_count", None, count_of="entries", fmt="B"),
        PacketListField("entries", [], CmdSetEntryPacket, count_from=lambda pkt: pkt.entry_count),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        next_str = "END" if self.next_list_entry == 0xFF else f"0x{self.next_list_entry:02X}"
        entry_strs = [e.mysummary() for e in self.entries] if self.entries else []
        entries_str = ", ".join(entry_strs)
        summary = f"{self.name} (next={next_str}, sets=[{entries_str}])"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class CmdSetSupportCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 1:
            return CmdSetSupportRequestPacket
        return CmdSetSupportResponsePacket


bind_layers(
    MsftVdmProtocolPacket,
    CmdSetSupportCmdPacket,
    cmd_set=MsftVdmCommandSets.BASE,
    cmd=MsftVdmBaseCmdCodes.CMD_SET_SUPPORT,
)


# --- CAP_NEGOTIATION (0x02) ---


class CapNegotiationRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-CapNeg-Req"
    fields_desc = [
        XLEShortField("max_message_size", 0),
        XLEShortField("max_packet_size", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (max_msg={self.max_message_size}, max_pkt={self.max_packet_size})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class CapNegotiationResponsePacket(AllowRawSummary, Packet):
    name = "MsftVdm-CapNeg"
    fields_desc = [
        XLEShortField("max_message_size", 0),
        XLEShortField("max_packet_size", 0),
        XLEShortField("message_timeout", 0),
        XByteField("feature_flags", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        features = []
        if self.feature_flags & 0x01:
            features.append("TEMP")
        if self.feature_flags & 0x02:
            features.append("HB")
        feat_str = "|".join(features) if features else "none"
        summary = (
            f"{self.name} (max_msg={self.max_message_size}, max_pkt={self.max_packet_size}, "
            f"timeout={self.message_timeout}, features={feat_str})"
        )
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class CapNegotiationCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 4:
            return CapNegotiationRequestPacket
        return CapNegotiationResponsePacket


bind_layers(
    MsftVdmProtocolPacket,
    CapNegotiationCmdPacket,
    cmd_set=MsftVdmCommandSets.BASE,
    cmd=MsftVdmBaseCmdCodes.CAP_NEGOTIATION,
)


# --- HEARTBEAT_CTRL (0x04) ---


class HeartbeatControlRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-HeartbeatCtrl-Req"
    fields_desc = [XByteField("control", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        start = bool(self.control & 0x01)
        force = bool(self.control & 0x02)
        summary = f"{self.name} (start={start}, force={force})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    MsftVdmProtocolPacket,
    HeartbeatControlRequestPacket,
    cmd_set=MsftVdmCommandSets.BASE,
    cmd=MsftVdmBaseCmdCodes.HEARTBEAT_CTRL,
)


# --- HEARTBEAT (0x05) ---


class HeartbeatRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-Heartbeat-Req"
    fields_desc = [
        XLEShortField("timeout", 0),
        FieldLenField("cpu_count", None, count_of="health_entries", fmt="B"),
        FieldListField("health_entries", [], XLEIntField("", 0), count_from=lambda pkt: pkt.cpu_count),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        count = self.cpu_count if self.cpu_count is not None else len(self.health_entries)
        summary = f"{self.name} (timeout={self.timeout}, cpus={count})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    MsftVdmProtocolPacket,
    HeartbeatRequestPacket,
    cmd_set=MsftVdmCommandSets.BASE,
    cmd=MsftVdmBaseCmdCodes.HEARTBEAT,
)
