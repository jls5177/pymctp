from enum import IntEnum

from scapy.fields import (
    ConditionalField,
    FieldLenField,
    FlagsField,
    PacketListField,
    StrField,
    XByteField,
    XLEIntField,
    XLEShortField,
)
from scapy.packet import Packet, bind_layers

from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.mctp.types import AnyPacketType
from ..types import MsftVdmCommandSets
from .msft_vdm import MsftVdmProtocolPacket, _is_response
from .types import MsftVdmRotCmdCodes


class RotFeature(IntEnum):
    ROT_RESET = 0
    TENANCY_TRANSFER = 1
    DEBUG_UNLOCK = 2
    RUNTIME_UNLOCK = 3
    CRASH_DUMP = 4
    TIME = 5
    INTRUSION_DETECTION = 6
    WARM_RESET_EVENTS = 7
    LOG = 8


ROT_FEATURE_FLAGS = [f.name for f in RotFeature]


# --- GET_ROT_CAPABILITIES (0x00) ---


class GetRotCapabilitiesRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-GetRotCaps-Req"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return self.name, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class GetRotCapabilitiesResponsePacket(AllowRawSummary, Packet):
    name = "MsftVdm-RotCaps"
    fields_desc = [
        FlagsField("feature_flags", 0, -16, ROT_FEATURE_FLAGS),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        flags = []
        for f in RotFeature:
            if self.feature_flags & (1 << f.value):
                flags.append(f.name)
        feat_str = "|".join(flags) if flags else "none"
        summary = f"{self.name} (features={feat_str})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class GetRotCapabilitiesCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 0:
            return GetRotCapabilitiesRequestPacket
        return GetRotCapabilitiesResponsePacket


bind_layers(
    MsftVdmProtocolPacket,
    GetRotCapabilitiesCmdPacket,
    cmd_set=MsftVdmCommandSets.ROT,
    cmd=MsftVdmRotCmdCodes.GET_ROT_CAPABILITIES,
)


# --- RESET_ROT (0x01) - request only, no payload ---


class ResetRotRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-ResetRot-Req"
    fields_desc = [
        XByteField("core_id", 0xFF),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        core = "ALL" if self.core_id == 0xFF else f"0x{self.core_id:02X}"
        return f"{self.name} (core={core})", [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    MsftVdmProtocolPacket,
    ResetRotRequestPacket,
    cmd_set=MsftVdmCommandSets.ROT,
    cmd=MsftVdmRotCmdCodes.RESET_ROT,
)


# --- SET_TIME (0x0B) - request only ---


class SetTimeRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-SetTime-Req"
    fields_desc = [
        XLEIntField("seconds", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} (seconds=0x{self.seconds:08X})", [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    MsftVdmProtocolPacket,
    SetTimeRequestPacket,
    cmd_set=MsftVdmCommandSets.ROT,
    cmd=MsftVdmRotCmdCodes.SET_TIME,
)


# --- GET_INTRUSION_DETECTION (0x0C) ---


class GetIntrusionDetectionRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-GetIntrusionDet-Req"
    fields_desc = [
        XByteField("control", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        set_ctrl = bool(self.control & 0x01)
        start = bool(self.control & 0x02)
        force = bool(self.control & 0x04)
        summary = f"{self.name} (set={set_ctrl}, start={start}, force={force})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class GetIntrusionDetectionResponsePacket(AllowRawSummary, Packet):
    name = "MsftVdm-IntrusionDet"
    fields_desc = [
        XByteField("detection", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        detected = bool(self.detection & 0x01)
        return f"{self.name} (detected={detected})", [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class GetIntrusionDetectionCmdPacket(Packet):
    """Both request and response are 1 byte; use TO bit to differentiate."""

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        # Both are 1 byte; use TO bit from TransportHdrPacket
        underlayer = kargs.get("_underlayer")
        if underlayer is not None:
            try:
                to = underlayer.underlayer.underlayer.getfieldval("to")
                if to == 0:
                    return GetIntrusionDetectionResponsePacket
            except (AttributeError, KeyError):
                pass
        return GetIntrusionDetectionRequestPacket


bind_layers(
    MsftVdmProtocolPacket,
    GetIntrusionDetectionCmdPacket,
    cmd_set=MsftVdmCommandSets.ROT,
    cmd=MsftVdmRotCmdCodes.GET_INTRUSION_DETECTION,
)


# --- INTRUSION_EVENT (0x0D) - request only (notification from RoT) ---


class IntrusionEventRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-IntrusionEvent"
    fields_desc = [
        XByteField("detection", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} (detection=0x{self.detection:02X})", [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    MsftVdmProtocolPacket,
    IntrusionEventRequestPacket,
    cmd_set=MsftVdmCommandSets.ROT,
    cmd=MsftVdmRotCmdCodes.INTRUSION_EVENT,
)


# --- PREPARE_FOR_WARM_RESET (0x10) ---


class PrepareForWarmResetRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-PrepWarmReset-Req"
    fields_desc = [
        XByteField("core_id", 0xFF),
        XByteField("reserved", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        core = "ALL" if self.core_id == 0xFF else f"0x{self.core_id:02X}"
        return f"{self.name} (core={core})", [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    MsftVdmProtocolPacket,
    PrepareForWarmResetRequestPacket,
    cmd_set=MsftVdmCommandSets.ROT,
    cmd=MsftVdmRotCmdCodes.PREPARE_FOR_WARM_RESET,
)


# --- WARM_RESET_COMPLETE (0x11) - request only, no payload ---


class WarmResetCompleteRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-WarmResetComplete"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return self.name, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    MsftVdmProtocolPacket,
    WarmResetCompleteRequestPacket,
    cmd_set=MsftVdmCommandSets.ROT,
    cmd=MsftVdmRotCmdCodes.WARM_RESET_COMPLETE,
)


# --- SEND_LOG (0x12) ---


# --- Shared enums for RAS log commands (SendLog / ReadLog) ---


class RasLogType(IntEnum):
    LIST_ALL = 0x00
    SEL = 0x01
    HCP_UEC_CPER = 0x02
    MINI_CRASH = 0x03
    SCP_CPER_DIE0 = 0x04
    SCP_CPER_DIE1 = 0x05
    UNKNOWN = 0xFF


class RasHashType(IntEnum):
    SHA2_256 = 0
    SHA2_384 = 1
    SHA2_512 = 2


_HASH_DIGEST_LEN = {
    RasHashType.SHA2_256: 32,
    RasHashType.SHA2_384: 48,
    RasHashType.SHA2_512: 64,
}


def _format_log_type(val: int) -> str:
    try:
        return RasLogType(val).name
    except ValueError:
        return f"0x{val:02X}"


def _format_hash_type(val: int) -> str:
    try:
        return RasHashType(val).name
    except ValueError:
        return f"0x{val:02X}"


SEND_LOG_FLAGS = ["LogReadRequested"]


def _send_log_read_requested(pkt: Packet) -> bool:
    return bool(pkt.flags & 0x01)


class SendLogRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-SendLog-Req"
    fields_desc = [
        XByteField("log_type", 0),
        FlagsField("flags", 0, -8, SEND_LOG_FLAGS),
        # Fields present only when LogReadRequested is set
        ConditionalField(XLEShortField("log_id", 0), _send_log_read_requested),
        ConditionalField(XLEIntField("total_length", 0), _send_log_read_requested),
        ConditionalField(XByteField("hash_type", 0), _send_log_read_requested),
        ConditionalField(
            StrField("digest", b""),
            _send_log_read_requested,
        ),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        lt = _format_log_type(self.log_type)

        if _send_log_read_requested(self):
            ht = _format_hash_type(self.hash_type)
            summary = f"{self.name} (type={lt}, log_id=0x{self.log_id:04X}, len={self.total_length}, hash={ht})"
        else:
            payload_len = len(self.payload) if self.payload else 0
            summary = f"{self.name} (type={lt}, content_len={payload_len})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class SendLogResponsePacket(AllowRawSummary, Packet):
    name = "MsftVdm-SendLog-Res"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return f"{self.name} ()", [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class SendLogCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        underlayer = kargs.get("_underlayer")
        if underlayer is not None:
            try:
                if _is_response(underlayer):
                    return SendLogResponsePacket
            except (AttributeError, KeyError):
                pass
        return SendLogRequestPacket


bind_layers(
    MsftVdmProtocolPacket,
    SendLogCmdPacket,
    cmd_set=MsftVdmCommandSets.ROT,
    cmd=MsftVdmRotCmdCodes.SEND_LOG,
)


# --- READ_LOG (0x13) ---


class ReadLogRequestPacket(AllowRawSummary, Packet):
    name = "MsftVdm-ReadLog-Req"
    fields_desc = [
        XByteField("log_type", 0),
        XLEShortField("log_id", 0),
        XLEIntField("offset", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        lt = _format_log_type(self.log_type)
        summary = f"{self.name} (type={lt}, log_id=0x{self.log_id:04X}, offset={self.offset})"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class LogInfoEntryPacket(Packet):
    """Single log info entry in a ReadLog list response."""

    name = "LogInfoEntry"
    fields_desc = [
        XByteField("log_type", 0),
        XLEShortField("log_id", 0),
        XLEIntField("total_length", 0),
        XByteField("hash_type", 0),
        StrField("digest", b""),
    ]

    def extract_padding(self, s: bytes) -> tuple[bytes, bytes]:
        # Determine digest length from hash_type, consume only that many bytes
        digest_len = _HASH_DIGEST_LEN.get(self.hash_type, 0)
        # digest field already consumed everything; split it
        actual_digest = bytes(self.digest)[:digest_len]
        remaining = bytes(self.digest)[digest_len:]
        self.digest = actual_digest
        return remaining, b""

    def mysummary(self) -> str:
        lt = _format_log_type(self.log_type)
        ht = _format_hash_type(self.hash_type)
        return f"LogInfo(type={lt}, id=0x{self.log_id:04X}, len={self.total_length}, hash={ht})"


class ReadLogListResponsePacket(AllowRawSummary, Packet):
    """ReadLog response when request log_type==0 (list all logs)."""

    name = "MsftVdm-ReadLog-List"
    fields_desc = [
        FieldLenField("entry_count", None, count_of="entries", fmt="B"),
        PacketListField("entries", [], LogInfoEntryPacket, count_from=lambda pkt: pkt.entry_count),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        count = len(self.entries) if self.entries else 0
        entry_strs = [e.mysummary() for e in self.entries] if self.entries else []
        summary = f"{self.name} (count={count}, [{', '.join(entry_strs)}])"
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ReadLogDataResponsePacket(AllowRawSummary, Packet):
    """ReadLog response when request log_type!=0 (data read)."""

    name = "MsftVdm-ReadLog-Data"
    fields_desc = [
        XByteField("log_type", 0),
        XLEShortField("log_id", 0),
        XLEIntField("offset", 0),
        XByteField("hash_type", 0),
        StrField("digest", b""),
    ]

    def pre_dissect(self, s: bytes) -> bytes:
        """Split digest from trailing data based on hash_type."""
        if len(s) >= 8:
            hash_type_val = s[7]
            digest_len = _HASH_DIGEST_LEN.get(hash_type_val, 0)
            # Store boundary so post_dissect can split payload
            self._data_offset = 8 + digest_len
        else:
            self._data_offset = len(s)
        return s

    def post_dissect(self, s: bytes) -> bytes:
        """Separate digest field from remaining data payload."""
        boundary = getattr(self, "_data_offset", len(self.digest) + 8) - 8
        actual_digest = bytes(self.digest)[:boundary]
        remaining = bytes(self.digest)[boundary:]
        self.digest = actual_digest
        return remaining

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        lt = _format_log_type(self.log_type)
        ht = _format_hash_type(self.hash_type)
        data_len = len(self.payload) if self.payload else 0
        summary = (
            f"{self.name} (type={lt}, log_id=0x{self.log_id:04X}, offset={self.offset}, hash={ht}, data_len={data_len})"
        )
        return summary, [MsftVdmProtocolPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ReadLogCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        underlayer = kargs.get("_underlayer")
        if underlayer is not None:
            try:
                if _is_response(underlayer):
                    return ReadLogDataResponsePacket
            except (AttributeError, KeyError):
                pass
        return ReadLogRequestPacket


bind_layers(
    MsftVdmProtocolPacket,
    ReadLogCmdPacket,
    cmd_set=MsftVdmCommandSets.ROT,
    cmd=MsftVdmRotCmdCodes.READ_LOG,
)
