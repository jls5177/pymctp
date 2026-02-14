from enum import IntEnum

from scapy.fields import (
    FlagsField,
    XByteField,
    XLEIntField,
)
from scapy.packet import Packet, bind_layers

from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.mctp.types import AnyPacketType
from ..types import MsftVdmCommandSets
from .msft_vdm import MsftVdmProtocolPacket
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
