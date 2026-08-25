# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Basic PLDM responder behaviors."""

from __future__ import annotations

import binascii
import copy
import importlib
import json
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields
from enum import IntEnum
import logging
from pathlib import Path
import struct
import threading
import time
from typing import TYPE_CHECKING, Any
import uuid

from scapy.compat import raw
from scapy.packet import Packet, Raw

from ...layers.mctp.pldm.pdr import (
    PDR_TYPE_ENTITY_AUXILIARY_NAMES,
    PDR_TYPE_EFFECTER_AUXILIARY_NAMES,
    PDR_TYPE_NUMERIC_EFFECTER,
    PDR_TYPE_NUMERIC_SENSOR,
    PDR_TYPE_SENSOR_AUXILIARY_NAMES,
    PDR_TYPE_STATE_EFFECTER,
    PDR_TYPE_STATE_SENSOR,
    PDR_TYPE_TERMINUS_LOCATOR,
    NumericEffecterPdr,
    StateEffecterPdr,
    decode_pdr,
    encode_pdr,
    pdr_from_dict,
)
from ...layers.mctp.pldm.fru import FruRepository, PldmFruCmdCodes, encode_fru_record, fru_record_from_dict
from ...layers.mctp.pldm.pldm import PldmHdr, PldmHdrPacket
from ...layers.mctp.pldm.type1_base import (
    GetPLDMCommandsPacket,
    GetPLDMTypesPacket,
    GetPLDMVersionOperation,
    GetPLDMVersionPacket,
    GetPLDMVersionTransferFlag,
    GetTIDPacket,
    SetTIDPacket,
)
from ...layers.mctp.pldm.type_2_platform_monitoring import (
    GetSensorReadingDataSizeEnum,
    GetSensorReadingEventMsgEnableEnum,
    GetSensorReadingOperationalStateEnum,
    GetSensorReadingPacket,
    GetSensorReadingPresentEnum,
    PlatformEventMsgClasses,
    PlatformEventMsgPacket,
    PlatformEventMsgStatus,
    PldmPlatformMonitoringCmdCodes,
    PollForPlatformEventMsgPacket,
    PollForPlatformEventOperation,
    PollForPlatformEventTransferFlag,
)
from ...layers.mctp.pldm.types import CompletionCodes, PldmControlCmdCodes, PldmTypeCodes
from ...layers.mctp.transport import TransportHdrPacket
from ...layers.mctp.types import EndpointContext, MsgTypes
from ..sessions import HandlerResponse
from .base import Behavior
from .replies import build_layered_reply

if TYPE_CHECKING:
    from ..role_endpoint import RoleBasedEndpointAM

logger = logging.getLogger(__name__)

ReadingValue = float | int
ReadingSource = ReadingValue | Callable[[], ReadingValue]
PdrRecord = Any

_PDR_HEADER_VERSION = 1
_PDR_TYPE_NUMERIC_SENSOR = 2
_PDR_TYPE_STATE_SENSOR = 4
_PDR_COMMON_HEADER = struct.Struct("<IBBHH")
_PLDM_TIMESTAMP104_SIZE = 13
_PLATFORM_CC_INVALID_DATA_TRANSFER_HANDLE = 0x80
_PLATFORM_CC_INVALID_TRANSFER_OPERATION_FLAG = 0x81
_PLATFORM_CC_INVALID_RECORD_HANDLE = 0x82
_PLATFORM_CC_INVALID_RECORD_CHANGE_NUMBER = 0x83
_FRU_CC_INVALID_DATA_TRANSFER_HANDLE = 0x80
_FRU_CC_INVALID_TRANSFER_OPERATION_FLAG = 0x81
#: DSP0248 SetNumericSensorEnable / GetSensorReading command-specific codes.
_PLATFORM_CC_INVALID_SENSOR_ID = 0x80
_PLATFORM_CC_INVALID_EFFECTER_ID = 0x80
_PLATFORM_CC_EVENT_GENERATION_NOT_SUPPORTED = 0x82
_PLATFORM_TRANSFER_DONE = 0
_PLATFORM_EVENT_FORMAT_VERSION = 1
_PLATFORM_SENSOR_EVENT_NUMERIC_SENSOR_STATE = 2
_MCTP_TRANSPORT_PROTOCOL_TYPE = 0
_EVENT_ID_NONE = 0
_RANGE_FIELD_NOMINAL_VALUE = 0
_RANGE_FIELD_NORMAL_MAX = 1
_RANGE_FIELD_NORMAL_MIN = 2
_RANGE_FIELD_WARNING_HIGH = 3
_RANGE_FIELD_WARNING_LOW = 4
_RANGE_FIELD_CRITICAL_HIGH = 5
_RANGE_FIELD_CRITICAL_LOW = 6

_BASE_COMMANDS = [
    PldmControlCmdCodes.SetTID,
    PldmControlCmdCodes.GetTID,
    PldmControlCmdCodes.GetPLDMVersion,
    PldmControlCmdCodes.GetPLDMTypes,
    PldmControlCmdCodes.GetPLDMCommands,
]
_PLATFORM_COMMANDS = [
    PldmPlatformMonitoringCmdCodes.GetTerminusUID,
    PldmPlatformMonitoringCmdCodes.SetEventReceiver,
    PldmPlatformMonitoringCmdCodes.PlatformEventMessage,
    PldmPlatformMonitoringCmdCodes.PollForPlatformEventMessage,
    PldmPlatformMonitoringCmdCodes.EventMessageSupported,
    PldmPlatformMonitoringCmdCodes.EventMessageBufferSize,
    PldmPlatformMonitoringCmdCodes.SetNumericSensorEnable,
    PldmPlatformMonitoringCmdCodes.GetSensorReading,
    PldmPlatformMonitoringCmdCodes.SetStateSensorEnables,
    PldmPlatformMonitoringCmdCodes.GetStateSensorReadings,
    PldmPlatformMonitoringCmdCodes.SetNumericEffecterEnable,
    PldmPlatformMonitoringCmdCodes.SetNumericEffecterValue,
    PldmPlatformMonitoringCmdCodes.GetNumericEffecterValue,
    PldmPlatformMonitoringCmdCodes.SetStateEffecterEnables,
    PldmPlatformMonitoringCmdCodes.SetStateEffecterStates,
    PldmPlatformMonitoringCmdCodes.GetStateEffecterStates,
    PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo,
    PldmPlatformMonitoringCmdCodes.GetPDR,
]
_FRU_COMMANDS = [
    PldmFruCmdCodes.GetFRURecordTableMetadata,
    PldmFruCmdCodes.GetFRURecordTable,
]


class GetPDRTransferOperation(IntEnum):
    """DSP0248 transfer operation values used by GetPDR's raw packet."""

    GET_NEXT_PART = 0
    GET_FIRST_PART = 1


class GetPDRTransferFlag(IntEnum):
    """DSP0248 platform transfer flag values for GetPDR responses."""

    START = 0
    MIDDLE = 1
    END = 4
    START_AND_END = 5


@dataclass
class PldmBaseProfile:
    """PLDM Type 0 capability profile advertised by ``PldmBaseBehavior``."""

    tid: int = 1
    #: FRU is deliberately absent by default. Advertising a type we cannot
    #: serve is worse than not offering it: a requester that asks for a FRU
    #: table and gets a response with no table data rejects it as malformed
    #: and discards the whole terminus, sensors included.
    supported_types: list[int] = field(
        default_factory=lambda: [
            int(PldmTypeCodes.CONTROL),
            int(PldmTypeCodes.PLATFORM_MONITORING),
        ]
    )
    #: Spec revisions a real terminus reports, taken from a hardware capture:
    #: DSP0240 (base) 1.1.0 and DSP0248 (platform monitoring) 1.3.0.
    versions: dict[int, list[str]] = field(
        default_factory=lambda: {
            int(PldmTypeCodes.CONTROL): ["1.1.0"],
            int(PldmTypeCodes.PLATFORM_MONITORING): ["1.3.0"],
            int(PldmTypeCodes.FRU): ["1.0.0"],
        }
    )
    commands: dict[int, list[int]] = field(
        default_factory=lambda: {
            int(PldmTypeCodes.CONTROL): [int(cmd) for cmd in _BASE_COMMANDS],
            int(PldmTypeCodes.PLATFORM_MONITORING): [int(cmd) for cmd in _PLATFORM_COMMANDS],
            int(PldmTypeCodes.FRU): [int(cmd) for cmd in _FRU_COMMANDS],
        }
    )

    def __post_init__(self) -> None:
        self.tid = int(self.tid) & 0xFF
        self.supported_types = [int(pldm_type) for pldm_type in self.supported_types]
        self.versions = {int(pldm_type): list(versions) for pldm_type, versions in self.versions.items()}
        self.commands = {
            int(pldm_type): [int(command) for command in commands] for pldm_type, commands in self.commands.items()
        }


class PldmBaseBehavior(Behavior):
    """Answers PLDM Type 0 discovery and TID commands for a mocked endpoint."""

    def __init__(self, *, profile: PldmBaseProfile | dict[str, Any] | None = None, **overrides: Any) -> None:
        base_profile = self._coerce_profile(profile)
        if overrides:
            profile_fields = {item.name for item in fields(PldmBaseProfile)}
            unknown = sorted(set(overrides) - profile_fields)
            if unknown:
                msg = f"Unknown PLDM base profile option(s): {', '.join(unknown)}"
                raise TypeError(msg)
            data = {item.name: getattr(base_profile, item.name) for item in fields(PldmBaseProfile)}
            data.update(overrides)
            base_profile = PldmBaseProfile(**data)
        self.profile = base_profile
        self._ctx: EndpointContext | None = None

    @property
    def name(self) -> str:
        return "pldm-base"

    def on_bind(self, am: Any, ctx: EndpointContext) -> None:
        self._ctx = ctx
        self._state(ctx)

    def on_attach(self, ctx: EndpointContext) -> None:
        self._ctx = ctx
        self._state(ctx)

    def can_handle(self, pkt: Packet, ctx: EndpointContext) -> bool:
        if MsgTypes.PLDM not in ctx.supported_msg_types:
            return False
        pldm = pkt.getlayer(PldmHdrPacket)
        return bool(pldm is not None and pldm.rq == 1 and pldm.pldm_type == PldmTypeCodes.CONTROL)

    def handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse | None:
        self._ctx = ctx
        try:
            return self._handle(pkt, ctx)
        except Exception:
            logger.exception("Failed to handle PLDM Type 0 request")
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR)

    def _handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        pldm = pkt.getlayer(PldmHdrPacket)
        if pldm is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        self._state(ctx)
        try:
            cmd_code = PldmControlCmdCodes(pldm.cmd_code)
        except ValueError:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_UNSUPPORTED_CMD)

        handlers = {
            PldmControlCmdCodes.SetTID: self._delegate_tid_command,
            PldmControlCmdCodes.GetTID: self._delegate_tid_command,
            PldmControlCmdCodes.GetPLDMVersion: self._get_pldm_version,
            PldmControlCmdCodes.GetPLDMTypes: self._get_pldm_types,
            PldmControlCmdCodes.GetPLDMCommands: self._get_pldm_commands,
        }
        handler = handlers.get(cmd_code)
        if handler is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_UNSUPPORTED_CMD)
        return handler(pkt, ctx, pldm)

    def _delegate_tid_command(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        state = self._state(ctx)
        legacy_state = ctx.msg_type_context["pldm"]
        legacy_state["tid"] = state["tid"]

        payload = pkt.getlayer(GetTIDPacket) if pldm.cmd_code == PldmControlCmdCodes.GetTID else pkt.getlayer(SetTIDPacket)
        if payload is None and pldm.cmd_code == PldmControlCmdCodes.GetTID:
            payload = GetTIDPacket(_underlayer=pldm)
        if payload is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        completion_code, payload_resp = payload.make_ctrl_reply(ctx)
        state["tid"] = int(legacy_state.get("tid", state["tid"])) & 0xFF
        return self._reply(pkt, ctx, payload_resp, completion_code)

    def _get_pldm_types(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        type_bytes = _bitfield_bytes(self._state(ctx)["supported_types"], 8)
        payload = GetPLDMTypesPacket(
            PLDMTypes1=type_bytes[0],
            PLDMTypes2=type_bytes[1],
            PLDMTypes3=type_bytes[2],
            PLDMTypes4=type_bytes[3],
            PLDMTypes5=type_bytes[4],
            PLDMTypes6=type_bytes[5],
            PLDMTypes7=type_bytes[6],
            PLDMTypes8=type_bytes[7],
        )
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _get_pldm_commands(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        request = pkt.getlayer(GetPLDMCommandsPacket)
        if request is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        pldm_type = int(request.PLDMType)
        state = self._state(ctx)
        if pldm_type not in state["supported_types"]:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_PLDM_TYPE)

        payload = GetPLDMCommandsPacket(cmds=list(_bitfield_bytes(state["commands"].get(pldm_type, []), 32)))
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _get_pldm_version(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        request = pkt.getlayer(GetPLDMVersionPacket)
        if request is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        state = self._state(ctx)
        pldm_type = int(request.PLDMType)
        if pldm_type not in state["supported_types"] or pldm_type not in state["versions"]:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_PLDM_TYPE)

        if request.TransferOperationFlag not in (
            GetPLDMVersionOperation.GET_FIRST_PART.value,
            int(GetPLDMVersionOperation.GET_FIRST_PART),
        ):
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        payload = GetPLDMVersionPacket(
            NextDataTransferHandle=0,
            TransferFlag=GetPLDMVersionTransferFlag.START_AND_END,
        )
        version_bytes = b"".join(_encode_pldm_version(version) for version in state["versions"][pldm_type])
        # DSP0240: the final transfer carries a CRC-32 over the accumulated
        # version data. Requesters reject a response without it - openbmc's
        # pldmd logs "Version response length is less than expected" for
        # anything under 8 bytes and then verifies the checksum.
        version_bytes += _pldm_version_crc32(version_bytes)
        return self._reply(pkt, ctx, payload / version_bytes, CompletionCodes.SUCCESS)

    def _reply(
        self,
        pkt: Packet,
        ctx: EndpointContext,
        payload: Packet | bytes | None,
        completion_code: int | None,
    ) -> HandlerResponse:
        pldm = pkt.getlayer(PldmHdrPacket)
        pldm_payload = pldm.build_reply(ctx, payload, completion_code) if pldm is not None else payload
        return HandlerResponse(stop_processing=True, reply=build_layered_reply(pkt, ctx, pldm_payload))

    def _state(self, ctx: EndpointContext) -> dict[str, Any]:
        state = ctx.msg_type_context[self.name]
        if not state:
            state.update(
                {
                    "tid": self.profile.tid,
                    "supported_types": list(self.profile.supported_types),
                    "versions": {pldm_type: list(versions) for pldm_type, versions in self.profile.versions.items()},
                    "commands": {pldm_type: list(commands) for pldm_type, commands in self.profile.commands.items()},
                }
            )
        return state

    @staticmethod
    def _coerce_profile(profile: PldmBaseProfile | dict[str, Any] | None) -> PldmBaseProfile:
        if profile is None:
            return PldmBaseProfile()
        if isinstance(profile, PldmBaseProfile):
            return profile
        return PldmBaseProfile(**profile)


@dataclass
class SensorSimulation:
    """Simple ramping reading source with optional threshold values."""

    minimum: ReadingValue = 0
    maximum: ReadingValue = 100
    step: ReadingValue = 1
    current: ReadingValue | None = None
    warning_high: ReadingValue | None = None
    warning_low: ReadingValue | None = None
    critical_high: ReadingValue | None = None
    critical_low: ReadingValue | None = None
    direction: int = 1

    def __post_init__(self) -> None:
        self.direction = 1 if int(self.direction) >= 0 else -1
        if self.current is None:
            self.current = self.minimum

    def next_reading(self) -> ReadingValue:
        """Return the current value, then move one step within the configured bounds."""
        value = self.current if self.current is not None else self.minimum
        next_value = value + self.step * self.direction
        if next_value > self.maximum:
            next_value = self.maximum
            self.direction = -1
        elif next_value < self.minimum:
            next_value = self.minimum
            self.direction = 1
        self.current = next_value
        return value


@dataclass
class StateSensorSimulation:
    """Simple state source for composite PLDM state sensors."""

    possible_states: dict[int, Iterable[int]] = field(default_factory=lambda: {0: [0]})
    operational_states: list[GetSensorReadingOperationalStateEnum | int] = field(default_factory=list)
    event_message_enables: list[GetSensorReadingEventMsgEnableEnum | int] = field(default_factory=list)
    present_states: list[int] = field(default_factory=list)
    previous_states: list[int] = field(default_factory=list)
    event_states: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.possible_states = {
            int(state_set): [int(state) for state in states] for state_set, states in self.possible_states.items()
        }
        count = self.composite_count
        first_states = [states[0] if states else 0 for states in self.possible_states.values()]
        self.operational_states = [
            GetSensorReadingOperationalStateEnum(value)
            for value in _state_list(self.operational_states, count, GetSensorReadingOperationalStateEnum.ENABLED)
        ]
        self.event_message_enables = [
            GetSensorReadingEventMsgEnableEnum(value)
            for value in _state_list(
                self.event_message_enables,
                count,
                GetSensorReadingEventMsgEnableEnum.NO_EVENT_GENERATION,
            )
        ]
        self.present_states = [int(value) for value in _state_list(self.present_states, count, first_states)]
        self.previous_states = [int(value) for value in _state_list(self.previous_states, count, 0)]
        self.event_states = [int(value) for value in _state_list(self.event_states, count, self.present_states)]

    @property
    def composite_count(self) -> int:
        return len(self.possible_states)

    def next_readings(self) -> list[tuple[GetSensorReadingOperationalStateEnum, int, int, int]]:
        readings = list(
            zip(self.operational_states, self.present_states, self.previous_states, self.event_states, strict=False)
        )
        for index, states in enumerate(self.possible_states.values()):
            present = self.present_states[index]
            next_state = _next_state_value(states, present)
            self.previous_states[index] = present
            self.present_states[index] = next_state
            self.event_states[index] = next_state
        return readings


@dataclass
class SensorDefinition:
    """A PLDM sensor definition and its current reading source."""

    sensor_id: int
    reading: ReadingSource = 0
    data_size: GetSensorReadingDataSizeEnum = GetSensorReadingDataSizeEnum.UINT8
    operational_state: GetSensorReadingOperationalStateEnum = GetSensorReadingOperationalStateEnum.ENABLED
    present_state: GetSensorReadingPresentEnum = GetSensorReadingPresentEnum.NORMAL
    previous_state: GetSensorReadingPresentEnum = GetSensorReadingPresentEnum.NORMAL
    event_state: GetSensorReadingPresentEnum = GetSensorReadingPresentEnum.NORMAL
    event_message_enable: GetSensorReadingEventMsgEnableEnum = GetSensorReadingEventMsgEnableEnum.NO_EVENT_GENERATION
    simulation: SensorSimulation | dict[str, Any] | None = None
    entity_type: int = 0
    entity_instance: int = 1
    container_id: int = 0
    base_unit: int = 0
    warning_high: ReadingValue | None = None
    warning_low: ReadingValue | None = None
    critical_high: ReadingValue | None = None
    critical_low: ReadingValue | None = None
    state_sensor: StateSensorSimulation | dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self.sensor_id = int(self.sensor_id)
        self.data_size = GetSensorReadingDataSizeEnum(self.data_size)
        self.operational_state = GetSensorReadingOperationalStateEnum(self.operational_state)
        self.present_state = GetSensorReadingPresentEnum(self.present_state)
        self.previous_state = GetSensorReadingPresentEnum(self.previous_state)
        self.event_state = GetSensorReadingPresentEnum(self.event_state)
        self.event_message_enable = GetSensorReadingEventMsgEnableEnum(self.event_message_enable)
        if isinstance(self.simulation, dict):
            self.simulation = SensorSimulation(**self.simulation)
        if isinstance(self.state_sensor, dict):
            self.state_sensor = StateSensorSimulation(**self.state_sensor)
        if self.simulation is not None:
            self.warning_high = self.warning_high if self.warning_high is not None else self.simulation.warning_high
            self.warning_low = self.warning_low if self.warning_low is not None else self.simulation.warning_low
            self.critical_high = self.critical_high if self.critical_high is not None else self.simulation.critical_high
            self.critical_low = self.critical_low if self.critical_low is not None else self.simulation.critical_low

    def next_reading(self) -> ReadingValue:
        """Return the next raw reading value, calling dynamic sources when configured."""
        if self.simulation is not None:
            return self.simulation.next_reading()
        return self.reading() if callable(self.reading) else self.reading

    def threshold_state(self, reading: ReadingValue) -> GetSensorReadingPresentEnum:
        """Return the PLDM present state implied by the configured thresholds."""
        value = float(reading)
        if self.critical_high is not None and value >= float(self.critical_high):
            return GetSensorReadingPresentEnum.UPPERCRITICAL
        if self.critical_low is not None and value <= float(self.critical_low):
            return GetSensorReadingPresentEnum.LOWERCRITICAL
        if self.warning_high is not None and value >= float(self.warning_high):
            return GetSensorReadingPresentEnum.UPPERWARNING
        if self.warning_low is not None and value <= float(self.warning_low):
            return GetSensorReadingPresentEnum.LOWERWARNING
        return GetSensorReadingPresentEnum.NORMAL


@dataclass
class StateEffecterSimulation:
    """Current state for a composite PLDM state effecter."""

    possible_states: dict[int, Iterable[int]] = field(default_factory=lambda: {0: [0]})
    operational_states: list[GetSensorReadingOperationalStateEnum | int] = field(default_factory=list)
    event_message_enables: list[GetSensorReadingEventMsgEnableEnum | int] = field(default_factory=list)
    pending_states: list[int] = field(default_factory=list)
    present_states: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.possible_states = {
            int(state_set): [int(state) for state in states] for state_set, states in self.possible_states.items()
        }
        count = self.composite_count
        first_states = [states[0] if states else 0 for states in self.possible_states.values()]
        self.operational_states = [
            GetSensorReadingOperationalStateEnum(value)
            for value in _state_list(self.operational_states, count, GetSensorReadingOperationalStateEnum.ENABLED)
        ]
        self.event_message_enables = [
            GetSensorReadingEventMsgEnableEnum(value)
            for value in _state_list(
                self.event_message_enables,
                count,
                GetSensorReadingEventMsgEnableEnum.NO_EVENT_GENERATION,
            )
        ]
        self.pending_states = [int(value) for value in _state_list(self.pending_states, count, first_states)]
        self.present_states = [int(value) for value in _state_list(self.present_states, count, first_states)]

    @property
    def composite_count(self) -> int:
        return len(self.possible_states)

    def states(self) -> list[tuple[GetSensorReadingOperationalStateEnum, int, int]]:
        return list(zip(self.operational_states, self.pending_states, self.present_states, strict=False))

    def set_states(self, requests: Iterable[tuple[int, int]]) -> bool:
        for index, (set_request, effecter_state) in enumerate(requests):
            if not set_request:
                continue
            possible_states = list(self.possible_states.values())[index]
            if possible_states and int(effecter_state) not in possible_states:
                return False
            self.pending_states[index] = int(effecter_state)
            self.present_states[index] = int(effecter_state)
        return True


@dataclass
class EffecterDefinition:
    """A PLDM effecter definition and current reported value or state."""

    effecter_id: int
    data_size: GetSensorReadingDataSizeEnum = GetSensorReadingDataSizeEnum.UINT8
    operational_state: GetSensorReadingOperationalStateEnum = GetSensorReadingOperationalStateEnum.ENABLED
    event_message_enable: GetSensorReadingEventMsgEnableEnum = GetSensorReadingEventMsgEnableEnum.NO_EVENT_GENERATION
    pending_value: ReadingValue = 0
    present_value: ReadingValue = 0
    entity_type: int = 0
    entity_instance: int = 1
    container_id: int = 0
    base_unit: int = 0
    min_settable: ReadingValue | None = None
    max_settable: ReadingValue | None = None
    state_effecter: StateEffecterSimulation | dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self.effecter_id = int(self.effecter_id)
        self.data_size = GetSensorReadingDataSizeEnum(self.data_size)
        self.operational_state = GetSensorReadingOperationalStateEnum(self.operational_state)
        self.event_message_enable = GetSensorReadingEventMsgEnableEnum(self.event_message_enable)
        if isinstance(self.state_effecter, dict):
            self.state_effecter = StateEffecterSimulation(**self.state_effecter)


@dataclass
class NumericSensorPdr:
    """DSP0248 Numeric Sensor PDR.

    The common PDR header is encoded exactly as ``recordHandle, version, type,
    recordChangeNumber, dataLength``.  For a small mock endpoint, units,
    auxiliary units, tolerances, accuracy and timing fields default to zero;
    resolution is fixed at 1.0, offset at 0.0 and ``isLinear`` at true.
    """

    record_handle: int
    sensor_id: int
    data_size: GetSensorReadingDataSizeEnum = GetSensorReadingDataSizeEnum.UINT8
    record_change_number: int = 0
    terminus_handle: int = 0
    entity_type: int = 0
    entity_instance: int = 1
    container_id: int = 0
    sensor_init: int = 0
    sensor_auxiliary_names_pdr: int = 0
    base_unit: int = 0
    unit_modifier: int = 0
    rate_unit: int = 0
    base_oem_unit_handle: int = 0
    aux_unit: int = 0
    aux_unit_modifier: int = 0
    aux_rate_unit: int = 0
    rel: int = 0
    aux_oem_unit_handle: int = 0
    is_linear: int = 1
    resolution: float = 1.0
    offset: float = 0.0
    accuracy: int = 0
    plus_tolerance: int = 0
    minus_tolerance: int = 0
    hysteresis: ReadingValue = 0
    supported_thresholds: int = 0
    threshold_and_hysteresis_volatility: int = 0
    state_transition_interval: float = 0.0
    update_interval: float = 0.0
    max_readable: ReadingValue | None = None
    min_readable: ReadingValue | None = None
    range_field_format: GetSensorReadingDataSizeEnum | int | None = None
    range_field_support: int = 0
    nominal_value: ReadingValue = 0
    normal_max: ReadingValue = 0
    normal_min: ReadingValue = 0
    warning_high: ReadingValue | None = None
    warning_low: ReadingValue | None = None
    critical_high: ReadingValue | None = None
    critical_low: ReadingValue | None = None
    fatal_high: ReadingValue = 0
    fatal_low: ReadingValue = 0

    def __post_init__(self) -> None:
        self.record_handle = int(self.record_handle)
        self.sensor_id = int(self.sensor_id)
        self.data_size = GetSensorReadingDataSizeEnum(self.data_size)
        if self.range_field_format is None:
            self.range_field_format = self.data_size
        else:
            self.range_field_format = _numeric_range_format(self.range_field_format)
        self.supported_thresholds = self.supported_thresholds or _threshold_support_bits(
            self.warning_high,
            self.warning_low,
            self.critical_high,
            self.critical_low,
            self.fatal_high,
            self.fatal_low,
        )

    @classmethod
    def from_sensor(cls, sensor: SensorDefinition, record_handle: int | None = None) -> NumericSensorPdr:
        """Create a numeric sensor PDR from a configured ``SensorDefinition``."""
        return cls(
            record_handle=record_handle if record_handle is not None else sensor.sensor_id,
            sensor_id=sensor.sensor_id,
            data_size=sensor.data_size,
            entity_type=sensor.entity_type,
            entity_instance=sensor.entity_instance,
            container_id=sensor.container_id,
            base_unit=sensor.base_unit,
            warning_high=sensor.warning_high,
            warning_low=sensor.warning_low,
            critical_high=sensor.critical_high,
            critical_low=sensor.critical_low,
            max_readable=_max_for_data_size(sensor.data_size),
            min_readable=_min_for_data_size(sensor.data_size),
        )

    def to_bytes(self) -> bytes:
        """Encode this PDR to wire bytes."""
        body = self._body()
        return _pdr_header(self.record_handle, _PDR_TYPE_NUMERIC_SENSOR, self.record_change_number, len(body)) + body

    def _body(self) -> bytes:
        fixed = struct.pack(
            "<HHHHHBBBbBBBBbBBBBffHBB",
            self.terminus_handle,
            self.sensor_id,
            self.entity_type,
            self.entity_instance,
            self.container_id,
            self.sensor_init & 0xFF,
            self.sensor_auxiliary_names_pdr & 0xFF,
            self.base_unit & 0xFF,
            _int8(self.unit_modifier),
            self.rate_unit & 0xFF,
            self.base_oem_unit_handle & 0xFF,
            self.aux_unit & 0xFF,
            _int8(self.aux_unit_modifier),
            self.aux_rate_unit & 0xFF,
            self.rel & 0xFF,
            self.aux_oem_unit_handle & 0xFF,
            self.is_linear & 0xFF,
            int(self.data_size),
            float(self.resolution),
            float(self.offset),
            self.accuracy & 0xFFFF,
            self.plus_tolerance & 0xFF,
            self.minus_tolerance & 0xFF,
        )
        sensor_values = b"".join(
            _encode_sensor_value(self.data_size, value)
            for value in (
                self.hysteresis,
                self.max_readable if self.max_readable is not None else _max_for_data_size(self.data_size),
                self.min_readable if self.min_readable is not None else _min_for_data_size(self.data_size),
            )
        )
        range_format = self.range_field_format or self.data_size
        range_values = b"".join(
            _encode_sensor_value(range_format, value)
            for value in (
                self.nominal_value,
                self.normal_max,
                self.normal_min,
                self.warning_high or 0,
                self.warning_low or 0,
                self.critical_high or 0,
                self.critical_low or 0,
                self.fatal_high,
                self.fatal_low,
            )
        )
        return (
            fixed
            + sensor_values[: _sensor_value_size(self.data_size)]
            + bytes([self.supported_thresholds & 0xFF, self.threshold_and_hysteresis_volatility & 0xFF])
            + struct.pack("<ff", float(self.state_transition_interval), float(self.update_interval))
            + sensor_values[_sensor_value_size(self.data_size) :]
            + bytes([int(range_format), self.range_field_support & 0xFF])
            + range_values
        )


@dataclass
class StateSensorPdr:
    """DSP0248 State Sensor PDR with a compact possible-states table."""

    record_handle: int
    sensor_id: int
    possible_states: dict[int, Iterable[int]] = field(default_factory=lambda: {0: [1]})
    record_change_number: int = 0
    terminus_handle: int = 0
    entity_type: int = 0
    entity_instance: int = 1
    container_id: int = 0
    sensor_init: int = 0
    sensor_auxiliary_names_pdr: int = 0
    trailing_data: bytes = b""

    def __post_init__(self) -> None:
        self.record_handle = int(self.record_handle)
        self.sensor_id = int(self.sensor_id)
        self.possible_states = {int(state_set): [int(state) for state in states] for state_set, states in self.possible_states.items()}
        self.trailing_data = bytes(self.trailing_data)

    def to_bytes(self) -> bytes:
        """Encode this PDR to wire bytes."""
        possible = b"".join(
            struct.pack("<HB", state_set, len(bitfield)) + bitfield
            for state_set, bitfield in (
                (state_set, _state_bitfield(states)) for state_set, states in self.possible_states.items()
            )
        )
        body = (
            struct.pack(
                "<HHHHHBBB",
                self.terminus_handle,
                self.sensor_id,
                self.entity_type,
                self.entity_instance,
                self.container_id,
                self.sensor_init & 0xFF,
                self.sensor_auxiliary_names_pdr & 0xFF,
                len(self.possible_states) & 0xFF,
            )
            + possible
            + self.trailing_data
        )
        return _pdr_header(self.record_handle, _PDR_TYPE_STATE_SENSOR, self.record_change_number, len(body)) + body


@dataclass
class PdrRepository:
    """In-memory PLDM PDR repository."""

    records: list[PdrRecord] = field(default_factory=list)
    record_change_number: int = 0
    repository_state: int = 0
    reported_record_count: int | None = None
    reported_repository_size: int | None = None
    reported_largest_record_size: int | None = None
    data_transfer_handle_timeout: int = 0

    def __post_init__(self) -> None:
        self.records = list(self.records)
        self.record_change_number = int(self.record_change_number)
        self.repository_state = int(self.repository_state)
        self.reported_record_count = None if self.reported_record_count is None else int(self.reported_record_count)
        self.reported_repository_size = (
            None if self.reported_repository_size is None else int(self.reported_repository_size)
        )
        self.reported_largest_record_size = (
            None if self.reported_largest_record_size is None else int(self.reported_largest_record_size)
        )
        self.data_transfer_handle_timeout = int(self.data_transfer_handle_timeout)

    def add_record(self, record: PdrRecord) -> None:
        """Append a PDR record."""
        self.records.append(record)

    def encoded_records(self) -> list[bytes]:
        """Return records encoded as PDR wire bytes."""
        return [encode_pdr(record) for record in self.records]

    def get_record(self, record_handle: int) -> bytes | None:
        """Return the requested record, treating handle zero as the first record."""
        records = self.encoded_records()
        if record_handle == 0:
            return records[0] if records else None
        for record in records:
            handle = _decode_pdr_handle(record)
            if handle == record_handle:
                return record
        return None

    def next_record_handle(self, record_handle: int) -> int:
        """Return the next record handle after ``record_handle``, or zero at the end."""
        records = self.encoded_records()
        if not records:
            return 0
        handles = [_decode_pdr_handle(record) for record in records]
        current = handles[0] if record_handle == 0 else record_handle
        try:
            index = handles.index(current)
        except ValueError:
            return 0
        return handles[index + 1] if index + 1 < len(handles) else 0

    @property
    def record_count(self) -> int:
        if self.reported_record_count is not None:
            return self.reported_record_count
        return len(self.records)

    @property
    def repository_size(self) -> int:
        if self.reported_repository_size is not None:
            return self.reported_repository_size
        return sum(len(record) for record in self.encoded_records())

    @property
    def largest_record_size(self) -> int:
        if self.reported_largest_record_size is not None:
            return self.reported_largest_record_size
        return max((len(record) for record in self.encoded_records()), default=0)


@dataclass
class PlatformEvent:
    """One queued platform event."""

    event_id: int
    event_class: PlatformEventMsgClasses
    event_data: bytes


@dataclass
class PldmSensorProfile:
    """PLDM Type 2 sensors served by ``PldmSensorBehavior``."""

    sensors: dict[int, SensorDefinition] = field(default_factory=dict)
    effecters: dict[int, EffecterDefinition] = field(default_factory=dict)
    pdr_repository: PdrRepository | list[PdrRecord] | None = None
    fru_repository: FruRepository | list[Any] | dict[str, Any] | None = None
    pdrs_from: str | None = None
    pdrs_model: str | None = None
    emit_events: bool = False
    event_buffer_size: int = 256
    event_poll_chunk_size: int = 256
    fru_transfer_chunk_size: int = 0
    event_msg_tag: int = 0
    event_timeout_s: float = 0.5
    terminus_uid: uuid.UUID | str | bytes | None = None
    _device_name: str | None = None

    def __post_init__(self) -> None:
        if self.pdrs_from and self.pdrs_model:
            msg = (
                f"PLDM sensor profile options 'pdrs_from' ({self.pdrs_from!r}) and "
                f"'pdrs_model' ({self.pdrs_model!r}) are mutually exclusive"
                f" for device {_format_device_name(self._device_name)}"
            )
            raise ValueError(msg)
        configured_sensors = _coerce_sensors(self.sensors)
        configured_effecters = _coerce_effecters(self.effecters)
        loaded_repository: PdrRepository | None = None
        loaded_sensors: dict[int, SensorDefinition] = {}
        loaded_effecters: dict[int, EffecterDefinition] = {}
        loaded_fru: FruRepository | None = None
        if self.pdrs_from:
            loaded_repository, loaded_sensors, loaded_fru = _load_pdrs_from(self.pdrs_from)
        elif self.pdrs_model:
            loaded_profile = _load_pdrs_model(self.pdrs_model, self._device_name)
            loaded_repository = loaded_profile.pdr_repository
            loaded_sensors = loaded_profile.sensors
            loaded_effecters = loaded_profile.effecters
            loaded_fru = loaded_profile.fru_repository
        loaded_sensors.update(configured_sensors)
        loaded_effecters.update(configured_effecters)
        self.sensors = loaded_sensors
        self.effecters = loaded_effecters
        if self.pdr_repository is None:
            self.pdr_repository = (
                loaded_repository if loaded_repository is not None else _derive_pdr_repository(self.sensors, self.effecters)
            )
        elif isinstance(self.pdr_repository, PdrRepository):
            pass
        else:
            self.pdr_repository = PdrRepository(list(self.pdr_repository))
        if self.fru_repository is None:
            self.fru_repository = loaded_fru if loaded_fru is not None else FruRepository()
        elif isinstance(self.fru_repository, FruRepository):
            pass
        elif isinstance(self.fru_repository, dict):
            self.fru_repository = FruRepository(**self.fru_repository)
        else:
            self.fru_repository = FruRepository(list(self.fru_repository))
        self.sensors.update(_synthesized_sensors_from_pdrs(self.pdr_repository, self.sensors))
        self.effecters.update(_synthesized_effecters_from_pdrs(self.pdr_repository, self.effecters))
        _warn_sensor_pdr_mismatches(self.sensors, self.pdr_repository)
        _warn_effecter_pdr_mismatches(self.effecters, self.pdr_repository)
        self.emit_events = bool(self.emit_events)
        self.event_buffer_size = int(self.event_buffer_size)
        self.event_poll_chunk_size = int(self.event_poll_chunk_size)
        self.fru_transfer_chunk_size = int(self.fru_transfer_chunk_size)
        self.event_msg_tag = int(self.event_msg_tag)
        self.event_timeout_s = float(self.event_timeout_s)
        self.terminus_uid = _coerce_uuid(self.terminus_uid)


class PldmSensorBehavior(Behavior):
    """Answers PLDM Type 2 sensor, PDR repository and platform event requests."""

    def __init__(
        self,
        *,
        profile: PldmSensorProfile | dict[str, Any] | None = None,
        sensors: dict[int, SensorDefinition | dict[str, Any] | ReadingSource] | None = None,
        effecters: dict[int, EffecterDefinition | dict[str, Any] | ReadingValue] | None = None,
        **overrides: Any,
    ) -> None:
        sensor_profile = self._coerce_profile(profile)
        data = {item.name: getattr(sensor_profile, item.name) for item in fields(PldmSensorProfile)}
        if sensors is not None:
            data["sensors"] = sensors
            if "pdr_repository" not in overrides:
                data["pdr_repository"] = None
        if effecters is not None:
            data["effecters"] = effecters
            if "pdr_repository" not in overrides:
                data["pdr_repository"] = None
        loads_external_pdrs = overrides.get("pdrs_from") is not None or overrides.get("pdrs_model") is not None
        if loads_external_pdrs and "pdr_repository" not in overrides:
            data["pdr_repository"] = None
        # The default profile has already turned fru_repository into an empty
        # repository, so it has to be cleared for the loaded one to be adopted.
        if loads_external_pdrs and "fru_repository" not in overrides:
            data["fru_repository"] = None
        if overrides:
            profile_fields = {item.name for item in fields(PldmSensorProfile)}
            unknown = sorted(set(overrides) - profile_fields)
            if unknown:
                msg = f"Unknown PLDM sensor profile option(s): {', '.join(unknown)}"
                raise TypeError(msg)
            data.update(overrides)
        self.profile = PldmSensorProfile(**data)
        self._ctx: EndpointContext | None = None
        self._am: RoleBasedEndpointAM | None = None
        self._shutdown = threading.Event()
        self._event_ready = threading.Event()
        self._event_lock = threading.Lock()
        self._event_thread: threading.Thread | None = None

    @property
    def name(self) -> str:
        return "pldm-sensor"

    @property
    def event_thread_running(self) -> bool:
        """True when the optional platform-event initiator worker is alive."""
        return bool(self._event_thread and self._event_thread.is_alive())

    def on_bind(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        self._am = am
        self._ctx = ctx
        self._state(ctx)

    def on_attach(self, ctx: EndpointContext) -> None:
        self._ctx = ctx
        self._state(ctx)

    def on_start(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        self._am = am
        self._ctx = ctx
        self._state(ctx)
        if not self.profile.emit_events:
            return
        if self._event_thread and self._event_thread.is_alive():
            self._event_ready.set()
            return
        self._shutdown.clear()
        self._event_thread = threading.Thread(target=self._event_loop, args=(ctx,), name=f"pldm-events-{ctx.eid}", daemon=True)
        self._event_thread.start()
        self._event_ready.set()

    def on_stop(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        self._shutdown.set()
        self._event_ready.set()
        thread, self._event_thread = self._event_thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)
        self._am = None

    def can_handle(self, pkt: Packet, ctx: EndpointContext) -> bool:
        if MsgTypes.PLDM not in ctx.supported_msg_types:
            return False
        pldm = pkt.getlayer(PldmHdrPacket)
        return bool(
            pldm is not None
            and pldm.rq == 1
            and pldm.pldm_type in (PldmTypeCodes.PLATFORM_MONITORING, PldmTypeCodes.FRU)
        )

    def handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse | None:
        self._ctx = ctx
        try:
            return self._handle(pkt, ctx)
        except Exception:
            logger.exception("Failed to handle PLDM Type 2 request")
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR)

    def set_reading(self, sensor_id: int, value: ReadingSource) -> None:
        """Set or create a sensor reading on the currently attached endpoint context."""
        sensor_id = int(sensor_id)
        self.profile.sensors.setdefault(sensor_id, SensorDefinition(sensor_id=sensor_id)).reading = value
        if self._ctx is not None:
            sensors = self._state(self._ctx)["sensors"]
            sensors.setdefault(sensor_id, SensorDefinition(sensor_id=sensor_id)).reading = value
            self._ensure_sensor_pdr(self._ctx, sensors[sensor_id])

    def queue_event(
        self,
        event_class: PlatformEventMsgClasses | int,
        event_data: bytes | Packet,
        *,
        event_id: int | None = None,
        ctx: EndpointContext | None = None,
    ) -> PlatformEvent:
        """Queue a platform event for polling and optional asynchronous emission."""
        ctx = ctx or self._ctx
        if ctx is None:
            msg = "PLDM sensor behavior is not attached to an endpoint context"
            raise RuntimeError(msg)
        state = self._state(ctx)
        with self._event_lock:
            if event_id is None:
                event_id = int(state["next_event_id"])
                state["next_event_id"] = 1 if event_id >= 0xFFFE else event_id + 1
            event = PlatformEvent(int(event_id) & 0xFFFF, PlatformEventMsgClasses(int(event_class)), bytes(event_data))
            state["event_queue"].append(event)
        self._event_ready.set()
        return event

    def trigger_threshold_event(
        self,
        sensor_id: int,
        new_state: GetSensorReadingPresentEnum | int,
        *,
        ctx: EndpointContext | None = None,
        reading: ReadingValue | None = None,
    ) -> PlatformEvent:
        """Programmatically queue a numeric sensor state event."""
        ctx = ctx or self._ctx
        if ctx is None:
            msg = "PLDM sensor behavior is not attached to an endpoint context"
            raise RuntimeError(msg)
        sensors = self._state(ctx)["sensors"]
        sensor = sensors.setdefault(int(sensor_id), SensorDefinition(sensor_id=int(sensor_id)))
        previous = sensor.present_state
        sensor.previous_state = previous
        sensor.present_state = GetSensorReadingPresentEnum(new_state)
        sensor.event_state = sensor.present_state
        value = sensor.next_reading() if reading is None else reading
        return self.queue_event(
            PlatformEventMsgClasses.PLDM_SENSOR_EVENT,
            _numeric_sensor_event_data(sensor, sensor.present_state, previous, value),
            ctx=ctx,
        )

    def _note_repeated_request(self, ctx: EndpointContext, pldm: PldmHdrPacket) -> None:
        """Report a request the requester is asking for again.

        PLDM reuses the instance id on a retry, so the same id arriving twice
        for the same command means our previous response never got there, or
        was rejected. That is the one fact worth having when a transfer fails
        intermittently, and it is invisible in a packet dump without counting
        instance ids by hand.
        """
        key = (int(pldm.pldm_type), int(pldm.cmd_code), int(pldm.instance_id))
        state = self._state(ctx)
        now = time.monotonic()
        previous = state.get("last_request")
        state["last_request"] = (key, now)
        if previous is None or previous[0] != key:
            return
        logger.warning(
            "eid 0x%02X: requester repeated PLDM type %d cmd 0x%02X instance %d after %.2fs -- "
            "the previous response of %d byte(s) did not get through",
            ctx.assigned_eid or 0,
            key[0],
            key[1],
            key[2],
            now - previous[1],
            state.get("last_response_bytes", 0),
        )

    def _handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        pldm = pkt.getlayer(PldmHdrPacket)
        if pldm is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)
        self._note_repeated_request(ctx, pldm)
        if pldm.pldm_type == PldmTypeCodes.FRU:
            return self._handle_fru(pkt, ctx, pldm)

        try:
            cmd_code = PldmPlatformMonitoringCmdCodes(pldm.cmd_code)
        except ValueError:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_UNSUPPORTED_CMD)

        handlers = {
            PldmPlatformMonitoringCmdCodes.GetTerminusUID: self._get_terminus_uid,
            PldmPlatformMonitoringCmdCodes.SetNumericSensorEnable: self._set_numeric_sensor_enable,
            PldmPlatformMonitoringCmdCodes.GetSensorReading: self._get_sensor_reading,
            PldmPlatformMonitoringCmdCodes.SetStateSensorEnables: self._set_state_sensor_enables,
            PldmPlatformMonitoringCmdCodes.GetStateSensorReadings: self._get_state_sensor_readings,
            PldmPlatformMonitoringCmdCodes.SetNumericEffecterEnable: self._set_numeric_effecter_enable,
            PldmPlatformMonitoringCmdCodes.SetNumericEffecterValue: self._set_numeric_effecter_value,
            PldmPlatformMonitoringCmdCodes.GetNumericEffecterValue: self._get_numeric_effecter_value,
            PldmPlatformMonitoringCmdCodes.SetStateEffecterEnables: self._set_state_effecter_enables,
            PldmPlatformMonitoringCmdCodes.SetStateEffecterStates: self._set_state_effecter_states,
            PldmPlatformMonitoringCmdCodes.GetStateEffecterStates: self._get_state_effecter_states,
            PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo: self._get_pdr_repository_info,
            PldmPlatformMonitoringCmdCodes.GetPDR: self._get_pdr,
            PldmPlatformMonitoringCmdCodes.SetEventReceiver: self._set_event_receiver,
            PldmPlatformMonitoringCmdCodes.EventMessageBufferSize: self._event_message_buffer_size,
            PldmPlatformMonitoringCmdCodes.EventMessageSupported: self._event_message_supported,
            PldmPlatformMonitoringCmdCodes.PollForPlatformEventMessage: self._poll_for_platform_event_message,
            PldmPlatformMonitoringCmdCodes.PlatformEventMessage: self._platform_event_message,
        }
        handler = handlers.get(cmd_code)
        if handler is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_UNSUPPORTED_CMD)
        return handler(pkt, ctx, pldm)

    def _handle_fru(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        try:
            cmd_code = PldmFruCmdCodes(pldm.cmd_code)
        except ValueError:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_UNSUPPORTED_CMD)

        handlers = {
            PldmFruCmdCodes.GetFRURecordTableMetadata: self._get_fru_record_table_metadata,
            PldmFruCmdCodes.GetFRURecordTable: self._get_fru_record_table,
        }
        handler = handlers.get(cmd_code)
        if handler is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_UNSUPPORTED_CMD)
        return handler(pkt, ctx, pldm)

    def _set_numeric_sensor_enable(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        """DSP0248 SetNumericSensorEnable (0x10).

        The requester enables each sensor before it starts polling, so refusing
        this command aborts sensor discovery outright ("Sensor Handler Init
        failed") even though GetSensorReading itself works.

        Request is sensorID (uint16 LE), sensorOperationalState (enum8) and
        sensorEventMessageEnable (enum8); the response carries only the
        completion code.
        """
        data = _pldm_payload_bytes(pldm)
        if len(data) < 4:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        sensor_id, operational_state, event_message_enable = struct.unpack_from("<HBB", data)
        sensor = self._state(ctx)["sensors"].get(sensor_id)
        if sensor is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_SENSOR_ID)

        try:
            state = GetSensorReadingOperationalStateEnum(operational_state)
        except ValueError:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)
        try:
            events = GetSensorReadingEventMsgEnableEnum(event_message_enable)
        except ValueError:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_EVENT_GENERATION_NOT_SUPPORTED)

        sensor.operational_state = state
        sensor.event_message_enable = events
        return self._reply(pkt, ctx, None, CompletionCodes.SUCCESS)

    def _get_terminus_uid(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        if _pldm_payload_bytes(pldm):
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)
        return self._reply(pkt, ctx, _terminus_uid_bytes(ctx, self.profile.terminus_uid), CompletionCodes.SUCCESS)

    def _get_sensor_reading(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        request = pkt.getlayer(GetSensorReadingPacket)
        if request is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        sensor = self._state(ctx)["sensors"].get(int(request.sensorID))
        if sensor is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        reading = sensor.next_reading()
        self._record_threshold_transition(ctx, sensor, reading)
        payload = _sensor_reading_payload(sensor, reading)
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _set_state_sensor_enables(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        data = _pldm_payload_bytes(pldm)
        if len(data) < 3:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        sensor_id, composite_count = struct.unpack_from("<HB", data)
        expected_size = 3 + (int(composite_count) * 2)
        if len(data) < expected_size:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        state_sensor = self._state_sensor(ctx, sensor_id)
        if state_sensor is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_SENSOR_ID)
        if composite_count != state_sensor.composite_count:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        operational_states: list[GetSensorReadingOperationalStateEnum] = []
        event_enables: list[GetSensorReadingEventMsgEnableEnum] = []
        offset = 3
        for _ in range(composite_count):
            operational_state, event_message_enable = struct.unpack_from("<BB", data, offset)
            offset += 2
            try:
                operational_states.append(GetSensorReadingOperationalStateEnum(operational_state))
            except ValueError:
                return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)
            try:
                event_enables.append(GetSensorReadingEventMsgEnableEnum(event_message_enable))
            except ValueError:
                return self._reply(pkt, ctx, None, _PLATFORM_CC_EVENT_GENERATION_NOT_SUPPORTED)

        state_sensor.operational_states = operational_states
        state_sensor.event_message_enables = event_enables
        return self._reply(pkt, ctx, None, CompletionCodes.SUCCESS)

    def _get_state_sensor_readings(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        data = _pldm_payload_bytes(pldm)
        if len(data) < 4:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        sensor_id, _sensor_rearm, _reserved = struct.unpack_from("<HBB", data)
        state_sensor = self._state_sensor(ctx, sensor_id)
        if state_sensor is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_SENSOR_ID)

        payload = bytes([state_sensor.composite_count & 0xFF]) + b"".join(
            struct.pack("<BBBB", int(operational_state), present_state, previous_state, event_state)
            for operational_state, present_state, previous_state, event_state in state_sensor.next_readings()
        )
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _set_numeric_effecter_enable(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        data = _pldm_payload_bytes(pldm)
        if len(data) < 3:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        effecter_id, operational_state = struct.unpack_from("<HB", data)
        effecter = self._numeric_effecter(ctx, effecter_id)
        if effecter is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_EFFECTER_ID)

        try:
            effecter.operational_state = GetSensorReadingOperationalStateEnum(operational_state)
        except ValueError:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)
        return self._reply(pkt, ctx, None, CompletionCodes.SUCCESS)

    def _set_numeric_effecter_value(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        data = _pldm_payload_bytes(pldm)
        if len(data) < 3:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        effecter_id, data_size_value = struct.unpack_from("<HB", data)
        effecter = self._numeric_effecter(ctx, effecter_id)
        if effecter is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_EFFECTER_ID)
        try:
            data_size = GetSensorReadingDataSizeEnum(data_size_value)
        except ValueError:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)
        if data_size != effecter.data_size:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        value_size = _sensor_value_size(data_size)
        if len(data) < 3 + value_size:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        value = _decode_numeric_value(data_size, data, 3)
        effecter.pending_value = value
        effecter.present_value = value
        return self._reply(pkt, ctx, None, CompletionCodes.SUCCESS)

    def _get_numeric_effecter_value(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        data = _pldm_payload_bytes(pldm)
        if len(data) < 2:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        (effecter_id,) = struct.unpack_from("<H", data)
        effecter = self._numeric_effecter(ctx, effecter_id)
        if effecter is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_EFFECTER_ID)

        payload = (
            bytes([int(effecter.data_size) & 0xFF, int(effecter.operational_state) & 0xFF])
            + _encode_sensor_value(effecter.data_size, effecter.pending_value)
            + _encode_sensor_value(effecter.data_size, effecter.present_value)
        )
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _set_state_effecter_enables(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        data = _pldm_payload_bytes(pldm)
        if len(data) < 3:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        effecter_id, composite_count = struct.unpack_from("<HB", data)
        expected_size = 3 + (int(composite_count) * 2)
        if len(data) < expected_size:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        state_effecter = self._state_effecter(ctx, effecter_id)
        if state_effecter is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_EFFECTER_ID)
        if composite_count != state_effecter.composite_count:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        operational_states: list[GetSensorReadingOperationalStateEnum] = []
        event_enables: list[GetSensorReadingEventMsgEnableEnum] = []
        offset = 3
        for _ in range(composite_count):
            operational_state, event_message_enable = struct.unpack_from("<BB", data, offset)
            offset += 2
            try:
                operational_states.append(GetSensorReadingOperationalStateEnum(operational_state))
            except ValueError:
                return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)
            try:
                event_enables.append(GetSensorReadingEventMsgEnableEnum(event_message_enable))
            except ValueError:
                return self._reply(pkt, ctx, None, _PLATFORM_CC_EVENT_GENERATION_NOT_SUPPORTED)

        state_effecter.operational_states = operational_states
        state_effecter.event_message_enables = event_enables
        return self._reply(pkt, ctx, None, CompletionCodes.SUCCESS)

    def _set_state_effecter_states(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        data = _pldm_payload_bytes(pldm)
        if len(data) < 3:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        effecter_id, composite_count = struct.unpack_from("<HB", data)
        expected_size = 3 + (int(composite_count) * 2)
        if len(data) < expected_size:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        state_effecter = self._state_effecter(ctx, effecter_id)
        if state_effecter is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_EFFECTER_ID)
        if composite_count != state_effecter.composite_count:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        requests: list[tuple[int, int]] = []
        offset = 3
        for _ in range(composite_count):
            set_request, effecter_state = struct.unpack_from("<BB", data, offset)
            offset += 2
            if set_request not in (0, 1):
                return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)
            requests.append((set_request, effecter_state))

        if not state_effecter.set_states(requests):
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)
        return self._reply(pkt, ctx, None, CompletionCodes.SUCCESS)

    def _get_state_effecter_states(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        data = _pldm_payload_bytes(pldm)
        if len(data) < 2:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)

        (effecter_id,) = struct.unpack_from("<H", data)
        state_effecter = self._state_effecter(ctx, effecter_id)
        if state_effecter is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_EFFECTER_ID)

        payload = bytes([state_effecter.composite_count & 0xFF]) + b"".join(
            struct.pack("<BBB", int(operational_state), pending_state, present_state)
            for operational_state, pending_state, present_state in state_effecter.states()
        )
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _get_pdr_repository_info(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        repository = self._state(ctx)["pdr_repository"]
        payload = (
            bytes([repository.repository_state & 0xFF])
            + (b"\x00" * _PLDM_TIMESTAMP104_SIZE)
            + (b"\x00" * _PLDM_TIMESTAMP104_SIZE)
            + struct.pack(
                "<IIIB",
                repository.record_count,
                repository.repository_size,
                repository.largest_record_size,
                repository.data_transfer_handle_timeout,
            )
        )
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _get_pdr(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        data = _pldm_payload_bytes(pldm)
        if len(data) < 13:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)
        record_handle, transfer_handle, operation, request_count, record_change_number = struct.unpack_from(
            "<IIBHH", data
        )
        if record_change_number not in (0, self._state(ctx)["pdr_repository"].record_change_number):
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_RECORD_CHANGE_NUMBER)

        try:
            op = GetPDRTransferOperation(operation)
        except ValueError:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_TRANSFER_OPERATION_FLAG)
        if op == GetPDRTransferOperation.GET_FIRST_PART:
            return self._get_pdr_first_part(pkt, ctx, record_handle, transfer_handle, request_count)
        return self._get_pdr_next_part(pkt, ctx, transfer_handle, request_count)

    def _get_pdr_first_part(
        self,
        pkt: Packet,
        ctx: EndpointContext,
        record_handle: int,
        transfer_handle: int,
        request_count: int,
    ) -> HandlerResponse:
        if transfer_handle != 0:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_DATA_TRANSFER_HANDLE)
        state = self._state(ctx)
        record = state["pdr_repository"].get_record(record_handle)
        if record is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_RECORD_HANDLE)
        next_record_handle = state["pdr_repository"].next_record_handle(record_handle)
        count = _slice_count(request_count, len(record), self.profile.event_buffer_size)
        chunk = record[:count]
        if count >= len(record):
            payload = _get_pdr_response(next_record_handle, _PLATFORM_TRANSFER_DONE, GetPDRTransferFlag.START_AND_END, chunk)
            return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)
        next_transfer_handle = state["next_pdr_transfer_handle"]
        state["next_pdr_transfer_handle"] += 1
        state["pdr_transfers"][next_transfer_handle] = {
            "record": record,
            "offset": count,
            "next_record_handle": next_record_handle,
        }
        payload = _get_pdr_response(next_record_handle, next_transfer_handle, GetPDRTransferFlag.START, chunk)
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _get_pdr_next_part(
        self,
        pkt: Packet,
        ctx: EndpointContext,
        transfer_handle: int,
        request_count: int,
    ) -> HandlerResponse:
        state = self._state(ctx)
        transfer = state["pdr_transfers"].get(transfer_handle)
        if transfer is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_DATA_TRANSFER_HANDLE)
        record = transfer["record"]
        offset = int(transfer["offset"])
        count = _slice_count(request_count, len(record) - offset, self.profile.event_buffer_size)
        chunk = record[offset : offset + count]
        end = offset + count >= len(record)
        if end:
            del state["pdr_transfers"][transfer_handle]
            payload = _get_pdr_response(
                transfer["next_record_handle"],
                _PLATFORM_TRANSFER_DONE,
                GetPDRTransferFlag.END,
                chunk,
                crc=binascii.crc32(record) & 0xFFFFFFFF,
            )
            return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)
        next_transfer_handle = state["next_pdr_transfer_handle"]
        state["next_pdr_transfer_handle"] += 1
        state["pdr_transfers"][next_transfer_handle] = {
            "record": record,
            "offset": offset + count,
            "next_record_handle": transfer["next_record_handle"],
        }
        del state["pdr_transfers"][transfer_handle]
        payload = _get_pdr_response(transfer["next_record_handle"], next_transfer_handle, GetPDRTransferFlag.MIDDLE, chunk)
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _get_fru_record_table_metadata(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        if _pldm_payload_bytes(pldm):
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)
        repository = self._state(ctx)["fru_repository"]
        return self._reply(pkt, ctx, repository.metadata().to_bytes(), CompletionCodes.SUCCESS)

    def _get_fru_record_table(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        data = _pldm_payload_bytes(pldm)
        if len(data) < 5:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_LENGTH)
        transfer_handle, operation = struct.unpack_from("<IB", data)
        try:
            op = GetPDRTransferOperation(operation)
        except ValueError:
            return self._reply(pkt, ctx, None, _FRU_CC_INVALID_TRANSFER_OPERATION_FLAG)
        if op == GetPDRTransferOperation.GET_FIRST_PART:
            return self._get_fru_record_table_first_part(pkt, ctx, transfer_handle)
        return self._get_fru_record_table_next_part(pkt, ctx, transfer_handle)

    def _get_fru_record_table_first_part(
        self,
        pkt: Packet,
        ctx: EndpointContext,
        transfer_handle: int,
    ) -> HandlerResponse:
        if transfer_handle != 0:
            return self._reply(pkt, ctx, None, _FRU_CC_INVALID_DATA_TRANSFER_HANDLE)
        state = self._state(ctx)
        table = state["fru_repository"].response_table()
        if not table:
            # A response carrying no table data is indistinguishable from a
            # truncated one, so DSP0257 requesters reject it outright rather
            # than reading it as an empty table. Refusing plainly lets the
            # requester keep the rest of the terminus.
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_UNSUPPORTED_CMD)
        self._check_fru_table_matches_metadata(ctx, state, table)
        count = _fru_slice_count(len(table), self.profile.fru_transfer_chunk_size)
        chunk = table[:count]
        if count >= len(table):
            payload = _get_fru_record_table_response(_PLATFORM_TRANSFER_DONE, GetPDRTransferFlag.START_AND_END, chunk)
            return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)
        next_transfer_handle = state["next_fru_transfer_handle"]
        state["next_fru_transfer_handle"] += 1
        state["fru_transfers"][next_transfer_handle] = {"table": table, "offset": count}
        payload = _get_fru_record_table_response(next_transfer_handle, GetPDRTransferFlag.START, chunk)
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _check_fru_table_matches_metadata(
        self,
        ctx: EndpointContext,
        state: dict[str, Any],
        table: bytes,
    ) -> None:
        """Log the table we are about to serve against the checksum we advertised.

        A requester that reports a FRU checksum mismatch has either been sent
        the wrong bytes or received them damaged, and only one of those is ours
        to fix. Recording both values at the moment we serve them settles which
        it is without needing a packet capture: if they agree here, the table
        left intact and the damage happened downstream.
        """
        repository = state["fru_repository"]
        advertised = repository.integrity_checksum
        served = binascii.crc32(table) & 0xFFFFFFFF
        if served != advertised:
            logger.warning(
                "eid 0x%02X: serving a FRU table whose checksum 0x%08X differs from the advertised 0x%08X",
                ctx.assigned_eid or 0,
                served,
                advertised,
            )
            return
        logger.debug(
            "eid 0x%02X: serving FRU table, %d byte(s), checksum 0x%08X (as advertised)",
            ctx.assigned_eid or 0,
            len(table),
            served,
        )

    def _get_fru_record_table_next_part(
        self,
        pkt: Packet,
        ctx: EndpointContext,
        transfer_handle: int,
    ) -> HandlerResponse:
        state = self._state(ctx)
        transfer = state["fru_transfers"].get(transfer_handle)
        if transfer is None:
            return self._reply(pkt, ctx, None, _FRU_CC_INVALID_DATA_TRANSFER_HANDLE)
        table = transfer["table"]
        offset = int(transfer["offset"])
        count = _fru_slice_count(len(table) - offset, self.profile.fru_transfer_chunk_size)
        chunk = table[offset : offset + count]
        end = offset + count >= len(table)
        if end:
            del state["fru_transfers"][transfer_handle]
            payload = _get_fru_record_table_response(_PLATFORM_TRANSFER_DONE, GetPDRTransferFlag.END, chunk)
            return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)
        next_transfer_handle = state["next_fru_transfer_handle"]
        state["next_fru_transfer_handle"] += 1
        state["fru_transfers"][next_transfer_handle] = {"table": table, "offset": offset + count}
        del state["fru_transfers"][transfer_handle]
        payload = _get_fru_record_table_response(next_transfer_handle, GetPDRTransferFlag.MIDDLE, chunk)
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _set_event_receiver(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        data = _pldm_payload_bytes(pldm)
        transport = pkt.getlayer(TransportHdrPacket)
        receiver_eid = int(transport.src) if transport is not None else None
        event_enable = int(data[0]) if data else 0
        protocol_type = int(data[1]) if len(data) > 1 else _MCTP_TRANSPORT_PROTOCOL_TYPE
        if len(data) > 2:
            receiver_eid = int(data[2])
        state = self._state(ctx)
        state["event_receiver"] = {
            "event_message_global_enable": event_enable,
            "transport_protocol_type": protocol_type,
            "eid": receiver_eid,
            "heartbeat_timer": int.from_bytes(data[3:5].ljust(2, b"\x00"), "little") if len(data) > 3 else 0,
        }
        self._event_ready.set()
        return self._reply(pkt, ctx, None, CompletionCodes.SUCCESS)

    def _event_message_buffer_size(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        return self._reply(pkt, ctx, struct.pack("<H", self.profile.event_buffer_size), CompletionCodes.SUCCESS)

    def _event_message_supported(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        payload = bytes(
            [
                0x03,
                0x03,
                1,
                PlatformEventMsgClasses.PLDM_SENSOR_EVENT,
            ]
        )
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _poll_for_platform_event_message(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        request = pkt.getlayer(PollForPlatformEventMsgPacket)
        if request is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)
        operation = PollForPlatformEventOperation(int(request.TransferOperationFlag))
        if operation == PollForPlatformEventOperation.ACK_ONLY:
            return self._reply(pkt, ctx, _poll_no_event_payload(ctx), CompletionCodes.SUCCESS)
        if operation == PollForPlatformEventOperation.GET_FIRST_PART:
            return self._poll_first_event(pkt, ctx)
        return self._poll_next_event(pkt, ctx, int(request.DataTransferHandle))

    def _poll_first_event(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        state = self._state(ctx)
        with self._event_lock:
            if not state["event_queue"]:
                return self._reply(pkt, ctx, _poll_no_event_payload(ctx), CompletionCodes.SUCCESS)
            event = state["event_queue"][0]
        return self._poll_event_chunk(pkt, ctx, event, 0, first=True)

    def _poll_next_event(self, pkt: Packet, ctx: EndpointContext, transfer_handle: int) -> HandlerResponse:
        transfer = self._state(ctx)["event_transfers"].get(transfer_handle)
        if transfer is None:
            return self._reply(pkt, ctx, None, _PLATFORM_CC_INVALID_DATA_TRANSFER_HANDLE)
        return self._poll_event_chunk(pkt, ctx, transfer["event"], int(transfer["offset"]), first=False, old_handle=transfer_handle)

    def _poll_event_chunk(
        self,
        pkt: Packet,
        ctx: EndpointContext,
        event: PlatformEvent,
        offset: int,
        *,
        first: bool,
        old_handle: int | None = None,
    ) -> HandlerResponse:
        state = self._state(ctx)
        chunk_size = max(1, min(self.profile.event_poll_chunk_size, self.profile.event_buffer_size))
        chunk = event.event_data[offset : offset + chunk_size]
        end = offset + len(chunk) >= len(event.event_data)
        if end:
            if old_handle is not None:
                state["event_transfers"].pop(old_handle, None)
            with self._event_lock:
                if state["event_queue"] and state["event_queue"][0].event_id == event.event_id:
                    state["event_queue"].popleft()
            transfer_flag = (
                PollForPlatformEventTransferFlag.START_AND_END if first else PollForPlatformEventTransferFlag.END
            )
            next_handle = _PLATFORM_TRANSFER_DONE
        else:
            if old_handle is not None:
                state["event_transfers"].pop(old_handle, None)
            next_handle = state["next_event_transfer_handle"]
            state["next_event_transfer_handle"] += 1
            state["event_transfers"][next_handle] = {"event": event, "offset": offset + len(chunk)}
            transfer_flag = PollForPlatformEventTransferFlag.START if first else PollForPlatformEventTransferFlag.MIDDLE
        payload = PollForPlatformEventMsgPacket(
            tid=_tid(ctx),
            eventID=event.event_id,
            NextDataTransferHandle=next_handle,
            TransferFlag=transfer_flag,
            eventClass=event.event_class,
            eventData=list(chunk),
        )
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _platform_event_message(self, pkt: Packet, ctx: EndpointContext, pldm: PldmHdrPacket) -> HandlerResponse:
        payload = PlatformEventMsgPacket(status=PlatformEventMsgStatus.ACCEPTED_FOR_LOGGING)
        return self._reply(pkt, ctx, payload, CompletionCodes.SUCCESS)

    def _record_threshold_transition(self, ctx: EndpointContext, sensor: SensorDefinition, reading: ReadingValue) -> None:
        new_state = sensor.threshold_state(reading)
        if new_state == sensor.present_state:
            return
        previous = sensor.present_state
        sensor.previous_state = previous
        sensor.present_state = new_state
        sensor.event_state = new_state
        self.queue_event(
            PlatformEventMsgClasses.PLDM_SENSOR_EVENT,
            _numeric_sensor_event_data(sensor, new_state, previous, reading),
            ctx=ctx,
        )

    def _ensure_sensor_pdr(self, ctx: EndpointContext, sensor: SensorDefinition) -> None:
        repository = self._state(ctx)["pdr_repository"]
        handles = {_decode_pdr_handle(record) for record in repository.encoded_records()}
        if sensor.sensor_id not in handles:
            repository.add_record(NumericSensorPdr.from_sensor(sensor))

    def _state_sensor(self, ctx: EndpointContext, sensor_id: int) -> StateSensorSimulation | None:
        sensor = self._state(ctx)["sensors"].get(int(sensor_id))
        if sensor is None:
            return None
        return sensor.state_sensor

    def _numeric_effecter(self, ctx: EndpointContext, effecter_id: int) -> EffecterDefinition | None:
        effecter = self._state(ctx)["effecters"].get(int(effecter_id))
        if effecter is None or effecter.state_effecter is not None:
            return None
        return effecter

    def _state_effecter(self, ctx: EndpointContext, effecter_id: int) -> StateEffecterSimulation | None:
        effecter = self._state(ctx)["effecters"].get(int(effecter_id))
        if effecter is None:
            return None
        return effecter.state_effecter

    def _event_loop(self, ctx: EndpointContext) -> None:
        while not self._shutdown.is_set():
            self._event_ready.wait(timeout=0.1)
            self._event_ready.clear()
            if self._shutdown.is_set():
                break
            try:
                self._emit_available_events(ctx)
            except Exception:
                logger.exception("PLDM platform event emission failed")

    def _emit_available_events(self, ctx: EndpointContext) -> None:
        while not self._shutdown.is_set():
            state = self._state(ctx)
            receiver = state.get("event_receiver") or {}
            receiver_eid = receiver.get("eid")
            if not self.profile.emit_events or receiver_eid is None or not receiver.get("event_message_global_enable"):
                return
            with self._event_lock:
                if not state["event_queue"]:
                    return
                event = state["event_queue"].popleft()
            self._send_platform_event(ctx, event, int(receiver_eid))

    def _send_platform_event(self, ctx: EndpointContext, event: PlatformEvent, receiver_eid: int) -> Packet | None:
        am = self._am
        if am is None or am.session is None:
            return None
        request = (
            PldmHdr(
                rq=True,
                instance_id=event.event_id & 0x1F,
                pldm_type=PldmTypeCodes.PLATFORM_MONITORING,
                cmd_code=PldmPlatformMonitoringCmdCodes.PlatformEventMessage,
                completion_code=None,
            )
            / PlatformEventMsgPacket(formatVersion=_PLATFORM_EVENT_FORMAT_VERSION, tid=_tid(ctx), eventClass=event.event_class)
            / event.event_data
        )
        return am.session.sndrcv_mctp_msg(
            request,
            dst_eid=receiver_eid,
            msg_type=MsgTypes.PLDM,
            msg_tag=self.profile.event_msg_tag,
            timeout_s=self.profile.event_timeout_s,
            threaded=True,
        )

    def _reply(
        self,
        pkt: Packet,
        ctx: EndpointContext,
        payload: Packet | bytes | None,
        completion_code: int | None,
    ) -> HandlerResponse:
        pldm = pkt.getlayer(PldmHdrPacket)
        pldm_payload = pldm.build_reply(ctx, payload, completion_code) if pldm is not None else payload
        state = ctx.msg_type_context[self.name]
        if state:
            state["last_response_bytes"] = len(raw(pldm_payload)) if pldm_payload else 0
        return HandlerResponse(stop_processing=True, reply=build_layered_reply(pkt, ctx, pldm_payload))

    def _state(self, ctx: EndpointContext) -> dict[str, Any]:
        state = ctx.msg_type_context[self.name]
        if not state:
            state.update(
                {
                    "sensors": _clone_sensors(self.profile.sensors),
                    "effecters": _clone_effecters(self.profile.effecters),
                    "pdr_repository": _clone_repository(self.profile.pdr_repository),
                    "fru_repository": _clone_fru_repository(self.profile.fru_repository),
                    "pdr_transfers": {},
                    "next_pdr_transfer_handle": 1,
                    "fru_transfers": {},
                    "next_fru_transfer_handle": 1,
                    "event_receiver": {},
                    "event_queue": deque(),
                    "event_transfers": {},
                    "next_event_transfer_handle": 1,
                    "next_event_id": 1,
                }
            )
        return state

    @staticmethod
    def _coerce_profile(profile: PldmSensorProfile | dict[str, Any] | None) -> PldmSensorProfile:
        if profile is None:
            return PldmSensorProfile()
        if isinstance(profile, PldmSensorProfile):
            return profile
        return PldmSensorProfile(**profile)


def _bitfield_bytes(values: list[int], length: int) -> bytes:
    data = bytearray(length)
    for value in values:
        if 0 <= int(value) < length * 8:
            data[int(value) // 8] |= 1 << (int(value) % 8)
    return bytes(data)


def _pldm_version_crc32(version_bytes: bytes) -> bytes:
    """CRC-32 over GetPLDMVersion version data, little endian.

    DSP0240 requires the final version-data transfer to end with a checksum.
    libpldm's ``crc32`` is the standard reflected CRC-32 (polynomial
    0xEDB88320), which is what :func:`binascii.crc32` computes.
    """
    return binascii.crc32(version_bytes).to_bytes(4, "little")


def _encode_pldm_version(version: str | int) -> bytes:
    """Encode a PLDM ``ver32`` field.

    DSP0240 transmits the four BCD-encoded bytes in ``major, minor, update,
    alpha`` order, so version 1.1.0 is ``F1 F1 F0 00`` on the wire - confirmed
    against a real PLDM terminus, whose base/platform/FRU/OEM versions all
    decode this way and whose CRC-32 covers the bytes in that order.
    """
    if isinstance(version, int):
        return int(version).to_bytes(4, "big")

    numeric, _, alpha = version.partition("-")
    parts = [int(part) for part in numeric.split(".")]
    while len(parts) < 3:
        parts.append(0)
    major, minor, update = parts[:3]
    alpha_byte = ord(alpha[0]) if alpha else 0
    return bytes(
        (
            _bcd_with_final_marker(major),
            _bcd_with_final_marker(minor),
            _bcd_with_final_marker(update),
            alpha_byte,
        )
    )


def _bcd_with_final_marker(value: int) -> int:
    if 0 <= value <= 9:
        return 0xF0 | value
    if 10 <= value <= 99:
        return ((value // 10) << 4) | (value % 10)
    msg = f"PLDM dotted versions support components 0 through 99, got {value}"
    raise ValueError(msg)


def _coerce_sensors(sensors: dict[int, SensorDefinition | dict[str, Any] | ReadingSource]) -> dict[int, SensorDefinition]:
    coerced: dict[int, SensorDefinition] = {}
    for sensor_id, sensor in sensors.items():
        key = int(sensor_id)
        if isinstance(sensor, SensorDefinition):
            coerced[key] = sensor
        elif isinstance(sensor, dict):
            data = dict(sensor)
            data.setdefault("sensor_id", key)
            coerced[key] = SensorDefinition(**data)
        else:
            coerced[key] = SensorDefinition(sensor_id=key, reading=sensor)
    return coerced


def _coerce_effecters(
    effecters: dict[int, EffecterDefinition | dict[str, Any] | ReadingValue],
) -> dict[int, EffecterDefinition]:
    coerced: dict[int, EffecterDefinition] = {}
    for effecter_id, effecter in effecters.items():
        key = int(effecter_id)
        if isinstance(effecter, EffecterDefinition):
            coerced[key] = effecter
        elif isinstance(effecter, dict):
            data = dict(effecter)
            data.setdefault("effecter_id", key)
            coerced[key] = EffecterDefinition(**data)
        else:
            coerced[key] = EffecterDefinition(effecter_id=key, pending_value=effecter, present_value=effecter)
    return coerced


def _load_pdrs_from(path: str) -> tuple[PdrRepository, dict[int, SensorDefinition], FruRepository]:
    model_path = Path(path)
    try:
        text = model_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        msg = f"PLDM sensor profile option 'pdrs_from' file not found: {model_path}"
        raise ValueError(msg) from exc
    except OSError as exc:
        msg = f"PLDM sensor profile option 'pdrs_from' could not read {model_path}: {exc}"
        raise ValueError(msg) from exc

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"PLDM sensor profile option 'pdrs_from' file {model_path} contains malformed JSON: {exc.msg}"
        raise ValueError(msg) from exc

    if not isinstance(data, Mapping):
        msg = f"PLDM sensor profile option 'pdrs_from' file {model_path} must contain a JSON object"
        raise ValueError(msg)

    pdrs = data.get("pdrs", [])
    if not isinstance(pdrs, list):
        msg = f"PLDM sensor profile option 'pdrs_from' file {model_path} field 'pdrs' must be a list"
        raise ValueError(msg)

    repository = PdrRepository(records=_load_pdr_records(pdrs, model_path))
    repository_info = data.get("repository_info")
    if repository_info is not None:
        if not isinstance(repository_info, Mapping):
            msg = f"PLDM sensor profile option 'pdrs_from' file {model_path} field 'repository_info' must be an object"
            raise ValueError(msg)
        repository.repository_state = int(repository_info.get("repository_state", repository.repository_state))
        repository.reported_record_count = _optional_int(repository_info.get("record_count"))
        repository.reported_repository_size = _optional_int(repository_info.get("repository_size"))
        repository.reported_largest_record_size = _optional_int(repository_info.get("largest_record_size"))
        repository.data_transfer_handle_timeout = int(
            repository_info.get("data_transfer_handle_timeout", repository.data_transfer_handle_timeout)
        )

    sensors = data.get("sensors", {})
    if not isinstance(sensors, Mapping):
        msg = f"PLDM sensor profile option 'pdrs_from' file {model_path} field 'sensors' must be an object"
        raise ValueError(msg)
    try:
        coerced = _coerce_sensors(dict(sensors))
    except (TypeError, ValueError) as exc:
        msg = f"PLDM sensor profile option 'pdrs_from' file {model_path} has invalid sensors: {exc}"
        raise ValueError(msg) from exc

    fru = data.get("fru")
    if fru is None:
        return repository, coerced, FruRepository()
    if not isinstance(fru, Mapping):
        msg = f"PLDM sensor profile option 'pdrs_from' file {model_path} field 'fru' must be an object"
        raise ValueError(msg)
    try:
        return repository, coerced, _fru_repository_from_artifact(fru)
    except (TypeError, ValueError) as exc:
        msg = f"PLDM sensor profile option 'pdrs_from' file {model_path} has invalid FRU data: {exc}"
        raise ValueError(msg) from exc


def _fru_repository_from_artifact(fru: Mapping[str, Any]) -> FruRepository:
    """Build a FRU repository from a generated artifact's ``fru`` object."""
    metadata = fru.get("metadata") or {}
    padding = fru.get("table_padding") or ""
    return FruRepository(
        records=[fru_record_from_dict(dict(record)) for record in fru.get("records", [])],
        table_padding=bytes.fromhex(padding) if isinstance(padding, str) else bytes(padding),
        major_version=int(metadata.get("major_version", 1)),
        minor_version=int(metadata.get("minor_version", 0)),
        table_maximum_size=int(metadata.get("table_maximum_size", 0)),
        reported_table_length=_optional_int(metadata.get("table_length")),
        reported_record_set_count=_optional_int(metadata.get("total_record_set_identifiers")),
        reported_record_count=_optional_int(metadata.get("total_records")),
        reported_integrity_checksum=_optional_int(metadata.get("integrity_checksum")),
    )


def _load_pdrs_model(reference: str, device_name: str | None) -> PldmSensorProfile:
    if not isinstance(reference, str):
        msg = (
            f"PLDM sensor profile option 'pdrs_model' reference {reference!r} for device "
            f"{_format_device_name(device_name)} must be in module:attribute form"
        )
        raise ValueError(msg)
    module_name, separator, attribute_name = reference.partition(":")
    if not separator or not module_name or not attribute_name:
        msg = (
            f"PLDM sensor profile option 'pdrs_model' reference {reference!r} for device "
            f"{_format_device_name(device_name)} must be in module:attribute form"
        )
        raise ValueError(msg)
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        msg = (
            f"PLDM sensor profile option 'pdrs_model' reference {reference!r} for device "
            f"{_format_device_name(device_name)} could not import module {module_name!r}: {exc}"
        )
        raise ValueError(msg) from exc

    try:
        value = getattr(module, attribute_name)
    except AttributeError as exc:
        msg = (
            f"PLDM sensor profile option 'pdrs_model' reference {reference!r} for device "
            f"{_format_device_name(device_name)} has no attribute {attribute_name!r}"
        )
        raise ValueError(msg) from exc

    from pymctp.pldm.model import Terminus

    if callable(value):
        try:
            value = value()
        except TypeError as exc:
            msg = (
                f"PLDM sensor profile option 'pdrs_model' reference {reference!r} for device "
                f"{_format_device_name(device_name)} callable must accept no arguments and return Terminus: {exc}"
            )
            raise ValueError(msg) from exc
    if not isinstance(value, Terminus):
        msg = (
            f"PLDM sensor profile option 'pdrs_model' reference {reference!r} for device "
            f"{_format_device_name(device_name)} must be a Terminus or a zero-argument callable returning Terminus, "
            f"got {type(value).__name__}"
        )
        raise ValueError(msg)
    return value.build()


def _format_device_name(device_name: str | None) -> str:
    return repr(device_name or "<unknown>")


def _load_pdr_records(pdrs: list[Any], model_path: Path) -> list[PdrRecord]:
    records: list[PdrRecord] = []
    for index, item in enumerate(pdrs):
        if not isinstance(item, Mapping):
            msg = f"PLDM sensor profile option 'pdrs_from' file {model_path} has invalid pdrs[{index}]: expected object"
            raise ValueError(msg)
        try:
            pdr_type = int(item["pdr_type"])
            if pdr_type not in _KNOWN_JSON_PDR_TYPES and "data" not in item:
                msg = f"unknown pdr_type {pdr_type} requires opaque 'data'"
                raise ValueError(msg)
            record = _decode_structured_json_data_pdr(item, pdr_type)
            records.append(record if record is not None else pdr_from_dict(dict(item)))
        except (KeyError, TypeError, ValueError) as exc:
            msg = f"PLDM sensor profile option 'pdrs_from' file {model_path} has invalid pdrs[{index}]: {exc}"
            raise ValueError(msg) from exc
    return records


def _decode_structured_json_data_pdr(item: Mapping[str, Any], pdr_type: int) -> PdrRecord | None:
    if "data" not in item or pdr_type not in _STRUCTURED_JSON_DATA_PDR_TYPES:
        return None
    body = bytes.fromhex(str(item["data"]))
    header = _PDR_COMMON_HEADER.pack(
        int(item.get("record_handle", 0)) & 0xFFFFFFFF,
        int(item.get("header_version", _PDR_HEADER_VERSION)) & 0xFF,
        pdr_type & 0xFF,
        int(item.get("record_change_number", 0)) & 0xFFFF,
        len(body) & 0xFFFF,
    )
    try:
        return decode_pdr(header + body)
    except ValueError:
        return None


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


_STRUCTURED_JSON_DATA_PDR_TYPES = {
    PDR_TYPE_NUMERIC_EFFECTER,
    PDR_TYPE_STATE_EFFECTER,
}

_KNOWN_JSON_PDR_TYPES = {
    -1,
    PDR_TYPE_TERMINUS_LOCATOR,
    PDR_TYPE_NUMERIC_SENSOR,
    PDR_TYPE_STATE_SENSOR,
    PDR_TYPE_SENSOR_AUXILIARY_NAMES,
    PDR_TYPE_NUMERIC_EFFECTER,
    PDR_TYPE_STATE_EFFECTER,
    PDR_TYPE_EFFECTER_AUXILIARY_NAMES,
    PDR_TYPE_ENTITY_AUXILIARY_NAMES,
}


def _clone_sensors(sensors: dict[int, SensorDefinition]) -> dict[int, SensorDefinition]:
    return {
        sensor_id: SensorDefinition(
            sensor_id=sensor.sensor_id,
            reading=sensor.reading,
            data_size=sensor.data_size,
            operational_state=sensor.operational_state,
            present_state=sensor.present_state,
            previous_state=sensor.previous_state,
            event_state=sensor.event_state,
            event_message_enable=sensor.event_message_enable,
            simulation=_clone_simulation(sensor.simulation),
            entity_type=sensor.entity_type,
            entity_instance=sensor.entity_instance,
            container_id=sensor.container_id,
            base_unit=sensor.base_unit,
            warning_high=sensor.warning_high,
            warning_low=sensor.warning_low,
            critical_high=sensor.critical_high,
            critical_low=sensor.critical_low,
            state_sensor=_clone_state_simulation(sensor.state_sensor),
        )
        for sensor_id, sensor in sensors.items()
    }


def _clone_effecters(effecters: dict[int, EffecterDefinition]) -> dict[int, EffecterDefinition]:
    return {
        effecter_id: EffecterDefinition(
            effecter_id=effecter.effecter_id,
            data_size=effecter.data_size,
            operational_state=effecter.operational_state,
            event_message_enable=effecter.event_message_enable,
            pending_value=effecter.pending_value,
            present_value=effecter.present_value,
            entity_type=effecter.entity_type,
            entity_instance=effecter.entity_instance,
            container_id=effecter.container_id,
            base_unit=effecter.base_unit,
            min_settable=effecter.min_settable,
            max_settable=effecter.max_settable,
            state_effecter=_clone_state_effecter_simulation(effecter.state_effecter),
        )
        for effecter_id, effecter in effecters.items()
    }


def _clone_simulation(simulation: SensorSimulation | None) -> SensorSimulation | None:
    if simulation is None:
        return None
    return SensorSimulation(
        minimum=simulation.minimum,
        maximum=simulation.maximum,
        step=simulation.step,
        current=simulation.current,
        warning_high=simulation.warning_high,
        warning_low=simulation.warning_low,
        critical_high=simulation.critical_high,
        critical_low=simulation.critical_low,
        direction=simulation.direction,
    )


def _clone_state_simulation(simulation: StateSensorSimulation | None) -> StateSensorSimulation | None:
    if simulation is None:
        return None
    return StateSensorSimulation(
        possible_states={state_set: list(states) for state_set, states in simulation.possible_states.items()},
        operational_states=list(simulation.operational_states),
        event_message_enables=list(simulation.event_message_enables),
        present_states=list(simulation.present_states),
        previous_states=list(simulation.previous_states),
        event_states=list(simulation.event_states),
    )


def _clone_state_effecter_simulation(simulation: StateEffecterSimulation | None) -> StateEffecterSimulation | None:
    if simulation is None:
        return None
    return StateEffecterSimulation(
        possible_states={state_set: list(states) for state_set, states in simulation.possible_states.items()},
        operational_states=list(simulation.operational_states),
        event_message_enables=list(simulation.event_message_enables),
        pending_states=list(simulation.pending_states),
        present_states=list(simulation.present_states),
    )


def _sensor_reading_payload(sensor: SensorDefinition, reading: ReadingValue | None = None) -> GetSensorReadingPacket:
    if reading is None:
        reading = sensor.next_reading()
    reading_field, encoded_reading = _reading_field(sensor.data_size, reading)
    return GetSensorReadingPacket(
        sensorDataSize=sensor.data_size,
        sensorOperationalState=sensor.operational_state,
        sensorEventMessageEnable=sensor.event_message_enable,
        presentState=sensor.present_state,
        previousState=sensor.previous_state,
        eventState=sensor.event_state,
        **{reading_field: encoded_reading},
    )


def _reading_field(data_size: GetSensorReadingDataSizeEnum, reading: ReadingValue) -> tuple[str, int]:
    value = int(reading)
    metadata = {
        GetSensorReadingDataSizeEnum.UINT8: ("presentReading8", 8, False),
        GetSensorReadingDataSizeEnum.SINT8: ("presentReading8", 8, True),
        GetSensorReadingDataSizeEnum.UINT16: ("presentReading16", 16, False),
        GetSensorReadingDataSizeEnum.SINT16: ("presentReading16", 16, True),
        GetSensorReadingDataSizeEnum.UINT32: ("presentReading32", 32, False),
        GetSensorReadingDataSizeEnum.SINT32: ("presentReading32", 32, True),
    }
    field_name, bits, signed = metadata[data_size]
    lower = -(1 << (bits - 1)) if signed else 0
    upper = (1 << (bits - 1)) - 1 if signed else (1 << bits) - 1
    if not lower <= value <= upper:
        msg = f"Sensor {data_size.name} reading {value} is outside [{lower}, {upper}]"
        raise ValueError(msg)
    return field_name, value & ((1 << bits) - 1)


def _derive_pdr_repository(
    sensors: dict[int, SensorDefinition],
    effecters: dict[int, EffecterDefinition] | None = None,
) -> PdrRepository:
    repository = PdrRepository()
    for sensor_id in sorted(sensors):
        repository.add_record(NumericSensorPdr.from_sensor(sensors[sensor_id]))
    for effecter_id in sorted(effecters or {}):
        effecter = effecters[effecter_id]
        if effecter.state_effecter is None:
            repository.add_record(_numeric_effecter_pdr_from_effecter(effecter, 0x10000 + effecter_id))
        else:
            repository.add_record(_state_effecter_pdr_from_effecter(effecter, 0x10000 + effecter_id))
    return repository


def _numeric_effecter_pdr_from_effecter(effecter: EffecterDefinition, record_handle: int) -> NumericEffecterPdr:
    return NumericEffecterPdr(
        record_handle=record_handle,
        effecter_id=effecter.effecter_id,
        effecter_data_size=effecter.data_size,
        entity_type=effecter.entity_type,
        entity_instance=effecter.entity_instance,
        container_id=effecter.container_id,
        base_unit=effecter.base_unit,
        max_settable=effecter.max_settable if effecter.max_settable is not None else _max_for_data_size(effecter.data_size),
        min_settable=effecter.min_settable if effecter.min_settable is not None else _min_for_data_size(effecter.data_size),
    )


def _state_effecter_pdr_from_effecter(effecter: EffecterDefinition, record_handle: int) -> StateEffecterPdr:
    state_effecter = effecter.state_effecter or StateEffecterSimulation()
    return StateEffecterPdr(
        record_handle=record_handle,
        effecter_id=effecter.effecter_id,
        entity_type=effecter.entity_type,
        entity_instance=effecter.entity_instance,
        container_id=effecter.container_id,
        possible_states=state_effecter.possible_states,
    )


def _synthesized_sensors_from_pdrs(
    repository: PdrRepository,
    existing_sensors: dict[int, SensorDefinition],
) -> dict[int, SensorDefinition]:
    sensors: dict[int, SensorDefinition] = {}
    for record in _sensor_pdr_records(repository):
        sensor_id = int(record.sensor_id)
        if sensor_id in existing_sensors:
            if isinstance(record, StateSensorPdr) and existing_sensors[sensor_id].state_sensor is None:
                existing_sensors[sensor_id].state_sensor = StateSensorSimulation(possible_states=record.possible_states)
            continue
        if sensor_id in sensors:
            continue
        if isinstance(record, NumericSensorPdr):
            sensors[sensor_id] = _sensor_from_numeric_pdr(record)
        elif isinstance(record, StateSensorPdr):
            sensors[sensor_id] = _sensor_from_state_pdr(record)
    return sensors


def _synthesized_effecters_from_pdrs(
    repository: PdrRepository,
    existing_effecters: dict[int, EffecterDefinition],
) -> dict[int, EffecterDefinition]:
    effecters: dict[int, EffecterDefinition] = {}
    for record in _effecter_pdr_records(repository):
        effecter_id = int(record.effecter_id)
        if effecter_id in existing_effecters or effecter_id in effecters:
            continue
        if isinstance(record, NumericEffecterPdr):
            effecters[effecter_id] = _effecter_from_numeric_pdr(record)
        elif isinstance(record, StateEffecterPdr):
            effecters[effecter_id] = _effecter_from_state_pdr(record)
    return effecters


def _sensor_pdr_records(repository: PdrRepository) -> Iterable[NumericSensorPdr | StateSensorPdr]:
    for record in repository.records:
        decoded = _decode_repository_record(record)
        if isinstance(decoded, (NumericSensorPdr, StateSensorPdr)):
            yield decoded
        elif _is_state_sensor_pdr_like(decoded):
            yield _state_sensor_pdr_from_like(decoded)
        elif _is_opaque_state_sensor_pdr(decoded):
            yield _state_sensor_pdr_from_opaque(decoded)


def _effecter_pdr_records(repository: PdrRepository) -> Iterable[NumericEffecterPdr | StateEffecterPdr]:
    for record in repository.records:
        decoded = _decode_repository_record(record)
        if isinstance(decoded, (NumericEffecterPdr, StateEffecterPdr)):
            yield decoded


def _decode_repository_record(record: PdrRecord) -> PdrRecord:
    if isinstance(record, (NumericSensorPdr, StateSensorPdr, NumericEffecterPdr, StateEffecterPdr)):
        return record
    if isinstance(record, (bytes, bytearray)):
        return decode_pdr(bytes(record))
    return record


def _is_state_sensor_pdr_like(record: PdrRecord) -> bool:
    return all(hasattr(record, attr) for attr in ("record_handle", "sensor_id", "possible_states"))


def _is_opaque_state_sensor_pdr(record: PdrRecord) -> bool:
    header = getattr(record, "header", None)
    return getattr(header, "pdr_type", None) == _PDR_TYPE_STATE_SENSOR and hasattr(record, "data")


def _state_sensor_pdr_from_like(record: PdrRecord) -> StateSensorPdr:
    return StateSensorPdr(
        record_handle=getattr(record, "record_handle"),
        record_change_number=getattr(record, "record_change_number", 0),
        terminus_handle=getattr(record, "terminus_handle", 0),
        sensor_id=getattr(record, "sensor_id"),
        entity_type=getattr(record, "entity_type", 0),
        entity_instance=getattr(record, "entity_instance", 1),
        container_id=getattr(record, "container_id", 0),
        sensor_init=getattr(record, "sensor_init", 0),
        sensor_auxiliary_names_pdr=getattr(record, "sensor_auxiliary_names_pdr", 0),
        possible_states=getattr(record, "possible_states"),
        trailing_data=getattr(record, "trailing_data", b""),
    )


def _state_sensor_pdr_from_opaque(record: PdrRecord) -> StateSensorPdr:
    body = bytes(getattr(record, "data"))
    if len(body) < 13:
        msg = "State Sensor PDR body is truncated"
        raise ValueError(msg)
    (
        terminus_handle,
        sensor_id,
        entity_type,
        entity_instance,
        container_id,
        sensor_init,
        sensor_auxiliary_names_pdr,
        possible_states_count,
    ) = struct.unpack_from("<HHHHHBBB", body)
    offset = struct.calcsize("<HHHHHBBB")
    possible_states: dict[int, list[int]] = {}
    for _ in range(possible_states_count):
        if offset + 3 > len(body):
            break
        state_set_id, possible_states_size = struct.unpack_from("<HB", body, offset)
        offset += 3
        remaining = len(body) - offset
        possible_states_bytes = min(remaining, possible_states_size)
        if possible_states_size > remaining:
            possible_states_bytes = min(remaining, (possible_states_size + 7) // 8)
        possible_states[state_set_id] = _states_from_bitfield(body[offset : offset + possible_states_bytes])
        offset += possible_states_bytes
    return StateSensorPdr(
        record_handle=getattr(record.header, "record_handle"),
        record_change_number=getattr(record.header, "record_change_number", 0),
        terminus_handle=terminus_handle,
        sensor_id=sensor_id,
        entity_type=entity_type,
        entity_instance=entity_instance,
        container_id=container_id,
        sensor_init=sensor_init,
        sensor_auxiliary_names_pdr=sensor_auxiliary_names_pdr,
        possible_states=possible_states,
        trailing_data=body[offset:],
    )


def _sensor_from_numeric_pdr(record: NumericSensorPdr) -> SensorDefinition:
    return SensorDefinition(
        sensor_id=record.sensor_id,
        reading=_starting_reading_from_numeric_pdr(record),
        data_size=record.data_size,
        entity_type=record.entity_type,
        entity_instance=record.entity_instance,
        container_id=record.container_id,
        base_unit=record.base_unit,
        warning_high=_range_field(record, _RANGE_FIELD_WARNING_HIGH, "warning_high"),
        warning_low=_range_field(record, _RANGE_FIELD_WARNING_LOW, "warning_low"),
        critical_high=_range_field(record, _RANGE_FIELD_CRITICAL_HIGH, "critical_high"),
        critical_low=_range_field(record, _RANGE_FIELD_CRITICAL_LOW, "critical_low"),
    )


def _sensor_from_state_pdr(record: StateSensorPdr) -> SensorDefinition:
    return SensorDefinition(
        sensor_id=record.sensor_id,
        entity_type=record.entity_type,
        entity_instance=record.entity_instance,
        container_id=record.container_id,
        state_sensor=StateSensorSimulation(possible_states=record.possible_states),
    )


def _effecter_from_numeric_pdr(record: NumericEffecterPdr) -> EffecterDefinition:
    starting_value = _starting_value_from_numeric_effecter_pdr(record)
    return EffecterDefinition(
        effecter_id=record.effecter_id,
        data_size=record.effecter_data_size,
        pending_value=starting_value,
        present_value=starting_value,
        entity_type=record.entity_type,
        entity_instance=record.entity_instance,
        container_id=record.container_id,
        base_unit=record.base_unit,
        min_settable=record.min_settable,
        max_settable=record.max_settable,
    )


def _effecter_from_state_pdr(record: StateEffecterPdr) -> EffecterDefinition:
    return EffecterDefinition(
        effecter_id=record.effecter_id,
        entity_type=record.entity_type,
        entity_instance=record.entity_instance,
        container_id=record.container_id,
        state_effecter=StateEffecterSimulation(possible_states=record.possible_states),
    )


def _range_field(record: NumericSensorPdr, bit: int, field_name: str) -> ReadingValue | None:
    if not int(record.range_field_support) & (1 << bit):
        return None
    return getattr(record, field_name)


def _starting_reading_from_numeric_pdr(record: NumericSensorPdr) -> ReadingValue:
    candidates: list[ReadingValue] = []
    nominal = _range_field(record, _RANGE_FIELD_NOMINAL_VALUE, "nominal_value")
    if nominal is not None:
        candidates.append(nominal)
    normal_min = _range_field(record, _RANGE_FIELD_NORMAL_MIN, "normal_min")
    normal_max = _range_field(record, _RANGE_FIELD_NORMAL_MAX, "normal_max")
    if normal_min is not None and normal_max is not None:
        candidates.append((normal_min + normal_max) / 2)
    candidates.extend(value for value in (normal_min, normal_max) if value is not None)
    min_readable, max_readable = _numeric_readable_bounds(record)
    candidates.append((min_readable + max_readable) / 2)
    candidates.extend((min_readable, max_readable, 0))

    lower, upper = _normalized_bounds(min_readable, max_readable)
    for candidate in candidates:
        if lower <= float(candidate) <= upper:
            return _coerce_reading_for_data_size(record.data_size, candidate)
    return _coerce_reading_for_data_size(record.data_size, min(max(candidates[0], lower), upper))


def _starting_value_from_numeric_effecter_pdr(record: NumericEffecterPdr) -> ReadingValue:
    candidates: list[ReadingValue] = []
    if int(record.range_field_support) & (1 << _RANGE_FIELD_NOMINAL_VALUE):
        candidates.append(record.nominal_value)
    if int(record.range_field_support) & (1 << _RANGE_FIELD_NORMAL_MIN) and int(record.range_field_support) & (
        1 << _RANGE_FIELD_NORMAL_MAX
    ):
        candidates.append((record.normal_min + record.normal_max) / 2)
    min_settable, max_settable = _numeric_settable_bounds(record)
    candidates.extend((min_settable, max_settable, 0))

    lower, upper = _normalized_bounds(min_settable, max_settable)
    for candidate in candidates:
        if lower <= float(candidate) <= upper:
            return _coerce_reading_for_data_size(record.effecter_data_size, candidate)
    return _coerce_reading_for_data_size(record.effecter_data_size, min(max(candidates[0], lower), upper))


def _numeric_readable_bounds(record: NumericSensorPdr) -> tuple[ReadingValue, ReadingValue]:
    min_readable = record.min_readable if record.min_readable is not None else _min_for_data_size(record.data_size)
    max_readable = record.max_readable if record.max_readable is not None else _max_for_data_size(record.data_size)
    return min_readable, max_readable


def _numeric_settable_bounds(record: NumericEffecterPdr) -> tuple[ReadingValue, ReadingValue]:
    return record.min_settable, record.max_settable


def _normalized_bounds(minimum: ReadingValue, maximum: ReadingValue) -> tuple[float, float]:
    lower = float(minimum)
    upper = float(maximum)
    return (lower, upper) if lower <= upper else (upper, lower)


def _coerce_reading_for_data_size(data_size: GetSensorReadingDataSizeEnum, value: ReadingValue) -> ReadingValue:
    coerced = int(round(float(value)))
    lower = _min_for_data_size(data_size)
    upper = _max_for_data_size(data_size)
    return min(max(coerced, lower), upper)


def _warn_sensor_pdr_mismatches(sensors: dict[int, SensorDefinition], repository: PdrRepository) -> None:
    pdr_sensor_ids = {int(record.sensor_id) for record in _sensor_pdr_records(repository)}
    sensor_ids = set(sensors)
    missing_definitions = sorted(pdr_sensor_ids - sensor_ids)
    missing_pdrs = sorted(sensor_ids - pdr_sensor_ids)
    if not missing_definitions and not missing_pdrs:
        return
    logger.warning(
        "PLDM sensor/PDR mismatch: PDR sensor(s) without definitions: %s; sensor definition(s) without PDRs: %s",
        missing_definitions,
        missing_pdrs,
    )


def _warn_effecter_pdr_mismatches(effecters: dict[int, EffecterDefinition], repository: PdrRepository) -> None:
    pdr_effecter_ids = {int(record.effecter_id) for record in _effecter_pdr_records(repository)}
    effecter_ids = set(effecters)
    missing_definitions = sorted(pdr_effecter_ids - effecter_ids)
    missing_pdrs = sorted(effecter_ids - pdr_effecter_ids)
    if not missing_definitions and not missing_pdrs:
        return
    logger.warning(
        "PLDM effecter/PDR mismatch: PDR effecter(s) without definitions: %s; effecter definition(s) without PDRs: %s",
        missing_definitions,
        missing_pdrs,
    )


def _clone_repository(repository: PdrRepository | list[PdrRecord] | None) -> PdrRepository:
    if repository is None:
        return PdrRepository()
    if not isinstance(repository, PdrRepository):
        return PdrRepository(list(repository))
    cloned = PdrRepository(
        record_change_number=repository.record_change_number,
        repository_state=repository.repository_state,
        reported_record_count=repository.reported_record_count,
        reported_repository_size=repository.reported_repository_size,
        reported_largest_record_size=repository.reported_largest_record_size,
        data_transfer_handle_timeout=repository.data_transfer_handle_timeout,
    )
    for record in repository.records:
        cloned.add_record(encode_pdr(record))
    return cloned


def _clone_fru_repository(repository: FruRepository | list[Any] | None) -> FruRepository:
    if repository is None:
        return FruRepository()
    if not isinstance(repository, FruRepository):
        return FruRepository(list(repository))
    return FruRepository(
        records=copy.deepcopy(repository.records),
        table_padding=repository.table_padding,
        major_version=repository.major_version,
        minor_version=repository.minor_version,
        table_maximum_size=repository.table_maximum_size,
        reported_table_length=repository.reported_table_length,
        reported_record_set_count=repository.reported_record_set_count,
        reported_record_count=repository.reported_record_count,
        reported_integrity_checksum=repository.reported_integrity_checksum,
    )


def _pdr_header(record_handle: int, pdr_type: int, record_change_number: int, data_length: int) -> bytes:
    return _PDR_COMMON_HEADER.pack(
        int(record_handle) & 0xFFFFFFFF,
        _PDR_HEADER_VERSION,
        int(pdr_type) & 0xFF,
        int(record_change_number) & 0xFFFF,
        int(data_length) & 0xFFFF,
    )


def _decode_pdr_handle(record: bytes) -> int:
    if len(record) < 4:
        return 0
    return int.from_bytes(record[:4], "little")


def _threshold_support_bits(*thresholds: ReadingValue | None) -> int:
    bits = 0
    for index, threshold in enumerate(thresholds):
        if threshold is not None and threshold != 0:
            bits |= 1 << index
    return bits


def _numeric_range_format(data_size: GetSensorReadingDataSizeEnum | int) -> GetSensorReadingDataSizeEnum | int:
    value = int(data_size)
    if value in (6, 7):
        return value
    return GetSensorReadingDataSizeEnum(value)


def _sensor_value_size(data_size: GetSensorReadingDataSizeEnum | int) -> int:
    data_size = _numeric_range_format(data_size)
    return {
        GetSensorReadingDataSizeEnum.UINT8: 1,
        GetSensorReadingDataSizeEnum.SINT8: 1,
        GetSensorReadingDataSizeEnum.UINT16: 2,
        GetSensorReadingDataSizeEnum.SINT16: 2,
        GetSensorReadingDataSizeEnum.UINT32: 4,
        GetSensorReadingDataSizeEnum.SINT32: 4,
        6: 4,
        7: 8,
    }[data_size]


def _encode_sensor_value(data_size: GetSensorReadingDataSizeEnum | int, value: ReadingValue) -> bytes:
    data_size = _numeric_range_format(data_size)
    formats = {
        GetSensorReadingDataSizeEnum.UINT8: "<B",
        GetSensorReadingDataSizeEnum.SINT8: "<b",
        GetSensorReadingDataSizeEnum.UINT16: "<H",
        GetSensorReadingDataSizeEnum.SINT16: "<h",
        GetSensorReadingDataSizeEnum.UINT32: "<I",
        GetSensorReadingDataSizeEnum.SINT32: "<i",
        6: "<f",
        7: "<d",
    }
    if data_size in (6, 7):
        return struct.pack(formats[data_size], float(value))
    return struct.pack(formats[data_size], int(value))


def _decode_numeric_value(data_size: GetSensorReadingDataSizeEnum, data: bytes, offset: int = 0) -> ReadingValue:
    formats = {
        GetSensorReadingDataSizeEnum.UINT8: "<B",
        GetSensorReadingDataSizeEnum.SINT8: "<b",
        GetSensorReadingDataSizeEnum.UINT16: "<H",
        GetSensorReadingDataSizeEnum.SINT16: "<h",
        GetSensorReadingDataSizeEnum.UINT32: "<I",
        GetSensorReadingDataSizeEnum.SINT32: "<i",
    }
    return struct.unpack_from(formats[data_size], data, offset)[0]


def _max_for_data_size(data_size: GetSensorReadingDataSizeEnum) -> int:
    return {
        GetSensorReadingDataSizeEnum.UINT8: 0xFF,
        GetSensorReadingDataSizeEnum.SINT8: 0x7F,
        GetSensorReadingDataSizeEnum.UINT16: 0xFFFF,
        GetSensorReadingDataSizeEnum.SINT16: 0x7FFF,
        GetSensorReadingDataSizeEnum.UINT32: 0xFFFFFFFF,
        GetSensorReadingDataSizeEnum.SINT32: 0x7FFFFFFF,
    }[data_size]


def _min_for_data_size(data_size: GetSensorReadingDataSizeEnum) -> int:
    return {
        GetSensorReadingDataSizeEnum.UINT8: 0,
        GetSensorReadingDataSizeEnum.SINT8: -0x80,
        GetSensorReadingDataSizeEnum.UINT16: 0,
        GetSensorReadingDataSizeEnum.SINT16: -0x8000,
        GetSensorReadingDataSizeEnum.UINT32: 0,
        GetSensorReadingDataSizeEnum.SINT32: -0x80000000,
    }[data_size]


def _state_bitfield(states: Iterable[int]) -> bytes:
    values = [int(state) for state in states]
    size = max(1, (max(values, default=0) // 8) + 1)
    return _bitfield_bytes(values, size)


def _states_from_bitfield(bitfield: bytes) -> list[int]:
    states: list[int] = []
    for byte_index, value in enumerate(bitfield):
        for bit_index in range(8):
            if value & (1 << bit_index):
                states.append((byte_index * 8) + bit_index)
    return states


def _state_list(values: Iterable[Any], count: int, default: Any) -> list[Any]:
    items = list(values)
    defaults = list(default) if isinstance(default, list) else [default] * count
    while len(defaults) < count:
        defaults.append(defaults[-1] if defaults else 0)
    items.extend(defaults[len(items) : count])
    return items[:count]


def _next_state_value(states: Iterable[int], present: int) -> int:
    values = list(states)
    if not values:
        return 0
    try:
        index = values.index(int(present))
    except ValueError:
        return values[0]
    return values[(index + 1) % len(values)]


def _int8(value: int) -> int:
    value = int(value)
    if not -128 <= value <= 127:
        msg = f"int8 value out of range: {value}"
        raise ValueError(msg)
    return value


def _pldm_payload_bytes(pldm: PldmHdrPacket) -> bytes:
    payload = pldm.payload
    if isinstance(payload, Raw):
        return bytes(payload.load)
    if payload is None:
        return b""
    return bytes(payload)


def _coerce_uuid(value: uuid.UUID | str | bytes | None) -> uuid.UUID | None:
    if value is None or isinstance(value, uuid.UUID):
        return value
    if isinstance(value, bytes):
        if not value:
            return None
        return uuid.UUID(bytes=bytes(value))
    return uuid.UUID(str(value))


def _terminus_uid_bytes(ctx: EndpointContext, configured_uid: uuid.UUID | None) -> bytes:
    if configured_uid is not None:
        return configured_uid.bytes
    endpoint_uuid = _coerce_uuid(getattr(ctx, "endpoint_uuid", None))
    if endpoint_uuid is None:
        return b"\x00" * 16
    return endpoint_uuid.bytes


def _slice_count(request_count: int, remaining: int, fallback: int) -> int:
    if remaining <= 0:
        return 0
    count = int(request_count) if request_count else int(fallback)
    return max(0, min(count, remaining))


def _fru_slice_count(remaining: int, chunk_size: int) -> int:
    if remaining <= 0:
        return 0
    count = int(chunk_size) if chunk_size else remaining
    return max(0, min(count, remaining))


def _get_pdr_response(
    next_record_handle: int,
    next_transfer_handle: int,
    transfer_flag: GetPDRTransferFlag,
    chunk: bytes,
    *,
    crc: int | None = None,
) -> bytes:
    payload = struct.pack(
        "<IIBH",
        int(next_record_handle) & 0xFFFFFFFF,
        int(next_transfer_handle) & 0xFFFFFFFF,
        int(transfer_flag) & 0xFF,
        len(chunk) & 0xFFFF,
    ) + chunk
    if crc is not None:
        payload += struct.pack("<I", crc & 0xFFFFFFFF)
    return payload


def _get_fru_record_table_response(
    next_transfer_handle: int,
    transfer_flag: GetPDRTransferFlag,
    chunk: bytes,
) -> bytes:
    return struct.pack("<IB", int(next_transfer_handle) & 0xFFFFFFFF, int(transfer_flag) & 0xFF) + bytes(chunk)


def _poll_no_event_payload(ctx: EndpointContext) -> PollForPlatformEventMsgPacket:
    return PollForPlatformEventMsgPacket(tid=_tid(ctx), eventID=_EVENT_ID_NONE)


def _numeric_sensor_event_data(
    sensor: SensorDefinition,
    event_state: GetSensorReadingPresentEnum,
    previous_state: GetSensorReadingPresentEnum,
    reading: ReadingValue,
) -> bytes:
    return (
        struct.pack(
            "<HBBB",
            sensor.sensor_id,
            _PLATFORM_SENSOR_EVENT_NUMERIC_SENSOR_STATE,
            int(event_state) & 0xFF,
            int(previous_state) & 0xFF,
        )
        + bytes([int(sensor.data_size) & 0xFF])
        + _encode_sensor_value(sensor.data_size, reading)
    )


def _tid(ctx: EndpointContext) -> int:
    base_state = ctx.msg_type_context.get("pldm-base", {})
    legacy_state = ctx.msg_type_context.get("pldm", {})
    return int(base_state.get("tid", legacy_state.get("tid", 1))) & 0xFF
