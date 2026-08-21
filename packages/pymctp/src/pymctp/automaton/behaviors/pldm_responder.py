# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Basic PLDM responder behaviors."""

from __future__ import annotations

import binascii
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, fields
from enum import IntEnum
import logging
import struct
import threading
from typing import TYPE_CHECKING, Any

from scapy.packet import Packet, Raw

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

_PDR_HEADER_VERSION = 1
_PDR_TYPE_NUMERIC_SENSOR = 2
_PDR_TYPE_STATE_SENSOR = 4
_PDR_COMMON_HEADER = struct.Struct("<IBBHH")
_PLDM_TIMESTAMP104_SIZE = 13
_PLATFORM_CC_INVALID_DATA_TRANSFER_HANDLE = 0x80
_PLATFORM_CC_INVALID_TRANSFER_OPERATION_FLAG = 0x81
_PLATFORM_CC_INVALID_RECORD_HANDLE = 0x82
_PLATFORM_CC_INVALID_RECORD_CHANGE_NUMBER = 0x83
_PLATFORM_TRANSFER_DONE = 0
_PLATFORM_EVENT_FORMAT_VERSION = 1
_PLATFORM_SENSOR_EVENT_NUMERIC_SENSOR_STATE = 2
_MCTP_TRANSPORT_PROTOCOL_TYPE = 0
_EVENT_ID_NONE = 0

_BASE_COMMANDS = [
    PldmControlCmdCodes.SetTID,
    PldmControlCmdCodes.GetTID,
    PldmControlCmdCodes.GetPLDMVersion,
    PldmControlCmdCodes.GetPLDMTypes,
    PldmControlCmdCodes.GetPLDMCommands,
]
_PLATFORM_COMMANDS = [
    PldmPlatformMonitoringCmdCodes.SetEventReceiver,
    PldmPlatformMonitoringCmdCodes.PlatformEventMessage,
    PldmPlatformMonitoringCmdCodes.PollForPlatformEventMessage,
    PldmPlatformMonitoringCmdCodes.EventMessageSupported,
    PldmPlatformMonitoringCmdCodes.EventMessageBufferSize,
    PldmPlatformMonitoringCmdCodes.GetSensorReading,
    PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo,
    PldmPlatformMonitoringCmdCodes.GetPDR,
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
    supported_types: list[int] = field(
        default_factory=lambda: [int(PldmTypeCodes.CONTROL), int(PldmTypeCodes.PLATFORM_MONITORING)]
    )
    versions: dict[int, list[str]] = field(
        default_factory=lambda: {
            int(PldmTypeCodes.CONTROL): ["1.0.0"],
            int(PldmTypeCodes.PLATFORM_MONITORING): ["1.0.0"],
        }
    )
    commands: dict[int, list[int]] = field(
        default_factory=lambda: {
            int(PldmTypeCodes.CONTROL): [int(cmd) for cmd in _BASE_COMMANDS],
            int(PldmTypeCodes.PLATFORM_MONITORING): [int(cmd) for cmd in _PLATFORM_COMMANDS],
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
class SensorDefinition:
    """A numeric PLDM sensor definition and its current reading source."""

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
    range_field_format: GetSensorReadingDataSizeEnum | None = None
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
            self.range_field_format = GetSensorReadingDataSizeEnum(self.range_field_format)
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

    def __post_init__(self) -> None:
        self.record_handle = int(self.record_handle)
        self.sensor_id = int(self.sensor_id)
        self.possible_states = {int(state_set): [int(state) for state in states] for state_set, states in self.possible_states.items()}

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
        )
        return _pdr_header(self.record_handle, _PDR_TYPE_STATE_SENSOR, self.record_change_number, len(body)) + body


@dataclass
class PdrRepository:
    """In-memory PLDM PDR repository."""

    records: list[NumericSensorPdr | StateSensorPdr | bytes] = field(default_factory=list)
    record_change_number: int = 0
    repository_state: int = 0

    def __post_init__(self) -> None:
        self.records = list(self.records)

    def add_record(self, record: NumericSensorPdr | StateSensorPdr | bytes) -> None:
        """Append a PDR record."""
        self.records.append(record)

    def encoded_records(self) -> list[bytes]:
        """Return records encoded as PDR wire bytes."""
        return [record if isinstance(record, bytes) else record.to_bytes() for record in self.records]

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
        return len(self.records)

    @property
    def repository_size(self) -> int:
        return sum(len(record) for record in self.encoded_records())

    @property
    def largest_record_size(self) -> int:
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
    pdr_repository: PdrRepository | list[NumericSensorPdr | StateSensorPdr | bytes] | None = None
    emit_events: bool = False
    event_buffer_size: int = 256
    event_poll_chunk_size: int = 256
    event_msg_tag: int = 0
    event_timeout_s: float = 0.5

    def __post_init__(self) -> None:
        self.sensors = _coerce_sensors(self.sensors)
        if self.pdr_repository is None:
            self.pdr_repository = _derive_pdr_repository(self.sensors)
        elif isinstance(self.pdr_repository, PdrRepository):
            pass
        else:
            self.pdr_repository = PdrRepository(list(self.pdr_repository))
        self.emit_events = bool(self.emit_events)
        self.event_buffer_size = int(self.event_buffer_size)
        self.event_poll_chunk_size = int(self.event_poll_chunk_size)
        self.event_msg_tag = int(self.event_msg_tag)
        self.event_timeout_s = float(self.event_timeout_s)


class PldmSensorBehavior(Behavior):
    """Answers PLDM Type 2 sensor, PDR repository and platform event requests."""

    def __init__(
        self,
        *,
        profile: PldmSensorProfile | dict[str, Any] | None = None,
        sensors: dict[int, SensorDefinition | dict[str, Any] | ReadingSource] | None = None,
        **overrides: Any,
    ) -> None:
        sensor_profile = self._coerce_profile(profile)
        data = {item.name: getattr(sensor_profile, item.name) for item in fields(PldmSensorProfile)}
        if sensors is not None:
            data["sensors"] = sensors
            if "pdr_repository" not in overrides:
                data["pdr_repository"] = None
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
        return bool(pldm is not None and pldm.rq == 1 and pldm.pldm_type == PldmTypeCodes.PLATFORM_MONITORING)

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

    def _handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        pldm = pkt.getlayer(PldmHdrPacket)
        if pldm is None:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_INVALID_DATA)

        try:
            cmd_code = PldmPlatformMonitoringCmdCodes(pldm.cmd_code)
        except ValueError:
            return self._reply(pkt, ctx, None, CompletionCodes.ERROR_UNSUPPORTED_CMD)

        handlers = {
            PldmPlatformMonitoringCmdCodes.GetSensorReading: self._get_sensor_reading,
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
                0,
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
        return HandlerResponse(stop_processing=True, reply=build_layered_reply(pkt, ctx, pldm_payload))

    def _state(self, ctx: EndpointContext) -> dict[str, Any]:
        state = ctx.msg_type_context[self.name]
        if not state:
            state.update(
                {
                    "sensors": _clone_sensors(self.profile.sensors),
                    "pdr_repository": _clone_repository(self.profile.pdr_repository),
                    "pdr_transfers": {},
                    "next_pdr_transfer_handle": 1,
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
    if isinstance(version, int):
        return int(version).to_bytes(4, "little")

    numeric, _, alpha = version.partition("-")
    parts = [int(part) for part in numeric.split(".")]
    while len(parts) < 3:
        parts.append(0)
    major, minor, update = parts[:3]
    alpha_byte = ord(alpha[0]) if alpha else 0
    encoded = (_bcd_with_final_marker(major) << 24) | (_bcd_with_final_marker(minor) << 16) | (
        _bcd_with_final_marker(update) << 8
    ) | alpha_byte
    return encoded.to_bytes(4, "little")


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
        )
        for sensor_id, sensor in sensors.items()
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


def _derive_pdr_repository(sensors: dict[int, SensorDefinition]) -> PdrRepository:
    repository = PdrRepository()
    for sensor_id in sorted(sensors):
        repository.add_record(NumericSensorPdr.from_sensor(sensors[sensor_id]))
    return repository


def _clone_repository(repository: PdrRepository | list[NumericSensorPdr | StateSensorPdr | bytes] | None) -> PdrRepository:
    if repository is None:
        return PdrRepository()
    if not isinstance(repository, PdrRepository):
        return PdrRepository(list(repository))
    cloned = PdrRepository(record_change_number=repository.record_change_number, repository_state=repository.repository_state)
    for record in repository.records:
        cloned.add_record(record if isinstance(record, bytes) else record.to_bytes())
    return cloned


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


def _sensor_value_size(data_size: GetSensorReadingDataSizeEnum) -> int:
    return {
        GetSensorReadingDataSizeEnum.UINT8: 1,
        GetSensorReadingDataSizeEnum.SINT8: 1,
        GetSensorReadingDataSizeEnum.UINT16: 2,
        GetSensorReadingDataSizeEnum.SINT16: 2,
        GetSensorReadingDataSizeEnum.UINT32: 4,
        GetSensorReadingDataSizeEnum.SINT32: 4,
    }[data_size]


def _encode_sensor_value(data_size: GetSensorReadingDataSizeEnum, value: ReadingValue) -> bytes:
    value = int(value)
    formats = {
        GetSensorReadingDataSizeEnum.UINT8: "<B",
        GetSensorReadingDataSizeEnum.SINT8: "<b",
        GetSensorReadingDataSizeEnum.UINT16: "<H",
        GetSensorReadingDataSizeEnum.SINT16: "<h",
        GetSensorReadingDataSizeEnum.UINT32: "<I",
        GetSensorReadingDataSizeEnum.SINT32: "<i",
    }
    return struct.pack(formats[data_size], value)


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


def _slice_count(request_count: int, remaining: int, fallback: int) -> int:
    if remaining <= 0:
        return 0
    count = int(request_count) if request_count else int(fallback)
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
