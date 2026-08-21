# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Readable Python model for PLDM termini."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, TypeVar

from pymctp.automaton.behaviors.pldm_responder import (
    EffecterDefinition,
    NumericSensorPdr,
    PdrRepository,
    PldmSensorProfile,
    SensorDefinition,
    StateSensorPdr,
)
from pymctp.layers.mctp.pldm.pdr import (
    PDR_TYPE_EFFECTER_AUXILIARY_NAMES,
    PDR_TYPE_NUMERIC_EFFECTER,
    PDR_TYPE_NUMERIC_SENSOR,
    PDR_TYPE_SENSOR_AUXILIARY_NAMES,
    PDR_TYPE_STATE_EFFECTER,
    PDR_TYPE_STATE_SENSOR,
    EffecterAuxiliaryNamesEntry,
    EffecterAuxiliaryNamesPdr,
    NumericEffecterPdr,
    OpaquePdr,
    PdrNameString,
    PdrHeader,
    RawPdr,
    SensorAuxiliaryNamesEntry,
    SensorAuxiliaryNamesPdr,
    StateEffecterPdr,
    decode_pdr,
    encode_pdr,
    pdr_from_dict,
    pdr_to_dict,
)
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import GetSensorReadingDataSizeEnum

_DEFAULT_ENTITY_TYPE = 135
_DEFAULT_ENTITY_INSTANCE = 0
_DEFAULT_SENSOR_INIT = 0
_DEFAULT_AUXILIARY_NAMES_PDR = 1
_DEFAULT_SENSOR_STATE_TRANSITION_INTERVAL = 0.5
_DEFAULT_SENSOR_UPDATE_INTERVAL = 1.0
_DEFAULT_THRESHOLD_VOLATILITY = 31
_DEFAULT_NUMERIC_RANGE_FIELD_SUPPORT = 8
_DEFAULT_NUMERIC_SUPPORTED_THRESHOLDS = None
_DEFAULT_NUMERIC_DATA_SIZE = GetSensorReadingDataSizeEnum.UINT32
_DEFAULT_NUMERIC_RANGE_FORMAT = None
_DEFAULT_LANGUAGE_TAG = "en"

_T = TypeVar("_T", bound="_Cloneable")


class _Cloneable:
    def clone(self: _T, **overrides: Any) -> _T:
        item = copy.deepcopy(self)
        for name, value in overrides.items():
            if not hasattr(item, name):
                msg = f"Unknown {type(self).__name__} field: {name}"
                raise TypeError(msg)
            setattr(item, name, value)
        if "name" in overrides and hasattr(item, "auxiliary_name_bytes") and "auxiliary_name_bytes" not in overrides:
            setattr(item, "auxiliary_name_bytes", None)
        return item


@dataclass
class NumericSensor(_Cloneable):
    name: str
    sensor_id: int
    data_size: GetSensorReadingDataSizeEnum | int = _DEFAULT_NUMERIC_DATA_SIZE
    terminus_handle: int = 0
    entity_type: int = _DEFAULT_ENTITY_TYPE
    entity_instance: int = _DEFAULT_ENTITY_INSTANCE
    container_id: int = 0
    sensor_init: int = _DEFAULT_SENSOR_INIT
    sensor_auxiliary_names_pdr: int = _DEFAULT_AUXILIARY_NAMES_PDR
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
    hysteresis: int | float = 0
    supported_thresholds: int | None = _DEFAULT_NUMERIC_SUPPORTED_THRESHOLDS
    threshold_and_hysteresis_volatility: int = _DEFAULT_THRESHOLD_VOLATILITY
    state_transition_interval: float = _DEFAULT_SENSOR_STATE_TRANSITION_INTERVAL
    update_interval: float = _DEFAULT_SENSOR_UPDATE_INTERVAL
    max_readable: int | float | None = None
    min_readable: int | float | None = None
    range_field_format: GetSensorReadingDataSizeEnum | int | None = _DEFAULT_NUMERIC_RANGE_FORMAT
    range_field_support: int = _DEFAULT_NUMERIC_RANGE_FIELD_SUPPORT
    nominal_value: int | float = 0
    normal_max: int | float = 0
    normal_min: int | float = 0
    warning_high: int | float | None = None
    warning_low: int | float | None = None
    critical_high: int | float | None = None
    critical_low: int | float | None = None
    fatal_high: int | float = 0
    fatal_low: int | float = 0
    emit_auxiliary_names: bool = True
    auxiliary_language_tag: str = _DEFAULT_LANGUAGE_TAG
    auxiliary_language_tag_bytes: bytes | None = None
    auxiliary_name_bytes: bytes | None = None
    auxiliary_entries: list[SensorAuxiliaryNamesEntry] | None = None
    auxiliary_trailing_data: bytes = b""

    def __post_init__(self) -> None:
        self.sensor_id = int(self.sensor_id)
        self.data_size = GetSensorReadingDataSizeEnum(self.data_size)
        if self.range_field_format is None:
            self.range_field_format = self.data_size
        elif int(self.range_field_format) in {0, 1, 2, 3, 4, 5}:
            self.range_field_format = GetSensorReadingDataSizeEnum(self.range_field_format)
        self.auxiliary_trailing_data = bytes(self.auxiliary_trailing_data)

    def pdr(self, record_handle: int) -> NumericSensorPdr:
        record = NumericSensorPdr(
            record_handle=record_handle,
            sensor_id=self.sensor_id,
            data_size=self.data_size,
            terminus_handle=self.terminus_handle,
            entity_type=self.entity_type,
            entity_instance=self.entity_instance,
            container_id=self.container_id,
            sensor_init=self.sensor_init,
            sensor_auxiliary_names_pdr=self.sensor_auxiliary_names_pdr,
            base_unit=self.base_unit,
            unit_modifier=self.unit_modifier,
            rate_unit=self.rate_unit,
            base_oem_unit_handle=self.base_oem_unit_handle,
            aux_unit=self.aux_unit,
            aux_unit_modifier=self.aux_unit_modifier,
            aux_rate_unit=self.aux_rate_unit,
            rel=self.rel,
            aux_oem_unit_handle=self.aux_oem_unit_handle,
            is_linear=self.is_linear,
            resolution=self.resolution,
            offset=self.offset,
            accuracy=self.accuracy,
            plus_tolerance=self.plus_tolerance,
            minus_tolerance=self.minus_tolerance,
            hysteresis=self.hysteresis,
            supported_thresholds=self.supported_thresholds or 0,
            threshold_and_hysteresis_volatility=self.threshold_and_hysteresis_volatility,
            state_transition_interval=self.state_transition_interval,
            update_interval=self.update_interval,
            max_readable=self.max_readable,
            min_readable=self.min_readable,
            range_field_format=self.range_field_format,
            range_field_support=self.range_field_support,
            nominal_value=self.nominal_value,
            normal_max=self.normal_max,
            normal_min=self.normal_min,
            warning_high=self.warning_high,
            warning_low=self.warning_low,
            critical_high=self.critical_high,
            critical_low=self.critical_low,
            fatal_high=self.fatal_high,
            fatal_low=self.fatal_low,
        )
        if self.supported_thresholds is not None:
            record.supported_thresholds = int(self.supported_thresholds)
        return record

    def auxiliary_pdr(self, record_handle: int) -> SensorAuxiliaryNamesPdr:
        entries = _sensor_auxiliary_entries(
            self.name,
            self.auxiliary_entries,
            self.auxiliary_language_tag,
            self.auxiliary_language_tag_bytes,
            self.auxiliary_name_bytes,
        )
        return SensorAuxiliaryNamesPdr(
            record_handle=record_handle,
            pldm_terminus_handle=self.terminus_handle,
            sensor_id=self.sensor_id,
            sensors=entries,
            trailing_data=self.auxiliary_trailing_data,
        )

    def definition(self) -> SensorDefinition:
        return SensorDefinition(
            sensor_id=self.sensor_id,
            data_size=self.data_size,
            entity_type=self.entity_type,
            entity_instance=self.entity_instance,
            container_id=self.container_id,
            base_unit=self.base_unit,
            warning_high=self.warning_high,
            warning_low=self.warning_low,
            critical_high=self.critical_high,
            critical_low=self.critical_low,
        )


@dataclass
class TemperatureSensor(NumericSensor):
    base_unit: int = 2
    data_size: GetSensorReadingDataSizeEnum | int = GetSensorReadingDataSizeEnum.SINT32
    unit_modifier: int = 0


@dataclass
class PowerSensor(NumericSensor):
    base_unit: int = 7
    data_size: GetSensorReadingDataSizeEnum | int = GetSensorReadingDataSizeEnum.UINT32
    unit_modifier: int = 0


@dataclass
class VoltageSensor(NumericSensor):
    base_unit: int = 5
    data_size: GetSensorReadingDataSizeEnum | int = GetSensorReadingDataSizeEnum.UINT32
    unit_modifier: int = -3


@dataclass
class CurrentSensor(NumericSensor):
    base_unit: int = 6
    data_size: GetSensorReadingDataSizeEnum | int = GetSensorReadingDataSizeEnum.SINT32
    unit_modifier: int = -3


@dataclass
class CounterSensor(NumericSensor):
    base_unit: int = 20
    data_size: GetSensorReadingDataSizeEnum | int = GetSensorReadingDataSizeEnum.UINT32
    unit_modifier: int = 0


@dataclass
class StateSensor(_Cloneable):
    name: str
    sensor_id: int
    possible_states: dict[int, list[int]] = field(default_factory=lambda: {244: [0, 1]})
    possible_state_sizes: dict[int, int] = field(default_factory=dict)
    terminus_handle: int = 0
    entity_type: int = _DEFAULT_ENTITY_TYPE
    entity_instance: int = _DEFAULT_ENTITY_INSTANCE
    container_id: int = 0
    sensor_init: int = _DEFAULT_SENSOR_INIT
    sensor_auxiliary_names_pdr: int = _DEFAULT_AUXILIARY_NAMES_PDR
    trailing_data: bytes = b""
    emit_auxiliary_names: bool = True
    auxiliary_language_tag: str = _DEFAULT_LANGUAGE_TAG
    auxiliary_language_tag_bytes: bytes | None = None
    auxiliary_name_bytes: bytes | None = None
    auxiliary_entries: list[SensorAuxiliaryNamesEntry] | None = None
    auxiliary_trailing_data: bytes = b""

    def __post_init__(self) -> None:
        self.sensor_id = int(self.sensor_id)
        self.possible_states = {int(key): [int(value) for value in values] for key, values in self.possible_states.items()}
        self.possible_state_sizes = {int(key): int(value) for key, value in self.possible_state_sizes.items()}
        self.trailing_data = bytes(self.trailing_data)
        self.auxiliary_trailing_data = bytes(self.auxiliary_trailing_data)

    def pdr(self, record_handle: int) -> Any:
        if self.possible_state_sizes:
            return pdr_from_dict(
                {
                    "pdr_type": PDR_TYPE_STATE_SENSOR,
                    "record_handle": record_handle,
                    "terminus_handle": self.terminus_handle,
                    "sensor_id": self.sensor_id,
                    "entity_type": self.entity_type,
                    "entity_instance": self.entity_instance,
                    "container_id": self.container_id,
                    "sensor_init": self.sensor_init,
                    "sensor_auxiliary_names_pdr": self.sensor_auxiliary_names_pdr,
                    "possible_states": self.possible_states,
                    "possible_state_sizes": self.possible_state_sizes,
                    "trailing_data": self.trailing_data.hex(),
                }
            )
        return StateSensorPdr(
            record_handle=record_handle,
            sensor_id=self.sensor_id,
            possible_states=self.possible_states,
            terminus_handle=self.terminus_handle,
            entity_type=self.entity_type,
            entity_instance=self.entity_instance,
            container_id=self.container_id,
            sensor_init=self.sensor_init,
            sensor_auxiliary_names_pdr=self.sensor_auxiliary_names_pdr,
            trailing_data=self.trailing_data,
        )

    def auxiliary_pdr(self, record_handle: int) -> SensorAuxiliaryNamesPdr:
        entries = _sensor_auxiliary_entries(
            self.name,
            self.auxiliary_entries,
            self.auxiliary_language_tag,
            self.auxiliary_language_tag_bytes,
            self.auxiliary_name_bytes,
        )
        return SensorAuxiliaryNamesPdr(
            record_handle=record_handle,
            pldm_terminus_handle=self.terminus_handle,
            sensor_id=self.sensor_id,
            sensors=entries,
            trailing_data=self.auxiliary_trailing_data,
        )

    def definition(self) -> SensorDefinition:
        return SensorDefinition(
            sensor_id=self.sensor_id,
            entity_type=self.entity_type,
            entity_instance=self.entity_instance,
            container_id=self.container_id,
            state_sensor={"possible_states": self.possible_states},
        )


@dataclass
class NumericEffecter(_Cloneable):
    name: str
    effecter_id: int
    data_size: GetSensorReadingDataSizeEnum | int = _DEFAULT_NUMERIC_DATA_SIZE
    terminus_handle: int = 0
    entity_type: int = _DEFAULT_ENTITY_TYPE
    entity_instance: int = _DEFAULT_ENTITY_INSTANCE
    container_id: int = 0
    effecter_semantic_id: int = 0
    effecter_init: int = 0
    effecter_auxiliary_names_pdr: int = _DEFAULT_AUXILIARY_NAMES_PDR
    base_unit: int = 0
    unit_modifier: int = 0
    rate_unit: int = 0
    base_oem_unit_handle: int = 0
    aux_unit: int = 0
    aux_unit_modifier: int = 0
    aux_rate_unit: int = 0
    aux_oem_unit_handle: int = 0
    is_linear: int = 1
    resolution: float = 1.0
    offset: float = 0.0
    accuracy: int = 0
    plus_tolerance: int = 0
    minus_tolerance: int = 0
    state_transition_interval: float = 0.0
    transition_interval: float = 0.0
    max_settable: int | float = 0
    min_settable: int | float = 0
    range_field_format: GetSensorReadingDataSizeEnum | int | None = _DEFAULT_NUMERIC_RANGE_FORMAT
    range_field_support: int = 0
    nominal_value: int | float = 0
    normal_max: int | float = 0
    normal_min: int | float = 0
    rated_max: int | float = 0
    rated_min: int | float = 0
    emit_auxiliary_names: bool = True
    auxiliary_language_tag: str = _DEFAULT_LANGUAGE_TAG
    auxiliary_language_tag_bytes: bytes | None = None
    auxiliary_name_bytes: bytes | None = None
    auxiliary_entries: list[EffecterAuxiliaryNamesEntry] | None = None
    auxiliary_trailing_data: bytes = b""

    def __post_init__(self) -> None:
        self.effecter_id = int(self.effecter_id)
        self.data_size = GetSensorReadingDataSizeEnum(self.data_size)
        if self.range_field_format is not None and int(self.range_field_format) in {0, 1, 2, 3, 4, 5}:
            self.range_field_format = GetSensorReadingDataSizeEnum(self.range_field_format)
        self.auxiliary_trailing_data = bytes(self.auxiliary_trailing_data)

    def pdr(self, record_handle: int) -> NumericEffecterPdr:
        return NumericEffecterPdr(
            record_handle=record_handle,
            effecter_id=self.effecter_id,
            effecter_data_size=self.data_size,
            terminus_handle=self.terminus_handle,
            entity_type=self.entity_type,
            entity_instance=self.entity_instance,
            container_id=self.container_id,
            effecter_semantic_id=self.effecter_semantic_id,
            effecter_init=self.effecter_init,
            effecter_auxiliary_names_pdr=self.effecter_auxiliary_names_pdr,
            base_unit=self.base_unit,
            unit_modifier=self.unit_modifier,
            rate_unit=self.rate_unit,
            base_oem_unit_handle=self.base_oem_unit_handle,
            aux_unit=self.aux_unit,
            aux_unit_modifier=self.aux_unit_modifier,
            aux_rate_unit=self.aux_rate_unit,
            aux_oem_unit_handle=self.aux_oem_unit_handle,
            is_linear=self.is_linear,
            resolution=self.resolution,
            offset=self.offset,
            accuracy=self.accuracy,
            plus_tolerance=self.plus_tolerance,
            minus_tolerance=self.minus_tolerance,
            state_transition_interval=self.state_transition_interval,
            transition_interval=self.transition_interval,
            max_settable=self.max_settable,
            min_settable=self.min_settable,
            range_field_format=self.range_field_format,
            range_field_support=self.range_field_support,
            nominal_value=self.nominal_value,
            normal_max=self.normal_max,
            normal_min=self.normal_min,
            rated_max=self.rated_max,
            rated_min=self.rated_min,
        )

    def auxiliary_pdr(self, record_handle: int) -> EffecterAuxiliaryNamesPdr:
        entries = _effecter_auxiliary_entries(
            self.name,
            self.auxiliary_entries,
            self.auxiliary_language_tag,
            self.auxiliary_language_tag_bytes,
            self.auxiliary_name_bytes,
        )
        return EffecterAuxiliaryNamesPdr(
            record_handle=record_handle,
            pldm_terminus_handle=self.terminus_handle,
            effecter_id=self.effecter_id,
            effecters=entries,
            trailing_data=self.auxiliary_trailing_data,
        )

    def definition(self) -> EffecterDefinition:
        return EffecterDefinition(
            effecter_id=self.effecter_id,
            data_size=self.data_size,
            entity_type=self.entity_type,
            entity_instance=self.entity_instance,
            container_id=self.container_id,
            base_unit=self.base_unit,
            min_settable=self.min_settable,
            max_settable=self.max_settable,
        )


@dataclass
class StateEffecter(_Cloneable):
    name: str
    effecter_id: int
    possible_states: dict[int, list[int]] = field(default_factory=lambda: {0: [1]})
    terminus_handle: int = 0
    entity_type: int = _DEFAULT_ENTITY_TYPE
    entity_instance: int = _DEFAULT_ENTITY_INSTANCE
    container_id: int = 0
    effecter_semantic_id: int = 0
    effecter_init: int = 0
    effecter_description_pdr: int = _DEFAULT_AUXILIARY_NAMES_PDR
    possible_state_sizes: dict[int, int] = field(default_factory=dict)
    trailing_data: bytes = b""
    emit_auxiliary_names: bool = True
    auxiliary_language_tag: str = _DEFAULT_LANGUAGE_TAG
    auxiliary_language_tag_bytes: bytes | None = None
    auxiliary_name_bytes: bytes | None = None
    auxiliary_entries: list[EffecterAuxiliaryNamesEntry] | None = None
    auxiliary_trailing_data: bytes = b""

    def __post_init__(self) -> None:
        self.effecter_id = int(self.effecter_id)
        self.possible_states = {int(key): [int(value) for value in values] for key, values in self.possible_states.items()}
        self.possible_state_sizes = {int(key): int(value) for key, value in self.possible_state_sizes.items()}
        self.trailing_data = bytes(self.trailing_data)
        self.auxiliary_trailing_data = bytes(self.auxiliary_trailing_data)

    def pdr(self, record_handle: int) -> StateEffecterPdr:
        return StateEffecterPdr(
            record_handle=record_handle,
            effecter_id=self.effecter_id,
            possible_states=self.possible_states,
            terminus_handle=self.terminus_handle,
            entity_type=self.entity_type,
            entity_instance=self.entity_instance,
            container_id=self.container_id,
            effecter_semantic_id=self.effecter_semantic_id,
            effecter_init=self.effecter_init,
            effecter_description_pdr=self.effecter_description_pdr,
            possible_state_sizes=self.possible_state_sizes,
            trailing_data=self.trailing_data,
        )

    def auxiliary_pdr(self, record_handle: int) -> EffecterAuxiliaryNamesPdr:
        entries = _effecter_auxiliary_entries(
            self.name,
            self.auxiliary_entries,
            self.auxiliary_language_tag,
            self.auxiliary_language_tag_bytes,
            self.auxiliary_name_bytes,
        )
        return EffecterAuxiliaryNamesPdr(
            record_handle=record_handle,
            pldm_terminus_handle=self.terminus_handle,
            effecter_id=self.effecter_id,
            effecters=entries,
            trailing_data=self.auxiliary_trailing_data,
        )

    def definition(self) -> EffecterDefinition:
        return EffecterDefinition(
            effecter_id=self.effecter_id,
            entity_type=self.entity_type,
            entity_instance=self.entity_instance,
            container_id=self.container_id,
            state_effecter={"possible_states": self.possible_states},
        )


@dataclass
class VerbatimRecord:
    """A PDR record that is passed through without reinterpretation or handle rewriting."""

    record: Any
    reason: str = "verbatim escape hatch"

    def __post_init__(self) -> None:
        if isinstance(self.record, (bytes, bytearray)):
            self.record = bytes(self.record)
        else:
            self.record = copy.deepcopy(self.record)

    @property
    def encoded(self) -> bytes:
        return encode_pdr(self.record)

    @property
    def record_handle(self) -> int | None:
        try:
            return int(decode_pdr(self.encoded).header.record_handle)
        except (AttributeError, ValueError):
            return None

    @property
    def pdr_type(self) -> int | None:
        try:
            return int(decode_pdr(self.encoded).header.pdr_type)
        except (AttributeError, ValueError):
            return None


TerminusItem = NumericSensor | StateSensor | NumericEffecter | StateEffecter | VerbatimRecord


@dataclass
class Terminus:
    eid: int
    tid: int
    items: list[TerminusItem] = field(default_factory=list)
    repository_state: int = 0
    reported_record_count: int | None = None
    reported_repository_size: int | None = None
    reported_largest_record_size: int | None = None
    data_transfer_handle_timeout: int = 0
    verbatim_fallbacks: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.eid = int(self.eid)
        self.tid = int(self.tid)
        self._reindex()

    def add(self, item: TerminusItem | bytes | bytearray) -> TerminusItem:
        if isinstance(item, (bytes, bytearray)):
            item = VerbatimRecord(bytes(item), reason="caller supplied raw PDR bytes")
        elif not isinstance(item, (NumericSensor, StateSensor, NumericEffecter, StateEffecter, VerbatimRecord)):
            item = VerbatimRecord(item, reason="caller supplied decoded PDR record")
        self.items.append(item)
        self._reindex()
        return item

    def add_verbatim(self, record: Any, *, reason: str = "caller supplied verbatim PDR") -> VerbatimRecord:
        item = VerbatimRecord(record, reason=reason)
        self.add(item)
        return item

    def __getitem__(self, key: str | int) -> TerminusItem:
        return self._by_name[key] if isinstance(key, str) else self._by_id[int(key)]

    def build(self) -> PldmSensorProfile:
        records: list[Any] = []
        sensors: dict[int, SensorDefinition] = {}
        effecters: dict[int, EffecterDefinition] = {}
        next_handle = 0
        for item in self.items:
            if isinstance(item, VerbatimRecord):
                records.append(item.record)
                next_handle += 1
                continue
            records.append(item.pdr(next_handle))
            next_handle += 1
            if item.emit_auxiliary_names:
                records.append(item.auxiliary_pdr(next_handle))
                next_handle += 1
            if isinstance(item, (NumericSensor, StateSensor)):
                sensors[item.sensor_id] = item.definition()
            else:
                effecters[item.effecter_id] = item.definition()

        repository = PdrRepository(
            records=records,
            repository_state=self.repository_state,
            reported_record_count=self.reported_record_count,
            reported_repository_size=self.reported_repository_size,
            reported_largest_record_size=self.reported_largest_record_size,
            data_transfer_handle_timeout=self.data_transfer_handle_timeout,
        )
        return PldmSensorProfile(sensors=sensors, effecters=effecters, pdr_repository=repository)

    @classmethod
    def from_artifact(cls, artifact: str | Path | Mapping[str, Any]) -> Terminus:
        data = _artifact_data(artifact)
        repository_info = data.get("repository_info", {})
        terminus = cls(
            eid=int(data.get("eid", 0)),
            tid=int(data.get("tid", 0)),
            repository_state=int(repository_info.get("repository_state", 0)),
            reported_record_count=_optional_int(repository_info.get("record_count")),
            reported_repository_size=_optional_int(repository_info.get("repository_size")),
            reported_largest_record_size=_optional_int(repository_info.get("largest_record_size")),
            data_transfer_handle_timeout=int(repository_info.get("data_transfer_handle_timeout", 0)),
        )
        pdrs = data.get("pdrs", [])
        if not isinstance(pdrs, list):
            msg = "PLDM artifact field 'pdrs' must be a list"
            raise ValueError(msg)

        index = 0
        while index < len(pdrs):
            item = pdrs[index]
            if not isinstance(item, Mapping):
                msg = f"PLDM artifact pdrs[{index}] must be an object"
                raise ValueError(msg)
            next_item = pdrs[index + 1] if index + 1 < len(pdrs) and isinstance(pdrs[index + 1], Mapping) else None
            structured_item = _structured_artifact_record(item)
            structured_next_item = _structured_artifact_record(next_item) if next_item is not None else None
            model_item = _model_item_from_artifact_record(structured_item, structured_next_item)
            uses_auxiliary = _uses_auxiliary_record(structured_item, structured_next_item)
            source_items = [item, next_item] if uses_auxiliary and next_item is not None else [item]
            if model_item is not None and _model_item_matches_artifact(model_item, source_items):
                terminus.add(model_item)
                index += len(source_items)
                continue
            if model_item is None:
                reason = _verbatim_reason(structured_item, structured_next_item)
            else:
                reason = "high-level model would not round-trip byte-for-byte"
            for offset, source_item in enumerate(source_items):
                assert source_item is not None
                record = _artifact_record(source_item)
                terminus.add_verbatim(record, reason=reason)
                terminus.verbatim_fallbacks.append(_fallback_entry(index + offset, source_item, reason))
            index += len(source_items)
        return terminus

    def _reindex(self) -> None:
        self._by_name: dict[str, TerminusItem] = {}
        self._by_id: dict[int, TerminusItem] = {}
        for item in self.items:
            name = getattr(item, "name", None)
            if isinstance(name, str):
                self._by_name[name] = item
            item_id = getattr(item, "sensor_id", getattr(item, "effecter_id", None))
            if item_id is not None:
                self._by_id[int(item_id)] = item


def _artifact_data(artifact: str | Path | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(artifact, Mapping):
        return artifact
    return json.loads(Path(artifact).read_text(encoding="utf-8"))


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _model_item_from_artifact_record(item: Mapping[str, Any], next_item: Mapping[str, Any] | None) -> TerminusItem | None:
    pdr_type = int(item.get("pdr_type", -999))
    if "data" in item:
        return None
    if pdr_type == PDR_TYPE_NUMERIC_SENSOR:
        return _numeric_sensor_from_artifact(item, next_item)
    if pdr_type == PDR_TYPE_STATE_SENSOR:
        return _state_sensor_from_artifact(item, next_item)
    if pdr_type == PDR_TYPE_NUMERIC_EFFECTER:
        return _numeric_effecter_from_artifact(item, next_item)
    if pdr_type == PDR_TYPE_STATE_EFFECTER:
        return _state_effecter_from_artifact(item, next_item)
    return None


def _numeric_sensor_from_artifact(item: Mapping[str, Any], next_item: Mapping[str, Any] | None) -> NumericSensor:
    name, entries, trailing, emit = _sensor_auxiliary_data(item, next_item)
    kwargs = _common_kwargs(NumericSensor, item)
    kwargs.update({"name": name, "auxiliary_entries": entries, "auxiliary_trailing_data": trailing, "emit_auxiliary_names": emit})
    return NumericSensor(**kwargs)


def _state_sensor_from_artifact(item: Mapping[str, Any], next_item: Mapping[str, Any] | None) -> StateSensor:
    name, entries, trailing, emit = _sensor_auxiliary_data(item, next_item)
    kwargs = _common_kwargs(StateSensor, item)
    kwargs["possible_states"] = {int(key): value for key, value in dict(item["possible_states"]).items()}
    kwargs["possible_state_sizes"] = {int(key): value for key, value in dict(item.get("possible_state_sizes", {})).items()}
    kwargs.update({"name": name, "auxiliary_entries": entries, "auxiliary_trailing_data": trailing, "emit_auxiliary_names": emit})
    return StateSensor(**kwargs)


def _numeric_effecter_from_artifact(item: Mapping[str, Any], next_item: Mapping[str, Any] | None) -> NumericEffecter:
    name, entries, trailing, emit = _effecter_auxiliary_data(item, next_item)
    kwargs = _common_kwargs(NumericEffecter, item)
    if "effecter_data_size" in item and "data_size" not in kwargs:
        kwargs["data_size"] = item["effecter_data_size"]
    kwargs.update({"name": name, "auxiliary_entries": entries, "auxiliary_trailing_data": trailing, "emit_auxiliary_names": emit})
    return NumericEffecter(**kwargs)


def _state_effecter_from_artifact(item: Mapping[str, Any], next_item: Mapping[str, Any] | None) -> StateEffecter:
    name, entries, trailing, emit = _effecter_auxiliary_data(item, next_item)
    kwargs = _common_kwargs(StateEffecter, item)
    kwargs["possible_states"] = {int(key): value for key, value in dict(item["possible_states"]).items()}
    kwargs["possible_state_sizes"] = {int(key): value for key, value in dict(item.get("possible_state_sizes", {})).items()}
    kwargs.update({"name": name, "auxiliary_entries": entries, "auxiliary_trailing_data": trailing, "emit_auxiliary_names": emit})
    return StateEffecter(**kwargs)


def _common_kwargs(cls: type[Any], item: Mapping[str, Any]) -> dict[str, Any]:
    ignored = {"pdr_type", "record_handle", "record_change_number", "header_version", "effecter_data_size"}
    names = {item.name for item in fields(cls)} - ignored
    kwargs = {name: _artifact_field_value(name, value) for name, value in item.items() if name in names}
    if "record_change_number" in item and "record_change_number" in names:
        kwargs["record_change_number"] = int(item["record_change_number"])
    return kwargs


def _model_item_matches_artifact(model_item: TerminusItem, source_items: list[Mapping[str, Any] | None]) -> bool:
    if isinstance(model_item, VerbatimRecord):
        return False
    first = source_items[0]
    if first is None:
        return False
    handle = int(first.get("record_handle", 0))
    records = [encode_pdr(model_item.pdr(handle))]
    if model_item.emit_auxiliary_names:
        records.append(encode_pdr(model_item.auxiliary_pdr(handle + 1)))
    source_records = [encode_pdr(_artifact_record(item)) for item in source_items if item is not None]
    return records == source_records


def _structured_artifact_record(item: Mapping[str, Any]) -> Mapping[str, Any]:
    record = _artifact_record(item)
    if isinstance(record, (OpaquePdr, RawPdr)):
        return item
    return pdr_to_dict(record)


def _artifact_record(item: Mapping[str, Any]) -> Any:
    if "data" not in item:
        return pdr_from_dict(dict(item))
    body = bytes.fromhex(str(item.get("data", "")))
    header = PdrHeader(
        record_handle=int(item.get("record_handle", 0)),
        header_version=int(item.get("header_version", 1)),
        pdr_type=int(item["pdr_type"]),
        record_change_number=int(item.get("record_change_number", 0)),
        data_length=int(item.get("data_length", len(body))),
    )
    return decode_pdr(header.to_bytes() + body)


def _artifact_field_value(name: str, value: Any) -> Any:
    if name in {"trailing_data", "auxiliary_trailing_data"} and isinstance(value, str):
        return bytes.fromhex(value)
    return copy.deepcopy(value)


def _sensor_auxiliary_data(
    item: Mapping[str, Any],
    next_item: Mapping[str, Any] | None,
) -> tuple[str, list[SensorAuxiliaryNamesEntry] | None, bytes, bool]:
    if not _uses_auxiliary_record(item, next_item):
        return f"sensor_{int(item['sensor_id']):04x}", None, b"", False
    assert next_item is not None
    aux = pdr_from_dict(dict(next_item))
    if not isinstance(aux, SensorAuxiliaryNamesPdr):
        return f"sensor_{int(item['sensor_id']):04x}", None, b"", False
    return _first_sensor_name(aux), copy.deepcopy(aux.sensors), bytes(aux.trailing_data), True


def _effecter_auxiliary_data(
    item: Mapping[str, Any],
    next_item: Mapping[str, Any] | None,
) -> tuple[str, list[EffecterAuxiliaryNamesEntry] | None, bytes, bool]:
    if not _uses_auxiliary_record(item, next_item):
        return f"effecter_{int(item['effecter_id']):04x}", None, b"", False
    assert next_item is not None
    aux = pdr_from_dict(dict(next_item))
    if not isinstance(aux, EffecterAuxiliaryNamesPdr):
        return f"effecter_{int(item['effecter_id']):04x}", None, b"", False
    return _first_effecter_name(aux), copy.deepcopy(aux.effecters), bytes(aux.trailing_data), True


def _uses_auxiliary_record(item: Mapping[str, Any], next_item: Mapping[str, Any] | None) -> bool:
    if next_item is None or "data" in item or "data" in next_item:
        return False
    pdr_type = int(item.get("pdr_type", -999))
    next_type = int(next_item.get("pdr_type", -999))
    if pdr_type in {PDR_TYPE_NUMERIC_SENSOR, PDR_TYPE_STATE_SENSOR}:
        return next_type == PDR_TYPE_SENSOR_AUXILIARY_NAMES and int(item["sensor_id"]) == int(next_item.get("sensor_id", -1))
    if pdr_type in {PDR_TYPE_NUMERIC_EFFECTER, PDR_TYPE_STATE_EFFECTER}:
        return next_type == PDR_TYPE_EFFECTER_AUXILIARY_NAMES and int(item["effecter_id"]) == int(next_item.get("effecter_id", -1))
    return False


def _sensor_auxiliary_entries(
    name: str,
    entries: list[SensorAuxiliaryNamesEntry] | None,
    language_tag: str,
    language_tag_bytes: bytes | None,
    name_bytes: bytes | None,
) -> list[SensorAuxiliaryNamesEntry]:
    if entries is None:
        return [SensorAuxiliaryNamesEntry([PdrNameString(language_tag, name, language_tag_bytes, name_bytes)])]
    entries = copy.deepcopy(entries)
    _replace_first_name(entries[0].names, name, name_bytes)
    return entries


def _effecter_auxiliary_entries(
    name: str,
    entries: list[EffecterAuxiliaryNamesEntry] | None,
    language_tag: str,
    language_tag_bytes: bytes | None,
    name_bytes: bytes | None,
) -> list[EffecterAuxiliaryNamesEntry]:
    if entries is None:
        return [EffecterAuxiliaryNamesEntry([PdrNameString(language_tag, name, language_tag_bytes, name_bytes)])]
    entries = copy.deepcopy(entries)
    _replace_first_name(entries[0].names, name, name_bytes)
    return entries


def _replace_first_name(names: list[PdrNameString], name: str, name_bytes: bytes | None) -> None:
    if not names:
        names.append(PdrNameString(_DEFAULT_LANGUAGE_TAG, name, name_bytes=name_bytes))
        return
    old_name = names[0].name
    previous_name_bytes = names[0].name_bytes
    names[0].name = name
    names[0].name_bytes = name_bytes if name_bytes is not None else previous_name_bytes if old_name == name else None


def _first_sensor_name(aux: SensorAuxiliaryNamesPdr) -> str:
    if aux.sensors and aux.sensors[0].names:
        return aux.sensors[0].names[0].name
    return f"sensor_{aux.sensor_id:04x}"


def _first_effecter_name(aux: EffecterAuxiliaryNamesPdr) -> str:
    if aux.effecters and aux.effecters[0].names:
        return aux.effecters[0].names[0].name
    return f"effecter_{aux.effecter_id:04x}"


def _verbatim_reason(item: Mapping[str, Any], next_item: Mapping[str, Any] | None) -> str:
    pdr_type = int(item.get("pdr_type", -999))
    if pdr_type in {PDR_TYPE_NUMERIC_SENSOR, PDR_TYPE_STATE_SENSOR, PDR_TYPE_NUMERIC_EFFECTER, PDR_TYPE_STATE_EFFECTER}:
        if "data" in item:
            return "record is opaque in the artifact"
        if _uses_auxiliary_record(item, next_item) and next_item is not None and "data" in next_item:
            return "paired auxiliary names record is opaque"
    if pdr_type in {PDR_TYPE_SENSOR_AUXILIARY_NAMES, PDR_TYPE_EFFECTER_AUXILIARY_NAMES}:
        return "unpaired auxiliary names record"
    return "PDR type is outside the high-level terminus model"


def _fallback_entry(index: int, item: Mapping[str, Any], reason: str) -> dict[str, Any]:
    return {
        "index": index,
        "record_handle": int(item.get("record_handle", 0)),
        "pdr_type": int(item.get("pdr_type", -999)),
        "reason": reason,
    }


__all__ = [
    "CounterSensor",
    "CurrentSensor",
    "NumericEffecter",
    "NumericSensor",
    "PowerSensor",
    "StateEffecter",
    "StateSensor",
    "TemperatureSensor",
    "Terminus",
    "VerbatimRecord",
    "VoltageSensor",
]
