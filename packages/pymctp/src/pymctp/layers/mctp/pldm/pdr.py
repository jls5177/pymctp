# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""PLDM Platform Descriptor Record codecs."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import IntEnum
import logging
import struct
from typing import Any

from .type_2_platform_monitoring import GetSensorReadingDataSizeEnum

logger = logging.getLogger(__name__)

PDR_HEADER_LEN = 10

PDR_TYPE_TERMINUS_LOCATOR = 1
PDR_TYPE_NUMERIC_SENSOR = 2
PDR_TYPE_STATE_SENSOR = 4
PDR_TYPE_SENSOR_AUXILIARY_NAMES = 6
PDR_TYPE_NUMERIC_EFFECTER = 9
PDR_TYPE_STATE_EFFECTER = 11
PDR_TYPE_EFFECTER_AUXILIARY_NAMES = 13
PDR_TYPE_ENTITY_AUXILIARY_NAMES = 16

_PDR_HEADER = struct.Struct("<IBBHH")
_PDR_HEADER_VERSION = 1
_NUMERIC_SENSOR_FIXED = struct.Struct("<HHHHHBBBbBBBBbBBBBffHBB")
_NUMERIC_EFFECTER_FIXED = struct.Struct("<HHHHHHBBBbBBBbBBBBffHBBff")
_STATE_SENSOR_FIXED = struct.Struct("<HHHHHBBB")
_STATE_EFFECTER_FIXED = struct.Struct("<HHHHHHBBB")
_TERMINUS_LOCATOR_FIXED = struct.Struct("<HBBHBB")
_SENSOR_AUX_NAMES_FIXED = struct.Struct("<HHB")
_EFFECTER_AUX_NAMES_FIXED = struct.Struct("<HHB")
_ENTITY_AUX_NAMES_FIXED = struct.Struct("<HHHBB")


@dataclass
class PdrHeader:
    record_handle: int
    header_version: int
    pdr_type: int
    record_change_number: int
    data_length: int

    def to_bytes(self) -> bytes:
        return _PDR_HEADER.pack(
            self.record_handle & 0xFFFFFFFF,
            self.header_version & 0xFF,
            self.pdr_type & 0xFF,
            self.record_change_number & 0xFFFF,
            self.data_length & 0xFFFF,
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> PdrHeader:
        if len(raw) < PDR_HEADER_LEN:
            msg = f"PDR header requires {PDR_HEADER_LEN} bytes, got {len(raw)}"
            raise ValueError(msg)
        return cls(*_PDR_HEADER.unpack_from(raw))


@dataclass
class OpaquePdr:
    """Any PDR type we do not model structurally: decoded header + raw body."""

    header: PdrHeader
    data: bytes


@dataclass
class RawPdr:
    """A byte sequence too short to contain a common PDR header."""

    data: bytes


@dataclass
class TerminusLocatorPdr:
    record_handle: int
    pldm_terminus_handle: int
    validity: int
    tid: int
    container_id: int
    terminus_locator_type: int
    terminus_locator_value: bytes
    record_change_number: int = 0
    header_version: int = _PDR_HEADER_VERSION

    @property
    def eid(self) -> int | None:
        if self.terminus_locator_type == 0x00 and len(self.terminus_locator_value) == 1:
            return self.terminus_locator_value[0]
        return None

    def to_bytes(self) -> bytes:
        body = _TERMINUS_LOCATOR_FIXED.pack(
            self.pldm_terminus_handle & 0xFFFF,
            self.validity & 0xFF,
            self.tid & 0xFF,
            self.container_id & 0xFFFF,
            self.terminus_locator_type & 0xFF,
            len(self.terminus_locator_value) & 0xFF,
        ) + bytes(self.terminus_locator_value)
        header = PdrHeader(
            self.record_handle,
            self.header_version,
            PDR_TYPE_TERMINUS_LOCATOR,
            self.record_change_number,
            len(body),
        )
        return header.to_bytes() + body


@dataclass
class PdrNameString:
    language_tag: str
    name: str
    language_tag_bytes: bytes | None = None
    name_bytes: bytes | None = None

    def to_bytes(self) -> bytes:
        language_tag = self.language_tag_bytes if self.language_tag_bytes is not None else self.language_tag.encode("ascii")
        name = self.name_bytes if self.name_bytes is not None else self.name.encode("utf-16-be")
        return language_tag + b"\x00" + name + b"\x00\x00"


@dataclass
class SensorAuxiliaryNamesEntry:
    names: list[PdrNameString]

    def to_bytes(self) -> bytes:
        return bytes([len(self.names) & 0xFF]) + b"".join(name.to_bytes() for name in self.names)


@dataclass
class SensorAuxiliaryNamesPdr:
    record_handle: int
    pldm_terminus_handle: int
    sensor_id: int
    sensors: list[SensorAuxiliaryNamesEntry]
    record_change_number: int = 0
    header_version: int = _PDR_HEADER_VERSION
    trailing_data: bytes = b""

    def to_bytes(self) -> bytes:
        body = (
            _SENSOR_AUX_NAMES_FIXED.pack(
                self.pldm_terminus_handle & 0xFFFF,
                self.sensor_id & 0xFFFF,
                len(self.sensors) & 0xFF,
            )
            + b"".join(sensor.to_bytes() for sensor in self.sensors)
            + bytes(self.trailing_data)
        )
        header = PdrHeader(
            self.record_handle,
            self.header_version,
            PDR_TYPE_SENSOR_AUXILIARY_NAMES,
            self.record_change_number,
            len(body),
        )
        return header.to_bytes() + body


@dataclass
class _StateSensorPdrWithSizes:
    record_handle: int
    sensor_id: int
    possible_states: dict[int, list[int]]
    possible_state_sizes: dict[int, int]
    record_change_number: int = 0
    header_version: int = _PDR_HEADER_VERSION
    terminus_handle: int = 0
    entity_type: int = 0
    entity_instance: int = 1
    container_id: int = 0
    sensor_init: int = 0
    sensor_auxiliary_names_pdr: int = 0
    trailing_data: bytes = b""

    def __post_init__(self) -> None:
        self.possible_states = {int(state_set): [int(state) for state in states] for state_set, states in self.possible_states.items()}
        self.possible_state_sizes = {int(state_set): int(size) for state_set, size in self.possible_state_sizes.items()}
        self.trailing_data = bytes(self.trailing_data)

    def to_bytes(self) -> bytes:
        possible = b"".join(
            struct.pack("<HB", state_set, self.possible_state_sizes.get(state_set, len(bitfield))) + bitfield
            for state_set, bitfield in (
                (
                    state_set,
                    _state_bitfield(states, _state_bitfield_size(self.possible_state_sizes.get(state_set))),
                )
                for state_set, states in self.possible_states.items()
            )
        )
        body = (
            _STATE_SENSOR_FIXED.pack(
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
        header = PdrHeader(
            self.record_handle,
            self.header_version,
            PDR_TYPE_STATE_SENSOR,
            self.record_change_number,
            len(body),
        )
        return header.to_bytes() + body


@dataclass
class NumericEffecterPdr:
    record_handle: int
    effecter_id: int
    effecter_data_size: GetSensorReadingDataSizeEnum | int = GetSensorReadingDataSizeEnum.UINT8
    record_change_number: int = 0
    header_version: int = _PDR_HEADER_VERSION
    terminus_handle: int = 0
    entity_type: int = 0
    entity_instance: int = 1
    container_id: int = 0
    effecter_semantic_id: int = 0
    effecter_init: int = 0
    effecter_auxiliary_names_pdr: int = 0
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
    max_settable: float | int = 0
    min_settable: float | int = 0
    range_field_format: GetSensorReadingDataSizeEnum | int | None = None
    range_field_support: int = 0
    nominal_value: float | int = 0
    normal_max: float | int = 0
    normal_min: float | int = 0
    rated_max: float | int = 0
    rated_min: float | int = 0

    def __post_init__(self) -> None:
        self.record_handle = int(self.record_handle)
        self.effecter_id = int(self.effecter_id)
        self.effecter_data_size = _numeric_range_format(self.effecter_data_size)
        if self.range_field_format is None:
            self.range_field_format = self.effecter_data_size
        else:
            self.range_field_format = _numeric_range_format(self.range_field_format)

    @classmethod
    def from_bytes(cls, raw: bytes) -> NumericEffecterPdr:
        header, body = _pdr_header_and_body(raw, PDR_TYPE_NUMERIC_EFFECTER)
        return _decode_numeric_effecter_pdr(header, body)

    def to_bytes(self) -> bytes:
        fixed = _NUMERIC_EFFECTER_FIXED.pack(
            self.terminus_handle & 0xFFFF,
            self.effecter_id & 0xFFFF,
            self.entity_type & 0xFFFF,
            self.entity_instance & 0xFFFF,
            self.container_id & 0xFFFF,
            self.effecter_semantic_id & 0xFFFF,
            self.effecter_init & 0xFF,
            self.effecter_auxiliary_names_pdr & 0xFF,
            self.base_unit & 0xFF,
            _int8(self.unit_modifier),
            self.rate_unit & 0xFF,
            self.base_oem_unit_handle & 0xFF,
            self.aux_unit & 0xFF,
            _int8(self.aux_unit_modifier),
            self.aux_rate_unit & 0xFF,
            self.aux_oem_unit_handle & 0xFF,
            self.is_linear & 0xFF,
            int(self.effecter_data_size),
            float(self.resolution),
            float(self.offset),
            self.accuracy & 0xFFFF,
            self.plus_tolerance & 0xFF,
            self.minus_tolerance & 0xFF,
            float(self.state_transition_interval),
            float(self.transition_interval),
        )
        body = (
            fixed
            + _encode_sensor_value(self.effecter_data_size, self.max_settable)
            + _encode_sensor_value(self.effecter_data_size, self.min_settable)
            + bytes([int(self.range_field_format or self.effecter_data_size), self.range_field_support & 0xFF])
            + b"".join(
                _encode_sensor_value(self.range_field_format or self.effecter_data_size, value)
                for value in (self.nominal_value, self.normal_max, self.normal_min, self.rated_max, self.rated_min)
            )
        )
        header = PdrHeader(
            self.record_handle,
            self.header_version,
            PDR_TYPE_NUMERIC_EFFECTER,
            self.record_change_number,
            len(body),
        )
        return header.to_bytes() + body


@dataclass
class StateEffecterPdr:
    record_handle: int
    effecter_id: int
    possible_states: dict[int, list[int]] = field(default_factory=lambda: {0: [1]})
    record_change_number: int = 0
    header_version: int = _PDR_HEADER_VERSION
    terminus_handle: int = 0
    entity_type: int = 0
    entity_instance: int = 1
    container_id: int = 0
    effecter_semantic_id: int = 0
    effecter_init: int = 0
    effecter_description_pdr: int = 0
    possible_state_sizes: dict[int, int] = field(default_factory=dict)
    trailing_data: bytes = b""

    def __post_init__(self) -> None:
        self.record_handle = int(self.record_handle)
        self.effecter_id = int(self.effecter_id)
        self.possible_states = {int(state_set): [int(state) for state in states] for state_set, states in self.possible_states.items()}
        self.possible_state_sizes = {int(state_set): int(size) for state_set, size in self.possible_state_sizes.items()}
        self.trailing_data = bytes(self.trailing_data)

    @classmethod
    def from_bytes(cls, raw: bytes) -> StateEffecterPdr:
        header, body = _pdr_header_and_body(raw, PDR_TYPE_STATE_EFFECTER)
        return _decode_state_effecter_pdr(header, body)

    def to_bytes(self) -> bytes:
        possible = b"".join(
            struct.pack("<HB", state_set, len(bitfield)) + bitfield
            for state_set, bitfield in (
                (state_set, _state_bitfield(states, self.possible_state_sizes.get(state_set)))
                for state_set, states in self.possible_states.items()
            )
        )
        body = (
            _STATE_EFFECTER_FIXED.pack(
                self.terminus_handle & 0xFFFF,
                self.effecter_id & 0xFFFF,
                self.entity_type & 0xFFFF,
                self.entity_instance & 0xFFFF,
                self.container_id & 0xFFFF,
                self.effecter_semantic_id & 0xFFFF,
                self.effecter_init & 0xFF,
                self.effecter_description_pdr & 0xFF,
                len(self.possible_states) & 0xFF,
            )
            + possible
            + self.trailing_data
        )
        header = PdrHeader(
            self.record_handle,
            self.header_version,
            PDR_TYPE_STATE_EFFECTER,
            self.record_change_number,
            len(body),
        )
        return header.to_bytes() + body


@dataclass
class EffecterAuxiliaryNamesEntry:
    names: list[PdrNameString]

    def to_bytes(self) -> bytes:
        return bytes([len(self.names) & 0xFF]) + b"".join(name.to_bytes() for name in self.names)


@dataclass
class EffecterAuxiliaryNamesPdr:
    record_handle: int
    pldm_terminus_handle: int
    effecter_id: int
    effecters: list[EffecterAuxiliaryNamesEntry]
    record_change_number: int = 0
    header_version: int = _PDR_HEADER_VERSION
    trailing_data: bytes = b""

    @classmethod
    def from_bytes(cls, raw: bytes) -> EffecterAuxiliaryNamesPdr:
        header, body = _pdr_header_and_body(raw, PDR_TYPE_EFFECTER_AUXILIARY_NAMES)
        return _decode_effecter_auxiliary_names_pdr(header, body)

    def to_bytes(self) -> bytes:
        body = (
            _EFFECTER_AUX_NAMES_FIXED.pack(
                self.pldm_terminus_handle & 0xFFFF,
                self.effecter_id & 0xFFFF,
                len(self.effecters) & 0xFF,
            )
            + b"".join(effecter.to_bytes() for effecter in self.effecters)
            + bytes(self.trailing_data)
        )
        header = PdrHeader(
            self.record_handle,
            self.header_version,
            PDR_TYPE_EFFECTER_AUXILIARY_NAMES,
            self.record_change_number,
            len(body),
        )
        return header.to_bytes() + body


@dataclass
class EntityAuxiliaryNamesPdr:
    record_handle: int
    entity_type: int
    entity_instance_number: int
    entity_container_id: int
    shared_name_count: int
    names: list[PdrNameString]
    record_change_number: int = 0
    header_version: int = _PDR_HEADER_VERSION
    trailing_data: bytes = b""

    def to_bytes(self) -> bytes:
        body = (
            _ENTITY_AUX_NAMES_FIXED.pack(
                self.entity_type & 0xFFFF,
                self.entity_instance_number & 0xFFFF,
                self.entity_container_id & 0xFFFF,
                self.shared_name_count & 0xFF,
                len(self.names) & 0xFF,
            )
            + b"".join(name.to_bytes() for name in self.names)
            + bytes(self.trailing_data)
        )
        header = PdrHeader(
            self.record_handle,
            self.header_version,
            PDR_TYPE_ENTITY_AUXILIARY_NAMES,
            self.record_change_number,
            len(body),
        )
        return header.to_bytes() + body


def decode_pdr(raw: bytes) -> Any:
    """Decode one PDR record, falling back to opaque on any lossy structured decode."""
    raw = bytes(raw)
    if len(raw) < PDR_HEADER_LEN:
        logger.warning("PDR record is shorter than the common header; keeping %d raw bytes", len(raw))
        return RawPdr(raw)

    header = PdrHeader.from_bytes(raw)
    opaque = OpaquePdr(header, raw[PDR_HEADER_LEN:])
    if len(opaque.data) != header.data_length:
        if header.pdr_type in _MODELLED_DECODERS:
            logger.warning(
                "PDR type %d length mismatch: header says %d body bytes, got %d; keeping opaque",
                header.pdr_type,
                header.data_length,
                len(opaque.data),
            )
        return opaque

    decoder = _MODELLED_DECODERS.get(header.pdr_type)
    if decoder is None:
        return opaque

    try:
        record = decoder(header, opaque.data)
    except (UnicodeDecodeError, ValueError, struct.error) as exc:
        logger.warning("Failed to decode PDR type %d; keeping opaque: %s", header.pdr_type, exc)
        return opaque

    encoded = encode_pdr(record)
    if encoded != raw:
        logger.warning("Structured PDR type %d did not round-trip byte-for-byte; keeping opaque", header.pdr_type)
        return opaque
    return record


def encode_pdr(record: Any) -> bytes:
    """Encode any record produced by decode_pdr back to wire bytes."""
    if isinstance(record, RawPdr):
        return bytes(record.data)
    if isinstance(record, OpaquePdr):
        return record.header.to_bytes() + bytes(record.data)
    if isinstance(record, (bytes, bytearray)):
        return bytes(record)
    to_bytes = getattr(record, "to_bytes", None)
    if callable(to_bytes):
        return bytes(to_bytes())
    msg = f"Unsupported PDR record type: {type(record).__name__}"
    raise TypeError(msg)


def pdr_to_dict(record: Any) -> dict[str, Any]:
    """Return a JSON-safe dictionary representation of a PDR record."""
    if isinstance(record, RawPdr):
        return {"pdr_type": -1, "record_handle": 0, "data": record.data.hex(), "truncated_header": True}
    if isinstance(record, OpaquePdr):
        return {
            "pdr_type": record.header.pdr_type,
            "record_handle": record.header.record_handle,
            "header_version": record.header.header_version,
            "record_change_number": record.header.record_change_number,
            "data_length": record.header.data_length,
            "data": record.data.hex(),
        }
    if isinstance(record, TerminusLocatorPdr):
        data = _dataclass_to_dict(record)
        data["pdr_type"] = PDR_TYPE_TERMINUS_LOCATOR
        data["terminus_locator_value"] = record.terminus_locator_value.hex()
        data["eid"] = record.eid
        return data
    if isinstance(record, SensorAuxiliaryNamesPdr):
        return {
            "pdr_type": PDR_TYPE_SENSOR_AUXILIARY_NAMES,
            "record_handle": record.record_handle,
            "header_version": record.header_version,
            "record_change_number": record.record_change_number,
            "pldm_terminus_handle": record.pldm_terminus_handle,
            "sensor_id": record.sensor_id,
            "sensor_count": len(record.sensors),
            "sensors": [_sensor_aux_entry_to_dict(sensor) for sensor in record.sensors],
            "trailing_data": record.trailing_data.hex(),
        }
    if isinstance(record, EntityAuxiliaryNamesPdr):
        return {
            "pdr_type": PDR_TYPE_ENTITY_AUXILIARY_NAMES,
            "record_handle": record.record_handle,
            "header_version": record.header_version,
            "record_change_number": record.record_change_number,
            "entity_type": record.entity_type,
            "entity_instance_number": record.entity_instance_number,
            "entity_container_id": record.entity_container_id,
            "shared_name_count": record.shared_name_count,
            "name_string_count": len(record.names),
            "names": [_name_to_dict(name) for name in record.names],
            "trailing_data": record.trailing_data.hex(),
        }
    if isinstance(record, NumericEffecterPdr):
        data = _dataclass_to_dict(record)
        data["pdr_type"] = PDR_TYPE_NUMERIC_EFFECTER
        return data
    if isinstance(record, StateEffecterPdr):
        data = _dataclass_to_dict(record)
        data["pdr_type"] = PDR_TYPE_STATE_EFFECTER
        return data
    if isinstance(record, EffecterAuxiliaryNamesPdr):
        return {
            "pdr_type": PDR_TYPE_EFFECTER_AUXILIARY_NAMES,
            "record_handle": record.record_handle,
            "header_version": record.header_version,
            "record_change_number": record.record_change_number,
            "pldm_terminus_handle": record.pldm_terminus_handle,
            "effecter_id": record.effecter_id,
            "effecter_count": len(record.effecters),
            "effecters": [_effecter_aux_entry_to_dict(effecter) for effecter in record.effecters],
            "trailing_data": record.trailing_data.hex(),
        }
    if isinstance(record, _StateSensorPdrWithSizes):
        data = _dataclass_to_dict(record)
        data["pdr_type"] = PDR_TYPE_STATE_SENSOR
        return data

    numeric_cls, state_cls = _sensor_pdr_classes()
    if isinstance(record, numeric_cls):
        data = _dataclass_to_dict(record)
        data["pdr_type"] = PDR_TYPE_NUMERIC_SENSOR
        return data
    if isinstance(record, state_cls):
        data = _dataclass_to_dict(record)
        data["pdr_type"] = PDR_TYPE_STATE_SENSOR
        return data

    msg = f"Unsupported PDR record type: {type(record).__name__}"
    raise TypeError(msg)


def pdr_from_dict(data: dict[str, Any]) -> Any:
    """Build a PDR record from a dictionary returned by pdr_to_dict."""
    pdr_type = int(data["pdr_type"])
    if pdr_type == -1:
        return RawPdr(bytes.fromhex(data.get("data", "")))
    if "data" in data:
        return _opaque_from_dict(data)
    if pdr_type == PDR_TYPE_TERMINUS_LOCATOR:
        return TerminusLocatorPdr(
            record_handle=int(data["record_handle"]),
            header_version=int(data.get("header_version", _PDR_HEADER_VERSION)),
            record_change_number=int(data.get("record_change_number", 0)),
            pldm_terminus_handle=int(data["pldm_terminus_handle"]),
            validity=int(data["validity"]),
            tid=int(data["tid"]),
            container_id=int(data["container_id"]),
            terminus_locator_type=int(data["terminus_locator_type"]),
            terminus_locator_value=bytes.fromhex(data["terminus_locator_value"]),
        )
    if pdr_type == PDR_TYPE_NUMERIC_SENSOR:
        numeric_cls, _ = _sensor_pdr_classes()
        record = numeric_cls(**_constructor_kwargs(numeric_cls, data))
        if "supported_thresholds" in data:
            record.supported_thresholds = int(data["supported_thresholds"])
        return record
    if pdr_type == PDR_TYPE_STATE_SENSOR:
        if "possible_state_sizes" in data:
            kwargs = _constructor_kwargs(_StateSensorPdrWithSizes, data)
            kwargs["possible_state_sizes"] = {
                int(key): value for key, value in kwargs.get("possible_state_sizes", {}).items()
            }
            state_cls = _StateSensorPdrWithSizes
        else:
            _, state_cls = _sensor_pdr_classes()
            kwargs = _constructor_kwargs(state_cls, data)
        kwargs["possible_states"] = {int(key): value for key, value in kwargs["possible_states"].items()}
        if isinstance(kwargs.get("trailing_data"), str):
            kwargs["trailing_data"] = bytes.fromhex(kwargs["trailing_data"])
        return state_cls(**kwargs)
    if pdr_type == PDR_TYPE_SENSOR_AUXILIARY_NAMES:
        return SensorAuxiliaryNamesPdr(
            record_handle=int(data["record_handle"]),
            header_version=int(data.get("header_version", _PDR_HEADER_VERSION)),
            record_change_number=int(data.get("record_change_number", 0)),
            pldm_terminus_handle=int(data["pldm_terminus_handle"]),
            sensor_id=int(data["sensor_id"]),
            sensors=[_sensor_aux_entry_from_dict(sensor) for sensor in data["sensors"]],
            trailing_data=bytes.fromhex(data.get("trailing_data", "")),
        )
    if pdr_type == PDR_TYPE_NUMERIC_EFFECTER:
        return NumericEffecterPdr(**_constructor_kwargs(NumericEffecterPdr, data))
    if pdr_type == PDR_TYPE_STATE_EFFECTER:
        kwargs = _constructor_kwargs(StateEffecterPdr, data)
        kwargs["possible_states"] = {int(key): value for key, value in kwargs["possible_states"].items()}
        kwargs["possible_state_sizes"] = {int(key): value for key, value in kwargs.get("possible_state_sizes", {}).items()}
        if isinstance(kwargs.get("trailing_data"), str):
            kwargs["trailing_data"] = bytes.fromhex(kwargs["trailing_data"])
        return StateEffecterPdr(**kwargs)
    if pdr_type == PDR_TYPE_EFFECTER_AUXILIARY_NAMES:
        return EffecterAuxiliaryNamesPdr(
            record_handle=int(data["record_handle"]),
            header_version=int(data.get("header_version", _PDR_HEADER_VERSION)),
            record_change_number=int(data.get("record_change_number", 0)),
            pldm_terminus_handle=int(data["pldm_terminus_handle"]),
            effecter_id=int(data["effecter_id"]),
            effecters=[_effecter_aux_entry_from_dict(effecter) for effecter in data["effecters"]],
            trailing_data=bytes.fromhex(data.get("trailing_data", "")),
        )
    if pdr_type == PDR_TYPE_ENTITY_AUXILIARY_NAMES:
        return EntityAuxiliaryNamesPdr(
            record_handle=int(data["record_handle"]),
            header_version=int(data.get("header_version", _PDR_HEADER_VERSION)),
            record_change_number=int(data.get("record_change_number", 0)),
            entity_type=int(data["entity_type"]),
            entity_instance_number=int(data["entity_instance_number"]),
            entity_container_id=int(data["entity_container_id"]),
            shared_name_count=int(data["shared_name_count"]),
            names=[_name_from_dict(name) for name in data["names"]],
            trailing_data=bytes.fromhex(data.get("trailing_data", "")),
        )
    return _opaque_from_dict(data)


def split_pdr_records(raw: bytes) -> list[bytes]:
    """Split a concatenated PDR blob into records, ignoring a trailing partial record."""
    records: list[bytes] = []
    offset = 0
    raw = bytes(raw)
    while offset + PDR_HEADER_LEN <= len(raw):
        header = PdrHeader.from_bytes(raw[offset : offset + PDR_HEADER_LEN])
        end = offset + PDR_HEADER_LEN + header.data_length
        if end > len(raw):
            break
        records.append(raw[offset:end])
        offset = end
    return records


def _decode_terminus_locator_pdr(header: PdrHeader, body: bytes) -> TerminusLocatorPdr:
    if len(body) < _TERMINUS_LOCATOR_FIXED.size:
        msg = "Terminus Locator PDR body is truncated"
        raise ValueError(msg)
    terminus_handle, validity, tid, container_id, locator_type, locator_value_size = _TERMINUS_LOCATOR_FIXED.unpack_from(body)
    locator_value = body[_TERMINUS_LOCATOR_FIXED.size :]
    if len(locator_value) != locator_value_size:
        msg = "Terminus Locator PDR locator value size does not match the body length"
        raise ValueError(msg)
    return TerminusLocatorPdr(
        record_handle=header.record_handle,
        header_version=header.header_version,
        record_change_number=header.record_change_number,
        pldm_terminus_handle=terminus_handle,
        validity=validity,
        tid=tid,
        container_id=container_id,
        terminus_locator_type=locator_type,
        terminus_locator_value=locator_value,
    )


def _decode_numeric_sensor_pdr(header: PdrHeader, body: bytes) -> Any:
    if len(body) < _NUMERIC_SENSOR_FIXED.size:
        msg = "Numeric Sensor PDR body is truncated"
        raise ValueError(msg)
    (
        terminus_handle,
        sensor_id,
        entity_type,
        entity_instance,
        container_id,
        sensor_init,
        sensor_auxiliary_names_pdr,
        base_unit,
        unit_modifier,
        rate_unit,
        base_oem_unit_handle,
        aux_unit,
        aux_unit_modifier,
        aux_rate_unit,
        rel,
        aux_oem_unit_handle,
        is_linear,
        data_size_value,
        resolution,
        offset_value,
        accuracy,
        plus_tolerance,
        minus_tolerance,
    ) = _NUMERIC_SENSOR_FIXED.unpack_from(body)
    data_size = GetSensorReadingDataSizeEnum(data_size_value)
    value_size = _sensor_value_size(data_size)
    offset = _NUMERIC_SENSOR_FIXED.size
    hysteresis, offset = _decode_sensor_value(data_size, body, offset)
    if offset + 2 + 8 + (2 * value_size) + 2 > len(body):
        msg = "Numeric Sensor PDR threshold fields are truncated"
        raise ValueError(msg)
    supported_thresholds = body[offset]
    threshold_and_hysteresis_volatility = body[offset + 1]
    offset += 2
    state_transition_interval, update_interval = struct.unpack_from("<ff", body, offset)
    offset += 8
    max_readable, offset = _decode_sensor_value(data_size, body, offset)
    min_readable, offset = _decode_sensor_value(data_size, body, offset)
    range_field_format = _numeric_range_format(body[offset])
    range_field_support = body[offset + 1]
    offset += 2
    range_values: list[int] = []
    for _ in range(9):
        value, offset = _decode_sensor_value(range_field_format, body, offset)
        range_values.append(value)
    if offset != len(body):
        msg = "Numeric Sensor PDR has trailing bytes not produced by NumericSensorPdr.to_bytes()"
        raise ValueError(msg)

    numeric_cls, _ = _sensor_pdr_classes()
    record = numeric_cls(
        record_handle=header.record_handle,
        record_change_number=header.record_change_number,
        terminus_handle=terminus_handle,
        sensor_id=sensor_id,
        entity_type=entity_type,
        entity_instance=entity_instance,
        container_id=container_id,
        sensor_init=sensor_init,
        sensor_auxiliary_names_pdr=sensor_auxiliary_names_pdr,
        base_unit=base_unit,
        unit_modifier=unit_modifier,
        rate_unit=rate_unit,
        base_oem_unit_handle=base_oem_unit_handle,
        aux_unit=aux_unit,
        aux_unit_modifier=aux_unit_modifier,
        aux_rate_unit=aux_rate_unit,
        rel=rel,
        aux_oem_unit_handle=aux_oem_unit_handle,
        is_linear=is_linear,
        data_size=data_size,
        resolution=resolution,
        offset=offset_value,
        accuracy=accuracy,
        plus_tolerance=plus_tolerance,
        minus_tolerance=minus_tolerance,
        hysteresis=hysteresis,
        supported_thresholds=supported_thresholds,
        threshold_and_hysteresis_volatility=threshold_and_hysteresis_volatility,
        state_transition_interval=state_transition_interval,
        update_interval=update_interval,
        max_readable=max_readable,
        min_readable=min_readable,
        range_field_format=range_field_format,
        range_field_support=range_field_support,
        nominal_value=range_values[0],
        normal_max=range_values[1],
        normal_min=range_values[2],
        warning_high=range_values[3],
        warning_low=range_values[4],
        critical_high=range_values[5],
        critical_low=range_values[6],
        fatal_high=range_values[7],
        fatal_low=range_values[8],
    )
    record.supported_thresholds = supported_thresholds
    return record


def _decode_numeric_effecter_pdr(header: PdrHeader, body: bytes) -> NumericEffecterPdr:
    if len(body) < _NUMERIC_EFFECTER_FIXED.size:
        msg = "Numeric Effecter PDR body is truncated"
        raise ValueError(msg)
    (
        terminus_handle,
        effecter_id,
        entity_type,
        entity_instance,
        container_id,
        effecter_semantic_id,
        effecter_init,
        effecter_auxiliary_names_pdr,
        base_unit,
        unit_modifier,
        rate_unit,
        base_oem_unit_handle,
        aux_unit,
        aux_unit_modifier,
        aux_rate_unit,
        aux_oem_unit_handle,
        is_linear,
        effecter_data_size_value,
        resolution,
        offset_value,
        accuracy,
        plus_tolerance,
        minus_tolerance,
        state_transition_interval,
        transition_interval,
    ) = _NUMERIC_EFFECTER_FIXED.unpack_from(body)
    effecter_data_size = _numeric_range_format(effecter_data_size_value)
    offset = _NUMERIC_EFFECTER_FIXED.size
    max_settable, offset = _decode_sensor_value(effecter_data_size, body, offset)
    min_settable, offset = _decode_sensor_value(effecter_data_size, body, offset)
    if offset + 2 > len(body):
        msg = "Numeric Effecter PDR range-field metadata is truncated"
        raise ValueError(msg)
    range_field_format = _numeric_range_format(body[offset])
    range_field_support = body[offset + 1]
    offset += 2
    range_values: list[float | int] = []
    for _ in range(5):
        value, offset = _decode_sensor_value(range_field_format, body, offset)
        range_values.append(value)
    if offset != len(body):
        msg = "Numeric Effecter PDR has trailing bytes not produced by NumericEffecterPdr.to_bytes()"
        raise ValueError(msg)
    return NumericEffecterPdr(
        record_handle=header.record_handle,
        header_version=header.header_version,
        record_change_number=header.record_change_number,
        terminus_handle=terminus_handle,
        effecter_id=effecter_id,
        entity_type=entity_type,
        entity_instance=entity_instance,
        container_id=container_id,
        effecter_semantic_id=effecter_semantic_id,
        effecter_init=effecter_init,
        effecter_auxiliary_names_pdr=effecter_auxiliary_names_pdr,
        base_unit=base_unit,
        unit_modifier=unit_modifier,
        rate_unit=rate_unit,
        base_oem_unit_handle=base_oem_unit_handle,
        aux_unit=aux_unit,
        aux_unit_modifier=aux_unit_modifier,
        aux_rate_unit=aux_rate_unit,
        aux_oem_unit_handle=aux_oem_unit_handle,
        is_linear=is_linear,
        effecter_data_size=effecter_data_size,
        resolution=resolution,
        offset=offset_value,
        accuracy=accuracy,
        plus_tolerance=plus_tolerance,
        minus_tolerance=minus_tolerance,
        state_transition_interval=state_transition_interval,
        transition_interval=transition_interval,
        max_settable=max_settable,
        min_settable=min_settable,
        range_field_format=range_field_format,
        range_field_support=range_field_support,
        nominal_value=range_values[0],
        normal_max=range_values[1],
        normal_min=range_values[2],
        rated_max=range_values[3],
        rated_min=range_values[4],
    )


def _decode_state_sensor_pdr(header: PdrHeader, body: bytes) -> Any:
    if len(body) < _STATE_SENSOR_FIXED.size:
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
    ) = _STATE_SENSOR_FIXED.unpack_from(body)
    offset = _STATE_SENSOR_FIXED.size
    possible_states: dict[int, list[int]] = {}
    possible_state_sizes: dict[int, int] = {}
    preserves_declared_sizes = False
    for _ in range(possible_states_count):
        if offset + 3 > len(body):
            msg = "State Sensor PDR possible-states header is truncated"
            raise ValueError(msg)
        state_set_id, possible_states_size = struct.unpack_from("<HB", body, offset)
        offset += 3
        end = offset + possible_states_size
        if end > len(body):
            end = offset + _state_bitfield_size(possible_states_size)
            if end > len(body):
                msg = "State Sensor PDR possible-states bitfield is truncated"
                raise ValueError(msg)
            possible_state_sizes[state_set_id] = possible_states_size
            preserves_declared_sizes = True
        possible_states[state_set_id] = _states_from_bitfield(body[offset:end])
        offset = end
    if preserves_declared_sizes:
        return _StateSensorPdrWithSizes(
            record_handle=header.record_handle,
            header_version=header.header_version,
            record_change_number=header.record_change_number,
            terminus_handle=terminus_handle,
            sensor_id=sensor_id,
            entity_type=entity_type,
            entity_instance=entity_instance,
            container_id=container_id,
            sensor_init=sensor_init,
            sensor_auxiliary_names_pdr=sensor_auxiliary_names_pdr,
            possible_states=possible_states,
            possible_state_sizes=possible_state_sizes,
            trailing_data=body[offset:],
        )
    _, state_cls = _sensor_pdr_classes()
    return state_cls(
        record_handle=header.record_handle,
        record_change_number=header.record_change_number,
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


def _decode_state_effecter_pdr(header: PdrHeader, body: bytes) -> StateEffecterPdr:
    if len(body) < _STATE_EFFECTER_FIXED.size:
        msg = "State Effecter PDR body is truncated"
        raise ValueError(msg)
    (
        terminus_handle,
        effecter_id,
        entity_type,
        entity_instance,
        container_id,
        effecter_semantic_id,
        effecter_init,
        effecter_description_pdr,
        composite_effecter_count,
    ) = _STATE_EFFECTER_FIXED.unpack_from(body)
    offset = _STATE_EFFECTER_FIXED.size
    possible_states: dict[int, list[int]] = {}
    possible_state_sizes: dict[int, int] = {}
    for _ in range(composite_effecter_count):
        if offset + 3 > len(body):
            msg = "State Effecter PDR possible-states header is truncated"
            raise ValueError(msg)
        state_set_id, possible_states_size = struct.unpack_from("<HB", body, offset)
        offset += 3
        end = offset + possible_states_size
        if end > len(body):
            msg = "State Effecter PDR possible-states bitfield is truncated"
            raise ValueError(msg)
        possible_states[state_set_id] = _states_from_bitfield(body[offset:end])
        possible_state_sizes[state_set_id] = possible_states_size
        offset = end
    return StateEffecterPdr(
        record_handle=header.record_handle,
        header_version=header.header_version,
        record_change_number=header.record_change_number,
        terminus_handle=terminus_handle,
        effecter_id=effecter_id,
        entity_type=entity_type,
        entity_instance=entity_instance,
        container_id=container_id,
        effecter_semantic_id=effecter_semantic_id,
        effecter_init=effecter_init,
        effecter_description_pdr=effecter_description_pdr,
        possible_states=possible_states,
        possible_state_sizes=possible_state_sizes,
        trailing_data=body[offset:],
    )


def _decode_sensor_auxiliary_names_pdr(header: PdrHeader, body: bytes) -> SensorAuxiliaryNamesPdr:
    if len(body) < _SENSOR_AUX_NAMES_FIXED.size:
        msg = "Sensor Auxiliary Names PDR body is truncated"
        raise ValueError(msg)
    terminus_handle, sensor_id, sensor_count = _SENSOR_AUX_NAMES_FIXED.unpack_from(body)
    offset = _SENSOR_AUX_NAMES_FIXED.size
    sensors: list[SensorAuxiliaryNamesEntry] = []
    for _ in range(sensor_count):
        if offset >= len(body):
            msg = "Sensor Auxiliary Names PDR name-string count is truncated"
            raise ValueError(msg)
        name_string_count = body[offset]
        offset += 1
        names: list[PdrNameString] = []
        for _ in range(name_string_count):
            name, offset = _read_name_string(body, offset)
            names.append(name)
        sensors.append(SensorAuxiliaryNamesEntry(names))
    return SensorAuxiliaryNamesPdr(
        record_handle=header.record_handle,
        header_version=header.header_version,
        record_change_number=header.record_change_number,
        pldm_terminus_handle=terminus_handle,
        sensor_id=sensor_id,
        sensors=sensors,
        trailing_data=body[offset:],
    )


def _decode_effecter_auxiliary_names_pdr(header: PdrHeader, body: bytes) -> EffecterAuxiliaryNamesPdr:
    if len(body) < _EFFECTER_AUX_NAMES_FIXED.size:
        msg = "Effecter Auxiliary Names PDR body is truncated"
        raise ValueError(msg)
    terminus_handle, effecter_id, effecter_count = _EFFECTER_AUX_NAMES_FIXED.unpack_from(body)
    offset = _EFFECTER_AUX_NAMES_FIXED.size
    effecters: list[EffecterAuxiliaryNamesEntry] = []
    for _ in range(effecter_count):
        if offset >= len(body):
            msg = "Effecter Auxiliary Names PDR name-string count is truncated"
            raise ValueError(msg)
        name_string_count = body[offset]
        offset += 1
        names: list[PdrNameString] = []
        for _ in range(name_string_count):
            name, offset = _read_name_string(body, offset)
            names.append(name)
        effecters.append(EffecterAuxiliaryNamesEntry(names))
    return EffecterAuxiliaryNamesPdr(
        record_handle=header.record_handle,
        header_version=header.header_version,
        record_change_number=header.record_change_number,
        pldm_terminus_handle=terminus_handle,
        effecter_id=effecter_id,
        effecters=effecters,
        trailing_data=body[offset:],
    )


def _decode_entity_auxiliary_names_pdr(header: PdrHeader, body: bytes) -> EntityAuxiliaryNamesPdr:
    if len(body) < _ENTITY_AUX_NAMES_FIXED.size:
        msg = "Entity Auxiliary Names PDR body is truncated"
        raise ValueError(msg)
    entity_type, entity_instance, container_id, shared_name_count, name_string_count = _ENTITY_AUX_NAMES_FIXED.unpack_from(
        body
    )
    offset = _ENTITY_AUX_NAMES_FIXED.size
    names: list[PdrNameString] = []
    for _ in range(name_string_count):
        name, offset = _read_name_string(body, offset)
        names.append(name)
    return EntityAuxiliaryNamesPdr(
        record_handle=header.record_handle,
        header_version=header.header_version,
        record_change_number=header.record_change_number,
        entity_type=entity_type,
        entity_instance_number=entity_instance,
        entity_container_id=container_id,
        shared_name_count=shared_name_count,
        names=names,
        trailing_data=body[offset:],
    )


def _read_name_string(body: bytes, offset: int) -> tuple[PdrNameString, int]:
    language_tag_bytes, offset = _read_ascii_c_string(body, offset)
    name_bytes, offset = _read_utf16be_c_string(body, offset)
    return (
        PdrNameString(
            language_tag=language_tag_bytes.decode("ascii"),
            name=_decode_utf16_name(name_bytes),
            language_tag_bytes=language_tag_bytes,
            name_bytes=name_bytes,
        ),
        offset,
    )


def _read_ascii_c_string(body: bytes, offset: int) -> tuple[bytes, int]:
    end = body.find(b"\x00", offset)
    if end < 0:
        msg = "ASCII language tag is missing its null terminator"
        raise ValueError(msg)
    return body[offset:end], end + 1


def _read_utf16be_c_string(body: bytes, offset: int) -> tuple[bytes, int]:
    for index in range(offset, len(body) - 1, 2):
        if body[index : index + 2] == b"\x00\x00":
            return body[offset:index], index + 2
    msg = "UTF-16BE name is missing its null terminator"
    raise ValueError(msg)


def _decode_utf16_name(name: bytes) -> str:
    big_endian = name.decode("utf-16-be")
    little_endian = name.decode("utf-16-le")
    if _printable_ascii_score(little_endian) > _printable_ascii_score(big_endian):
        return little_endian
    return big_endian


def _printable_ascii_score(value: str) -> int:
    return sum(0x20 <= ord(char) <= 0x7E for char in value)


def _pdr_header_and_body(raw: bytes, expected_type: int) -> tuple[PdrHeader, bytes]:
    header = PdrHeader.from_bytes(raw)
    body = bytes(raw[PDR_HEADER_LEN:])
    if header.pdr_type != expected_type:
        msg = f"Expected PDR type {expected_type}, got {header.pdr_type}"
        raise ValueError(msg)
    if len(body) != header.data_length:
        msg = f"PDR type {expected_type} length mismatch"
        raise ValueError(msg)
    return header, body


def _decode_sensor_value(data_size: GetSensorReadingDataSizeEnum | int, body: bytes, offset: int) -> tuple[float | int, int]:
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
    fmt = formats[data_size]
    size = struct.calcsize(fmt)
    if offset + size > len(body):
        msg = f"Sensor value at offset {offset} is truncated"
        raise ValueError(msg)
    return struct.unpack_from(fmt, body, offset)[0], offset + size


def _encode_sensor_value(data_size: GetSensorReadingDataSizeEnum | int, value: float | int) -> bytes:
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


def _numeric_range_format(data_size: GetSensorReadingDataSizeEnum | int) -> GetSensorReadingDataSizeEnum | int:
    value = int(data_size)
    if value in (6, 7):
        return value
    return GetSensorReadingDataSizeEnum(value)


def _states_from_bitfield(bitfield: bytes) -> list[int]:
    states: list[int] = []
    for byte_index, value in enumerate(bitfield):
        for bit_index in range(8):
            if value & (1 << bit_index):
                states.append((byte_index * 8) + bit_index)
    return states


def _state_bitfield(states: list[int], size: int | None = None) -> bytes:
    max_state = max(states, default=-1)
    length = max((max_state // 8) + 1 if max_state >= 0 else 0, size or 0)
    bitfield = bytearray(length)
    for state in states:
        if state < 0:
            msg = f"State values must be non-negative, got {state}"
            raise ValueError(msg)
        index = state // 8
        if index >= len(bitfield):
            bitfield.extend(bytes(index + 1 - len(bitfield)))
        bitfield[index] |= 1 << (state % 8)
    return bytes(bitfield)


def _state_bitfield_size(possible_states_size: int | None) -> int | None:
    if possible_states_size is None:
        return None
    possible_states_size = int(possible_states_size)
    if possible_states_size <= 0:
        return 0
    return (possible_states_size + 7) // 8


def _int8(value: int) -> int:
    value = int(value)
    if value > 127:
        return value - 256
    if value < -128:
        return ((value + 128) % 256) - 128
    return value


def _sensor_pdr_classes() -> tuple[type[Any], type[Any]]:
    from pymctp.automaton.behaviors.pldm_responder import NumericSensorPdr, StateSensorPdr

    return NumericSensorPdr, StateSensorPdr


def _dataclass_to_dict(record: Any) -> dict[str, Any]:
    return {field.name: _json_value(getattr(record, field.name)) for field in fields(record)}


def _json_value(value: Any) -> Any:
    if isinstance(value, IntEnum):
        return int(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    return value


def _name_to_dict(name: PdrNameString) -> dict[str, Any]:
    data = {"language_tag": name.language_tag, "name": name.name}
    if name.language_tag_bytes is not None:
        data["language_tag_data"] = name.language_tag_bytes.hex()
    if name.name_bytes is not None:
        data["name_data"] = name.name_bytes.hex()
    return data


def _name_from_dict(data: dict[str, Any]) -> PdrNameString:
    return PdrNameString(
        language_tag=data["language_tag"],
        name=data["name"],
        language_tag_bytes=bytes.fromhex(data["language_tag_data"]) if "language_tag_data" in data else None,
        name_bytes=bytes.fromhex(data["name_data"]) if "name_data" in data else None,
    )


def _sensor_aux_entry_to_dict(entry: SensorAuxiliaryNamesEntry) -> dict[str, Any]:
    return {"name_string_count": len(entry.names), "names": [_name_to_dict(name) for name in entry.names]}


def _sensor_aux_entry_from_dict(data: dict[str, Any]) -> SensorAuxiliaryNamesEntry:
    return SensorAuxiliaryNamesEntry(names=[_name_from_dict(name) for name in data["names"]])


def _effecter_aux_entry_to_dict(entry: EffecterAuxiliaryNamesEntry) -> dict[str, Any]:
    return {"name_string_count": len(entry.names), "names": [_name_to_dict(name) for name in entry.names]}


def _effecter_aux_entry_from_dict(data: dict[str, Any]) -> EffecterAuxiliaryNamesEntry:
    return EffecterAuxiliaryNamesEntry(names=[_name_from_dict(name) for name in data["names"]])


def _constructor_kwargs(cls: type[Any], data: dict[str, Any]) -> dict[str, Any]:
    field_names = {field.name for field in fields(cls)}
    return {name: value for name, value in data.items() if name in field_names}


def _opaque_from_dict(data: dict[str, Any]) -> OpaquePdr:
    body = bytes.fromhex(data.get("data", ""))
    header = PdrHeader(
        record_handle=int(data.get("record_handle", 0)),
        header_version=int(data.get("header_version", _PDR_HEADER_VERSION)),
        pdr_type=int(data["pdr_type"]),
        record_change_number=int(data.get("record_change_number", 0)),
        data_length=int(data.get("data_length", len(body))),
    )
    return OpaquePdr(header, body)


_MODELLED_DECODERS = {
    PDR_TYPE_TERMINUS_LOCATOR: _decode_terminus_locator_pdr,
    PDR_TYPE_NUMERIC_SENSOR: _decode_numeric_sensor_pdr,
    PDR_TYPE_STATE_SENSOR: _decode_state_sensor_pdr,
    PDR_TYPE_SENSOR_AUXILIARY_NAMES: _decode_sensor_auxiliary_names_pdr,
    PDR_TYPE_NUMERIC_EFFECTER: _decode_numeric_effecter_pdr,
    PDR_TYPE_STATE_EFFECTER: _decode_state_effecter_pdr,
    PDR_TYPE_EFFECTER_AUXILIARY_NAMES: _decode_effecter_auxiliary_names_pdr,
    PDR_TYPE_ENTITY_AUXILIARY_NAMES: _decode_entity_auxiliary_names_pdr,
}

__all__ = [
    "PDR_HEADER_LEN",
    "PDR_TYPE_EFFECTER_AUXILIARY_NAMES",
    "PDR_TYPE_ENTITY_AUXILIARY_NAMES",
    "PDR_TYPE_NUMERIC_EFFECTER",
    "PDR_TYPE_NUMERIC_SENSOR",
    "PDR_TYPE_SENSOR_AUXILIARY_NAMES",
    "PDR_TYPE_STATE_EFFECTER",
    "PDR_TYPE_STATE_SENSOR",
    "PDR_TYPE_TERMINUS_LOCATOR",
    "EffecterAuxiliaryNamesEntry",
    "EffecterAuxiliaryNamesPdr",
    "EntityAuxiliaryNamesPdr",
    "NumericEffecterPdr",
    "OpaquePdr",
    "PdrHeader",
    "PdrNameString",
    "RawPdr",
    "SensorAuxiliaryNamesEntry",
    "SensorAuxiliaryNamesPdr",
    "StateEffecterPdr",
    "TerminusLocatorPdr",
    "decode_pdr",
    "encode_pdr",
    "pdr_from_dict",
    "pdr_to_dict",
    "split_pdr_records",
]
