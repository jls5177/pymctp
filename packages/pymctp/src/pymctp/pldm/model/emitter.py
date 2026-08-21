# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Emit editable Python modules for PLDM terminus models."""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, fields
from enum import IntEnum
from typing import Any

from pymctp.layers.mctp.pldm.pdr import (
    EffecterAuxiliaryNamesEntry,
    EffecterAuxiliaryNamesPdr,
    PDR_TYPE_EFFECTER_AUXILIARY_NAMES,
    PDR_TYPE_SENSOR_AUXILIARY_NAMES,
    PdrNameString,
    SensorAuxiliaryNamesEntry,
    SensorAuxiliaryNamesPdr,
    encode_pdr,
    pdr_from_dict,
    pdr_to_dict,
)
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import GetSensorReadingDataSizeEnum
from pymctp.pldm.model import (
    CounterSensor,
    CurrentSensor,
    NumericEffecter,
    NumericSensor,
    PowerSensor,
    StateEffecter,
    StateSensor,
    TemperatureSensor,
    Terminus,
    TerminusItem,
    VerbatimRecord,
    VoltageSensor,
)

_INDENT = " " * 4
_WRAPPED_TEXT_CHUNK = 88
_SENSOR_ID_FIELDS = {"sensor_id", "effecter_id"}
_NUMERIC_FORMAT_FIELDS = {"data_size", "range_field_format"}
_IGNORED_ITEM_FIELDS = {"name", "sensor_id", "effecter_id"}
_PRESET_SENSOR_CLASSES = (TemperatureSensor, PowerSensor, VoltageSensor, CurrentSensor, CounterSensor)
_AUXILIARY_NAME_PDR_TYPES = {PDR_TYPE_SENSOR_AUXILIARY_NAMES, PDR_TYPE_EFFECTER_AUXILIARY_NAMES}


@dataclass(frozen=True)
class PythonEmission:
    code: str
    preset_numeric_sensors: int
    plain_numeric_sensors: int
    verbatim_records: int
    verbatim_reasons: tuple[str, ...]


def emit_python_module(artifact: Mapping[str, Any]) -> PythonEmission:
    """Return an editable Python module that builds the terminus described by an artifact."""
    artifact_data = dict(artifact)
    if artifact_data.get("tid") is None:
        artifact_data["tid"] = 0
    if artifact_data.get("repository_info") is None:
        artifact_data["repository_info"] = {}
    terminus = Terminus.from_artifact(artifact_data)
    _apply_auxiliary_padding_policy(terminus, artifact_data)
    rendered_items = [_render_item(item) for item in terminus.items]
    imports = _imports_for_rendered_items(rendered_items)
    code = "\n".join(
        [
            "# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>",
            "#",
            "# SPDX-License-Identifier: MIT",
            "",
            '"""Generated from a PLDM capture.',
            "",
            "This module is safe to edit by hand.",
            '"""',
            "",
            "from __future__ import annotations",
            "",
            *imports,
            "",
            _render_terminus(terminus, rendered_items),
            "",
        ]
    )
    return PythonEmission(
        code=code,
        preset_numeric_sensors=sum(1 for item in rendered_items if item.is_preset_numeric_sensor),
        plain_numeric_sensors=sum(1 for item in rendered_items if item.class_name == "NumericSensor"),
        verbatim_records=sum(1 for item in rendered_items if item.class_name == "VerbatimRecord"),
        verbatim_reasons=tuple(item.reason for item in rendered_items if item.reason is not None),
    )


@dataclass(frozen=True)
class _RenderedItem:
    class_name: str
    expression: str
    section: str
    is_preset_numeric_sensor: bool = False
    reason: str | None = None


@dataclass(frozen=True)
class _RawExpression:
    code: str


def _imports_for_rendered_items(items: list[_RenderedItem]) -> list[str]:
    model_imports = sorted({item.class_name for item in items} | {"Terminus"})
    lines = []
    if any(item.class_name == "VerbatimRecord" for item in items):
        lines.extend(["from pymctp.layers.mctp.pldm.pdr import pdr_from_dict", ""])
    if _uses_any(items, "GetSensorReadingDataSizeEnum."):
        lines.extend(
            [
                "from pymctp.layers.mctp.pldm.type_2_platform_monitoring import GetSensorReadingDataSizeEnum",
                "",
            ]
        )
    pdr_imports = sorted(
        name
        for name in ("EffecterAuxiliaryNamesEntry", "PdrNameString", "SensorAuxiliaryNamesEntry")
        if _uses_any(items, f"{name}(")
    )
    if pdr_imports:
        if len(pdr_imports) == 1:
            lines.append(f"from pymctp.layers.mctp.pldm.pdr import {pdr_imports[0]}")
        else:
            lines.append("from pymctp.layers.mctp.pldm.pdr import (")
            lines.extend(f"{_INDENT}{name}," for name in pdr_imports)
            lines.append(")")
        lines.append("")
    lines.append("from pymctp.pldm.model import (")
    lines.extend(f"{_INDENT}{name}," for name in model_imports)
    lines.append(")")
    return lines


def _uses_any(items: list[_RenderedItem], needle: str) -> bool:
    return any(needle in item.expression for item in items)


def _render_terminus(terminus: Terminus, items: list[_RenderedItem]) -> str:
    args: list[tuple[str, Any]] = [("eid", terminus.eid), ("tid", terminus.tid)]
    for field_name in (
        "repository_state",
        "reported_record_count",
        "reported_repository_size",
        "reported_largest_record_size",
        "data_transfer_handle_timeout",
        "auxiliary_record_size",
    ):
        value = getattr(terminus, field_name)
        if value != getattr(Terminus(eid=terminus.eid, tid=terminus.tid), field_name):
            args.append((field_name, value))

    lines = ["terminus = Terminus("]
    for name, value in args:
        lines.append(f"{_INDENT}{name}={_literal(value, field_name=name, level=1)},")
    if items:
        lines.append(f"{_INDENT}items=[")
        previous_section = None
        for item in items:
            if item.section != previous_section:
                lines.append(f"{_INDENT * 2}# {item.section}")
                previous_section = item.section
            if item.reason is not None:
                lines.append(f"{_INDENT * 2}# Verbatim: {item.reason}.")
            lines.extend(f"{_INDENT * 2}{line}" if line else "" for line in item.expression.splitlines())
            lines[-1] += ","
        lines.append(f"{_INDENT}],")
    else:
        lines.append(f"{_INDENT}items=[],")
    lines.append(")")
    return "\n".join(lines)


def _render_item(item: TerminusItem) -> _RenderedItem:
    if isinstance(item, VerbatimRecord):
        return _render_verbatim_record(item)
    if isinstance(item, NumericSensor):
        cls = _numeric_sensor_class(item)
        return _RenderedItem(
            class_name=cls.__name__,
            expression=_constructor_expr(cls, item, id_field="sensor_id"),
            section="Numeric sensors",
            is_preset_numeric_sensor=cls is not NumericSensor,
        )
    if isinstance(item, StateSensor):
        return _RenderedItem(
            class_name="StateSensor",
            expression=_constructor_expr(StateSensor, item, id_field="sensor_id"),
            section="State sensors",
        )
    if isinstance(item, NumericEffecter):
        return _RenderedItem(
            class_name="NumericEffecter",
            expression=_constructor_expr(NumericEffecter, item, id_field="effecter_id"),
            section="Effecters",
        )
    return _RenderedItem(
        class_name="StateEffecter",
        expression=_constructor_expr(StateEffecter, item, id_field="effecter_id"),
        section="Effecters",
    )


def _render_verbatim_record(item: VerbatimRecord) -> _RenderedItem:
    pdr_dict = _verbatim_dict(item)
    expression = _call_expr(
        "VerbatimRecord",
        [("record", _RawExpression(f"pdr_from_dict({_literal(pdr_dict, level=2)})")), ("reason", item.reason)],
        level=0,
    )
    return _RenderedItem(
        class_name="VerbatimRecord",
        expression=expression,
        section="Verbatim records",
        reason=item.reason,
    )


def _verbatim_dict(item: VerbatimRecord) -> dict[str, Any]:
    try:
        return pdr_to_dict(item.record)
    except TypeError:
        return {"pdr_type": -1, "record_handle": item.record_handle or 0, "data": item.encoded.hex()}


def _numeric_sensor_class(item: NumericSensor) -> type[NumericSensor]:
    for cls in _PRESET_SENSOR_CLASSES:
        default = cls(name=item.name, sensor_id=item.sensor_id)
        if (
            int(item.base_unit) == int(default.base_unit)
            and int(item.data_size) == int(default.data_size)
            and int(item.range_field_format or item.data_size) == int(default.range_field_format or default.data_size)
            and int(item.unit_modifier) == int(default.unit_modifier)
        ):
            return cls
    return NumericSensor


def _constructor_expr(cls: type[Any], item: Any, *, id_field: str) -> str:
    required = {"name": item.name, id_field: getattr(item, id_field)}
    kwargs = _minimal_constructor_kwargs(cls, item, required, id_field=id_field)
    return _call_expr(cls.__name__, list(kwargs.items()), level=0)


def _minimal_constructor_kwargs(cls: type[Any], item: Any, required: dict[str, Any], *, id_field: str) -> dict[str, Any]:
    kwargs: dict[str, Any] = dict(required)
    candidate_fields = [
        field.name
        for field in fields(cls)
        if field.init and field.name not in _IGNORED_ITEM_FIELDS and hasattr(item, field.name)
    ]
    for name in candidate_fields:
        value = getattr(item, name)
        if not _same_constructor_default(cls, required, name, value, id_field=id_field):
            kwargs[name] = value

    for name in list(kwargs):
        if name in required:
            continue
        trial = dict(kwargs)
        del trial[name]
        if _item_records_match(item, cls(**trial)):
            del kwargs[name]
    return kwargs


def _same_constructor_default(
    cls: type[Any],
    required: dict[str, Any],
    name: str,
    value: Any,
    *,
    id_field: str,
) -> bool:
    default_item = cls(**required)
    return _values_equal_for_emit(getattr(default_item, name), value, field_name=name if name != id_field else "")


def _item_records_match(left: Any, right: Any) -> bool:
    return _encoded_item_records(left) == _encoded_item_records(right)


def _encoded_item_records(item: Any) -> list[bytes]:
    records = [encode_pdr(item.pdr(0))]
    if item.emit_auxiliary_names:
        records.append(encode_pdr(_pad_auxiliary_pdr(item.auxiliary_pdr(1), item.auxiliary_record_size)))
    return records


def _apply_auxiliary_padding_policy(terminus: Terminus, artifact: Mapping[str, Any]) -> None:
    source_records = _auxiliary_source_records(artifact)
    items = [
        item
        for item in terminus.items
        if not isinstance(item, VerbatimRecord) and item.emit_auxiliary_names and hasattr(item, "auxiliary_trailing_data")
    ]
    if len(source_records) != len(items):
        return

    if not any(_is_nonempty_zero_padding(_source_trailing_data(record)) for record in source_records):
        return

    record_sizes = [_encoded_artifact_record_size(record) for record in source_records]
    if len(set(record_sizes)) == 1:
        terminus.auxiliary_record_size = record_sizes[0]
        for item in items:
            if _is_zero_padding(item.auxiliary_trailing_data):
                item.auxiliary_trailing_data = b""
        return

    for item, record_size in zip(items, record_sizes, strict=True):
        if _is_nonempty_zero_padding(item.auxiliary_trailing_data):
            item.auxiliary_record_size = record_size
            item.auxiliary_trailing_data = b""


def _auxiliary_source_records(artifact: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    pdrs = artifact.get("pdrs", [])
    if not isinstance(pdrs, list):
        return []
    return [
        pdr
        for pdr in pdrs
        if isinstance(pdr, Mapping) and int(pdr.get("pdr_type", -999)) in _AUXILIARY_NAME_PDR_TYPES and "data" not in pdr
    ]


def _encoded_artifact_record_size(record: Mapping[str, Any]) -> int:
    return len(encode_pdr(pdr_from_dict(dict(record))))


def _source_trailing_data(record: Mapping[str, Any]) -> bytes:
    return bytes.fromhex(str(record.get("trailing_data", "")))


def _is_nonempty_zero_padding(data: bytes) -> bool:
    return bool(data) and not any(data)


def _is_zero_padding(data: bytes) -> bool:
    return not data or not any(data)


def _pad_auxiliary_pdr(
    record: SensorAuxiliaryNamesPdr | EffecterAuxiliaryNamesPdr,
    record_size: int | None,
) -> SensorAuxiliaryNamesPdr | EffecterAuxiliaryNamesPdr:
    if not record_size:
        return record
    current_size = len(encode_pdr(record))
    if current_size <= record_size:
        record.trailing_data += b"\x00" * (record_size - current_size)
    return record


def _values_equal_for_emit(left: Any, right: Any, *, field_name: str = "") -> bool:
    if field_name in _NUMERIC_FORMAT_FIELDS and left is not None and right is not None:
        return int(left) == int(right)
    return left == right


def _call_expr(name: str, args: list[tuple[str, str | Any]], *, level: int) -> str:
    lines = [f"{name}("]
    for arg_name, value in args:
        value_expr = value.code if isinstance(value, _RawExpression) else _literal(value, field_name=arg_name, level=level + 1)
        value_lines = value_expr.splitlines()
        if len(value_lines) == 1:
            lines.append(f"{_INDENT}{arg_name}={value_lines[0]},")
            continue
        lines.append(f"{_INDENT}{arg_name}={value_lines[0]}")
        lines.extend(f"{_INDENT}{line}" if line else "" for line in value_lines[1:])
        lines[-1] += ","
    lines.append(")")
    return "\n".join(lines)


def _literal(value: Any, *, field_name: str = "", level: int = 0) -> str:
    if isinstance(value, GetSensorReadingDataSizeEnum):
        return f"GetSensorReadingDataSizeEnum.{value.name}"
    if field_name in _NUMERIC_FORMAT_FIELDS and isinstance(value, int) and int(value) in GetSensorReadingDataSizeEnum._value2member_map_:
        return f"GetSensorReadingDataSizeEnum.{GetSensorReadingDataSizeEnum(int(value)).name}"
    if field_name in _SENSOR_ID_FIELDS and isinstance(value, int):
        return _id_literal(value)
    if isinstance(value, IntEnum):
        return str(int(value))
    if isinstance(value, bytes):
        return _bytes_literal(value, level=level)
    if isinstance(value, str):
        return _string_literal(value, level=level)
    if dataclasses.is_dataclass(value):
        return _dataclass_literal(value, level=level)
    if isinstance(value, Mapping):
        return _mapping_literal(value, level=level)
    if isinstance(value, list):
        return _sequence_literal(value, "[", "]", level=level)
    if isinstance(value, tuple):
        return _sequence_literal(list(value), "(", ")", level=level)
    return repr(value)


def _id_literal(value: int) -> str:
    return f"0x{value:04x}" if value >= 0x100 else str(value)


def _bytes_literal(value: bytes, *, level: int) -> str:
    if not value:
        return "b\"\""
    text = value.hex()
    if len(text) <= _WRAPPED_TEXT_CHUNK:
        return f'bytes.fromhex("{text}")'
    return _wrapped_call("bytes.fromhex", text, level=level)


def _string_literal(value: str, *, level: int) -> str:
    if len(value) <= _WRAPPED_TEXT_CHUNK:
        return repr(value)
    return _wrapped_text(value, level=level)


def _wrapped_call(function: str, text: str, *, level: int) -> str:
    return f"{function}(\n{_wrapped_text_body(text, level=level + 1)}\n{_INDENT * level})"


def _wrapped_text(text: str, *, level: int) -> str:
    return f"(\n{_wrapped_text_body(text, level=level + 1)}\n{_INDENT * level})"


def _wrapped_text_body(text: str, *, level: int) -> str:
    chunks = [text[index : index + _WRAPPED_TEXT_CHUNK] for index in range(0, len(text), _WRAPPED_TEXT_CHUNK)]
    return "\n".join(f"{_INDENT * level}{chunk!r}" for chunk in chunks)


def _dataclass_literal(value: Any, *, level: int) -> str:
    if isinstance(value, (SensorAuxiliaryNamesEntry, EffecterAuxiliaryNamesEntry)):
        return _call_expr(type(value).__name__, [("names", value.names)], level=level)
    if isinstance(value, PdrNameString):
        args: list[tuple[str, Any]] = [("language_tag", value.language_tag), ("name", value.name)]
        for name in (
            "language_tag_bytes",
            "name_bytes",
            "_preserve_language_tag_bytes",
            "_preserve_name_bytes",
            "_name_terminated",
        ):
            current = getattr(value, name)
            if current != getattr(PdrNameString(value.language_tag, value.name), name):
                args.append((name, current))
        return _call_expr("PdrNameString", args, level=level)
    msg = f"Cannot emit {type(value).__name__} as a Python literal"
    raise TypeError(msg)


def _mapping_literal(value: Mapping[Any, Any], *, level: int) -> str:
    if not value:
        return "{}"
    lines = ["{"]
    for key, item in value.items():
        key_expr = _literal(key, level=level + 1)
        item_expr = _literal(item, level=level + 1)
        item_lines = item_expr.splitlines()
        if len(item_lines) == 1:
            lines.append(f"{_INDENT * (level + 1)}{key_expr}: {item_lines[0]},")
            continue
        lines.append(f"{_INDENT * (level + 1)}{key_expr}: {item_lines[0]}")
        lines.extend(item_lines[1:])
        lines[-1] += ","
    lines.append(f"{_INDENT * level}}}")
    return "\n".join(lines)


def _sequence_literal(value: list[Any], open_bracket: str, close_bracket: str, *, level: int) -> str:
    if not value:
        return f"{open_bracket}{close_bracket}"
    lines = [open_bracket]
    for item in value:
        item_expr = _literal(item, level=level + 1)
        item_lines = item_expr.splitlines()
        lines.append(f"{_INDENT * (level + 1)}{item_lines[0]}")
        lines.extend(item_lines[1:])
        lines[-1] += ","
    lines.append(f"{_INDENT * level}{close_bracket}")
    return "\n".join(lines)
