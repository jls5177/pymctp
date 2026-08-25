# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Emit editable Python modules for PLDM terminus models."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from dataclasses import dataclass, field as dc_field, fields, replace
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
from pymctp.layers.mctp.pldm.fru import FruField, OpaqueFruField, _field_value_bytes, fru_record_to_dict
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import GetSensorReadingDataSizeEnum
from pymctp.pldm.model import (
    FrequencySensor,
    CurrentSensor,
    FruRecordItem,
    NumericEffecter,
    NumericSensor,
    PowerSensor,
    StateEffecter,
    StateSensor,
    TemperatureSensor,
    Terminus,
    VerbatimFruRecord,
    TerminusItem,
    VerbatimRecord,
    VoltageSensor,
)

_INDENT = " " * 4
#: Keep generated lines within the project's ruff line-length.
_MAX_LINE_LENGTH = 120
_WRAPPED_TEXT_CHUNK = 88
_SENSOR_ID_FIELDS = {"sensor_id", "effecter_id"}
_NUMERIC_FORMAT_FIELDS = {"data_size", "range_field_format"}
_IGNORED_ITEM_FIELDS = {"name", "sensor_id", "effecter_id"}
_IGNORED_SHAPE_FIELDS = {"record_handle", "sensor_id", "effecter_id", "pdr_type", "record_change_number"}
_NEAR_DUPLICATE_FIELD_LIMIT = 4
_PRESET_SENSOR_CLASSES = (TemperatureSensor, PowerSensor, VoltageSensor, CurrentSensor, FrequencySensor)
_AUXILIARY_NAME_PDR_TYPES = {PDR_TYPE_SENSOR_AUXILIARY_NAMES, PDR_TYPE_EFFECTER_AUXILIARY_NAMES}
_NUMERIC_UNIT_NAMES = {
    2: "temperature",
    5: "voltage",
    6: "current",
    7: "power",
    20: "counter",
}


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
    rendered_templates, rendered_items = _render_model(terminus.items)
    rendered_fru_records = _render_fru_records(terminus.fru_records)
    imports = _imports_for_rendered_items(rendered_items + rendered_fru_records, rendered_templates)
    templates = _render_templates(rendered_templates)
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
            *templates,
            _render_terminus(terminus, rendered_items, rendered_fru_records),
            "",
        ]
    )
    return PythonEmission(
        code=code,
        preset_numeric_sensors=sum(item.item_count for item in rendered_items if item.is_preset_numeric_sensor),
        plain_numeric_sensors=sum(item.item_count for item in rendered_items if item.class_name == "NumericSensor"),
        verbatim_records=sum(item.item_count for item in rendered_items if item.class_name == "VerbatimRecord"),
        verbatim_reasons=tuple(item.reason for item in rendered_items if item.reason is not None),
    )


@dataclass(frozen=True)
class _RenderedItem:
    class_name: str
    expression: str
    section: str
    is_preset_numeric_sensor: bool = False
    reason: str | None = None
    item_count: int = 1


@dataclass(frozen=True)
class _RawExpression:
    code: str


@dataclass(frozen=True)
class _RenderedTemplate:
    name: str
    cls: type[Any]
    class_name: str
    item: TerminusItem
    id_field: str
    first_index: int
    #: Every item that will clone from this template. A field is only safe to
    #: elide from the template if all of them still round-trip without it.
    members: list[TerminusItem] = dc_field(default_factory=list)

    def emitted_item(self) -> TerminusItem:
        """The template as the generated module will construct it.

        Clones inherit whatever survived reduction, so every decision about a
        clone has to be made against this rather than the richer source item.
        """
        kwargs = _minimal_constructor_kwargs(
            self.cls,
            self.item,
            {"name": self.item.name, self.id_field: getattr(self.item, self.id_field)},
            id_field=self.id_field,
            members=self.members,
        )
        return self.cls(**kwargs)


def _imports_for_rendered_items(items: list[_RenderedItem], templates: list[_RenderedTemplate]) -> list[str]:
    model_imports = sorted({item.class_name for item in items} | {template.class_name for template in templates} | {"Terminus"})
    expressions = [item.expression for item in items] + [
        _constructor_expr(template.cls, template.item, id_field=template.id_field) for template in templates
    ]
    lines = []
    if any(item.class_name == "VerbatimRecord" for item in items):
        lines.extend(["from pymctp.layers.mctp.pldm.pdr import pdr_from_dict", ""])
    if any(item.class_name == "VerbatimFruRecord" for item in items):
        lines.extend(["from pymctp.layers.mctp.pldm.fru import fru_record_from_dict", ""])
    if _uses_any(expressions, "GetSensorReadingDataSizeEnum."):
        lines.extend(
            [
                "from pymctp.layers.mctp.pldm.type_2_platform_monitoring import GetSensorReadingDataSizeEnum",
                "",
            ]
        )
    pdr_imports = sorted(
        name
        for name in ("EffecterAuxiliaryNamesEntry", "PdrNameString", "SensorAuxiliaryNamesEntry")
        if _uses_any(expressions, f"{name}(")
    )
    fru_imports = sorted(
        name for name in ("FruField", "OpaqueFruField") if _uses_any(expressions, f"{name}(")
    )
    if pdr_imports:
        if len(pdr_imports) == 1:
            lines.append(f"from pymctp.layers.mctp.pldm.pdr import {pdr_imports[0]}")
        else:
            lines.append("from pymctp.layers.mctp.pldm.pdr import (")
            lines.extend(f"{_INDENT}{name}," for name in pdr_imports)
            lines.append(")")
        lines.append("")
    if fru_imports:
        if len(fru_imports) == 1:
            lines.append(f"from pymctp.layers.mctp.pldm.fru import {fru_imports[0]}")
        else:
            lines.append("from pymctp.layers.mctp.pldm.fru import (")
            lines.extend(f"{_INDENT}{name}," for name in fru_imports)
            lines.append(")")
        lines.append("")
    lines.append("from pymctp.pldm.model import (")
    lines.extend(f"{_INDENT}{name}," for name in model_imports)
    lines.append(")")
    return lines


def _uses_any(expressions: list[str], needle: str) -> bool:
    return any(needle in expression for expression in expressions)


def _render_model(items: list[TerminusItem]) -> tuple[list[_RenderedTemplate], list[_RenderedItem]]:
    template_by_key, grouped_indices = _group_template_candidates(items)
    rendered_templates = _name_templates(template_by_key, grouped_indices, items)
    template_by_key = {_shape_key(template.item): template for template in rendered_templates}
    clone_templates = _clone_templates_by_item_index(items, rendered_templates, grouped_indices)

    rendered_items: list[_RenderedItem] = []
    index = 0
    while index < len(items):
        item = items[index]
        key = _shape_key(item)
        template = template_by_key.get(key)
        if template is not None and index in grouped_indices[key]:
            run: list[TerminusItem] = []
            while index < len(items) and _shape_key(items[index]) == key and index in grouped_indices[key]:
                run.append(items[index])
                index += 1
            rendered_items.append(_render_series(template, run))
            continue

        clone_template = clone_templates.get(index)
        if clone_template is not None:
            rendered_items.append(_render_clone(clone_template, item))
        else:
            rendered_items.append(_render_item(item))
        index += 1
    return rendered_templates, rendered_items


def _group_template_candidates(
    items: list[TerminusItem],
) -> tuple[dict[tuple[Any, ...], TerminusItem], dict[tuple[Any, ...], set[int]]]:
    grouped: dict[tuple[Any, ...], list[tuple[int, TerminusItem]]] = {}
    for index, item in enumerate(items):
        key = _shape_key(item)
        if key is not None:
            grouped.setdefault(key, []).append((index, item))

    template_by_key: dict[tuple[Any, ...], TerminusItem] = {}
    grouped_indices: dict[tuple[Any, ...], set[int]] = {}
    for key, indexed_items in grouped.items():
        if len(indexed_items) <= 1:
            continue
        template = indexed_items[0][1]
        compatible_indices = {index for index, member in indexed_items if _clone_matches_item(template, member, {})}
        if len(compatible_indices) <= 1:
            continue
        template_by_key[key] = template
        grouped_indices[key] = compatible_indices
    return template_by_key, grouped_indices


def _name_templates(
    template_by_key: dict[tuple[Any, ...], TerminusItem],
    grouped_indices: dict[tuple[Any, ...], set[int]],
    items: list[TerminusItem],
) -> list[_RenderedTemplate]:
    used: set[str] = set()
    templates: list[_RenderedTemplate] = []
    for index, key in enumerate(sorted(template_by_key, key=lambda item_key: min(grouped_indices[item_key])), start=1):
        template_item = template_by_key[key]
        members = [items[item_index] for item_index in sorted(grouped_indices[key])]
        cls, class_name, id_field, _ = _item_render_info(template_item)
        base = _template_base_name(template_item, members, class_name)
        name = _unique_template_name(base, used, fallback=f"{_snake_case(class_name)}_{index}")
        templates.append(
            _RenderedTemplate(
                name=name,
                cls=cls,
                class_name=class_name,
                item=template_item,
                id_field=id_field,
                first_index=min(grouped_indices[key]),
                members=members,
            )
        )
    return templates


def _clone_templates_by_item_index(
    items: list[TerminusItem],
    templates: list[_RenderedTemplate],
    grouped_indices: dict[tuple[Any, ...], set[int]],
) -> dict[int, _RenderedTemplate]:
    grouped_item_indices = {index for indices in grouped_indices.values() for index in indices}
    clone_templates: dict[int, _RenderedTemplate] = {}
    for index, item in enumerate(items):
        if index in grouped_item_indices or _shape_key(item) is None:
            continue
        candidates = []
        for template in templates:
            if _item_id_field(template.item) != _item_id_field(item):
                continue
            emitted = template.emitted_item()
            differences = _pdr_field_differences(emitted, item)
            if 0 < len(differences) <= _NEAR_DUPLICATE_FIELD_LIMIT and _clone_matches_item(
                emitted, item, _clone_overrides_from_pdr_fields(item, differences)
            ):
                candidates.append((len(differences), template.first_index, template))
        if candidates:
            clone_templates[index] = min(candidates, key=lambda candidate: (candidate[0], candidate[1]))[2]
    return clone_templates


def _render_templates(templates: list[_RenderedTemplate]) -> list[str]:
    lines: list[str] = []
    for template in templates:
        expression = _call_expr(
            template.cls.__name__,
            list(
                _minimal_constructor_kwargs(
                    template.cls,
                    template.item,
                    {"name": template.item.name, template.id_field: getattr(template.item, template.id_field)},
                    id_field=template.id_field,
                    members=template.members,
                ).items()
            ),
            level=0,
        )
        lines.append(f"{template.name} = {expression}")
        lines.append("")
    return lines


def _render_series(template: _RenderedTemplate, items: list[TerminusItem]) -> _RenderedItem:
    section = _item_render_info(template.item)[3]
    pairs = [(getattr(item, "name"), getattr(item, template.id_field)) for item in items]
    return _RenderedItem(
        class_name=template.class_name,
        expression=_series_expr(template.name, pairs, id_field=template.id_field),
        section=section,
        is_preset_numeric_sensor=template.class_name not in {"NumericSensor", "StateSensor", "NumericEffecter", "StateEffecter"},
        item_count=len(items),
    )


def _render_clone(template: _RenderedTemplate, item: TerminusItem) -> _RenderedItem:
    differences = _pdr_field_differences(template.emitted_item(), item)
    overrides = {"name": getattr(item, "name"), template.id_field: getattr(item, template.id_field)}
    overrides.update(_clone_overrides_from_pdr_fields(item, differences))
    return _RenderedItem(
        class_name=template.class_name,
        expression=_call_expr(f"{template.name}.clone", list(overrides.items()), level=0),
        section=_item_render_info(item)[3],
        is_preset_numeric_sensor=template.class_name not in {"NumericSensor", "StateSensor", "NumericEffecter", "StateEffecter"},
    )


_DERIVED_FRU_METADATA = {
    "fru_reported_table_length",
    "fru_reported_record_set_count",
    "fru_reported_record_count",
    "fru_reported_integrity_checksum",
    "fru_table_padding",
}


def _fru_metadata_is_derivable(terminus: Terminus, field_name: str, value: Any) -> bool:
    """True when the model would compute *value* anyway from the FRU records."""
    probe = replace(terminus, **{field_name: None if field_name != "fru_table_padding" else None})
    repository = probe.build().fru_repository
    derived = {
        "fru_reported_table_length": repository.table_length,
        "fru_reported_record_set_count": repository.record_set_count,
        "fru_reported_record_count": repository.record_count,
        "fru_reported_integrity_checksum": repository.integrity_checksum,
        "fru_table_padding": repository.padding_for(repository.encoded_table()),
    }[field_name]
    return derived == value


def _render_terminus(terminus: Terminus, items: list[_RenderedItem], fru_records: list[_RenderedItem]) -> str:
    args: list[tuple[str, Any]] = [("eid", terminus.eid), ("tid", terminus.tid)]
    for field_name in (
        "repository_state",
        "reported_record_count",
        "reported_repository_size",
        "reported_largest_record_size",
        "data_transfer_handle_timeout",
        "auxiliary_record_size",
        "fru_major_version",
        "fru_minor_version",
        "fru_table_maximum_size",
        "fru_reported_table_length",
        "fru_reported_record_set_count",
        "fru_reported_record_count",
        "fru_reported_integrity_checksum",
        "fru_table_padding",
    ):
        value = getattr(terminus, field_name)
        if value == getattr(Terminus(eid=terminus.eid, tid=terminus.tid), field_name):
            continue
        # FRU metadata a device merely restates is derived from the records, so
        # emitting it would freeze the captured numbers in place and make any
        # later edit fail the requester's length and checksum checks.
        if field_name in _DERIVED_FRU_METADATA and _fru_metadata_is_derivable(terminus, field_name, value):
            continue
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
    if fru_records:
        lines.append(f"{_INDENT}fru_records=[")
        for item in fru_records:
            if item.reason is not None:
                lines.append(f"{_INDENT * 2}# Verbatim: {item.reason}.")
            lines.extend(f"{_INDENT * 2}{line}" if line else "" for line in item.expression.splitlines())
            lines[-1] += ","
        lines.append(f"{_INDENT}],")
    lines.append(")")
    return "\n".join(lines)


def _render_item(item: TerminusItem) -> _RenderedItem:
    if isinstance(item, VerbatimRecord):
        return _render_verbatim_record(item)
    cls, class_name, id_field, section = _item_render_info(item)
    return _RenderedItem(
        class_name=class_name,
        expression=_constructor_expr(cls, item, id_field=id_field),
        section=section,
        is_preset_numeric_sensor=cls is not NumericSensor and isinstance(item, NumericSensor),
    )


def _compact_fru_field(field_: Any, encoding_type: int) -> Any:
    """Drop raw_value when the text alone re-encodes to the same bytes.

    A FRU field carries its value twice, and the raw bytes only matter when
    they do not round-trip through the declared encoding. Emitting both for
    every field doubles the FRU section and leaves stale bytes behind the
    moment someone edits the text.
    """
    if not isinstance(field_, FruField) or field_.raw_value is None:
        return field_
    if _field_value_bytes(field_.value, encoding_type, None) == field_.raw_value:
        return FruField(field_type=field_.field_type, value=field_.value)
    return field_


def _render_fru_records(items: list[Any]) -> list[_RenderedItem]:
    rendered: list[_RenderedItem] = []
    for item in items:
        if isinstance(item, VerbatimFruRecord):
            rendered.append(_render_verbatim_fru_record(item))
        elif isinstance(item, FruRecordItem):
            rendered.append(
                _RenderedItem(
                    class_name="FruRecordItem",
                    expression=_call_expr(
                        "FruRecordItem",
                        [
                            ("name", item.name),
                            ("record_set_identifier", item.record_set_identifier),
                            ("record_type", item.record_type),
                            ("encoding_type", item.encoding_type),
                            ("fields", [_compact_fru_field(f, item.encoding_type) for f in item.fields]),
                        ],
                        level=0,
                    ),
                    section="FRU records",
                )
            )
    return rendered


def _render_verbatim_fru_record(item: VerbatimFruRecord) -> _RenderedItem:
    expression = _call_expr(
        "VerbatimFruRecord",
        [
            ("record", _RawExpression(f"fru_record_from_dict({_literal(_verbatim_fru_dict(item), level=2)})")),
            ("reason", item.reason),
        ],
        level=0,
    )
    return _RenderedItem(
        class_name="VerbatimFruRecord",
        expression=expression,
        section="FRU records",
        reason=item.reason,
    )


def _verbatim_fru_dict(item: VerbatimFruRecord) -> dict[str, Any]:
    try:
        return fru_record_to_dict(item.record)
    except TypeError:
        return {"record_set_identifier": 0, "record_type": -1, "data": item.encoded.hex()}


def _item_render_info(item: TerminusItem) -> tuple[type[Any], str, str, str]:
    if isinstance(item, NumericSensor):
        cls = _numeric_sensor_class(item)
        return cls, cls.__name__, "sensor_id", "Numeric sensors"
    if isinstance(item, StateSensor):
        return StateSensor, "StateSensor", "sensor_id", "State sensors"
    if isinstance(item, NumericEffecter):
        return NumericEffecter, "NumericEffecter", "effecter_id", "Effecters"
    if isinstance(item, StateEffecter):
        return StateEffecter, "StateEffecter", "effecter_id", "Effecters"
    msg = f"Unsupported template item: {type(item).__name__}"
    raise TypeError(msg)


def _item_id_field(item: TerminusItem) -> str:
    if isinstance(item, (NumericSensor, StateSensor)):
        return "sensor_id"
    if isinstance(item, (NumericEffecter, StateEffecter)):
        return "effecter_id"
    return ""


def _shape_key(item: TerminusItem) -> tuple[Any, ...] | None:
    if isinstance(item, VerbatimRecord):
        return None
    return (
        _item_id_field(item),
        _item_render_info(item)[1],
        _normalized_record_shape(pdr_to_dict(item.pdr(0))),
        _normalized_auxiliary_shape(item),
    )


def _normalized_auxiliary_shape(item: TerminusItem) -> tuple[Any, ...] | None:
    if not getattr(item, "emit_auxiliary_names", False):
        return None
    record_size = getattr(item, "auxiliary_record_size", None)
    record = _pad_auxiliary_pdr(item.auxiliary_pdr(1), record_size)
    return _normalized_record_shape(pdr_to_dict(record), ignore_auxiliary_names=True)


def _normalized_record_shape(record: Mapping[str, Any], *, ignore_auxiliary_names: bool = False) -> tuple[Any, ...]:
    normalized = {
        key: _normalized_shape_value(value, ignore_auxiliary_names=ignore_auxiliary_names)
        for key, value in record.items()
        if key not in _IGNORED_SHAPE_FIELDS
    }
    return tuple(sorted(normalized.items()))


def _normalized_shape_value(value: Any, *, ignore_auxiliary_names: bool) -> Any:
    if isinstance(value, Mapping):
        normalized_items = []
        for key, item in value.items():
            if ignore_auxiliary_names and key in {"name", "name_bytes"}:
                normalized_items.append((key, ""))
            elif ignore_auxiliary_names and key == "name_data":
                normalized_items.append((key, _name_data_shape(str(value.get("name", "")), item)))
            else:
                normalized_items.append((key, _normalized_shape_value(item, ignore_auxiliary_names=ignore_auxiliary_names)))
        return tuple(sorted(normalized_items))
    if isinstance(value, list):
        return tuple(_normalized_shape_value(item, ignore_auxiliary_names=ignore_auxiliary_names) for item in value)
    if isinstance(value, tuple):
        return tuple(_normalized_shape_value(item, ignore_auxiliary_names=ignore_auxiliary_names) for item in value)
    if isinstance(value, IntEnum):
        return int(value)
    return value


def _name_data_shape(name: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    data = bytes.fromhex(value)
    if data == name.encode("utf-16-le"):
        return "utf-16-le"
    if data == name.encode("utf-16-be"):
        return "utf-16-be"
    return ("raw", data)


def _pdr_field_differences(template: TerminusItem, item: TerminusItem) -> list[str]:
    template_fields = _shape_fields(template)
    item_fields = _shape_fields(item)
    differences = [
        name
        for name in sorted(set(template_fields) | set(item_fields))
        if template_fields.get(name) != item_fields.get(name)
    ]
    return differences


def _shape_fields(item: TerminusItem) -> dict[str, Any]:
    if isinstance(item, VerbatimRecord):
        return {}
    record = pdr_to_dict(item.pdr(0))
    return {
        key: _normalized_shape_value(value, ignore_auxiliary_names=False)
        for key, value in record.items()
        if key not in _IGNORED_SHAPE_FIELDS
    }


def _clone_overrides_from_pdr_fields(item: TerminusItem, fields_to_override: list[str]) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    for name in fields_to_override:
        constructor_name = "data_size" if name == "effecter_data_size" else name
        if not hasattr(item, constructor_name):
            return {}
        overrides[constructor_name] = getattr(item, constructor_name)
    return overrides


def _clone_matches_item(template: TerminusItem, item: TerminusItem, overrides: dict[str, Any]) -> bool:
    if not hasattr(template, "clone"):
        return False
    id_field = _item_id_field(item)
    clone_overrides = {"name": getattr(item, "name"), id_field: getattr(item, id_field)}
    clone_overrides.update(overrides)
    return _item_records_match(item, template.clone(**clone_overrides))


def _template_base_name(template: TerminusItem, members: list[TerminusItem], class_name: str) -> str:
    if isinstance(template, (NumericSensor, NumericEffecter)):
        unit_name = _NUMERIC_UNIT_NAMES.get(int(template.base_unit))
        if unit_name is not None:
            return f"{unit_name}_{'effecter' if isinstance(template, NumericEffecter) else 'sensor'}"
    name_tokens = _common_name_tokens([getattr(member, "name") for member in members])
    if name_tokens:
        return "_".join(name_tokens[:3])
    return _snake_case(class_name)


def _common_name_tokens(names: list[str]) -> list[str]:
    tokenized = [[token for token in _name_tokens(name) if not token.isdigit()] for name in names]
    if not tokenized:
        return []
    common = set(tokenized[0])
    for tokens in tokenized[1:]:
        common &= set(tokens)
    return [token for token in tokenized[0] if token in common]


def _name_tokens(name: str) -> list[str]:
    return [token for token in re.split(r"[^0-9A-Za-z]+", name.lower()) if token]


def _snake_case(name: str) -> str:
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    value = re.sub(r"[^0-9a-zA-Z_]+", "_", value).strip("_")
    if not value or value[0].isdigit():
        value = f"template_{value}"
    return value


def _unique_template_name(base: str, used: set[str], *, fallback: str) -> str:
    candidate = _snake_case(base)
    if candidate in used:
        candidate = _snake_case(fallback)
    suffix = 2
    original = candidate
    while candidate in used:
        candidate = f"{original}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _series_expr(template_name: str, pairs: list[tuple[str, int]], *, id_field: str = "sensor_id") -> str:
    # Repository order interleaves item kinds, so a shape often appears as many
    # short runs. A run of one is not a series worth spelling out over three
    # lines - a plain clone says the same thing on one.
    if len(pairs) == 1:
        name, item_id = pairs[0]
        return f"{template_name}.clone(name={_literal(name)}, {id_field}={_id_literal(int(item_id))})"

    lines = [f"*{template_name}.series(["]
    for name, item_id in pairs:
        lines.append(f"{_INDENT}({_literal(name)}, {_id_literal(int(item_id))}),")
    lines.append("])")
    return "\n".join(lines)


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


def _constructor_expr(
    cls: type[Any],
    item: Any,
    *,
    id_field: str,
    members: list[Any] | None = None,
) -> str:
    required = {"name": item.name, id_field: getattr(item, id_field)}
    kwargs = _minimal_constructor_kwargs(cls, item, required, id_field=id_field, members=members)
    return _call_expr(cls.__name__, list(kwargs.items()), level=0)


def _minimal_constructor_kwargs(
    cls: type[Any],
    item: Any,
    required: dict[str, Any],
    *,
    id_field: str,
    members: list[Any] | None = None,
) -> dict[str, Any]:
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
        if not _item_records_match(item, cls(**trial)):
            continue
        # A template is reduced by checking it still reproduces itself, but its
        # clones inherit the reduced form. Some fields are derived from others
        # when left unset, so a field that is redundant for the template can
        # still be load-bearing for a member that overrides what it derives
        # from.
        if members and not all(_clone_matches_item(cls(**trial), member, {}) for member in members):
            continue
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
    if isinstance(value, (FruField, OpaqueFruField)):
        args = [
            (field.name, getattr(value, field.name))
            for field in fields(value)
            if getattr(value, field.name) is not None or field.default is not None
        ]
        single_line = f"{type(value).__name__}({', '.join(f'{n}={_literal(v)}' for n, v in args)})"
        if len(_INDENT * level) + len(single_line) <= _MAX_LINE_LENGTH:
            return single_line
        return _call_expr(type(value).__name__, args, level=level)
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
