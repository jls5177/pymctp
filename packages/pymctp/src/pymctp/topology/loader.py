# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Load, dump, and override machine topology specs."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pymctp.topology.types import EidMap, MachineSpec


def load_machine_spec(path_or_str: str | Path) -> MachineSpec:
    """Load a machine spec from a JSON/YAML file path or serialized string."""

    source_dir = _source_dir_for(path_or_str)
    data = _load_mapping(path_or_str)
    spec = MachineSpec.from_dict(data)
    if source_dir is not None:
        setattr(spec, "_source_dir", source_dir)
    return spec


def dump_machine_spec(spec: MachineSpec, path: str | Path | None = None) -> str | None:
    """Dump a machine spec as JSON or YAML; return JSON when *path* is omitted."""

    data = spec.to_dict()
    if path is None:
        return json.dumps(data, indent=2, sort_keys=True)
    output_path = Path(path)
    if output_path.suffix.lower() in {".yaml", ".yml"}:
        yaml = _import_yaml_for_path(output_path)
        text = yaml.safe_dump(data, sort_keys=True)
    else:
        text = json.dumps(data, indent=2, sort_keys=True)
    output_path.write_text(text, encoding="utf-8")
    return None


def load_eid_map(path: str | Path) -> EidMap:
    """Load an :class:`EidMap` from JSON or YAML."""

    data = _load_mapping(path)
    return EidMap.from_dict(data)


def parse_override_strings(overrides: Sequence[str]) -> dict[str, Any]:
    """Parse dotted ``key=value`` override strings into a nested mapping."""

    parsed: dict[str, Any] = {}
    for item in overrides:
        key, separator, raw_value = item.partition("=")
        if not separator or not key:
            msg = f"Override {item!r} must be in key=value form"
            raise ValueError(msg)
        _set_nested(parsed, key.split("."), _coerce_value(raw_value))
    return parsed


def apply_overrides(spec: MachineSpec, overrides: Mapping[str, Any] | Sequence[str]) -> MachineSpec:
    """Return a new machine spec with dotted-key overrides applied."""

    if not isinstance(overrides, Mapping):
        overrides = parse_override_strings(overrides)
    data = spec.to_dict()
    for key, value in _flatten_overrides(overrides).items():
        _apply_override(data, key.split("."), value)
    updated = MachineSpec.from_dict(data)
    source_dir = getattr(spec, "_source_dir", None)
    if source_dir is not None:
        setattr(updated, "_source_dir", source_dir)
    return updated


def _source_dir_for(path_or_str: str | Path) -> Path | None:
    if isinstance(path_or_str, Path):
        return path_or_str.resolve().parent
    possible_path = Path(path_or_str)
    return possible_path.resolve().parent if possible_path.exists() else None


def _load_mapping(path_or_str: str | Path) -> dict[str, Any]:
    if isinstance(path_or_str, Path):
        return _load_file(path_or_str)
    possible_path = Path(path_or_str)
    if possible_path.exists():
        return _load_file(possible_path)
    text = path_or_str.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        yaml = _import_yaml_for_string()
        data = yaml.safe_load(text)
    if not isinstance(data, dict):
        msg = f"Expected top-level mapping, got {type(data).__name__}"
        raise ValueError(msg)
    return data


def _load_file(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")
    if suffix == ".json":
        data = json.loads(text)
    elif suffix in {".yaml", ".yml"}:
        yaml = _import_yaml_for_path(path)
        data = yaml.safe_load(text)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            yaml = _import_yaml_for_path(path)
            data = yaml.safe_load(text)
    if not isinstance(data, dict):
        msg = f"Expected top-level mapping in {path}, got {type(data).__name__}"
        raise ValueError(msg)
    return data


def _import_yaml_for_path(path: Path) -> Any:
    try:
        import yaml
    except ImportError as exc:
        msg = f"YAML support requires PyYAML. Install it with: pip install pyyaml (needed for {path})"
        raise RuntimeError(msg) from exc
    return yaml


def _import_yaml_for_string() -> Any:
    try:
        import yaml
    except ImportError as exc:
        msg = "YAML support requires PyYAML. Install it with: pip install pyyaml"
        raise RuntimeError(msg) from exc
    return yaml


def _coerce_value(value: str) -> Any:
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        return int(value, 0)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _set_nested(target: dict[str, Any], parts: list[str], value: Any) -> None:
    current = target
    for part in parts[:-1]:
        next_value = current.setdefault(part, {})
        if not isinstance(next_value, dict):
            msg = f"Cannot nest override through non-mapping key {part!r}"
            raise ValueError(msg)
        current = next_value
    current[parts[-1]] = value


def _flatten_overrides(overrides: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in overrides.items():
        full_key = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping):
            flattened.update(_flatten_overrides(value, full_key))
        else:
            flattened[full_key] = value
    return flattened


def _apply_override(data: dict[str, Any], parts: list[str], value: Any) -> None:
    if not parts:
        return
    if parts[0] == "devices":
        _apply_device_override(data, parts, value)
        return
    if parts[0] == "eids" and len(parts) == 2:
        data.setdefault("eids", {}).setdefault("eids", {})[parts[1]] = value
        return
    if parts[0] == "defaults" and len(parts) == 2 and parts[1] in {"count", "timeout", "bg"}:
        data.setdefault("defaults", {}).setdefault("thread_kwargs", {})[parts[1]] = value
        return
    _set_nested(data, parts, value)


def _apply_device_override(data: dict[str, Any], parts: list[str], value: Any) -> None:
    if len(parts) < 3:
        msg = "Device overrides must use devices.<name>.<field>"
        raise ValueError(msg)
    device_name = parts[1]
    for device in data.get("devices", []):
        if device.get("name") == device_name:
            _set_nested(device, parts[2:], value)
            return
    known = ", ".join(device.get("name", "<unnamed>") for device in data.get("devices", [])) or "<none>"
    msg = f"Unknown device {device_name!r} in override. Available devices: {known}"
    raise KeyError(msg)
