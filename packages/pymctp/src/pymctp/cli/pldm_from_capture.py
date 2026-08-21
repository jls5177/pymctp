# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Build editable PLDM terminus models from packet captures."""

from __future__ import annotations

import json
import math
import pathlib
from collections.abc import Iterable
from datetime import datetime
from typing import Any

import click

from pymctp.layers.mctp.pldm.pdr import (
    PDR_TYPE_ENTITY_AUXILIARY_NAMES,
    PDR_TYPE_NUMERIC_SENSOR,
    PDR_TYPE_SENSOR_AUXILIARY_NAMES,
    OpaquePdr,
    RawPdr,
    decode_pdr,
    pdr_to_dict,
)
from pymctp.pldm.capture import TerminusCapture, extract_pldm, read_capture
from pymctp.pldm.model.emitter import emit_python_module


_REPOSITORY_INFO_KEYS = (
    "record_count",
    "repository_size",
    "largest_record_size",
    "repository_state",
    "data_transfer_handle_timeout",
)

#: DSP0248 PDR type values. Getting these wrong mislabels the summary a user
#: reads when deciding what a captured device actually exposes.
_PDR_TYPE_NAMES = {
    1: "Terminus Locator",
    2: "Numeric Sensor",
    3: "Numeric Sensor Initialization",
    4: "State Sensor",
    5: "State Sensor Initialization",
    6: "Sensor Auxiliary Names",
    7: "OEM Unit",
    8: "OEM State Set",
    9: "Numeric Effecter",
    10: "Numeric Effecter Initialization",
    11: "State Effecter",
    12: "State Effecter Initialization",
    13: "Effecter Auxiliary Names",
    14: "Effecter OEM Semantic",
    15: "Entity Association",
    16: "Entity Auxiliary Names",
    17: "OEM Entity ID",
    18: "Interrupt Association",
    19: "Event Log",
    20: "FRU Record Set",
    21: "Compact Numeric Sensor",
}

_THRESHOLD_FIELDS = ("warning_high", "warning_low", "critical_high", "critical_low")
_THRESHOLD_BITS = {"warning_high": 0x01, "warning_low": 0x02, "critical_high": 0x04, "critical_low": 0x08}


@click.command()
@click.argument("capture", type=click.Path(exists=True, path_type=pathlib.Path))
@click.option(
    "--output",
    "output_dir",
    required=True,
    type=click.Path(file_okay=False, dir_okay=True, path_type=pathlib.Path),
    help="Directory that receives generated terminus artifacts.",
)
@click.option("--eid", "eids", multiple=True, type=click.IntRange(0, 255), help="Restrict output to one EID.")
@click.option("--timezone", default="UTC", show_default=True, help="Timezone for text-capture timestamps.")
@click.option("--date", default=None, help="Date for text captures without dates (YYYY-MM-DD).")
@click.option("--force", is_flag=True, help="Overwrite existing artifacts.")
@click.option(
    "--emit",
    type=click.Choice(("json", "python", "both")),
    default="json",
    show_default=True,
    help="Artifact format to write.",
)
def pldm_from_capture(
    capture: pathlib.Path,
    output_dir: pathlib.Path,
    eids: tuple[int, ...],
    timezone: str,
    date: str | None,
    force: bool,
    emit: str,
) -> None:
    """Convert a PLDM packet CAPTURE into editable terminus artifacts."""
    if date is not None:
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except ValueError as exc:
            raise click.ClickException(f"invalid --date {date!r}; expected YYYY-MM-DD") from exc

    termini = extract_pldm(read_capture(capture, timezone=timezone, is_dst=False, date=date))
    if not termini:
        raise click.ClickException("no PLDM terminus found in capture")

    selected_eids = set(eids)
    selected = {eid: terminus for eid, terminus in sorted(termini.items()) if not selected_eids or eid in selected_eids}
    if not selected:
        requested = ", ".join(str(eid) for eid in sorted(selected_eids))
        raise click.ClickException(f"no PLDM terminus found for requested EID(s): {requested}")

    output_dir.mkdir(parents=True, exist_ok=True)
    targets = {eid: _targets(output_dir, eid, emit) for eid in selected}
    existing = [path for paths in targets.values() for path in paths if path.exists()]
    if existing and not force:
        names = ", ".join(str(path) for path in existing)
        raise click.ClickException(f"refusing to overwrite existing artifact(s): {names}; pass --force to replace")

    for eid, terminus in selected.items():
        decoded_pdrs = _decoded_pdrs(terminus.pdr_records)
        artifact = _artifact(capture.name, terminus, decoded_pdrs)
        written_paths: list[pathlib.Path] = []
        json_path = output_dir / f"pldm-terminus-{eid}.json"
        python_path = output_dir / f"pldm_terminus_{eid}.py"
        if emit in {"json", "both"}:
            json_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
            written_paths.append(json_path)
        if emit in {"python", "both"}:
            python_path.write_text(emit_python_module(artifact).code, encoding="utf-8")
            written_paths.append(python_path)
        _print_summary(terminus, decoded_pdrs, written_paths)


def _targets(output_dir: pathlib.Path, eid: int, emit: str) -> list[pathlib.Path]:
    targets = []
    if emit in {"json", "both"}:
        targets.append(output_dir / f"pldm-terminus-{eid}.json")
    if emit in {"python", "both"}:
        targets.append(output_dir / f"pldm_terminus_{eid}.py")
    return targets


def _decoded_pdrs(raw_records: Iterable[bytes]) -> list[tuple[Any, dict[str, Any]]]:
    decoded: list[tuple[Any, dict[str, Any]]] = []
    for raw_record in raw_records:
        record = decode_pdr(raw_record)
        decoded.append((record, pdr_to_dict(record)))
    return decoded


def _artifact(
    source: str,
    terminus: TerminusCapture,
    decoded_pdrs: list[tuple[Any, dict[str, Any]]],
) -> dict[str, Any]:
    return {
        "eid": terminus.eid,
        "tid": terminus.tid,
        "source": source,
        "repository_info": _repository_info(terminus.repository_info),
        "pdrs": [pdr_dict for _, pdr_dict in decoded_pdrs],
        "sensors": _sensors(terminus, decoded_pdrs),
        "warnings": list(terminus.warnings),
    }


def _repository_info(repository_info: dict[str, Any] | None) -> dict[str, Any] | None:
    if repository_info is None:
        return None
    return {key: repository_info.get(key) for key in _REPOSITORY_INFO_KEYS}


def _sensors(
    terminus: TerminusCapture,
    decoded_pdrs: list[tuple[Any, dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    thresholds = _thresholds_by_sensor(decoded_pdrs)
    sensors: dict[str, dict[str, Any]] = {}
    for sensor_id in sorted(terminus.sensor_readings):
        data_size = int(terminus.sensor_data_sizes.get(sensor_id, 0))
        sensors[str(sensor_id)] = {
            "data_size": data_size,
            "simulation": _simulation(terminus.sensor_readings[sensor_id], data_size, thresholds.get(sensor_id, {})),
        }
    return sensors


def _thresholds_by_sensor(decoded_pdrs: list[tuple[Any, dict[str, Any]]]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for record, pdr_dict in decoded_pdrs:
        if int(pdr_dict.get("pdr_type", -1)) != PDR_TYPE_NUMERIC_SENSOR:
            continue
        sensor_id = pdr_dict.get("sensor_id")
        if sensor_id is None:
            continue
        supported = pdr_dict.get("supported_thresholds")
        result[int(sensor_id)] = {
            field: _json_number(getattr(record, field, pdr_dict.get(field)))
            if supported is None or int(supported) & _THRESHOLD_BITS[field]
            else None
            for field in _THRESHOLD_FIELDS
        }
    return result


def _simulation(readings: list[float], data_size: int, thresholds: dict[str, Any]) -> dict[str, Any]:
    minimum = min(readings)
    maximum = max(readings)
    if minimum == maximum:
        minimum, maximum = _widen_constant_reading(minimum, data_size)
    step = _step_for_range(minimum, maximum)
    return {
        "minimum": _json_number(minimum),
        "maximum": _json_number(maximum),
        "step": _json_number(step),
        "warning_high": thresholds.get("warning_high"),
        "warning_low": thresholds.get("warning_low"),
        "critical_high": thresholds.get("critical_high"),
        "critical_low": thresholds.get("critical_low"),
    }


def _widen_constant_reading(value: float, data_size: int) -> tuple[float, float]:
    """Expand a single observed value by ±5% (at least one raw count), clamped to the sensor data size."""
    span = max(1, math.ceil(abs(value) * 0.05))
    minimum = value - span
    maximum = value + span
    bounds = _sensor_bounds(data_size)
    if bounds is None:
        return minimum, maximum

    lower, upper = bounds
    if minimum < lower:
        maximum = min(upper, value + ((lower - minimum) + span))
        minimum = lower
    if maximum > upper:
        minimum = max(lower, value - ((maximum - upper) + span))
        maximum = upper
    if minimum == maximum:
        maximum = min(upper, minimum + 1)
        minimum = max(lower, maximum - 1)
    return minimum, maximum


def _sensor_bounds(data_size: int) -> tuple[int, int] | None:
    return {
        0: (0, 0xFF),
        1: (-0x80, 0x7F),
        2: (0, 0xFFFF),
        3: (-0x8000, 0x7FFF),
        4: (0, 0xFFFFFFFF),
        5: (-0x80000000, 0x7FFFFFFF),
    }.get(data_size)


def _step_for_range(minimum: float, maximum: float) -> float:
    width = abs(maximum - minimum)
    if width <= 20:
        return 1
    return max(1, math.ceil(width / 20))


def _json_number(value: Any) -> Any:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _print_summary(
    terminus: TerminusCapture,
    decoded_pdrs: list[tuple[Any, dict[str, Any]]],
    output_paths: list[pathlib.Path],
) -> None:
    opaque_count = sum(isinstance(record, (OpaquePdr, RawPdr)) for record, _ in decoded_pdrs)
    structured_count = len(decoded_pdrs) - opaque_count

    click.echo(f"Terminus EID {terminus.eid} (TID {_format_tid(terminus.tid)})")
    if len(output_paths) == 1:
        click.echo(f"  Output: {output_paths[0]}")
    else:
        click.echo("  Outputs:")
        for output_path in output_paths:
            click.echo(f"    {output_path}")
    if terminus.repository_info is None:
        click.echo(f"  Repository: not observed; recovered {len(decoded_pdrs)} PDR record(s)")
    else:
        expected = terminus.repository_info.get("record_count")
        click.echo(f"  Repository: expected {expected} record(s); recovered {len(decoded_pdrs)}")
    click.echo(f"  PDRs: {structured_count} decoded, {opaque_count} opaque")
    _print_pdr_table(decoded_pdrs)
    _print_sensor_summary(terminus)
    if terminus.warnings:
        click.echo("  WARNINGS:")
        for warning in terminus.warnings:
            click.echo(f"    WARNING: {warning}")
    click.echo()


def _format_tid(tid: int | None) -> str:
    return "not observed" if tid is None else str(tid)


def _print_pdr_table(decoded_pdrs: list[tuple[Any, dict[str, Any]]]) -> None:
    if not decoded_pdrs:
        click.echo("  PDR table: (none)")
        return
    rows = [
        (
            str(pdr_dict.get("record_handle", "")),
            f"{pdr_dict.get('pdr_type', '')} ({_pdr_type_name(pdr_dict)})",
            _pdr_display_name(pdr_dict),
            "opaque" if isinstance(record, (OpaquePdr, RawPdr)) else "decoded",
        )
        for record, pdr_dict in decoded_pdrs
    ]
    _print_table(("Handle", "Type", "Name", "Decode"), rows, indent="  ")


def _pdr_type_name(pdr_dict: dict[str, Any]) -> str:
    pdr_type = int(pdr_dict.get("pdr_type", -1))
    return _PDR_TYPE_NAMES.get(pdr_type, "Unknown")


def _pdr_display_name(pdr_dict: dict[str, Any]) -> str:
    if int(pdr_dict.get("pdr_type", -1)) == PDR_TYPE_SENSOR_AUXILIARY_NAMES:
        return _first_sensor_aux_name(pdr_dict)
    if int(pdr_dict.get("pdr_type", -1)) == PDR_TYPE_ENTITY_AUXILIARY_NAMES:
        return _first_name(pdr_dict.get("names", []))
    if "sensor_id" in pdr_dict:
        return f"sensor_id={pdr_dict['sensor_id']}"
    if "eid" in pdr_dict and pdr_dict["eid"] is not None:
        return f"eid={pdr_dict['eid']}"
    return ""


def _first_sensor_aux_name(pdr_dict: dict[str, Any]) -> str:
    for sensor in pdr_dict.get("sensors", []):
        name = _first_name(sensor.get("names", []))
        if name:
            return name
    return ""


def _first_name(names: list[dict[str, Any]]) -> str:
    for name in names:
        value = name.get("name")
        if value:
            return str(value)
    return ""


def _print_sensor_summary(terminus: TerminusCapture) -> None:
    if not terminus.sensor_readings:
        click.echo("  Sensors: none with captured readings")
        return
    click.echo(f"  Sensors: {len(terminus.sensor_readings)} with captured readings")
    for sensor_id in sorted(terminus.sensor_readings):
        readings = terminus.sensor_readings[sensor_id]
        data_size = terminus.sensor_data_sizes.get(sensor_id)
        click.echo(
            f"    {sensor_id}: data_size={data_size}, readings={len(readings)}, "
            f"observed={_json_number(min(readings))}..{_json_number(max(readings))}"
        )


def _print_table(headers: tuple[str, ...], rows: list[tuple[str, ...]], *, indent: str = "") -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    click.echo(indent + "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    click.echo(indent + "  ".join("-" * width for width in widths))
    for row in rows:
        click.echo(indent + "  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))
