<!--
SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>

SPDX-License-Identifier: MIT
-->

# Generate PLDM PDR models from a capture

`pymctp pldm-from-capture` reads a PLDM packet capture, reconstructs each
terminus' PDR repository and observed sensor readings, and writes one model per
terminus:

```bash
pymctp pldm-from-capture CAPTURE --output DIR [--eid N] [--timezone TZ] [--date YYYY-MM-DD] [--emit {json,python,both}] [--force]
```

Inputs may be pcap files or ASCII tcpdump output. Text captures may also be
journal-wrapped, with each tcpdump line prefixed by an ISO-8601 timestamp.

Options:

- `--output DIR`: required output directory for generated models.
- `--eid N`: restrict output to one EID; repeat it for multiple termini.
- `--timezone TZ`: timezone for text captures; defaults to `UTC`.
- `--date YYYY-MM-DD`: date for text captures whose timestamps have no date.
- `--emit {json,python,both}`: choose JSON capture artifacts, editable Python
  models, or both. The default is `json`.
- `--force`: overwrite existing output files.

## JSON artifact shape

The JSON form is the faithful capture artifact. Each artifact is a JSON object:

```json
{
  "eid": 17,
  "tid": 1,
  "source": "capture.tcpdump.log",
  "repository_info": {
    "record_count": 25,
    "repository_size": 1980,
    "largest_record_size": 105,
    "repository_state": 0,
    "data_transfer_handle_timeout": 0
  },
  "pdrs": [],
  "sensors": {},
  "warnings": []
}
```

`pdrs` contains editable decoded PDR dictionaries when PyMCTP has a model for
the PDR type. Unmodelled or lossy records are stored as opaque records with the
common header fields plus raw hex `data`. Sensor ids under `sensors` are decimal
string keys so the file survives a JSON round trip exactly.

## Python model shape

The Python form is the maintainable model. Import the pieces from
`pymctp.pldm.model` and expose a `Terminus`:

```python
from pymctp.pldm.model import Terminus, TemperatureSensor, VoltageSensor

inlet = TemperatureSensor(name="Inlet Temp", sensor_id=0x1001, warning_high=70, critical_high=80)

terminus = Terminus(
    eid=17,
    tid=1,
    items=[
        inlet,
        inlet.clone(name="Outlet Temp", sensor_id=0x1002),
        VoltageSensor(name="12V Input", sensor_id=0x2001, normal_min=11_400, normal_max=12_600),
    ],
)
```

Use `NumericSensor`, `StateSensor`, `NumericEffecter`, and `StateEffecter` for
fully explicit records. The presets `TemperatureSensor`, `PowerSensor`,
`VoltageSensor`, `CurrentSensor`, and `CounterSensor` fill in common numeric
sensor fields. `clone()` duplicates an item while changing only fields such as
`name` and `sensor_id`.

The model owns the repeated PLDM bookkeeping so the user does not. Record
handles are assigned at build time. The auxiliary-names PDR is generated from
the item's `name`, so the name lives in exactly one place. Adding one item emits
both records in the right order.

Presets also encode units. Voltage and current presets use `unit_modifier=-3`,
so values are milli-volts and milli-amps; forgetting that modifier is wrong by a
factor of one thousand.

## Choosing JSON or Python

Use JSON when you need a byte-for-byte capture artifact. Use Python when you
need a reviewable model that can be edited over time.

For scale, a real device model is 9,033 lines of JSON, and 24 of the 44 fields
on every numeric sensor PDR have the same value across all 120 sensors. Defaults
and `clone()` make the Python form much shorter while still building the same
`PdrRepository` used by the responder.

## Use a model in a machine

Point a PLDM sensor endpoint at a JSON artifact with `pdrs_from`:

```json
{
  "roles": ["pldm-sensor"],
  "role_options": {
    "pldm-sensor": {
      "pdrs_from": "data/pldm-terminus-17.json"
    }
  }
}
```

Relative `pdrs_from` paths resolve against the directory containing the machine
spec that declared them.

Point at a Python model with `pdrs_model`:

```json
{
  "roles": ["pldm-sensor"],
  "role_options": {
    "pldm-sensor": {
      "pdrs_model": "my_board.models:hcp"
    }
  }
}
```

The reference is `module:attribute`. The attribute may be a `Terminus` or a
zero-argument callable returning one. The module must be importable, for example
because the package is installed or on `PYTHONPATH`. `pdrs_model` is not a path
and is preserved verbatim by `dump_machine_spec()` / `load_machine_spec()`.

`pdrs_from` and `pdrs_model` are mutually exclusive. With either form, explicit
`sensors` entries override only matching sensor ids from the loaded model, and
an explicit `pdr_repository` replaces the loaded PDRs.

## VerbatimRecord escape hatch

`VerbatimRecord` carries a decoded PDR or raw PDR bytes through the Python model
without interpreting or rewriting it. You normally see one when a generated
Python model cannot express a captured record without changing its bytes. Keep
it until PyMCTP has a high-level model for that PDR type or field combination.

## Round-trip guard

For every decoded PDR, the command immediately re-encodes it and compares the
result with the captured bytes. If the bytes differ, the record is downgraded to
an opaque JSON record or a Python `VerbatimRecord`. It still replays
byte-for-byte in `GetPDR`; it just is not editable field-by-field.

## Capture requirements

- Capture the whole PDR fetch. An excerpt that starts mid-fetch silently loses
  record handle 0, while later records can still look valid.
- Preserve MCTP fragmentation. A reader that treats one MCTP packet as one PLDM
  message truncates every multi-packet PDR while still seeing
  `transferFlag = StartAndEnd`, which looks like a successful transfer.
