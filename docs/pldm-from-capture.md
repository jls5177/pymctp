<!--
SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>

SPDX-License-Identifier: MIT
-->

# Generate PLDM PDR models from a capture

`pymctp pldm-from-capture` reads a PLDM packet capture, reconstructs each
terminus' PDR repository and observed sensor readings, and writes one JSON
artifact per terminus:

```bash
pymctp pldm-from-capture CAPTURE --output DIR [--eid N] [--timezone TZ] [--date YYYY-MM-DD] [--force]
```

Inputs may be pcap files or ASCII tcpdump output. Text captures may also be
journal-wrapped, with each tcpdump line prefixed by an ISO-8601 timestamp.

Options:

- `--output DIR`: required output directory for `pldm-terminus-<eid>.json`.
- `--eid N`: restrict output to one EID; repeat it for multiple termini.
- `--timezone TZ`: timezone for text captures; defaults to `UTC`.
- `--date YYYY-MM-DD`: date for text captures whose timestamps have no date.
- `--force`: overwrite existing output files.

## Artifact shape

Each artifact is a JSON object:

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

## Round-trip guard

For every decoded PDR, the command immediately re-encodes it and compares the
result with the captured bytes. If the bytes differ, the record is downgraded to
an opaque record. An opaque record still replays byte-for-byte in `GetPDR`; it
just is not editable field-by-field.

## Use the artifact in a machine

Point a PLDM sensor endpoint at the artifact with the `pdrs_from` role option:

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
spec that declared them. Explicit `sensors` entries override only matching sensor
ids from the artifact, and an explicit `pdr_repository` replaces the file's PDRs.

## Capture requirements

- Capture the whole PDR fetch. An excerpt that starts mid-fetch silently loses
  record handle 0, while later records can still look valid.
- Preserve MCTP fragmentation. A reader that treats one MCTP packet as one PLDM
  message truncates every multi-packet PDR while still seeing
  `transferFlag = StartAndEnd`, which looks like a successful transfer.
