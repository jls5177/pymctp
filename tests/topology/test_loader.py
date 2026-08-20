# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

from pathlib import Path

from pymctp.topology import DeviceSpec, EidMap, MachineSpec
from pymctp.topology.loader import apply_overrides, dump_machine_spec, load_eid_map, load_machine_spec
from pymctp.topology.loader import parse_override_strings


def test_json_string_round_trip() -> None:
    spec = MachineSpec(
        name="roundtrip",
        eids=EidMap({"hsp1": 34}),
        devices=[DeviceSpec(name="hsp1", transport={"type": "fake", "port": 1})],
    )

    dumped = dump_machine_spec(spec)

    assert dumped is not None
    assert load_machine_spec(dumped) == spec


def test_json_file_round_trip_and_eid_map_load() -> None:
    directory = Path(__file__).parent
    spec_path = directory / ".generated_machine.json"
    eids_path = directory / ".generated_eids.json"
    spec = MachineSpec(
        name="file-roundtrip",
        eids=EidMap({"hsp1": 34}),
        devices=[DeviceSpec(name="hsp1", transport={"type": "fake", "port": 1})],
    )
    try:
        dump_machine_spec(spec, spec_path)
        eids_path.write_text('{"eids": {"hsp1": 34}, "assignments": []}', encoding="utf-8")

        assert load_machine_spec(spec_path) == spec
        assert load_eid_map(eids_path) == EidMap({"hsp1": 34})
    finally:
        spec_path.unlink(missing_ok=True)
        eids_path.unlink(missing_ok=True)


def test_override_parsing_coercion_and_application() -> None:
    spec = MachineSpec(
        name="overrides",
        eids=EidMap({"hsp1": 34}),
        devices=[DeviceSpec(name="hsp1", transport={"type": "fake", "port": 1})],
    )

    overrides = parse_override_strings(
        [
            "devices.hsp1.transport.port=0x15df",
            "devices.hsp1.transport.dump_packet=false",
            "eids.hsp1=0x22",
            "defaults.timeout=12.5",
        ]
    )
    updated = apply_overrides(spec, overrides)

    assert updated.device("hsp1").transport["port"] == 5599
    assert updated.device("hsp1").transport["dump_packet"] is False
    assert updated.eids["hsp1"] == 34
    assert updated.defaults.thread_kwargs["timeout"] == 12.5
