# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from pymctp.automaton.manager import SupersocketConfig
from pymctp.cli.machine import machine
from pymctp.topology import DeviceSpec, EidMap, MachineSpec, dump_machine_spec, register_machine


class StubSocket:
    """Socket stub sufficient for building EndpointManager instances without I/O."""

    def __init__(self, name: str) -> None:
        self.id_str = name
        self.closed = False

    def close(self) -> None:
        self.closed = True


@dataclasses.dataclass
class MachineCliFakeConfig(SupersocketConfig):
    """Fake transport config that auto-registers under ``machine-cli-fake``."""

    type = "machine-cli-fake"
    name: str = "fake"
    port: int = 0
    dump_packet: bool = False
    dump_hex: bool = False
    socket: Any | None = dataclasses.field(
        default=None,
        init=False,
        metadata={"serialize": lambda value: None, "deserialize": lambda value: None},
    )

    def __post_init__(self) -> None:
        self.socket = StubSocket(self.name)

    def close_socket(self) -> None:
        assert self.socket is not None
        self.socket.close()


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def fake_spec() -> MachineSpec:
    return MachineSpec(
        name="cli-fake",
        description="Fake CLI machine",
        eids=EidMap({"hsp1": 0x22, "hsp2": 0x23}),
        devices=[
            DeviceSpec(
                name="hsp1",
                transport={"type": "machine-cli-fake", "port": 5558},
                eid_key="hsp1",
                physical_address=0x58,
            ),
            DeviceSpec(
                name="hsp2",
                transport={"type": "machine-cli-fake", "port": 5559},
                eid_key="hsp2",
                physical_address=0x59,
                enabled=False,
            ),
        ],
    )


@pytest.fixture
def registered_fake_machine(fake_spec: MachineSpec) -> Iterator[None]:
    from pymctp.topology import registry as registry_module

    registry_module._machine_registry.pop("cli-fake", None)
    register_machine("cli-fake", lambda **options: fake_spec)
    try:
        yield
    finally:
        registry_module._machine_registry.pop("cli-fake", None)


def test_machine_list_with_registered_fake_machine(runner: CliRunner, registered_fake_machine: None) -> None:
    result = runner.invoke(machine, ["list"])

    assert result.exit_code == 0
    assert "cli-fake" in result.output
    assert "Fake CLI machine" in result.output
    assert "2" in result.output

    json_result = runner.invoke(machine, ["list", "--json"])

    assert json_result.exit_code == 0
    assert '"name": "cli-fake"' in json_result.output
    assert '"device_count": 2' in json_result.output


def test_machine_show_registered_name(runner: CliRunner, registered_fake_machine: None) -> None:
    result = runner.invoke(machine, ["show", "cli-fake"])

    assert result.exit_code == 0
    assert "Machine: cli-fake" in result.output
    assert "hsp1" in result.output
    assert "0x22 (34)" in result.output
    assert "0x58 (88)" in result.output
    assert "machine-cli-fake (port=5558)" in result.output


def test_machine_show_file_with_eid_map_and_set_override(
    runner: CliRunner,
    fake_spec: MachineSpec,
    tmp_path: Path,
) -> None:
    spec_path = tmp_path / "machine.json"
    eid_map_path = tmp_path / "eids.json"
    dump_machine_spec(fake_spec, spec_path)
    eid_map_path.write_text('{"eids": {"hsp1": 42, "hsp2": 43}, "assignments": []}', encoding="utf-8")

    result = runner.invoke(
        machine,
        [
            "show",
            str(spec_path),
            "--eid-map",
            str(eid_map_path),
            "--set",
            "devices.hsp1.transport.port=6000",
        ],
    )

    assert result.exit_code == 0
    assert "0x2A (42)" in result.output
    assert "machine-cli-fake (port=6000)" in result.output

    json_result = runner.invoke(machine, ["show", str(spec_path), "--json"])

    assert json_result.exit_code == 0
    assert '"name": "cli-fake"' in json_result.output


def test_machine_validate_good_and_duplicate_eid(
    runner: CliRunner,
    fake_spec: MachineSpec,
    tmp_path: Path,
) -> None:
    good_path = tmp_path / "good.json"
    bad_path = tmp_path / "bad.json"
    duplicate = MachineSpec(
        name="duplicate",
        devices=[
            DeviceSpec(name="hsp1", transport={"type": "machine-cli-fake"}, eid=0x22),
            DeviceSpec(name="hsp2", transport={"type": "machine-cli-fake"}, eid=0x22),
        ],
    )
    dump_machine_spec(fake_spec, good_path)
    dump_machine_spec(duplicate, bad_path)

    good = runner.invoke(machine, ["validate", str(good_path)])
    bad = runner.invoke(machine, ["validate", str(bad_path)])

    assert good.exit_code == 0
    assert "is valid" in good.output
    assert bad.exit_code != 0
    assert "Duplicate EID" in bad.output


def test_machine_run_no_start_builds_and_exits_cleanly(
    runner: CliRunner,
    registered_fake_machine: None,
) -> None:
    result = runner.invoke(machine, ["run", "cli-fake", "--no-start"])

    assert result.exit_code == 0
    assert "Built machine 'cli-fake' without starting endpoints." in result.output
    assert "hsp1: EID 0x22 (34)" in result.output
    assert "Machine summary:" in result.output
    assert "hsp1 processed 0 packets" in result.output


def test_unknown_machine_name_is_helpful(runner: CliRunner) -> None:
    result = runner.invoke(machine, ["show", "definitely-missing"])

    assert result.exit_code != 0
    assert "not a registered machine" in result.output
    assert "Available machines" in result.output
