# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pytest

from pymctp.topology import DeviceSpec, MachineSpec, get_machine_spec, list_machines, machine_info, register_machine


def test_registry_register_list_get_and_info() -> None:
    def factory(**options: object) -> MachineSpec:
        return MachineSpec(
            name="unit-machine",
            description=str(options.get("description", "registered")),
            devices=[DeviceSpec(name="hsp1", transport={"type": "fake"}, eid=34)],
        )

    register_machine("unit-machine", factory)

    assert "unit-machine" in list_machines()
    assert get_machine_spec("unit-machine", description="custom").description == "custom"
    assert machine_info("unit-machine") == {
        "name": "unit-machine",
        "description": "registered",
        "device_count": 1,
    }


def test_registry_unknown_name_has_helpful_error() -> None:
    with pytest.raises(KeyError, match="Unknown machine 'definitely-missing'"):
        get_machine_spec("definitely-missing")
