# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

from pymctp.topology import DeviceSpec, EidMap, MachineBuilder, MachineDefaults, MachineSpec


def test_builder_produces_hand_written_equivalent_spec() -> None:
    built = (
        MachineBuilder("l4a40", description="example")
        .defaults(timeout=1800, dump_packet=True, host="localhost")
        .eids({"hsp1": 34})
        .device(
            "hsp1",
            transport={"type": "i2c-stream", "port": 5570, "master": True, "target_address": 0x12},
            physical_address=0x58,
            msg_types=["CTRL", "PLDM"],
            roles=["simple"],
        )
        .build()
    )
    expected = MachineSpec(
        name="l4a40",
        description="example",
        eids=EidMap({"hsp1": 34}),
        defaults=MachineDefaults(thread_kwargs={"count": 0, "timeout": 1800, "bg": False}, host="localhost"),
        devices=[
            DeviceSpec(
                name="hsp1",
                transport={"type": "i2c-stream", "port": 5570, "master": True, "target_address": 0x12},
                physical_address=0x58,
                supported_msg_types=["CTRL", "PLDM"],
                roles=["simple"],
            )
        ],
    )

    assert built == expected


def test_devices_bulk_helper_uses_index_and_name() -> None:
    spec = (
        MachineBuilder("bulk")
        .eids({"hsp1": 34, "hsp2": 35})
        .devices(
            ["hsp1", "hsp2"],
            lambda index, name: {"type": "i2c-stream", "port": 5570 + index, "name": name.upper()},
            physical_address=0x58,
        )
        .build()
    )

    assert spec.device_names() == ["hsp1", "hsp2"]
    assert spec.device("hsp1").transport["port"] == 5570
    assert spec.device("hsp2").transport["port"] == 5571
