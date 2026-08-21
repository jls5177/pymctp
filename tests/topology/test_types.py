# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from pymctp.automaton.manager import EndpointConfig, SupersocketConfig
from pymctp.topology.types import DeviceSpec, EidMap, MachineSpec


class FakeSocket:
    def __init__(self, name: str) -> None:
        self.id_str = name
        self.closed = False

    def close(self) -> None:
        self.closed = True


@dataclasses.dataclass
class TopologyFakeConfig(SupersocketConfig):
    type = "topology-fake"
    name: str = "fake"
    dump_packet: bool = False
    dump_hex: bool = False
    socket: Any | None = dataclasses.field(
        default=None,
        init=False,
        metadata={"serialize": lambda value: None, "deserialize": lambda value: None},
    )

    def __post_init__(self) -> None:
        self.socket = FakeSocket(self.name)

    def close_socket(self) -> None:
        self.socket.close()


def test_eid_map_lookup_merge_and_error_message() -> None:
    eids = EidMap({"bmc": 8})

    assert eids["bmc"] == 8
    assert eids.get("missing") is None
    assert eids.merged_with({"bmc": 9, "hsp1": 34}).eids == {"bmc": 9, "hsp1": 34}

    with pytest.raises(KeyError, match="Available EID keys: bmc"):
        _ = eids["hsp1"]


def test_device_to_endpoint_config_is_accepted_by_endpoint_config() -> None:
    spec = MachineSpec(
        name="unit",
        eids=EidMap({"hsp1": 34}),
        devices=[
            DeviceSpec(
                name="hsp1",
                transport={"type": "topology-fake"},
                physical_address=0x58,
                supported_msg_types=["CTRL", "PLDM"],
                roles=["simple"],
            )
        ],
    )

    raw = spec.device("hsp1").to_endpoint_config(spec, spec.eids)
    parsed = EndpointConfig.from_dict(raw)

    assert raw["context"]["physical_address"] == {"address": 0x58}
    assert raw["config"]["name"] == "hsp1"
    assert parsed.name == "hsp1"
    assert parsed.context.assigned_eid == 34
    assert parsed.context.physical_address.address == 0x58
    assert parsed.config.socket.id_str == "hsp1"


def test_device_omits_physical_address_when_none() -> None:
    spec = MachineSpec(
        name="unit",
        eids=EidMap({"hcp0": 38}),
        devices=[DeviceSpec(name="hcp0", transport={"type": "topology-fake"})],
    )

    raw = spec.device("hcp0").to_endpoint_config(spec, spec.eids)

    assert "physical_address" not in raw["context"]


def test_validate_catches_duplicate_names_duplicate_eids_unknown_downstream_and_missing_eid() -> None:
    with pytest.raises(ValueError, match="Duplicate device names"):
        MachineSpec(
            name="dupe-name",
            eids=EidMap({"a": 1}),
            devices=[
                DeviceSpec(name="a", transport={"type": "topology-fake"}),
                DeviceSpec(name="a", transport={"type": "topology-fake"}),
            ],
        ).validate()

    with pytest.raises(ValueError, match="Duplicate EID 1"):
        MachineSpec(
            name="dupe-eid",
            devices=[
                DeviceSpec(name="a", transport={"type": "topology-fake"}, eid=1),
                DeviceSpec(name="b", transport={"type": "topology-fake"}, eid=1),
            ],
        ).validate()

    with pytest.raises(ValueError, match="unknown downstream device"):
        MachineSpec(
            name="bad-downstream",
            devices=[DeviceSpec(name="a", transport={"type": "topology-fake"}, eid=1, downstream=["missing"])],
        ).validate()

    with pytest.raises(ValueError, match="Device 'a' could not resolve EID key 'missing'"):
        MachineSpec(
            name="missing-eid",
            eids=EidMap({"other": 1}),
            devices=[DeviceSpec(name="a", transport={"type": "topology-fake"}, eid_key="missing")],
        ).validate()


def test_validate_warns_when_vdpci_is_offered_without_a_capability_set(caplog) -> None:
    """An endpoint that offers VDPCI but declares no vendor capability set fails discovery.

    ``GetVendorDefinedMessageSupport`` answers ERROR_INVALID_DATA when
    ``supported_vdm_msg_types`` is empty, so a bus owner following up on the
    advertised VDPCI message type gets an error instead of the vendor id.
    """
    spec = MachineSpec(
        name="vdpci-no-caps",
        eids=EidMap({"a": 1}),
        devices=[
            DeviceSpec(
                name="a",
                transport={"type": "topology-fake"},
                supported_msg_types=["CTRL", "VDPCI"],
            )
        ],
    )

    with caplog.at_level("WARNING"):
        spec.validate()

    assert "supported_vdm_msg_types" in caplog.text


def test_validate_is_quiet_when_vdpci_declares_a_capability_set(caplog) -> None:
    spec = MachineSpec(
        name="vdpci-with-caps",
        eids=EidMap({"a": 1}),
        devices=[
            DeviceSpec(
                name="a",
                transport={"type": "topology-fake"},
                supported_msg_types=["CTRL", "VDPCI"],
                supported_vdm_msg_types=[{"vendor_id": 0x1414, "command_set_type": 0x04}],
            )
        ],
    )

    with caplog.at_level("WARNING"):
        spec.validate()

    assert "supported_vdm_msg_types" not in caplog.text


def test_validate_does_not_require_capability_sets_without_vdpci(caplog) -> None:
    spec = MachineSpec(
        name="no-vdpci",
        eids=EidMap({"a": 1}),
        devices=[
            DeviceSpec(name="a", transport={"type": "topology-fake"}, supported_msg_types=["CTRL", "PLDM"])
        ],
    )

    with caplog.at_level("WARNING"):
        spec.validate()

    assert "supported_vdm_msg_types" not in caplog.text
