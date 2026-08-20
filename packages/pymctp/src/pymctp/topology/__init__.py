# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Public topology API."""

from __future__ import annotations

from pymctp.topology.builder import MachineBuilder
from pymctp.topology.loader import apply_overrides, dump_machine_spec, load_eid_map, load_machine_spec
from pymctp.topology.loader import parse_override_strings
from pymctp.topology.machine import Machine, MachineBuildError
from pymctp.topology.registry import get_machine_spec, list_machines, machine_info, register_machine
from pymctp.topology.types import DeviceSpec, EidAssignment, EidMap, MachineDefaults, MachineSpec

__all__ = [
    "DeviceSpec",
    "EidAssignment",
    "EidMap",
    "Machine",
    "MachineBuildError",
    "MachineBuilder",
    "MachineDefaults",
    "MachineSpec",
    "apply_overrides",
    "dump_machine_spec",
    "get_machine_spec",
    "list_machines",
    "load_eid_map",
    "load_machine_spec",
    "machine_info",
    "parse_override_strings",
    "register_machine",
]
