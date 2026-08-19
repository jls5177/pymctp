# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the pluggable socket-config registry in manager.py.

A separate package can add a new endpoint transport by subclassing
:class:`SupersocketConfig` (which auto-registers it) — without editing
manager.py. ``EndpointConfig`` then (de)serializes the new type via the
registry.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from pymctp.automaton.manager import (
    EndpointConfig,
    SupersocketConfig,
    deserialize_supersocket,
    get_config_type,
    register_config_type,
    registered_config_types,
    serialize_supersocket,
)


def test_builtin_configs_are_registered():
    reg = registered_config_types()
    for t in ("socket", "i3c-socket", "i3c-stream", "i2c-stream", "aardvark", "chardev", "tty"):
        assert get_config_type(t) is not None
        assert t in reg


def test_subclassing_auto_registers_by_type():
    @dataclasses.dataclass()
    class _PluginConfig(SupersocketConfig):
        type = "unit-test-plugin"
        host: str = "h"
        socket: Any | None = dataclasses.field(
            default=None,
            init=False,
            metadata={"serialize": lambda x: None, "deserialize": lambda x: None},
        )

        def __post_init__(self):
            self.socket = f"SOCK({self.host})"

        def close_socket(self):
            pass

    assert get_config_type("unit-test-plugin") is _PluginConfig


def test_register_config_type_explicitly():
    @dataclasses.dataclass()
    class _Manual(SupersocketConfig):
        # no class-level ``type`` -> not auto-registered
        host: str = "h"
        socket: Any | None = dataclasses.field(
            default=None,
            init=False,
            metadata={"serialize": lambda x: None, "deserialize": lambda x: None},
        )

    assert get_config_type("manual-type") is None
    register_config_type("manual-type", _Manual)
    assert get_config_type("manual-type") is _Manual


def test_endpoint_config_deserializes_registered_plugin_type():
    @dataclasses.dataclass()
    class _PluginConfig2(SupersocketConfig):
        type = "unit-test-plugin2"
        host: str = "h"
        socket: Any | None = dataclasses.field(
            default=None,
            init=False,
            metadata={"serialize": lambda x: None, "deserialize": lambda x: None},
        )

        def __post_init__(self):
            self.socket = f"SOCK({self.host})"

        def close_socket(self):
            pass

    ec = EndpointConfig.from_dict(
        {
            "context": {"physical_address": {"address": 0x10}},
            "config": {"type": "unit-test-plugin2", "host": "xyz"},
        }
    )
    assert isinstance(ec.config, _PluginConfig2)
    assert ec.config.socket == "SOCK(xyz)"

    # round-trips: serialize re-injects the type discriminator
    dumped = serialize_supersocket(ec.config)
    assert dumped["type"] == "unit-test-plugin2"
    assert deserialize_supersocket(dumped).host == "xyz"


def test_unknown_config_type_raises():
    with pytest.raises(ValueError, match="Unknown config type"):
        deserialize_supersocket({"type": "does-not-exist"})
