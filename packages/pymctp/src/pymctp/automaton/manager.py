# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import dataclasses
import threading
from dataclasses import field
from enum import Enum
from threading import Thread
from typing import Any, Protocol, runtime_checkable

from mashumaro import DataClassDictMixin
from mashumaro.config import BaseConfig
from scapy.supersocket import SuperSocket

from pymctp.automaton import EndpointSession, SimpleEndpointAM
from pymctp.automaton.role_endpoint import RoleBasedEndpointAM
from pymctp.automaton.roles import create_endpoint
from pymctp.layers.mctp import EndpointContext


# --------------------------------------------------------------------------- #
# Pluggable socket-config registry
#
# EndpointConfig (de)serializes its ``config`` field by looking up the ``type``
# discriminator in this registry, so new socket transports can be added by
# separate packages WITHOUT editing this module. A config is registered simply
# by subclassing :class:`SupersocketConfig` and giving it a class-level ``type``
# string discriminator; ``__init_subclass__`` then
# registers it automatically. Packages may also call :func:`register_config_type`
# directly.
# --------------------------------------------------------------------------- #

_SOCKET_CONFIG_REGISTRY: dict[str, type] = {}


def _config_type_key(type_value: Any) -> str:
    """Normalise a config ``type`` discriminator to its string registry key.

    Accepts a plain string or any ``Enum`` whose value is the discriminator, so
    both resolve to the same registry entry.
    """
    if isinstance(type_value, Enum):
        return str(type_value.value)
    return str(type_value)


def register_config_type(type_value: Any, config_cls: type) -> None:
    """Register a socket-config dataclass under its ``type`` discriminator.

    Called automatically for every :class:`SupersocketConfig` subclass that
    defines a ``type``; may also be called directly by extension packages.
    """
    _SOCKET_CONFIG_REGISTRY[_config_type_key(type_value)] = config_cls


def get_config_type(type_value: Any) -> type | None:
    """Return the registered socket-config dataclass for ``type_value`` (or None)."""
    return _SOCKET_CONFIG_REGISTRY.get(_config_type_key(type_value))


def registered_config_types() -> dict[str, type]:
    """Return a copy of the config-type registry (discriminator -> config class)."""
    return dict(_SOCKET_CONFIG_REGISTRY)


@dataclasses.dataclass()
class SupersocketConfig(DataClassDictMixin):
    """Base class for endpoint socket configs.

    Subclasses declare a class-level ``type`` discriminator and build their
    ``socket`` in ``__post_init__``. Defining a subclass auto-registers it so
    :class:`EndpointConfig` can (de)serialize it — no changes to this module are
    required for a new transport provided by another package.
    """

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        type_value = getattr(cls, "type", None)
        if type_value is not None:
            register_config_type(type_value, cls)


@runtime_checkable
class ISessionConfig(Protocol):
    socket: SuperSocket

    def close_socket(self):
        pass




def deserialize_supersocket(value: dict) -> SupersocketConfig:
    """Deserialize a socket-config dict by looking up its ``type`` discriminator
    in the pluggable registry. Any package that registers a
    :class:`SupersocketConfig` subclass (see :func:`register_config_type`) is
    handled here without changes to this function."""
    config_type = value.get("type")
    config_cls = get_config_type(config_type)
    if config_cls is None:
        msg = (
            f"Unknown config type {config_type!r}. Registered types: "
            f"{sorted(registered_config_types())}"
        )
        raise ValueError(msg)
    return config_cls.from_dict(value)


def serialize_supersocket(config: SupersocketConfig) -> dict:
    """Serialize a socket config, injecting its ``type`` discriminator so the
    result round-trips through :func:`deserialize_supersocket`."""
    data = config.to_dict()
    type_value = getattr(config, "type", None)
    if type_value is not None:
        data["type"] = _config_type_key(type_value)
    return data


@dataclasses.dataclass()
class EndpointConfig(DataClassDictMixin):
    context: EndpointContext
    config: SupersocketConfig
    thread_kwargs: dict[str, Any] = field(default_factory=dict)
    downstream_endpoints: dict[int, EndpointContext] = field(default_factory=dict)
    role: str | None = None

    class Config(BaseConfig):
        serialization_strategy = {
            SupersocketConfig: {
                "serialize": serialize_supersocket,
                "deserialize": deserialize_supersocket,
            }
        }


@dataclasses.dataclass()
class EndpointManager:
    config: EndpointConfig
    session: EndpointSession
    socket: SuperSocket
    thread: Thread
    am: SimpleEndpointAM | RoleBasedEndpointAM

    @classmethod
    def from_config(cls, config: dict[Any, Any], start_thread=True, verbose: bool = False, prn=None):
        # Ensure exerciser packages — and the socket-config types they register
        # (see SupersocketConfig) — are imported before the config's ``type`` is
        # resolved from the registry.
        import pymctp.exerciser  # noqa: F401

        cfg = EndpointConfig.from_dict(config)
        print(f"DEBUG: {cfg or 'None'}")
        socket = cfg.config.socket
        session = EndpointSession(context=cfg.context, socket=socket)

        common_kwargs = dict(
            socket=socket,
            context=cfg.context,
            session=session,
            verbose=verbose,
            prn=prn or session.on_packet_received,
            downstream_endpoints=cfg.downstream_endpoints,
        )

        if cfg.role:
            am = create_endpoint(cfg.role, **common_kwargs)
        else:
            am = SimpleEndpointAM(**common_kwargs)
        if cfg.context.is_bus_owner:
            # TODO: add discovery flow answering machine here
            pass
        thread = threading.Thread(target=am, kwargs=cfg.thread_kwargs)
        if start_thread:
            thread.start()
        return EndpointManager(
            socket=socket,
            config=cfg,
            session=session,
            thread=thread,
            am=am,
        )

    @property
    def context(self) -> EndpointContext:
        return self.config.context

    @property
    def supersocket(self) -> SuperSocket:
        return self.config.config.socket

    def stop_sniffer(self):
        if self.am.sniffer.running:
            self.am.stop()
