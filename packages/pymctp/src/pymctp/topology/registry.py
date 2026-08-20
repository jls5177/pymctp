# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Named-machine registry with entry-point discovery."""

from __future__ import annotations

import logging
import sys
from typing import Any, Callable

from pymctp.topology.types import MachineSpec

if sys.version_info >= (3, 10):
    from importlib.metadata import entry_points
else:
    from importlib_metadata import entry_points  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "pymctp.machines"

_machine_registry: dict[str, Callable[..., MachineSpec]] = {}
_plugins_loaded = False


def register_machine(name: str, factory: Callable[..., MachineSpec]) -> None:
    """Register a named machine factory."""

    _machine_registry[name] = factory


def get_machine_spec(name: str, **options: Any) -> MachineSpec:
    """Instantiate a named machine spec."""

    _ensure_plugins_loaded()
    factory = _machine_registry.get(name)
    if factory is None:
        known = ", ".join(list_machines()) or "<none>"
        msg = f"Unknown machine {name!r}. Available machines: {known}"
        raise KeyError(msg)
    return factory(**options)


def list_machines() -> list[str]:
    """Return registered machine names."""

    _ensure_plugins_loaded()
    return sorted(_machine_registry)


def machine_info(name: str) -> dict[str, Any]:
    """Return basic metadata for a registered machine."""

    spec = get_machine_spec(name)
    return {
        "name": spec.name,
        "description": spec.description,
        "device_count": len(spec.devices),
    }


def _ensure_plugins_loaded() -> None:
    global _plugins_loaded  # noqa: PLW0603
    if _plugins_loaded:
        return
    _plugins_loaded = True

    try:
        eps = entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:
        eps = entry_points().get(ENTRY_POINT_GROUP, [])  # type: ignore[assignment]

    for ep in eps:
        try:
            factory = ep.load()
            if callable(factory):
                result = factory()
                if isinstance(result, dict):
                    for name, machine_factory in result.items():
                        if callable(machine_factory):
                            register_machine(name, machine_factory)
                        else:
                            logger.warning(
                                "Machine %r from entry point %r has non-callable factory",
                                name,
                                ep.name,
                            )
                else:
                    logger.warning(
                        "Machine entry point %r returned %s, expected dict[str, Callable]",
                        ep.name,
                        type(result).__name__,
                    )
            else:
                logger.warning(
                    "Machine entry point %r is not callable (got %s)",
                    ep.name,
                    type(factory).__name__,
                )
        except Exception:
            logger.warning("Failed to load machine entry point %r", ep.name, exc_info=True)
