# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Registry-based endpoint roles with plugin discovery.

Roles are named sets of behaviors.  Multiple roles can be combined
additively when creating an endpoint — their behavior lists are merged.

Built-in roles (``simple``, ``bridge``) are registered at import time.
Extension packages can register additional roles via the
``pymctp.roles`` entry point group::

    [project.entry-points."pymctp.roles"]
    cerberus = "my_package.roles:get_roles"

The entry point must reference a callable that returns a
``dict[str, list[Behavior]]`` mapping role name → behavior instances.
"""

from __future__ import annotations

import logging
import sys
from typing import Callable

from scapy.supersocket import SuperSocket

from ..layers.mctp.types import EndpointContext
from .behaviors.base import Behavior
from .role_endpoint import RoleBasedEndpointAM
from .sessions import EndpointSession

if sys.version_info >= (3, 10):
    from importlib.metadata import entry_points
else:
    from importlib_metadata import entry_points  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "pymctp.roles"

# Global role registry: role name → factory that returns list[Behavior]
_role_registry: dict[str, Callable[[], list[Behavior]]] = {}


def register_role(name: str, factory: Callable[[], list[Behavior]]) -> None:
    """Register a named role.

    Args:
        name: Role name (e.g. ``"bridge"``).
        factory: Callable that returns a list of Behavior instances.
    """
    _role_registry[name] = factory


def list_roles() -> list[str]:
    """Return all registered role names (including plugin-discovered ones)."""
    _ensure_plugins_loaded()
    return sorted(_role_registry.keys())


def get_behaviors_for_roles(*role_names: str) -> list[Behavior]:
    """Return the merged behavior list for one or more roles.

    Behaviors are deduplicated by name — if two roles contribute a
    behavior with the same ``name`` property, only the first is kept.
    """
    _ensure_plugins_loaded()
    seen_names: set[str] = set()
    behaviors: list[Behavior] = []
    for role_name in role_names:
        factory = _role_registry.get(role_name)
        if factory is None:
            msg = f"Unknown role: {role_name!r}. Available: {list_roles()}"
            raise ValueError(msg)
        for b in factory():
            if b.name not in seen_names:
                seen_names.add(b.name)
                behaviors.append(b)
    return behaviors


def create_endpoint(
    *role_names: str,
    session: EndpointSession | None = None,
    socket: SuperSocket | None = None,
    context: EndpointContext | None = None,
    timeout: float | None = None,
    downstream_endpoints: map | None = None,
    extra_behaviors: list[Behavior] | None = None,
    **kwargs,
) -> RoleBasedEndpointAM:
    """Factory that creates a RoleBasedEndpointAM for the given role(s).

    Roles are additive — passing ``"bridge", "cerberus"`` merges the
    behavior lists of both roles.  Additional one-off behaviors can be
    appended via *extra_behaviors*.
    """
    behaviors = get_behaviors_for_roles(*role_names)
    if extra_behaviors:
        seen = {b.name for b in behaviors}
        for b in extra_behaviors:
            if b.name not in seen:
                seen.add(b.name)
                behaviors.append(b)
    return RoleBasedEndpointAM(
        behaviors=behaviors,
        session=session,
        socket=socket,
        context=context,
        timeout=timeout,
        downstream_endpoints=downstream_endpoints,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Built-in roles
# ---------------------------------------------------------------------------


def _simple_behaviors() -> list[Behavior]:
    return []


def _bridge_behaviors() -> list[Behavior]:
    from .behaviors.bridge import BridgeBehavior

    return [BridgeBehavior()]


register_role("simple", _simple_behaviors)
register_role("bridge", _bridge_behaviors)


# ---------------------------------------------------------------------------
# Plugin discovery
# ---------------------------------------------------------------------------

_plugins_loaded = False


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
                    for name, behavior_factory in result.items():
                        if callable(behavior_factory):
                            register_role(name, behavior_factory)
                        else:
                            logger.warning(
                                "Role '%s' from entry point '%s' has non-callable factory",
                                name,
                                ep.name,
                            )
                else:
                    logger.warning(
                        "Role entry point '%s' returned %s, expected dict[str, Callable]",
                        ep.name,
                        type(result).__name__,
                    )
            else:
                logger.warning(
                    "Role entry point '%s' is not callable (got %s)",
                    ep.name,
                    type(factory).__name__,
                )
        except Exception:
            logger.warning("Failed to load role entry point '%s'", ep.name, exc_info=True)
