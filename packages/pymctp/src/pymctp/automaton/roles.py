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

Roles may be *parameterized*.  A role factory that declares keyword
arguments can be requested with options::

    create_endpoint(RoleSpec("spdm-responder", {"version": 0x12}), context=ctx)
    create_endpoint(("spdm-responder", {"version": 0x12}), context=ctx)

Zero-argument factories and bare role-name strings keep working unchanged.
"""

from __future__ import annotations

import dataclasses
import inspect
import logging
import sys
from collections.abc import Mapping
from typing import Any, Callable, Union

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
_role_registry: dict[str, Callable[..., list[Behavior]]] = {}


@dataclasses.dataclass(frozen=True)
class RoleSpec:
    """A role name plus the options to pass to its behavior factory."""

    name: str
    options: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.options is None:  # tolerate explicit None
            object.__setattr__(self, "options", {})

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.name}({dict(self.options)})" if self.options else self.name


#: Anything accepted where a role is expected.
AnyRole = Union[str, RoleSpec, tuple]


def register_role(name: str, factory: Callable[..., list[Behavior]]) -> None:
    """Register a named role.

    Args:
        name: Role name (e.g. ``"bridge"``).
        factory: Callable that returns a list of Behavior instances. It may
            take no arguments, or accept keyword arguments which are supplied
            through :class:`RoleSpec` options.
    """
    _role_registry[name] = factory


def list_roles() -> list[str]:
    """Return all registered role names (including plugin-discovered ones)."""
    _ensure_plugins_loaded()
    return sorted(_role_registry.keys())


def as_role_spec(role: AnyRole) -> RoleSpec:
    """Coerce a role name / ``(name, options)`` tuple / RoleSpec into a RoleSpec."""
    if isinstance(role, RoleSpec):
        return role
    if isinstance(role, str):
        return RoleSpec(role)
    if isinstance(role, tuple):
        if len(role) == 1:
            return RoleSpec(str(role[0]))
        if len(role) == 2:
            name, options = role
            return RoleSpec(str(name), dict(options or {}))
    msg = f"Cannot interpret {role!r} as a role (expected str, RoleSpec or (name, options) tuple)"
    raise TypeError(msg)


def normalize_roles(
    roles: AnyRole | list[AnyRole] | None,
    role_options: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[RoleSpec]:
    """Normalise a role declaration into a list of :class:`RoleSpec`.

    Accepts ``None``, a single role, or a list of roles.  *role_options* maps a
    role name to extra options and is merged in — this is what lets serialized
    configs express parameterized roles as plain JSON::

        {"role": ["spdm-responder"], "role_options": {"spdm-responder": {...}}}
    """
    if roles is None:
        items: list[AnyRole] = []
    elif isinstance(roles, (str, RoleSpec, tuple)):
        items = [roles]
    else:
        items = list(roles)

    specs: list[RoleSpec] = []
    for item in items:
        spec = as_role_spec(item)
        extra = (role_options or {}).get(spec.name)
        if extra:
            merged = dict(extra)
            merged.update(spec.options)
            spec = RoleSpec(spec.name, merged)
        specs.append(spec)
    return specs


def _invoke_factory(spec: RoleSpec, factory: Callable[..., list[Behavior]]) -> list[Behavior]:
    options = dict(spec.options)
    if not options:
        return factory()
    try:
        inspect.signature(factory).bind(**options)
    except TypeError as exc:
        msg = f"Role {spec.name!r} does not accept options {sorted(options)}: {exc}"
        raise TypeError(msg) from exc
    except ValueError:  # builtins without an introspectable signature
        pass
    return factory(**options)


def get_behaviors_for_roles(*roles: AnyRole) -> list[Behavior]:
    """Return the merged behavior list for one or more roles.

    Behaviors are deduplicated by name — if two roles contribute a
    behavior with the same ``name`` property, only the first is kept.
    """
    _ensure_plugins_loaded()
    seen_names: set[str] = set()
    behaviors: list[Behavior] = []
    for role in roles:
        spec = as_role_spec(role)
        factory = _role_registry.get(spec.name)
        if factory is None:
            msg = f"Unknown role: {spec.name!r}. Available: {list_roles()}"
            raise ValueError(msg)
        for b in _invoke_factory(spec, factory):
            if b.name not in seen_names:
                seen_names.add(b.name)
                behaviors.append(b)
    return behaviors


def create_endpoint(
    *roles: AnyRole,
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
    behaviors = get_behaviors_for_roles(*roles)
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


def _bus_owner_behaviors(**options: Any) -> list[Behavior]:
    from .behaviors.bus_owner import BusOwnerBehavior

    return [BusOwnerBehavior(**options)]


def _spdm_responder_behaviors(**options: Any) -> list[Behavior]:
    from .behaviors.spdm_responder import SpdmResponderBehavior

    return [SpdmResponderBehavior(**options)]


def _spdm_requester_behaviors(**options: Any) -> list[Behavior]:
    from .behaviors.spdm_requester import SpdmRequesterBehavior

    return [SpdmRequesterBehavior(**options)]


def _pldm_base_behaviors(**options: Any) -> list[Behavior]:
    from .behaviors.pldm_responder import PldmBaseBehavior

    return [PldmBaseBehavior(**options)]


def _pldm_sensor_behaviors(**options: Any) -> list[Behavior]:
    from .behaviors.pldm_responder import PldmBaseBehavior, PldmSensorBehavior

    # A sensor endpoint must also answer PLDM Type 0 discovery (GetPLDMTypes /
    # GetPLDMCommands) or a requester never learns Type 2 is supported.
    base_options = options.pop("base", None) or {}
    return [PldmBaseBehavior(**base_options), PldmSensorBehavior(**options)]


def _cerberus_rot_behaviors(**options: Any) -> list[Behavior]:
    from .behaviors.cerberus_responder import CerberusChallengeBehavior

    return [CerberusChallengeBehavior(**options)]


register_role("simple", _simple_behaviors)
register_role("bridge", _bridge_behaviors)
register_role("bus-owner", _bus_owner_behaviors)
register_role("spdm-responder", _spdm_responder_behaviors)
register_role("spdm-requester", _spdm_requester_behaviors)
register_role("pldm-base", _pldm_base_behaviors)
register_role("pldm-sensor", _pldm_sensor_behaviors)
register_role("cerberus-rot", _cerberus_rot_behaviors)


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
