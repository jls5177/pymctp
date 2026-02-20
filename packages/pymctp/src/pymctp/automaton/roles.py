# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Pre-built endpoint roles that compose behaviors for common use cases."""

from __future__ import annotations

from enum import Enum

from scapy.supersocket import SuperSocket

from ..layers.mctp.types import EndpointContext
from .behaviors.base import Behavior
from .role_endpoint import RoleBasedEndpointAM
from .sessions import EndpointSession


class EndpointRole(str, Enum):
    """Well-known endpoint roles."""

    SIMPLE = "simple"
    BRIDGE = "bridge"


def _get_behaviors_for_role(role: EndpointRole) -> list[Behavior]:
    """Return the list of behaviors for a given role.

    Imports are deferred to avoid circular dependencies and to keep
    optional behaviors lazy.
    """
    if role == EndpointRole.SIMPLE:
        return []

    if role == EndpointRole.BRIDGE:
        from .behaviors.bridge import BridgeBehavior

        return [BridgeBehavior()]

    msg = f"Unknown role: {role}"
    raise ValueError(msg)


def create_endpoint(
    role: EndpointRole,
    *,
    session: EndpointSession | None = None,
    socket: SuperSocket | None = None,
    context: EndpointContext | None = None,
    timeout: float | None = None,
    downstream_endpoints: map | None = None,
    **kwargs,
) -> RoleBasedEndpointAM:
    """Factory that creates a RoleBasedEndpointAM with the behaviors for *role*."""
    behaviors = _get_behaviors_for_role(role)
    return RoleBasedEndpointAM(
        behaviors=behaviors,
        session=session,
        socket=socket,
        context=context,
        timeout=timeout,
        downstream_endpoints=downstream_endpoints,
        **kwargs,
    )
