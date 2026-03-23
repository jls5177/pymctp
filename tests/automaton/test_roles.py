# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for RoleBasedEndpointAM and role factory."""

import pytest

from pymctp.automaton.behaviors.base import Behavior
from pymctp.automaton.behaviors.bridge import BridgeBehavior
from pymctp.automaton.role_endpoint import RoleBasedEndpointAM
from pymctp.automaton.roles import create_endpoint, register_role, list_roles, get_behaviors_for_roles
from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers.mctp.types import EndpointContext, Smbus7bitAddress, MsgTypes


@pytest.fixture
def ctx():
    return EndpointContext(
        physical_address=Smbus7bitAddress(0x10),
        assigned_eid=0x08,
        supported_msg_types=[MsgTypes.CTRL],
    )


class TestRoleBasedEndpointAM:
    def test_creation_with_no_behaviors(self, ctx):
        am = RoleBasedEndpointAM(context=ctx)
        assert am.behaviors == []
        assert am.role == []

    def test_add_remove_behavior(self, ctx):
        am = RoleBasedEndpointAM(context=ctx)
        b = BridgeBehavior()
        am.add_behavior(b)
        assert len(am.behaviors) == 1
        assert am.role == ["bridge"]
        am.remove_behavior(b)
        assert am.behaviors == []

    def test_creation_with_behaviors_list(self, ctx):
        b = BridgeBehavior()
        am = RoleBasedEndpointAM(behaviors=[b], context=ctx)
        assert am.role == ["bridge"]

    def test_on_attach_called(self, ctx):
        """Verify on_attach is called when behavior is added."""
        assert ctx.is_bus_owner is False
        am = RoleBasedEndpointAM(behaviors=[BridgeBehavior()], context=ctx)
        assert ctx.is_bus_owner is True  # BridgeBehavior.on_attach sets this


class TestEndpointRoles:
    def test_simple_role(self, ctx):
        am = create_endpoint("simple", context=ctx)
        assert isinstance(am, RoleBasedEndpointAM)
        assert am.role == []

    def test_bridge_role(self, ctx):
        am = create_endpoint("bridge", context=ctx)
        assert isinstance(am, RoleBasedEndpointAM)
        assert am.role == ["bridge"]
        assert ctx.is_bus_owner is True

    def test_unknown_role_raises(self, ctx):
        with pytest.raises(ValueError, match="Unknown role"):
            create_endpoint("nonexistent", context=ctx)

    def test_additive_roles(self, ctx):
        """Multiple roles merge their behaviors additively."""
        am = create_endpoint("simple", "bridge", context=ctx)
        assert isinstance(am, RoleBasedEndpointAM)
        assert am.role == ["bridge"]

    def test_list_roles(self):
        roles = list_roles()
        assert "simple" in roles
        assert "bridge" in roles

    def test_extra_behaviors(self, ctx):
        """Extra one-off behaviors are appended."""

        class DummyBehavior(Behavior):
            @property
            def name(self):
                return "dummy"

            def can_handle(self, pkt, ctx):
                return False

            def handle(self, pkt, ctx):
                return None

        am = create_endpoint("simple", context=ctx, extra_behaviors=[DummyBehavior()])
        assert am.role == ["dummy"]

    def test_deduplication(self, ctx):
        """Behaviors with the same name are deduplicated across roles."""
        am = create_endpoint("bridge", "bridge", context=ctx)
        assert len(am.behaviors) == 1
