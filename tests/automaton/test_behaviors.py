# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the Behavior framework and BridgeBehavior."""

import pytest

from pymctp.automaton.behaviors.base import Behavior
from pymctp.automaton.behaviors.bridge import BridgeBehavior
from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers.mctp.control import ControlHdr, ControlHdrPacket
from pymctp.layers.mctp.control.types import CompletionCodes, ContrlCmdCodes
from pymctp.layers.mctp.types import EndpointContext, RoutingTableEntry, Smbus7bitAddress


@pytest.fixture
def bridge_ctx():
    """A bridge endpoint context with a routing table."""
    return EndpointContext(
        physical_address=Smbus7bitAddress(0x10),
        assigned_eid=0x08,
        is_bus_owner=True,
        pool_size=8,
        routing_table=[
            RoutingTableEntry(starting_eid=0x20, port_number=1, phy_address=[0x30], eid_range=4),
            RoutingTableEntry(starting_eid=0x30, port_number=2, phy_address=[0x40], eid_range=1),
        ],
        routing_table_ready=True,
    )


@pytest.fixture
def simple_ctx():
    """A simple (non-bridge) endpoint context."""
    return EndpointContext(
        physical_address=Smbus7bitAddress(0x10),
        assigned_eid=0x15,
        is_bus_owner=False,
    )


class TestBehaviorABC:
    """Tests for the Behavior abstract base class."""

    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            Behavior()

    def test_concrete_implementation(self, simple_ctx):
        class DummyBehavior(Behavior):
            @property
            def name(self):
                return "dummy"

            def can_handle(self, pkt, ctx):
                return False

            def handle(self, pkt, ctx):
                return None

        b = DummyBehavior()
        assert b.name == "dummy"
        assert b.can_handle(None, simple_ctx) is False
        assert b.handle(None, simple_ctx) is None
        # lifecycle hooks should be no-ops by default
        b.on_attach(simple_ctx)
        b.on_detach(simple_ctx)


class TestBridgeBehavior:
    """Tests for BridgeBehavior."""

    def test_name(self):
        b = BridgeBehavior()
        assert b.name == "bridge"

    def test_on_attach_sets_bus_owner(self, simple_ctx):
        assert simple_ctx.is_bus_owner is False
        b = BridgeBehavior()
        b.on_attach(simple_ctx)
        assert simple_ctx.is_bus_owner is True

    def test_can_handle_bridge_commands(self, bridge_ctx):
        b = BridgeBehavior()
        for cmd in [
            ContrlCmdCodes.QueryHop,
            ContrlCmdCodes.GetRoutingTableEntries,
            ContrlCmdCodes.RoutingInformationUpdate,
            ContrlCmdCodes.ResolveEndpointID,
            ContrlCmdCodes.AllocateEndpointIDs,
        ]:
            pkt = ControlHdr(rq=True, cmd_code=cmd)
            # Force full packet build/parse cycle
            pkt = ControlHdrPacket(bytes(pkt))
            assert b.can_handle(pkt, bridge_ctx) is True, f"Should handle {cmd.name}"

    def test_ignores_non_bridge_commands(self, bridge_ctx):
        b = BridgeBehavior()
        pkt = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetEndpointID)
        pkt = ControlHdrPacket(bytes(pkt))
        assert b.can_handle(pkt, bridge_ctx) is False

    def test_ignores_response_packets(self, bridge_ctx):
        b = BridgeBehavior()
        pkt = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.QueryHop, completion_code=0)
        pkt = ControlHdrPacket(bytes(pkt))
        assert b.can_handle(pkt, bridge_ctx) is False


class TestQueryHopMakeCtrlReply:
    """Tests for QueryHopRequestPacket.make_ctrl_reply."""

    def test_query_hop_returns_next_bridge(self, bridge_ctx):
        from pymctp.layers.mctp.control.query_hop import QueryHopRequestPacket, QueryHopResponsePacket

        req = QueryHopRequestPacket(target_eid=0x21, mctp_ctrl_msg_type=0)
        cc, rsp = req.make_ctrl_reply(bridge_ctx)
        assert cc == CompletionCodes.SUCCESS
        assert rsp is not None
        rsp_pkt = QueryHopResponsePacket(bytes(rsp))
        assert rsp_pkt.next_bridge_eid == 0x20
        assert rsp_pkt.max_incoming_unit_size == bridge_ctx.mtu_size

    def test_query_hop_unknown_eid(self, bridge_ctx):
        from pymctp.layers.mctp.control.query_hop import QueryHopRequestPacket, QueryHopResponsePacket

        req = QueryHopRequestPacket(target_eid=0xFF, mctp_ctrl_msg_type=0)
        cc, rsp = req.make_ctrl_reply(bridge_ctx)
        assert cc == CompletionCodes.SUCCESS
        rsp_pkt = QueryHopResponsePacket(bytes(rsp))
        assert rsp_pkt.next_bridge_eid == 0x00  # no match

    def test_query_hop_non_bus_owner(self, simple_ctx):
        from pymctp.layers.mctp.control.query_hop import QueryHopRequestPacket

        req = QueryHopRequestPacket(target_eid=0x20, mctp_ctrl_msg_type=0)
        cc, rsp = req.make_ctrl_reply(simple_ctx)
        assert cc == CompletionCodes.ERROR_UNSUPPORTED_CMD
        assert rsp is None


class TestResolveEndpointIDMakeCtrlReply:
    """Tests for ResolveEndpointIDRequestPacket.make_ctrl_reply."""

    def test_resolve_known_eid(self, bridge_ctx):
        from pymctp.layers.mctp.control.resolve_eid import ResolveEndpointIDRequestPacket, ResolveEndpointIDResponsePacket

        req = ResolveEndpointIDRequestPacket(target_eid=0x20)
        cc, rsp = req.make_ctrl_reply(bridge_ctx)
        assert cc == CompletionCodes.SUCCESS
        assert rsp is not None
        rsp_pkt = ResolveEndpointIDResponsePacket(bytes(rsp))
        assert rsp_pkt.bridge_eid == bridge_ctx.eid

    def test_resolve_unknown_eid(self, bridge_ctx):
        from pymctp.layers.mctp.control.resolve_eid import ResolveEndpointIDRequestPacket

        req = ResolveEndpointIDRequestPacket(target_eid=0xFE)
        cc, rsp = req.make_ctrl_reply(bridge_ctx)
        assert cc == CompletionCodes.ERROR_INVALID_DATA
        assert rsp is None

    def test_resolve_non_bus_owner(self, simple_ctx):
        from pymctp.layers.mctp.control.resolve_eid import ResolveEndpointIDRequestPacket

        req = ResolveEndpointIDRequestPacket(target_eid=0x20)
        cc, rsp = req.make_ctrl_reply(simple_ctx)
        assert cc == CompletionCodes.ERROR_UNSUPPORTED_CMD


class TestRoutingInfoUpdateMakeCtrlReply:
    """Tests for RoutingInfoUpdateRequestPacket.make_ctrl_reply."""

    def test_routing_update_adds_entries(self):
        from pymctp.layers.mctp.control.routing_info_update import (
            RoutingInfoUpdateEntry1BAddressPacket,
            RoutingInfoUpdateRequestPacket,
        )

        ctx = EndpointContext(
            physical_address=Smbus7bitAddress(0x10),
            assigned_eid=0x08,
            is_bus_owner=True,
        )
        entry = RoutingInfoUpdateEntry1BAddressPacket(
            entry_type=0, entry_count=1, starting_eid=0x50, phy_address=0x60
        )
        req = RoutingInfoUpdateRequestPacket(entries=[entry])
        cc, rsp = req.make_ctrl_reply(ctx)
        assert cc == CompletionCodes.SUCCESS
        assert rsp is None  # per spec, no payload
        assert len(ctx.routing_table) == 1
        assert ctx.routing_table[0].starting_eid == 0x50

    def test_routing_update_replaces_existing(self):
        from pymctp.layers.mctp.control.routing_info_update import (
            RoutingInfoUpdateEntry1BAddressPacket,
            RoutingInfoUpdateRequestPacket,
        )

        ctx = EndpointContext(
            physical_address=Smbus7bitAddress(0x10),
            assigned_eid=0x08,
            is_bus_owner=True,
            routing_table=[
                RoutingTableEntry(starting_eid=0x50, port_number=0, phy_address=[0x60], eid_range=1),
            ],
        )
        entry = RoutingInfoUpdateEntry1BAddressPacket(
            entry_type=0, entry_count=2, starting_eid=0x50, phy_address=0x70
        )
        req = RoutingInfoUpdateRequestPacket(entries=[entry])
        cc, _ = req.make_ctrl_reply(ctx)
        assert cc == CompletionCodes.SUCCESS
        assert len(ctx.routing_table) == 1
        assert ctx.routing_table[0].phy_address == [0x70]
        assert ctx.routing_table[0].eid_range == 2
