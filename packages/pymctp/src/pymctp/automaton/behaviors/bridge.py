# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Bridge endpoint behavior — handles bridging-related MCTP control commands."""

from scapy.packet import Packet

from ...layers.mctp.control import (
    AllocateEndpointIDsRequestPacket,
    ControlHdrPacket,
    GetRoutingTableEntriesRequestPacket,
    QueryHopRequestPacket,
    ResolveEndpointIDRequestPacket,
    RoutingInfoUpdateRequestPacket,
)
from ...layers.mctp.control.types import ContrlCmdCodes
from ...layers.mctp.types import EndpointContext
from ..sessions import HandlerResponse
from .base import Behavior

# Control commands handled by this behavior
_BRIDGE_CMD_CODES = frozenset(
    {
        ContrlCmdCodes.QueryHop,
        ContrlCmdCodes.GetRoutingTableEntries,
        ContrlCmdCodes.RoutingInformationUpdate,
        ContrlCmdCodes.ResolveEndpointID,
        ContrlCmdCodes.AllocateEndpointIDs,
    }
)


class BridgeBehavior(Behavior):
    """Handles MCTP control commands related to bridging and routing.

    Delegates to the ``make_ctrl_reply`` methods already implemented on
    each request packet class.  The behavior's value-add is:

    * Claiming only bridge-specific commands so they are not processed
      by other behaviors.
    * Ensuring ``ctx.is_bridge`` is set when the behavior is attached, which
      is what the bridge/routing control commands gate on.  Note this is
      deliberately *not* ``is_bus_owner``: a bridge is not necessarily the
      bus owner (on L4A40 the BMC bridges for the head node).
    """

    @property
    def name(self) -> str:
        return "bridge"

    def on_attach(self, ctx: EndpointContext) -> None:
        if not ctx.is_bridge:
            ctx.is_bridge = True

    def can_handle(self, pkt: Packet, ctx: EndpointContext) -> bool:
        if not pkt.haslayer(ControlHdrPacket):
            return False
        ctrl: ControlHdrPacket = pkt.getlayer(ControlHdrPacket)
        return ctrl.rq == 1 and ctrl.cmd_code in _BRIDGE_CMD_CODES

    def handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse | None:
        # Let the default make_ctrl_reply path handle the response generation.
        # Returning None with stop_processing=False means "I claimed it but
        # have nothing extra to do — let the default reply path run".
        return None
