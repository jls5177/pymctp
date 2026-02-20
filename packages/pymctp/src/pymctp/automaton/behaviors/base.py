# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from abc import ABC, abstractmethod

from scapy.packet import Packet

from ...layers.mctp.types import EndpointContext
from ..sessions import HandlerResponse


class Behavior(ABC):
    """A composable behavior that handles a subset of MCTP protocol logic.

    Behaviors are attached to a RoleBasedEndpointAM and are checked in
    registration order. The first behavior that claims a packet (via
    can_handle) gets to produce the response.

    Stateful behaviors should store per-endpoint state in
    ``ctx.msg_type_context[self.name]``.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this behavior (used as key in msg_type_context)."""

    @abstractmethod
    def can_handle(self, pkt: Packet, ctx: EndpointContext) -> bool:
        """Return True if this behavior wants to handle this packet."""

    @abstractmethod
    def handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse | None:
        """Handle the packet and return a response (or None to pass through)."""

    def on_attach(self, ctx: EndpointContext) -> None:
        """Called when behavior is attached to an endpoint. Initialize state."""

    def on_detach(self, ctx: EndpointContext) -> None:
        """Called when behavior is removed from an endpoint. Cleanup."""
