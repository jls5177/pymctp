# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from scapy.packet import Packet

from ...layers.mctp.types import EndpointContext
from ..sessions import HandlerResponse

if TYPE_CHECKING:
    from ..role_endpoint import RoleBasedEndpointAM


class Behavior(ABC):
    """A composable behavior that handles a subset of MCTP protocol logic.

    Behaviors are attached to a RoleBasedEndpointAM and are checked in
    registration order. The first behavior that claims a packet (via
    can_handle) gets to produce the response.

    Stateful behaviors should store per-endpoint state in
    ``ctx.msg_type_context[self.name]``.

    Lifecycle::

        on_bind     -> behavior bound to its endpoint (AM known, socket not live)
        on_attach   -> behavior added to the endpoint; initialise context state
        on_start    -> the endpoint's sniffer is up and packets can flow
        on_stop     -> the sniffer has stopped
        on_detach   -> behavior removed from the endpoint

    ``on_start`` is what makes *initiator* behaviors possible (bus-owner
    discovery, heartbeats, sensor polling): it is the first point at which the
    behavior may send requests on the socket.  ``on_bind`` runs earlier and only
    hands over the answering machine, which lets a behavior be driven
    programmatically (a discovery sweep from a test) without ever starting a
    sniffer.
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

    def on_bind(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        """Called when the behavior is bound to an endpoint, before ``on_attach``.

        Gives the behavior a reference to its answering machine (and therefore
        ``am.session``) without implying the socket is live yet.
        """

    def on_attach(self, ctx: EndpointContext) -> None:
        """Called when behavior is attached to an endpoint. Initialize state."""

    def on_detach(self, ctx: EndpointContext) -> None:
        """Called when behavior is removed from an endpoint. Cleanup."""

    def on_start(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        """Called once the endpoint's sniffer is running and can send/receive.

        Use ``am.session`` to originate requests.  This hook runs *inside* the
        sniffer's startup path, so anything long-running (a discovery sweep, a
        heartbeat loop) must be dispatched to its own daemon thread rather than
        blocking here.
        """

    def on_stop(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        """Called after the endpoint's sniffer has stopped. Stop any threads."""
