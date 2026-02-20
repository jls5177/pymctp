# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.packet import Packet
from scapy.plist import _PacketIterable

from ..layers.mctp.types import EndpointContext, ICanReply
from .behaviors.base import Behavior
from .sessions import EndpointSession, HandlerResponse
from .simple_endpoint import SimpleEndpointAM


class RoleBasedEndpointAM(SimpleEndpointAM):
    """An endpoint answering machine that composes Behavior instances.

    Behaviors are checked in registration order before falling back to
    the default ``ICanReply`` pattern from ``SimpleEndpointAM``.

    Usage:
        >>> from pymctp.automaton.behaviors.bridge import BridgeBehavior
        >>> am = RoleBasedEndpointAM(socket=sock, context=ctx, session=session)
        >>> am.add_behavior(BridgeBehavior())
    """

    def __init__(self, behaviors: list[Behavior] | None = None, **kwargs):
        super().__init__(**kwargs)
        self._behaviors: list[Behavior] = []
        for b in behaviors or []:
            self.add_behavior(b)

    def add_behavior(self, behavior: Behavior) -> None:
        """Attach a behavior and call its on_attach lifecycle hook."""
        self._behaviors.append(behavior)
        behavior.on_attach(self.context)

    def remove_behavior(self, behavior: Behavior) -> None:
        """Detach a behavior and call its on_detach lifecycle hook."""
        self._behaviors.remove(behavior)
        behavior.on_detach(self.context)

    @property
    def behaviors(self) -> list[Behavior]:
        return list(self._behaviors)

    @property
    def role(self) -> list[str]:
        """Return the names of all attached behaviors."""
        return [b.name for b in self._behaviors]

    def make_reply(self, req: Packet | ICanReply) -> _PacketIterable:
        """Check behaviors first, then fall back to the default reply path."""
        ctx = self.get_context_for_endpoint(req)
        if ctx:
            for behavior in self._behaviors:
                if behavior.can_handle(req, ctx):
                    resp: HandlerResponse | None = behavior.handle(req, ctx)
                    if resp and resp.reply:
                        return resp.reply
                    if resp and resp.stop_processing:
                        return None
        # Fall back to default SimpleEndpointAM logic
        return super().make_reply(req)
