# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import logging

from scapy.packet import Packet
from scapy.plist import _PacketIterable

from ..layers.mctp.types import EndpointContext, ICanReply
from .behaviors.base import Behavior
from .sessions import EndpointSession, HandlerResponse
from .simple_endpoint import SimpleEndpointAM

logger = logging.getLogger(__name__)


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
        self._started = False
        for b in behaviors or []:
            self.add_behavior(b)

    def add_behavior(self, behavior: Behavior) -> None:
        """Attach a behavior and call its on_bind/on_attach lifecycle hooks.

        If the endpoint is already running, ``on_start`` is invoked too so a
        behavior added at runtime can begin originating traffic immediately.
        """
        self._behaviors.append(behavior)
        try:
            behavior.on_bind(self, self.context)
        except Exception:
            logger.exception("Behavior %r raised during on_bind", behavior.name)
        behavior.on_attach(self.context)
        if self._started:
            self._invoke_start(behavior)

    def remove_behavior(self, behavior: Behavior) -> None:
        """Detach a behavior and call its on_detach lifecycle hook."""
        if self._started:
            self._invoke_stop(behavior)
        self._behaviors.remove(behavior)
        behavior.on_detach(self.context)

    @property
    def behaviors(self) -> list[Behavior]:
        return list(self._behaviors)

    def get_behavior(self, name: str) -> Behavior | None:
        """Return the attached behavior with the given ``name`` (or None)."""
        for b in self._behaviors:
            if b.name == name:
                return b
        return None

    @property
    def role(self) -> list[str]:
        """Return the names of all attached behaviors."""
        return [b.name for b in self._behaviors]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _invoke_start(self, behavior: Behavior) -> None:
        try:
            behavior.on_start(self, self.context)
        except Exception:
            logger.exception("Behavior %r raised during on_start", behavior.name)

    def _invoke_stop(self, behavior: Behavior) -> None:
        try:
            behavior.on_stop(self, self.context)
        except Exception:
            logger.exception("Behavior %r raised during on_stop", behavior.name)

    def _on_sniff_started(self) -> None:
        self._started = True
        for behavior in list(self._behaviors):
            self._invoke_start(behavior)

    def _on_sniff_stopped(self) -> None:
        if not self._started:
            return
        self._started = False
        for behavior in reversed(list(self._behaviors)):
            self._invoke_stop(behavior)

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
