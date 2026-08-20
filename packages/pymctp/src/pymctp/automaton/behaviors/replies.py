# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Helpers for building layered replies from inside a :class:`Behavior`.

A behavior that wants to answer a request has to rebuild the whole stack that
carried it: the message-type payload, the MCTP transport header (with
fragmentation), and — for bus-addressed transports — the physical framing.
Every responder ends up writing the same three lines, and every example script
in the wild has its own copy of them::

    transport_rsp = pkt.getlayer(TransportHdrPacket).build_reply(ctx, payload)
    smbus_rsp = pkt.getlayer(SmbusTransportPacket).build_reply(ctx, transport_rsp)
    return HandlerResponse(stop_processing=True, reply=smbus_rsp)

:func:`build_layered_reply` does that once, and works for transports that have
no physical framing layer of their own (I3C and the TIP mailbox are
point-to-point: the socket adds the framing), where the physical step is simply
skipped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from scapy.packet import Packet

from ...layers.mctp.transport import SmbusTransportPacket, TransportHdrPacket, UartTransportPacket
from ..sessions import HandlerResponse

if TYPE_CHECKING:
    from ...layers.mctp.types import AnyPacketType, EndpointContext

#: Physical framing layers that know how to wrap a reply.  Ordered most- to
#: least-specific: ``TrimmedSmbusTransportPacket`` subclasses
#: ``SmbusTransportPacket``, so an ``isinstance``/``getlayer`` on the base class
#: finds either.
_PHYSICAL_LAYERS: tuple[type[Packet], ...] = (SmbusTransportPacket, UartTransportPacket)


def get_physical_layer(pkt: Packet) -> Packet | None:
    """Return the physical framing layer of *pkt*, or None for point-to-point links."""
    for layer_cls in _PHYSICAL_LAYERS:
        layer = pkt.getlayer(layer_cls)
        if layer is not None and hasattr(layer, "build_reply"):
            return layer
    return None


def build_layered_reply(
    pkt: Packet,
    ctx: EndpointContext,
    payload: AnyPacketType | bytes | None,
) -> AnyPacketType | None:
    """Wrap *payload* in the transport (and physical) headers that carried *pkt*.

    Args:
        pkt: The received request, with all of its layers intact.
        ctx: The endpoint context replying (supplies source EID and MTU).
        payload: The message-type payload to send back, e.g. a
            ``VdPciHdr(...) / SomeResponsePacket(...)`` chain.  ``None`` yields a
            bare transport-level acknowledgement.

    Returns:
        A packet or ``PacketList`` ready to hand to ``send_reply``, or ``None``
        when *pkt* carries no MCTP transport header.
    """
    transport = pkt.getlayer(TransportHdrPacket)
    if transport is None:
        return None
    reply = transport.build_reply(ctx, payload)

    physical = get_physical_layer(pkt)
    if physical is not None:
        reply = physical.build_reply(ctx, reply)
    return reply


def layered_reply_response(
    pkt: Packet,
    ctx: EndpointContext,
    payload: AnyPacketType | bytes | None,
    *,
    stop_processing: bool = True,
) -> HandlerResponse:
    """:func:`build_layered_reply` wrapped in the :class:`HandlerResponse` a Behavior returns."""
    return HandlerResponse(stop_processing=stop_processing, reply=build_layered_reply(pkt, ctx, payload))
