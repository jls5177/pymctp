# SPDX-FileCopyrightText: 2026 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Emitting a message must not let another message's packets into the middle.

MCTP reassembly is keyed on source EID, destination EID and tag. Two responses
that interleave their packets on one link are spliced by the receiver into a
single message that reassembles cleanly, with consecutive sequence numbers, but
carries bytes from both. The damage only shows up when something checks the
contents -- a PLDM FRU table checksum, say -- so it is caught here instead.
"""

from __future__ import annotations

import threading
import time

import pytest
from pymctp.automaton.simple_endpoint import SimpleEndpointAM
from pymctp.layers.mctp.transport import TransportHdr
from pymctp.layers.mctp.types import EndpointContext, MsgTypes
from scapy.plist import PacketList


class RecordingSocket:
    """A socket that records what it was handed, slowly enough to interleave."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self._lock = threading.Lock()

    def send(self, packet) -> None:  # noqa: ANN001
        payload = bytes(packet)[4:]
        # Yield the GIL mid-message: without a send lock this is where a
        # second sender gets its packets in.
        time.sleep(0.001)
        with self._lock:
            self.sent.append(payload)


def _message(marker: int, packets: int) -> PacketList:
    return PacketList(
        [
            TransportHdr(src=1, dst=2, som=i == 0, eom=i == packets - 1, pkt_seq=i, msg_type=MsgTypes.PLDM)
            / (bytes([marker]) * 8)
            for i in range(packets)
        ]
    )


def test_concurrent_replies_do_not_interleave_their_packets() -> None:
    socket = RecordingSocket()
    am = SimpleEndpointAM(socket=socket, context=EndpointContext())

    senders = [threading.Thread(target=am.send_reply, args=(_message(marker, 8),)) for marker in (0xAA, 0xBB)]
    for thread in senders:
        thread.start()
    for thread in senders:
        thread.join(10)

    assert len(socket.sent) == 16
    # The SOM packet leads with the message type byte, so read the marker from the tail.
    markers = [payload[-1] for payload in socket.sent]
    # Each message must appear as one uninterrupted run, so there is exactly
    # one transition between the two markers.
    transitions = sum(1 for previous, current in zip(markers, markers[1:]) if previous != current)  # noqa: B905
    assert transitions == 1, f"messages interleaved: {markers}"


def test_fragmented_replies_are_paced_but_whole_replies_are_not_delayed() -> None:
    """The gap between packets is load-bearing; the one before a reply is not.

    The emulated controllers we talk to take one frame at a time, so packets
    written back to back are accepted on the socket and then dropped before
    the requester sees them: every multi-packet reply vanishes while
    single-packet replies keep working. Removing this pacing broke PLDM PDR
    discovery outright, so it is asserted rather than left to a comment.

    Delaying the reply itself is the opposite -- it only makes requesters time
    out and retry, and a retry racing an in-flight fragmented reply is what
    corrupts a reassembled message.
    """
    socket = RecordingSocket()
    am = SimpleEndpointAM(socket=socket, context=EndpointContext())

    assert am.inter_packet_delay_s > 0, "packets of one message must be paced"
    assert not am.response_delay_s

    started = time.monotonic()
    am.send_reply(_message(0xCC, 1))
    elapsed = time.monotonic() - started
    assert elapsed < am.inter_packet_delay_s + 0.05, "a single-packet reply must not wait"


def test_send_function_is_used_when_supplied() -> None:
    """The parameter is documented, so it has to actually be honoured."""
    sent: list[object] = []
    am = SimpleEndpointAM(socket=RecordingSocket(), context=EndpointContext())

    am.send_reply(_message(0xDD, 3), send_function=sent.append)

    assert len(sent) == 3


@pytest.mark.parametrize("mtu", [62, 120, 231])
def test_fragments_are_uniform_and_within_the_transmission_unit(mtu: int) -> None:
    """Every packet but the last is one full unit, message type byte included.

    Budgeting the message type byte outside the unit made the first packet a
    byte larger than the rest, overrunning the unit and breaking DSP0236's
    equal-size rule. Real hardware sends a 922-byte FRU table as 120 x 7 + 82.
    """
    ctx = EndpointContext(assigned_eid=0x17)
    ctx.mtu_size = mtu
    request = TransportHdr(src=0x0E, dst=0x17, som=1, eom=1, pkt_seq=0, to=1, tag=0, msg_type=MsgTypes.PLDM)

    packets = request.build_reply(ctx, b"\x5a" * 900)

    sizes = [len(bytes(packet)) - 4 for packet in packets]
    assert len(sizes) > 1, "expected a fragmented message"
    assert set(sizes[:-1]) == {mtu}, f"non-uniform payloads: {sizes}"
    assert sizes[-1] <= mtu
    assert sum(sizes) == 900 + 1, "the message type byte rides in the first packet"
