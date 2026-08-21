# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""The MCTP TO bit decides whether a VDPCI message is a request.

Vendor protocols disagree about the VDPCI ``rq`` bit, so it cannot be used on
its own:

* Microsoft's VDM leaves ``rq`` **set** on responses. Treating ``rq`` as
  authoritative classified a response as a request, so an endpoint answered the
  reply it had just received with an empty message of its own.
* The Cerberus Utility does the opposite and leaves ``rq`` **clear** on its
  requests, so an ``rq``-based test rejected every genuine request.

Only the transport's TO (tag owner) bit is consistent: set on a request, clear
on a response.
"""

from __future__ import annotations

import pytest

from pymctp.layers.mctp import MsgTypes, Smbus7bitAddress
from pymctp.layers.mctp.transport import SmbusTransport, SmbusTransportPacket, TransportHdr
from pymctp.layers.mctp.vdpci import VdPCIVendorIds
from pymctp.layers.mctp.vdpci.vdpci import VdPciHdrPacket


def build(*, to: int, rq: int, payload: bytes = b"\x00\x01\x02") -> SmbusTransportPacket:
    body = VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=rq, vdm_cmd_code=0xFF) / payload
    pkt = SmbusTransport(
        dst_addr=Smbus7bitAddress(0x41),
        src_addr=Smbus7bitAddress(0x10),
        load=TransportHdr(src=0x0F, dst=0x20, som=1, eom=1, to=to, tag=0, msg_type=MsgTypes.VDPCI) / body,
    )
    return SmbusTransport(bytes(pkt))


@pytest.mark.parametrize(
    ("to", "rq", "expected", "why"),
    [
        (1, 1, True, "ordinary request"),
        (0, 0, False, "ordinary response"),
        (1, 0, True, "Cerberus Utility: request with rq clear"),
        (0, 1, False, "Microsoft VDM: response with rq still set"),
    ],
)
def test_to_bit_is_authoritative(to: int, rq: int, expected: bool, why: str) -> None:
    pkt = build(to=to, rq=rq)
    assert pkt.getlayer(VdPciHdrPacket).is_request() is expected, why


def test_falls_back_to_rq_without_a_transport_header() -> None:
    """A bare VDPCI header has no TO bit to consult."""
    assert VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=1, vdm_cmd_code=0xFF).is_request() is True
    assert VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=0, vdm_cmd_code=0xFF).is_request() is False
