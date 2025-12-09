# SPDX-FileCopyrightText: 2024 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""
Test FwVersionResponsePacket parsing from raw packet data.
"""

from pymctp.layers.mctp import TransportHdrPacket, VdPciHdrPacket
from pymctp.layers import *
from pymctp_oem_microsoft.layers.mctp.vdpci.cerberus_challenge import FwVersionResponsePacket
from pymctp.utils import str_to_pkt


def test_fw_version_response_packet_parsing():
    """
    Test that a raw packet string is parsed correctly into multiple layers,
    including FwVersionResponsePacket with the correct version field.
    """
    # Parse the raw packet data
    req = str_to_pkt(
        "01 0a 41 c0 7e 14 14 00 01 34 2e 30 2e 33 2e 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
        TransportHdrPacket,
    )

    # Verify the packet has multiple layers
    assert req is not None
    assert req.haslayer(TransportHdrPacket)
    assert req.haslayer(VdPciHdrPacket)
    assert req.haslayer(FwVersionResponsePacket)

    # Get the FwVersionResponsePacket layer
    fw_layer = req.getlayer(FwVersionResponsePacket)
    assert fw_layer is not None

    # Verify the version field
    # The version field is a fixed-length field (32 bytes) padded with null bytes
    assert fw_layer.version.rstrip(b"\x00") == b"4.0.3.0"

    # Verify the full module path of the layer
    assert fw_layer.__class__.__module__ == "pymctp_oem_microsoft.layers.mctp.vdpci.cerberus_challenge"
    assert fw_layer.__class__.__name__ == "FwVersionResponsePacket"
