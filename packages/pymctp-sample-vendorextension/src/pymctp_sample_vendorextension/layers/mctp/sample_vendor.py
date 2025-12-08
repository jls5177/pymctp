# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Sample vendor-defined message (VDM) protocol implementation.

This module demonstrates how to create custom MCTP vendor-specific packets.
Use this as a template for your own vendor protocol implementations.
"""

from scapy.fields import ByteField, StrLenField, XByteField
from scapy.packet import Packet, bind_layers

from pymctp.layers.mctp.vdpci import VdPciHdrPacket

# Example vendor ID - In production, use your official PCI Vendor ID
# You can get an official ID from PCI-SIG: https://pcisig.com/
SAMPLE_VENDOR_ID = 0x9999  # Example only - not a real vendor ID


class SampleVendorPacket(Packet):
    """Sample vendor-specific packet.

    This demonstrates a simple vendor protocol with a command field
    and variable-length data payload.

    In your implementation, replace this with your actual protocol fields.
    """

    name = "SAMPLE-VENDOR"
    fields_desc = [
        XByteField("command", 0),  # Command code
        ByteField("status", 0),  # Status/flags field
        ByteField("sequence", 0),  # Sequence number
        ByteField("data_len", None),  # Length of data field
        StrLenField("data", b"", length_from=lambda pkt: pkt.data_len if pkt.data_len is not None else len(pkt.data)),
    ]

    def mysummary(self):
        """Custom packet summary for display."""
        return (
            f"SAMPLE-VENDOR (cmd={self.command:#04x}, status={self.status}, seq={self.sequence}, len={self.data_len})"
        )


class SampleVendorGetVersionRequest(Packet):
    """Example: Get firmware version request packet."""

    name = "SAMPLE-GET-VERSION-REQ"
    fields_desc = [
        ByteField("component_id", 0),  # Which component to query
    ]


class SampleVendorGetVersionResponse(Packet):
    """Example: Get firmware version response packet."""

    name = "SAMPLE-GET-VERSION-RSP"
    fields_desc = [
        ByteField("component_id", 0),
        ByteField("major", 0),
        ByteField("minor", 0),
        ByteField("patch", 0),
        StrLenField("build_info", b"", length_from=lambda pkt: 16),
    ]


# Bind the sample vendor packet to MCTP VDM layer
# This makes it automatically decode when the vendor_id matches
bind_layers(
    VdPciHdrPacket,
    SampleVendorPacket,
    vendor_id=SAMPLE_VENDOR_ID,
    vdm_cmd_code=0x00,  # General message
)

# Bind specific command packets
bind_layers(
    VdPciHdrPacket,
    SampleVendorGetVersionRequest,
    vendor_id=SAMPLE_VENDOR_ID,
    rq=1,  # Request
    vdm_cmd_code=0x01,  # Get version command
)

bind_layers(
    VdPciHdrPacket,
    SampleVendorGetVersionResponse,
    vendor_id=SAMPLE_VENDOR_ID,
    rq=0,  # Response
    vdm_cmd_code=0x01,  # Get version command
)

# Export packet classes
__all__ = [
    "SAMPLE_VENDOR_ID",
    "SampleVendorPacket",
    "SampleVendorGetVersionRequest",
    "SampleVendorGetVersionResponse",
]
