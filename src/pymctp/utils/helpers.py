# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""
Collection of helper classes and methods to simplify user applications.
Note: these should not be used internally within the PyMCTP package to prevent
      circular dependencies.
"""

import binascii

import crc8
from scapy.config import conf
from scapy.packet import Raw

from ..layers import ipmi, mctp

ALL_1s_BLOCK = bytes([0xFF] * 4096)


class PrintableRawPacket(Raw):
    name = "PRaw"
    __slots__ = ["_mysummary_cls"]

    def set_mysummary_classes(self, classes):
        self._mysummary_cls = classes

    def mysummary(self):
        if self.load == ALL_1s_BLOCK[: len(self.load)]:
            summary = f"Padded [0xff] * {len(self.load)}"
        else:
            # add CRC to make it easy to compare raw payloads
            crc = crc8.crc8()
            crc.update(self.load)
            if len(self.load) > 64:
                summary = f"Raw ${crc.hexdigest().upper()} [{len(self.load)}] {binascii.hexlify(self.load[:8], b' ', -2).decode()} ..."
            else:
                summary = f"Raw ${crc.hexdigest().upper()} [{len(self.load)}] {binascii.hexlify(self.load, b' ', -2).decode()}"
        if hasattr(self, "_mysummary_cls"):
            return summary, [
                *self._mysummary_cls,
                mctp.SmbusTransportPacket,
                mctp.TransportHdrPacket,
                ipmi.TransportHdrPacket,
            ]
        return summary, [mctp.SmbusTransportPacket, mctp.TransportHdrPacket, ipmi.TransportHdrPacket]


def set_printable_raw_layer():
    """Replaces the default Raw Packet to one that supports printing underlayers by default"""
    conf.raw_layer = PrintableRawPacket
