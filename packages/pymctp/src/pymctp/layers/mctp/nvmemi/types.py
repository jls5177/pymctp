# SPDX-FileCopyrightText: 2025 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from enum import IntEnum


class NvmeMIMessageType(IntEnum):
    CNTRL = 0x00
    CMD = 0x01
    ADMIN_CMD = 0x02
    # RSVD = 0x03
    PCIE_CMD = 0x04

    def __str__(self):
        return self.name
