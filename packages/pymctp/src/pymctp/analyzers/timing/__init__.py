# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Timing-related analysis rules."""

from .response_timeout import ResponseTimeoutRule
from .inter_packet_gap import InterPacketGapRule

__all__ = [
    "InterPacketGapRule",
    "ResponseTimeoutRule",
]
