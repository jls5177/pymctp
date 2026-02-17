# SPDX-FileCopyrightText: 2024 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Analysis rule that detects IPMI responses exceeding a time threshold."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.interfaces import AnyPacketType
from pymctp.layers.ipmi import TransportHdrPacket as IpmiTransportHdrPacket


class IpmiSlowResponseRule(AnalysisRule):
    """Detects IPMI responses that took longer than a configurable threshold.

    Args:
        threshold: Maximum acceptable response time. Defaults to 500 ms.
    """

    @property
    def rule_id(self) -> str:
        return "IPMI-SLOW-001"

    @property
    def description(self) -> str:
        return "Detects IPMI responses exceeding a time threshold"

    def __init__(self, threshold: timedelta = timedelta(milliseconds=500)) -> None:
        self._threshold = threshold
        self._req_index: int | None = None
        self._req_timestamp: datetime | None = None
        self._req_packet: IpmiTransportHdrPacket | None = None

    def feed(
        self,
        index: int,
        timestamp: datetime | None,
        packet: AnyPacketType,
    ) -> Sequence[Finding]:
        if not isinstance(packet, IpmiTransportHdrPacket):
            return []

        if packet.is_request():
            self._req_index = index
            self._req_timestamp = timestamp
            self._req_packet = packet
            return []

        # Response — check elapsed time
        if self._req_timestamp is not None and timestamp is not None:
            elapsed = timestamp - self._req_timestamp
            if elapsed > self._threshold:
                elapsed_ms = elapsed.total_seconds() * 1000
                finding = Finding(
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    message=f"Slow response: {elapsed_ms:.2f} ms (threshold: {self._threshold.total_seconds() * 1000:.0f} ms)",
                    packet_index=self._req_index,
                    timestamp=self._req_timestamp,
                    packet_summary=(f"{self._req_packet.summary()}\n{timestamp.isoformat()}: {packet.summary()}"),
                )
                self._req_packet = None
                self._req_index = None
                self._req_timestamp = None
                return [finding]

        self._req_packet = None
        self._req_index = None
        self._req_timestamp = None
        return []

    def reset(self) -> None:
        self._req_index = None
        self._req_timestamp = None
        self._req_packet = None
