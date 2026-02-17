# SPDX-FileCopyrightText: 2024 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Analysis rule that detects KCS IPMI requests with no matching response."""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.interfaces import AnyPacketType
from pymctp.layers.ipmi import TransportHdrPacket as IpmiTransportHdrPacket


class IpmiMissingResponseRule(AnalysisRule):
    """Detects KCS IPMI requests that never receive a response.

    The rule tracks the most recent KCS request.  When a new request arrives
    before a response to the previous one, a finding is emitted.  Any
    remaining pending request at end-of-stream is also reported via
    :meth:`finalize`.
    """

    @property
    def rule_id(self) -> str:
        return "IPMI-MISS-001"

    @property
    def description(self) -> str:
        return "Detects KCS requests with no matching response"

    def __init__(self) -> None:
        self._pending_index: int | None = None
        self._pending_timestamp: datetime | None = None
        self._pending_packet: IpmiTransportHdrPacket | None = None
        self._pending_intf: str | None = None

    def feed(
        self,
        index: int,
        timestamp: datetime | None,
        packet: AnyPacketType,
    ) -> Sequence[Finding]:
        if not isinstance(packet, IpmiTransportHdrPacket):
            return []

        # The CLI sets ``packet.ipmi_intf`` before feeding to the engine.
        intf: str | None = getattr(packet, "ipmi_intf", None)

        findings: list[Finding] = []

        if packet.is_request():
            # A new request while previous KCS request is still pending
            if self._pending_packet is not None and self._pending_intf == "KCS":
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.WARNING,
                        message="Response missing for KCS request",
                        packet_index=self._pending_index,
                        timestamp=self._pending_timestamp,
                        packet_summary=self._pending_packet.summary(),
                    )
                )
            self._pending_index = index
            self._pending_timestamp = timestamp
            self._pending_packet = packet
            self._pending_intf = intf
        else:
            # Response received — clear pending request
            self._pending_packet = None
            self._pending_index = None
            self._pending_timestamp = None
            self._pending_intf = None

        return findings

    def finalize(self) -> Sequence[Finding]:
        if self._pending_packet is not None and self._pending_intf == "KCS":
            return [
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.WARNING,
                    message="Response missing for KCS request (end of capture)",
                    packet_index=self._pending_index,
                    timestamp=self._pending_timestamp,
                    packet_summary=self._pending_packet.summary(),
                )
            ]
        return []

    def reset(self) -> None:
        self._pending_index = None
        self._pending_timestamp = None
        self._pending_packet = None
        self._pending_intf = None
