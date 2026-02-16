# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Base classes for the packet analysis rule engine."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Sequence

from pymctp.layers.interfaces import AnyPacketType


class Severity(IntEnum):
    """Severity levels for analysis findings, ordered from least to most severe."""

    INFO = 0
    WARNING = 1
    ERROR = 2
    CRITICAL = 3


_SEVERITY_LETTER = {Severity.INFO: "I", Severity.WARNING: "W", Severity.ERROR: "E", Severity.CRITICAL: "C"}


@dataclass
class Finding:
    """A single issue discovered during analysis.

    Attributes:
        rule_id: Unique identifier of the rule that produced this finding.
        severity: How severe the issue is.
        message: Human-readable description of the issue.
        packet_index: Zero-based index into the packet list, if applicable.
        timestamp: UTC timestamp of the packet that triggered the finding.
        context: Arbitrary structured data for programmatic consumers
                 (e.g., ``{"delta_s": 6.3, "request_index": 42}``).
        packet_summary: Optional Scapy packet summary string.  When present
                        it is displayed on a second line indented with an arrow.
    """

    rule_id: str
    severity: Severity
    message: str
    packet_index: int | None = None
    timestamp: datetime | None = None
    context: dict = field(default_factory=dict)
    packet_summary: str | None = None

    def __str__(self) -> str:
        letter = _SEVERITY_LETTER.get(self.severity, "?")
        idx = f" pkt#{self.packet_index}" if self.packet_index is not None else ""
        header = f"[{letter}] {self.rule_id}{idx}: {self.message}"
        ts = self.timestamp.isoformat() if self.timestamp else "???"
        if self.packet_summary:
            lines = self.packet_summary.split("\n")
            header += f"\n  \u21b3 {ts}: {lines[0]}"
            for extra in lines[1:]:
                header += f"\n  \u21b3 {extra}"
        else:
            header += f"\n  \u21b3 {ts}"
        return header


class AnalysisRule(abc.ABC):
    """Abstract base class for all analysis rules.

    Rules are **stateful and streaming** — they receive packets one at a time
    via :meth:`feed`, maintaining whatever internal state they need (e.g.,
    "waiting for a response to the last request").

    After all packets have been fed, :meth:`finalize` is called so the rule can
    emit any remaining findings (e.g., "request at end of capture with no
    response").

    Lifecycle::

        rule.reset()                       # clear state
        for i, (ts, pkt) in enumerate(packets):
            findings += rule.feed(i, ts, pkt)
        findings += rule.finalize()

    This streaming design means rules work on arbitrarily large captures
    without loading all packets into memory at once.
    """

    @property
    @abc.abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for the rule, e.g. ``'SPDM-SEQ-001'``."""

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Human-readable description of what this rule checks."""

    @abc.abstractmethod
    def feed(
        self,
        index: int,
        timestamp: datetime | None,
        packet: AnyPacketType,
    ) -> Sequence[Finding]:
        """Process a single packet.

        Args:
            index: Zero-based position in the packet stream.
            timestamp: UTC timestamp of the packet, or *None* if unavailable.
            packet: The parsed MCTP packet (Scapy ``Packet``).

        Returns:
            Zero or more findings triggered by this packet.
        """

    def finalize(self) -> Sequence[Finding]:
        """Called after all packets have been fed.

        Override this to emit findings about end-of-stream conditions such as
        unanswered requests.

        Returns:
            Zero or more final findings.
        """
        return []

    def reset(self) -> None:
        """Reset internal state so the rule can be reused on another capture."""
