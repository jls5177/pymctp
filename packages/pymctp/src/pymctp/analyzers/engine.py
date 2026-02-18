# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Analysis engine that runs rules over a packet stream and collects findings."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable, Sequence

import click

from pymctp.layers.interfaces import AnyPacketType

from .base import AnalysisRule, Finding, Severity


class AnalysisEngine:
    """Runs a set of :class:`AnalysisRule` instances over a packet stream.

    Usage::

        engine = AnalysisEngine()
        engine.add_rule(ResponseTimeoutRule())
        engine.add_rule(SpdmNegotiationSequenceRule())

        findings = engine.analyze(packets)
        engine.print_report()
    """

    def __init__(self, rules: Sequence[AnalysisRule] | None = None):
        self.rules: list[AnalysisRule] = list(rules or [])
        self.findings: list[Finding] = []

    def add_rule(self, rule: AnalysisRule) -> None:
        """Register an additional analysis rule."""
        self.rules.append(rule)

    def reset(self) -> None:
        """Clear findings and reset all rules for a fresh analysis pass."""
        self.findings.clear()
        for rule in self.rules:
            rule.reset()

    def feed(self, index: int, timestamp: datetime | None, packet: AnyPacketType) -> list[Finding]:
        """Feed a single packet to all rules and collect any immediate findings.

        This enables streaming / single-pass processing where packets are
        processed as they are parsed rather than accumulated into a list first.

        Args:
            index: Zero-based packet index within the capture.
            timestamp: Packet timestamp (may be ``None``).
            packet: The parsed packet.

        Returns:
            Findings produced by this packet (may be empty).
        """
        pkt_findings: list[Finding] = []
        for rule in self.rules:
            pkt_findings.extend(rule.feed(index, timestamp, packet))
        self.findings.extend(pkt_findings)
        return pkt_findings

    def finalize_analysis(self) -> list[Finding]:
        """Finalize all rules, sort findings, and return the complete list.

        Call this after the last packet has been fed to collect end-of-stream
        findings (e.g. pending requests that never received a response).

        Returns:
            Sorted list of all findings across all rules.
        """
        for rule in self.rules:
            self.findings.extend(rule.finalize())

        # Sort by timestamp (earliest first), then severity (most severe first).
        # Use a fallback that matches the tz-awareness of actual timestamps.
        _sentinel = datetime.min
        for f in self.findings:
            if f.timestamp is not None:
                if f.timestamp.tzinfo is not None:
                    _sentinel = datetime.min.replace(tzinfo=timezone.utc)
                break
        self.findings.sort(key=lambda f: (f.timestamp or _sentinel, -f.severity))
        return self.findings

    def analyze(
        self,
        packets: Iterable[tuple[datetime | None, AnyPacketType]],
    ) -> list[Finding]:
        """Run all registered rules over *packets* and return combined findings.

        This is a convenience wrapper around :meth:`reset`, :meth:`feed`, and
        :meth:`finalize_analysis` for callers that already have all packets
        available.

        Args:
            packets: Iterable of ``(timestamp, packet)`` tuples as produced
                     by :func:`~pymctp.cli.analyze_tcpdump.parse_pcap_file`
                     or :func:`~pymctp.cli.analyze_tcpdump.parse_text_file`.

        Returns:
            Sorted list of all findings across all rules.
        """
        self.reset()

        for index, (timestamp, packet) in enumerate(packets):
            self.feed(index, timestamp, packet)

        return self.finalize_analysis()

    # ------------------------------------------------------------------
    # Reporting helpers
    # ------------------------------------------------------------------

    def print_report(self, min_severity: Severity = Severity.INFO) -> None:
        """Print a human-readable report of findings to the terminal.

        Args:
            min_severity: Only show findings at or above this severity level.
        """
        filtered = [f for f in self.findings if f.severity >= min_severity]
        if not filtered:
            click.echo("No issues found.")
            return

        counts = {s: 0 for s in Severity}
        for f in filtered:
            counts[f.severity] += 1
            click.echo(str(f))

        click.echo(
            f"\nSummary: {len(filtered)} finding(s) "
            f"({counts[Severity.CRITICAL]} critical, "
            f"{counts[Severity.ERROR]} error, "
            f"{counts[Severity.WARNING]} warning, "
            f"{counts[Severity.INFO]} info)"
        )

    def to_json(self, min_severity: Severity = Severity.INFO) -> str:
        """Serialize findings to a JSON string for programmatic consumption.

        Args:
            min_severity: Only include findings at or above this severity level.

        Returns:
            A JSON string containing a list of finding dictionaries.
        """
        filtered = [f for f in self.findings if f.severity >= min_severity]

        def _serialize(f: Finding) -> dict:
            d = {
                "rule_id": f.rule_id,
                "severity": f.severity.name,
                "message": f.message,
                "packet_index": f.packet_index,
                "context": f.context,
            }
            if f.timestamp:
                d["timestamp"] = f.timestamp.isoformat()
            if f.packet_summary:
                d["packet_summary"] = f.packet_summary
            return d

        return json.dumps([_serialize(f) for f in filtered], indent=2)
