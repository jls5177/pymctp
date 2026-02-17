# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Shared triage options and rule-building helpers for analyzer CLI commands.

This module provides reusable Click options and utility functions so that
multiple analyzer commands (e.g., ``analyze-tcpdump``, ``analyze-ipmi-audit-log``)
share the same triage interface without duplicating code.
"""

from __future__ import annotations

import functools
import pathlib
from collections import Counter
from datetime import datetime, timedelta

import click

from pymctp.analyzers import AnalysisEngine, Severity
from pymctp.analyzers.base import AnalysisRule
from pymctp.analyzers.cerberus import CerberusLogTransferRule
from pymctp.analyzers.mctp import FragmentationRule, TagReuseRule
from pymctp.analyzers.plugin_loader import discover_analyzer_rules
from pymctp.analyzers.spdm import (
    SpdmCertChainRule,
    SpdmErrorResponseRule,
    SpdmMeasurementsRule,
    SpdmNegotiationSequenceRule,
)
from pymctp.analyzers.timing import InterPacketGapRule, ResponseTimeoutRule
from pymctp.layers.interfaces import AnyPacketType
from pymctp.layers.mctp.types import MsgTypes

_SEVERITY_CHOICES = [s.name.lower() for s in Severity]


def triage_options(func):
    """Decorator that adds the standard triage CLI options to a Click command.

    Adds the following options: ``--triage``, ``--min-severity``, ``--rules``,
    ``--response-timeout``, ``--gap-threshold``, ``--json-report``, ``--packet-log``.
    """

    @click.option(
        "--triage/--no-triage",
        default=False,
        help="Run analysis rules to detect protocol issues (default: disabled)",
    )
    @click.option(
        "--min-severity",
        type=click.Choice(_SEVERITY_CHOICES, case_sensitive=False),
        default="warning",
        help="Minimum severity level to report (default: warning)",
    )
    @click.option(
        "--rules",
        multiple=True,
        help="Rule IDs to enable (default: all). May be repeated, e.g. --rules TIMING-001 --rules SPDM-SEQ-001",
    )
    @click.option(
        "--response-timeout",
        type=float,
        default=5.0,
        show_default=True,
        help="Threshold in seconds for delayed response detection",
    )
    @click.option(
        "--gap-threshold",
        type=float,
        default=10.0,
        show_default=True,
        help="Threshold in seconds for inter-packet gap detection",
    )
    @click.option(
        "--json-report",
        type=click.Path(path_type=pathlib.Path),
        default=None,
        help="Write triage findings to a JSON file",
    )
    @click.option(
        "--packet-log",
        type=click.Path(path_type=pathlib.Path),
        default=None,
        help="Write per-packet listing to a file (useful in triage mode where terminal output is suppressed)",
    )
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def build_builtin_rules(
    response_timeout: float,
    gap_threshold: float,
) -> list[AnalysisRule]:
    """Instantiate all built-in analysis rules with the given parameters."""
    return [
        # Timing
        ResponseTimeoutRule(timeout=timedelta(seconds=response_timeout)),
        InterPacketGapRule(threshold=timedelta(seconds=gap_threshold)),
        # MCTP transport
        FragmentationRule(),
        TagReuseRule(),
        # SPDM
        SpdmNegotiationSequenceRule(),
        SpdmErrorResponseRule(),
        SpdmCertChainRule(),
        SpdmMeasurementsRule(),
        # Cerberus
        CerberusLogTransferRule(),
    ]


def setup_triage_engine(
    triage: bool,
    min_severity: str,
    rules: tuple[str, ...],
    response_timeout: float,
    gap_threshold: float,
    extra_rules: list[AnalysisRule] | None = None,
) -> tuple[AnalysisEngine | None, Severity]:
    """Build and configure the triage engine if triage mode is enabled.

    Args:
        triage: Whether triage mode is enabled.
        min_severity: Minimum severity level name (e.g., ``"warning"``).
        rules: Tuple of rule IDs to filter to (empty = all).
        response_timeout: Threshold in seconds for delayed responses.
        gap_threshold: Threshold in seconds for inter-packet gaps.
        extra_rules: Additional rules to register (e.g., IPMI-specific rules).

    Returns:
        A ``(engine, severity_level)`` tuple.  *engine* is ``None`` when
        triage is disabled.
    """
    severity_level = Severity[min_severity.upper()]

    if not triage:
        return None, severity_level

    all_rules = build_builtin_rules(response_timeout, gap_threshold)
    all_rules.extend(discover_analyzer_rules())

    if extra_rules:
        all_rules.extend(extra_rules)

    if rules:
        rule_ids = set(rules)
        all_rules = [r for r in all_rules if r.rule_id in rule_ids]
        if not all_rules:
            click.echo(
                f"Warning: no rules matched the requested IDs: {', '.join(rules)}",
                err=True,
            )
            return None, severity_level

    engine = AnalysisEngine(all_rules)
    engine.reset()
    return engine, severity_level


def print_triage_report(
    engine: AnalysisEngine,
    severity_level: Severity,
    type_counts: Counter[str] | None = None,
    json_report: pathlib.Path | None = None,
) -> None:
    """Finalize the engine and print the triage report.

    Args:
        engine: The analysis engine with fed packets.
        severity_level: Minimum severity to display.
        type_counts: Optional packet type breakdown counter.
        json_report: Optional path to write JSON findings.
    """
    click.echo(f"\n{'=' * 60}")
    click.echo(f"Triage Report  ({len(engine.rules)} rules active)")
    click.echo(f"{'=' * 60}")

    if type_counts:
        breakdown = ", ".join(f"{count} {name}" for name, count in type_counts.most_common())
        click.echo(f"Packet types: {breakdown}")

    engine.finalize_analysis()
    engine.print_report(min_severity=severity_level)

    if json_report is not None:
        json_report.write_text(engine.to_json(min_severity=severity_level))
        click.echo(f"\nJSON report written to: {json_report}")


def tally_mctp_packet(mctp_packet: AnyPacketType, type_counts: Counter[str]) -> None:
    """Tally message types for SOM packets into the counter."""
    if hasattr(mctp_packet, "som") and mctp_packet.som:
        try:
            type_counts[MsgTypes(mctp_packet.msg_type).name] += 1
        except (ValueError, AttributeError):
            type_counts[f"0x{mctp_packet.msg_type:02X}"] += 1
    elif hasattr(mctp_packet, "som"):
        type_counts["(fragment)"] += 1
