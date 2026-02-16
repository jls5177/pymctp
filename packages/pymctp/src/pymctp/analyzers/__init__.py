# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Packet analysis framework for triaging MCTP/SPDM/PLDM captures.

This module provides a rule-based analysis engine that can detect protocol
violations, timing issues, and other problems in MCTP packet captures.

Rules are organized by protocol layer:
- ``analyzers.timing`` — response timeouts, inter-packet gaps
- ``analyzers.spdm`` — SPDM negotiation sequences, error detection
- ``analyzers.mctp`` — fragmentation, tag reuse, EID issues
- ``analyzers.pldm`` — PLDM request/response completion

Third-party packages can register additional rules via the
``pymctp.analyzer_rules`` entry point group.
"""

from .base import AnalysisRule, Finding, Severity
from .engine import AnalysisEngine

__all__ = [
    "AnalysisEngine",
    "AnalysisRule",
    "Finding",
    "Severity",
]
