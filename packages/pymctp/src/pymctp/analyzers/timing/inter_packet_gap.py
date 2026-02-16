# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Detect abnormal time gaps between MCTP requests and their responses.

This rule tracks request→response pairs (matched by MCTP transport tag and
EID) and flags cases where the response arrives after a configurable
threshold.  Unlike ``TIMING-001`` (ResponseTimeoutRule) which focuses on
completely *missing* responses, this rule highlights *slow* responses that
may indicate firmware processing delays, bus contention, or retry storms.

Idle gaps between unrelated transactions (e.g., 90 s of silence between two
independent command sequences) are intentionally ignored.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.mctp import TransportHdrPacket

_DEFAULT_THRESHOLD = timedelta(seconds=10)


class InterPacketGapRule(AnalysisRule):
    """Flag request→response pairs separated by more than *threshold*.

    Only MCTP packets with a transport header are considered.  Requests are
    identified by ``to=1`` (tag owner) with ``som=1, eom=1`` and responses by
    ``to=0`` with matching ``(tag, swapped src/dst)``.

    Args:
        threshold: Maximum acceptable gap between a request and its response.
    """

    rule_id = "TIMING-002"  # type: ignore[assignment]
    description = "Detect abnormally large gaps between MCTP requests and responses"  # type: ignore[assignment]

    def __init__(self, threshold: timedelta = _DEFAULT_THRESHOLD):
        self.threshold = threshold
        # key → (packet_index, timestamp, summary)
        self._pending: dict[str, tuple[int, datetime, str]] = {}

    # ------------------------------------------------------------------

    @staticmethod
    def _make_key(pkt, *, as_response: bool = False) -> str | None:
        """Build a matching key from the transport header.

        For a request we store ``(tag, src, dst)``; for a response we look up
        ``(tag, dst, src)`` — i.e. the addresses are swapped.
        """
        if not pkt.haslayer(TransportHdrPacket):
            return None
        hdr = pkt.getlayer(TransportHdrPacket)
        if as_response:
            return f"{hdr.tag}:{hdr.dst}:{hdr.src}"
        return f"{hdr.tag}:{hdr.src}:{hdr.dst}"

    @staticmethod
    def _is_request(pkt) -> bool:
        if not pkt.haslayer(TransportHdrPacket):
            return False
        hdr = pkt.getlayer(TransportHdrPacket)
        return bool(hdr.to) and bool(hdr.som) and bool(hdr.eom)

    @staticmethod
    def _is_response(pkt) -> bool:
        if not pkt.haslayer(TransportHdrPacket):
            return False
        hdr = pkt.getlayer(TransportHdrPacket)
        return (not hdr.to) and bool(hdr.som) and bool(hdr.eom)

    # ------------------------------------------------------------------

    def feed(self, index: int, timestamp: datetime | None, packet) -> Sequence[Finding]:
        findings: list[Finding] = []

        if self._is_request(packet) and timestamp is not None:
            key = self._make_key(packet)
            if key is not None:
                self._pending[key] = (index, timestamp, packet.summary())

        elif self._is_response(packet) and timestamp is not None:
            key = self._make_key(packet, as_response=True)
            if key is not None and key in self._pending:
                req_idx, req_ts, req_summary = self._pending.pop(key)
                gap = timestamp - req_ts
                if gap > self.threshold:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.WARNING,
                            message=(
                                f"Gap of {gap.total_seconds():.3f}s to response pkt#{index} "
                                f"(threshold: {self.threshold.total_seconds():.1f}s)"
                            ),
                            packet_index=req_idx,
                            timestamp=req_ts,
                            context={
                                "gap_s": gap.total_seconds(),
                                "request_index": req_idx,
                            },
                            packet_summary=req_summary,
                        )
                    )

        return findings

    def reset(self) -> None:
        self._pending.clear()
