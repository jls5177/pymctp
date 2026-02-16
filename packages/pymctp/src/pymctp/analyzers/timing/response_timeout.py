# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Detect missing or delayed MCTP responses.

This rule tracks request packets (identified by the MCTP transport header
``to`` bit = 1) and checks that a matching response arrives within a
configurable timeout.  At the end of the stream, any unmatched requests are
reported as errors.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.mctp import TransportHdrPacket

_DEFAULT_TIMEOUT = timedelta(seconds=5)


class ResponseTimeoutRule(AnalysisRule):
    """Detect requests that have no matching response, or responses
    that arrive later than a configurable timeout threshold.

    The rule keys on ``(tag, src, dst)`` from the MCTP transport header.
    A response swaps ``src`` and ``dst`` while keeping the same ``tag``.

    Args:
        timeout: Maximum acceptable time between a request and its response.
    """

    rule_id = "TIMING-001"  # type: ignore[assignment]
    description = "Detect missing or delayed MCTP responses"  # type: ignore[assignment]

    def __init__(self, timeout: timedelta = _DEFAULT_TIMEOUT):
        self.timeout = timeout
        # key → (packet_index, timestamp, packet_summary)
        self._pending: dict[str, tuple[int, datetime | None, str]] = {}

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

        if self._is_request(packet):
            key = self._make_key(packet)
            if key is not None:
                self._pending[key] = (index, timestamp, packet.summary())

        elif self._is_response(packet):
            # Look up the matching request (response swaps src/dst)
            key = self._make_key(packet, as_response=True)
            if key is not None and key in self._pending:
                req_idx, req_ts, req_summary = self._pending.pop(key)
                if timestamp and req_ts:
                    delta = timestamp - req_ts
                    if delta > self.timeout:
                        rsp_ts = timestamp.isoformat() if timestamp else "???"
                        combined_summary = f"{req_summary}\n{rsp_ts}: {packet.summary()}"
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=Severity.WARNING,
                                message=(
                                    f"Delayed response: took {delta.total_seconds():.3f}s "
                                    f"(threshold: {self.timeout.total_seconds():.1f}s)"
                                ),
                                packet_index=req_idx,
                                timestamp=req_ts,
                                context={
                                    "request_index": req_idx,
                                    "response_index": index,
                                    "delta_s": delta.total_seconds(),
                                },
                                packet_summary=combined_summary,
                            )
                        )

        return findings

    def finalize(self) -> Sequence[Finding]:
        findings: list[Finding] = []
        for key, (idx, ts, summary) in self._pending.items():
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.ERROR,
                    message="No response for request",
                    packet_index=idx,
                    timestamp=ts,
                    packet_summary=summary,
                )
            )
        return findings

    def reset(self) -> None:
        self._pending.clear()
