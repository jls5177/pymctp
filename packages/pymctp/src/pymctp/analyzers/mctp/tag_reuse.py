# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Detect MCTP tag reuse while a previous transaction is still pending.

Per DSP0236, a tag value should not be reused by the same requester (same
``src`` EID with ``to=1``) until the previous transaction using that tag has
completed (response received or timed out).  Reusing a tag while a
transaction is in flight can cause response misrouting.
"""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.mctp import TransportHdrPacket


class TagReuseRule(AnalysisRule):
    """Detect MCTP message tag reuse while a previous request is still pending.

    Tracks outstanding requests keyed on ``(tag, src_eid)`` and flags when the
    same tag is reused by the same source before the previous transaction
    completes.
    """

    rule_id = "MCTP-TAG-001"  # type: ignore[assignment]
    description = "Detect MCTP tag reuse while previous transaction pending"  # type: ignore[assignment]

    def __init__(self):
        # (tag, src) → (packet_index, timestamp, summary)
        self._pending: dict[tuple[int, int], tuple[int, datetime | None, str]] = {}

    def feed(self, index: int, timestamp: datetime | None, packet) -> Sequence[Finding]:
        if not packet.haslayer(TransportHdrPacket):
            return []

        hdr = packet.getlayer(TransportHdrPacket)
        findings: list[Finding] = []
        tag = hdr.tag
        src = hdr.src
        dst = hdr.dst
        is_request = bool(hdr.to)

        if is_request and hdr.som and hdr.eom:
            # Only SOM+EOM requests start a new transaction
            key = (tag, src)
            if key in self._pending:
                prev_idx, prev_ts, prev_summary = self._pending[key]
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=(
                            f"Tag {tag} (EID 0x{src:02X}) never received a response "
                            f"before tag was reused at pkt#{index}"
                        ),
                        packet_index=prev_idx,
                        timestamp=prev_ts,
                        context={
                            "tag": tag,
                            "src_eid": src,
                            "reuse_index": index,
                        },
                        packet_summary=prev_summary,
                    )
                )
            self._pending[key] = (index, timestamp, packet.summary())

        elif not is_request and hdr.som:
            # A response with SOM (whether SOM+EOM or start of a fragmented
            # response) means the responder has begun replying — clear the
            # pending request.  We key on (tag, dst) because the response's
            # dst is the original requester.
            key = (tag, dst)
            self._pending.pop(key, None)

        return findings

    def reset(self) -> None:
        self._pending.clear()
