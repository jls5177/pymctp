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
from pymctp.layers.mctp.types import ICanReply


class TagReuseRule(AnalysisRule):
    """Detect MCTP message tag reuse while a previous request is still pending.

    Tracks outstanding requests keyed on ``(tag, src_eid)`` and flags when the
    same tag is reused by the same source before the previous transaction
    completes.
    """

    rule_id = "MCTP-TAG-001"  # type: ignore[assignment]
    description = "Detect MCTP tag reuse while previous transaction pending"  # type: ignore[assignment]

    def __init__(self):
        # (tag, src, dst) → (packet_index, timestamp, summary)
        self._pending: dict[tuple[int, int, int], tuple[int, datetime | None, str]] = {}

    def feed(self, index: int, timestamp: datetime | None, packet) -> Sequence[Finding]:
        if not packet.haslayer(TransportHdrPacket):
            return []

        hdr = packet.getlayer(TransportHdrPacket)
        findings: list[Finding] = []
        tag = hdr.tag
        src = hdr.src
        dst = hdr.dst
        is_request = bool(hdr.to)

        # Skip packets whose payload explicitly can't generate a reply
        if is_request and hdr.som and (not hdr.payload or isinstance(hdr.payload, ICanReply)):
            # Only SOM requests start a new transaction
            key = (tag, src, dst)
            if key in self._pending:
                prev_idx, prev_ts, prev_summary = self._pending[key]
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=(
                            f"Tag {tag} (EID 0x{src:02X}->0x{dst:02X}) never received a response "
                            f"before tag was reused at pkt#{index}"
                        ),
                        packet_index=prev_idx,
                        timestamp=prev_ts,
                        context={
                            "tag": tag,
                            "src_eid": src,
                            "dst_eid": dst,
                            "reuse_index": index,
                        },
                        packet_summary=prev_summary,
                    )
                )
            self._pending[key] = (index, timestamp, packet.summary())

        elif not is_request and hdr.som:
            # A response with SOM clears the pending request. The response's
            # dst is the original requester's src, and the response's src is
            # the original request's dst. Either side may have been NULL EID
            # (e.g. SetEndpointID), so also try matching with NULL.
            for req_dst in {src, 0x00}:
                for req_src in {dst, 0x00}:
                    self._pending.pop((tag, req_src, req_dst), None)

        return findings

    def reset(self) -> None:
        self._pending.clear()
