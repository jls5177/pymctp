# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Detect MCTP fragmentation / reassembly issues.

Checks:
- Missing SOM (middle-of-message fragment with no preceding SOM)
- Missing EOM (SOM seen but stream ends before EOM)
- Out-of-order packet sequence numbers within a fragmented message
- SOM+EOM both set but followed by more fragments with the same tag
"""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.mctp import TransportHdrPacket


class FragmentationRule(AnalysisRule):
    """Detect MCTP message fragmentation and reassembly issues.

    Tracks in-flight fragmented messages keyed on ``(tag, src, dst)`` and
    validates SOM/EOM/pkt_seq ordering.
    """

    rule_id = "MCTP-FRAG-001"  # type: ignore[assignment]
    description = "Detect MCTP fragmentation and reassembly issues"  # type: ignore[assignment]

    def __init__(self):
        # key → (last_pkt_seq, start_index, start_timestamp)
        self._in_flight: dict[str, tuple[int, int, datetime | None]] = {}

    @staticmethod
    def _make_key(pkt) -> str | None:
        if not pkt.haslayer(TransportHdrPacket):
            return None
        hdr = pkt.getlayer(TransportHdrPacket)
        return f"{hdr.tag}:{hdr.src}:{hdr.dst}"

    def feed(self, index: int, timestamp: datetime | None, packet) -> Sequence[Finding]:
        if not packet.haslayer(TransportHdrPacket):
            return []

        hdr = packet.getlayer(TransportHdrPacket)
        som = bool(hdr.som)
        eom = bool(hdr.eom)
        pkt_seq = hdr.pkt_seq
        key = self._make_key(packet)
        if key is None:
            return []

        findings: list[Finding] = []

        if som and eom:
            # Single-packet message — if we had an in-flight for this key,
            # the previous message was never completed
            if key in self._in_flight:
                prev_seq, start_idx, start_ts = self._in_flight.pop(key)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=(
                            f"Incomplete fragmented message abandoned (started pkt#{start_idx}, last seq={prev_seq})"
                        ),
                        packet_index=index,
                        timestamp=timestamp,
                        context={"start_index": start_idx, "last_seq": prev_seq},
                    )
                )
            return findings

        if som and not eom:
            # Start of fragmented message
            if key in self._in_flight:
                prev_seq, start_idx, start_ts = self._in_flight[key]
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=(
                            f"New SOM while previous "
                            f"fragmented message (started pkt#{start_idx}) "
                            f"was not completed (no EOM)"
                        ),
                        packet_index=index,
                        timestamp=timestamp,
                        context={"start_index": start_idx},
                    )
                )
            self._in_flight[key] = (pkt_seq, index, timestamp)
            return findings

        if not som and not eom:
            # Middle fragment
            if key not in self._in_flight:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=(f"Middle fragment with no preceding SOM for key {key}"),
                        packet_index=index,
                        timestamp=timestamp,
                    )
                )
            else:
                prev_seq, start_idx, _ = self._in_flight[key]
                expected_seq = (prev_seq + 1) % 4
                if pkt_seq != expected_seq:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.ERROR,
                            message=(f"Packet sequence out of order: expected {expected_seq}, got {pkt_seq}"),
                            packet_index=index,
                            timestamp=timestamp,
                            context={
                                "expected_seq": expected_seq,
                                "actual_seq": pkt_seq,
                                "start_index": start_idx,
                            },
                        )
                    )
                self._in_flight[key] = (pkt_seq, start_idx, self._in_flight[key][2])
            return findings

        if not som and eom:
            # End of fragmented message
            if key not in self._in_flight:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=(f"EOM with no preceding SOM for key {key}"),
                        packet_index=index,
                        timestamp=timestamp,
                    )
                )
            else:
                prev_seq, start_idx, _ = self._in_flight[key]
                expected_seq = (prev_seq + 1) % 4
                if pkt_seq != expected_seq:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.ERROR,
                            message=(f"Packet sequence out of order at EOM: expected {expected_seq}, got {pkt_seq}"),
                            packet_index=index,
                            timestamp=timestamp,
                            context={
                                "expected_seq": expected_seq,
                                "actual_seq": pkt_seq,
                                "start_index": start_idx,
                            },
                        )
                    )
                del self._in_flight[key]
            return findings

        return findings

    def finalize(self) -> Sequence[Finding]:
        findings: list[Finding] = []
        for key, (last_seq, start_idx, start_ts) in self._in_flight.items():
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.ERROR,
                    message=(f"Incomplete fragmented message at end of capture (last seq={last_seq}, key={key})"),
                    packet_index=start_idx,
                    timestamp=start_ts,
                )
            )
        return findings

    def reset(self) -> None:
        self._in_flight.clear()
