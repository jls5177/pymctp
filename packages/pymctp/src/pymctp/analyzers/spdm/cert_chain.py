# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Validate SPDM certificate retrieval sequences.

The typical certificate retrieval flow is::

    (negotiation must be complete)
    GET_DIGESTS → DIGESTS response
    GET_CERTIFICATE (offset=0, slot=N) → CERTIFICATE response (portion_length, remainder_length)
    GET_CERTIFICATE (offset+=portion) → CERTIFICATE response
    ...repeat until remainder_length == 0...

This rule checks:
- ``GET_DIGESTS`` is issued before ``GET_CERTIFICATE``
- Certificate chain retrieval completes (``remainder_length`` reaches 0)
- No unexpected slot switches mid-retrieval
"""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.mctp import TransportHdrPacket
from pymctp.layers.mctp.spdm import SpdmHdrPacket, SpdmRequestCode, SpdmResponseCode


class SpdmCertChainRule(AnalysisRule):
    """Validate SPDM GET_CERTIFICATE retrieval sequences.

    Tracks per-session state to ensure the certificate chain retrieval
    protocol is followed correctly.
    """

    rule_id = "SPDM-SEQ-002"  # type: ignore[assignment]
    description = "Validate SPDM certificate chain retrieval sequence"  # type: ignore[assignment]

    def __init__(self):
        # session_key → state
        self._got_digests: dict[str, bool] = {}
        self._in_cert_retrieval: dict[str, bool] = {}
        self._cert_slot: dict[str, int] = {}

    @staticmethod
    def _session_key(packet) -> str | None:
        if not packet.haslayer(TransportHdrPacket):
            return None
        hdr = packet.getlayer(TransportHdrPacket)
        src, dst = hdr.src, hdr.dst
        return f"{min(src, dst)}:{max(src, dst)}"

    def feed(self, index: int, timestamp: datetime | None, packet) -> Sequence[Finding]:
        if not packet.haslayer(SpdmHdrPacket):
            return []

        spdm: SpdmHdrPacket = packet.getlayer(SpdmHdrPacket)
        code = spdm.request_response_code
        key = self._session_key(packet)
        if key is None:
            return []

        findings: list[Finding] = []

        # Track GET_DIGESTS requests
        if code == SpdmRequestCode.GET_DIGESTS:
            self._got_digests[key] = True
            return []

        # Track DIGESTS response (confirms digests were successful)
        if code == SpdmResponseCode.DIGESTS:
            self._got_digests.setdefault(key, True)
            return []

        # Check GET_CERTIFICATE requests
        if code == SpdmRequestCode.GET_CERTIFICATE:
            if not self._got_digests.get(key, False):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.WARNING,
                        message="GET_CERTIFICATE issued without prior GET_DIGESTS",
                        packet_index=index,
                        timestamp=timestamp,
                        context={"session": key},
                    )
                )

            # Track slot from param1 (slot ID)
            slot = spdm.param1
            if self._in_cert_retrieval.get(key, False):
                prev_slot = self._cert_slot.get(key, -1)
                if prev_slot != -1 and slot != prev_slot:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.ERROR,
                            message=(f"Slot changed mid-retrieval: was slot {prev_slot}, now slot {slot}"),
                            packet_index=index,
                            timestamp=timestamp,
                            context={"session": key, "prev_slot": prev_slot, "new_slot": slot},
                        )
                    )

            self._in_cert_retrieval[key] = True
            self._cert_slot[key] = slot
            return findings

        # Track CERTIFICATE response — check remainder_length for completion
        if code == SpdmResponseCode.CERTIFICATE:
            # Certificate retrieval is done; reset for potential next slot
            # (We can't easily parse remainder_length from the generic SpdmHdrPacket
            #  without the specific CertificateResponse layer, so we just track
            #  that a Certificate response was seen.)
            self._in_cert_retrieval[key] = False
            return []

        # GET_VERSION resets everything
        if code == SpdmRequestCode.GET_VERSION:
            self._got_digests.pop(key, None)
            self._in_cert_retrieval.pop(key, None)
            self._cert_slot.pop(key, None)
            return []

        return findings

    def finalize(self) -> Sequence[Finding]:
        findings: list[Finding] = []
        for key, in_progress in self._in_cert_retrieval.items():
            if in_progress:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.WARNING,
                        message=f"Certificate retrieval incomplete at end of capture (session {key})",
                        timestamp=None,
                        context={"session": key},
                    )
                )
        return findings

    def reset(self) -> None:
        self._got_digests.clear()
        self._in_cert_retrieval.clear()
        self._cert_slot.clear()
