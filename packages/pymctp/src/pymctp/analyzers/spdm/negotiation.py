# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Validate that SPDM negotiation follows the required command order.

Per the SPDM specification, the mandatory negotiation sequence is::

    GET_VERSION → GET_CAPABILITIES → NEGOTIATE_ALGORITHMS

This must complete successfully before any other SPDM commands (digests,
certificates, measurements, etc.) can be issued.  The rule tracks separate
sessions identified by ``(src_eid, dst_eid)`` pairs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.mctp import TransportHdrPacket
from pymctp.layers.mctp.spdm import SpdmHdrPacket, SpdmRequestCode, SpdmResponseCode

# Expected negotiation sequence (request codes in order)
_NEGOTIATION_STEPS: list[tuple[int, str]] = [
    (SpdmRequestCode.GET_VERSION, "GET_VERSION"),
    (SpdmRequestCode.GET_CAPABILITIES, "GET_CAPABILITIES"),
    (SpdmRequestCode.NEGOTIATE_ALGORITHMS, "NEGOTIATE_ALGORITHMS"),
]

# Commands that are only valid *after* negotiation completes
_POST_NEGOTIATION_REQUESTS: set[int] = {
    SpdmRequestCode.GET_DIGESTS,
    SpdmRequestCode.GET_CERTIFICATE,
    SpdmRequestCode.CHALLENGE,
    SpdmRequestCode.GET_MEASUREMENTS,
    SpdmRequestCode.KEY_EXCHANGE,
    SpdmRequestCode.FINISH,
}


class SpdmNegotiationSequenceRule(AnalysisRule):
    """Validate SPDM negotiation ordering per session.

    Checks:
    - GET_VERSION must come first (and resets the sequence)
    - GET_CAPABILITIES must follow GET_VERSION
    - NEGOTIATE_ALGORITHMS must follow GET_CAPABILITIES
    - Operational commands (digests, certs, measurements, etc.) must not
      appear before negotiation is complete
    """

    rule_id = "SPDM-SEQ-001"  # type: ignore[assignment]
    description = "Validate SPDM negotiation command sequence"  # type: ignore[assignment]

    def __init__(self):
        # session_key → step index (0 = nothing yet, 3 = negotiation done)
        self._sessions: dict[str, int] = {}

    @staticmethod
    def _session_key(packet) -> str | None:
        if not packet.haslayer(TransportHdrPacket):
            return None
        hdr = packet.getlayer(TransportHdrPacket)
        src, dst = hdr.src, hdr.dst
        # Normalize so requester→responder and responder→requester share a key
        return f"{min(src, dst)}:{max(src, dst)}"

    def feed(self, index: int, timestamp: datetime | None, packet) -> Sequence[Finding]:
        if not packet.haslayer(SpdmHdrPacket):
            return []

        spdm: SpdmHdrPacket = packet.getlayer(SpdmHdrPacket)
        code = spdm.request_response_code

        # Only look at requests for sequencing (responses confirm, but the
        # ordering constraint is on the requester side)
        is_request = code in {step[0] for step in _NEGOTIATION_STEPS} | _POST_NEGOTIATION_REQUESTS

        # Also count error responses as they don't advance the sequence
        is_error = code == SpdmResponseCode.ERROR
        if not is_request and not is_error:
            return []

        key = self._session_key(packet)
        if key is None:
            return []

        step = self._sessions.get(key, 0)
        findings: list[Finding] = []

        # GET_VERSION always resets the session
        if code == SpdmRequestCode.GET_VERSION:
            self._sessions[key] = 1
            return []

        # If still in negotiation phase, check order
        if step < len(_NEGOTIATION_STEPS):
            expected_code, expected_name = _NEGOTIATION_STEPS[step]
            if code == expected_code:
                self._sessions[key] = step + 1
            elif code in _POST_NEGOTIATION_REQUESTS:
                cmd_name = (
                    SpdmRequestCode(code).name if code in SpdmRequestCode.__members__.values() else f"0x{code:02X}"
                )
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=(
                            f"SPDM {cmd_name} issued before negotiation "
                            f"complete (still at step {step}/{len(_NEGOTIATION_STEPS)}: "
                            f"expecting {expected_name})"
                        ),
                        packet_index=index,
                        timestamp=timestamp,
                        context={"session": key, "step": step, "code": code},
                    )
                )
            elif code in {s[0] for s in _NEGOTIATION_STEPS}:
                actual_name = SpdmRequestCode(code).name
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=(
                            f"SPDM negotiation out of order: expected "
                            f"{expected_name} (0x{expected_code:02X}) but got "
                            f"{actual_name} (0x{code:02X}) at step {step}"
                        ),
                        packet_index=index,
                        timestamp=timestamp,
                        context={"session": key, "step": step, "code": code},
                    )
                )

        return findings

    def reset(self) -> None:
        self._sessions.clear()
