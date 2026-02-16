# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Validate SPDM measurement retrieval sequences.

The typical measurement flow is::

    GET_MEASUREMENTS (MeasOp=AllMeasurements) → MEASUREMENTS response
      or
    GET_MEASUREMENTS (MeasOp=Index(N)) → MEASUREMENTS response  (repeated per index)

This rule checks:
- Measurement requests happen after negotiation (GET_VERSION seen)
- Tracks individual measurement index requests per session
- Flags if a signed measurement request (``Attr.GenSig``) has no
  corresponding successful response
"""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.mctp import TransportHdrPacket
from pymctp.layers.mctp.spdm import SpdmHdrPacket, SpdmRequestCode, SpdmResponseCode


class SpdmMeasurementsRule(AnalysisRule):
    """Validate SPDM GET_MEASUREMENTS retrieval flow.

    Tracks per-session state and reports:
    - Measurement requests without prior negotiation
    - Signed measurement requests that received no successful response
    """

    rule_id = "SPDM-SEQ-003"  # type: ignore[assignment]
    description = "Validate SPDM measurement retrieval sequence"  # type: ignore[assignment]

    def __init__(self):
        # session → whether negotiation was seen
        self._negotiated: dict[str, bool] = {}
        # session → list of (index, pkt_index, timestamp, has_sig_request) pending measurement requests
        self._pending_meas: dict[str, list[tuple[int, int, datetime | None, bool]]] = {}

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

        # Track negotiation
        if code == SpdmRequestCode.GET_VERSION:
            self._negotiated[key] = False
            self._pending_meas.pop(key, None)
            return []

        if code == SpdmResponseCode.ALGORITHMS:
            self._negotiated[key] = True
            return []

        # Handle GET_MEASUREMENTS request
        if code == SpdmRequestCode.GET_MEASUREMENTS:
            if not self._negotiated.get(key, False):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message="GET_MEASUREMENTS issued before negotiation complete",
                        packet_index=index,
                        timestamp=timestamp,
                        context={"session": key},
                    )
                )

            # param2 = MeasurementOperation (index or all)
            meas_op = spdm.param2
            # param1 bit 0 = GenerateSignature (Attr)
            gen_sig = bool(spdm.param1 & 0x01)

            pending = self._pending_meas.setdefault(key, [])
            pending.append((meas_op, index, timestamp, gen_sig))
            return findings

        # Handle MEASUREMENTS response — match to pending
        if code == SpdmResponseCode.MEASUREMENTS:
            pending = self._pending_meas.get(key, [])
            if pending:
                pending.pop(0)  # consume the oldest pending request
            return []

        return findings

    def finalize(self) -> Sequence[Finding]:
        findings: list[Finding] = []
        for key, pending in self._pending_meas.items():
            for meas_op, pkt_idx, ts, gen_sig in pending:
                severity = Severity.ERROR if gen_sig else Severity.WARNING
                sig_note = " (signed, GenSig=1)" if gen_sig else ""
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=severity,
                        message=(f"GET_MEASUREMENTS (op=0x{meas_op:02X}){sig_note} has no response"),
                        packet_index=pkt_idx,
                        timestamp=ts,
                        context={"session": key, "meas_op": meas_op, "gen_sig": gen_sig},
                    )
                )
        return findings

    def reset(self) -> None:
        self._negotiated.clear()
        self._pending_meas.clear()
