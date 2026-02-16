# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Detect SPDM ERROR responses and classify them.

This rule flags every SPDM ``ERROR`` response (code ``0x7F``) and reports
the error code from ``param1``.  Certain errors (e.g.,
``RESPONSE_NOT_READY``, ``REQUEST_RESYNCH``) are elevated to higher severity
because they indicate systemic issues.
"""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.mctp.spdm import SpdmHdrPacket, SpdmResponseCode, SpdmErrorCode

# Error codes that deserve elevated severity
_ELEVATED_ERRORS: dict[int, Severity] = {
    SpdmErrorCode.BUSY: Severity.WARNING,
    SpdmErrorCode.UNEXPECTED_REQUEST: Severity.ERROR,
    SpdmErrorCode.RESPONSE_NOT_READY: Severity.WARNING,
    SpdmErrorCode.REQUEST_RESYNCH: Severity.ERROR,
    SpdmErrorCode.VERSION_MISMATCH: Severity.ERROR,
}


class SpdmErrorResponseRule(AnalysisRule):
    """Report every SPDM ERROR response, with severity based on error code.

    - ``BUSY`` / ``RESPONSE_NOT_READY`` → WARNING (transient, but worth noting)
    - ``UNEXPECTED_REQUEST`` / ``REQUEST_RESYNCH`` / ``VERSION_MISMATCH`` → ERROR
    - All others → INFO
    """

    rule_id = "SPDM-ERR-001"  # type: ignore[assignment]
    description = "Detect SPDM ERROR responses"  # type: ignore[assignment]

    def feed(self, index: int, timestamp: datetime | None, packet) -> Sequence[Finding]:
        if not packet.haslayer(SpdmHdrPacket):
            return []

        spdm: SpdmHdrPacket = packet.getlayer(SpdmHdrPacket)
        if spdm.request_response_code != SpdmResponseCode.ERROR:
            return []

        error_code = spdm.param1
        try:
            error_name = SpdmErrorCode(error_code).name
        except ValueError:
            error_name = f"UNKNOWN(0x{error_code:02X})"

        severity = _ELEVATED_ERRORS.get(error_code, Severity.INFO)

        return [
            Finding(
                rule_id=self.rule_id,
                severity=severity,
                message=f"SPDM ERROR response: {error_name} (0x{error_code:02X})",
                packet_index=index,
                timestamp=timestamp,
                context={"error_code": error_code, "error_name": error_name},
            )
        ]

    def reset(self) -> None:
        pass
