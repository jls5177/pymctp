# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for SPDM analysis rules."""

from datetime import datetime, timedelta

import pytest

from pymctp.analyzers.base import Severity
from pymctp.analyzers.spdm import (
    SpdmCertChainRule,
    SpdmErrorResponseRule,
    SpdmMeasurementsRule,
    SpdmNegotiationSequenceRule,
)
from pymctp.layers.mctp.spdm import SpdmHdr, SpdmHdrPacket
from pymctp.layers.mctp.spdm.types import SpdmErrorCode, SpdmRequestCode, SpdmResponseCode
from pymctp.layers.mctp.transport import TransportHdr
from pymctp.layers.mctp.types import MsgTypes


def _spdm_pkt(code: int, src: int = 0x40, dst: int = 0x0C, param1: int = 0, param2: int = 0) -> SpdmHdrPacket:
    """Build an MCTP/SPDM packet for testing."""
    to = 1 if code in SpdmRequestCode.__members__.values() else 0
    pkt = TransportHdr(
        src=src,
        dst=dst,
        som=1,
        eom=1,
        to=to,
        tag=0,
        msg_type=MsgTypes.SPDM,
    ) / SpdmHdr(
        request_response_code=code,
        param1=param1,
        param2=param2,
    )
    # Force dissection so layers are available
    return SpdmHdrPacket(bytes(pkt.getlayer(SpdmHdrPacket)), _underlayer=pkt) if False else pkt


class TestSpdmNegotiationSequenceRule:
    def test_correct_sequence_no_findings(self):
        rule = SpdmNegotiationSequenceRule()
        t = datetime(2026, 1, 1)
        pkts = [
            (t, _spdm_pkt(SpdmRequestCode.GET_VERSION)),
            (t, _spdm_pkt(SpdmResponseCode.VERSION, src=0x0C, dst=0x40)),
            (t, _spdm_pkt(SpdmRequestCode.GET_CAPABILITIES)),
            (t, _spdm_pkt(SpdmResponseCode.CAPABILITIES, src=0x0C, dst=0x40)),
            (t, _spdm_pkt(SpdmRequestCode.NEGOTIATE_ALGORITHMS)),
            (t, _spdm_pkt(SpdmResponseCode.ALGORITHMS, src=0x0C, dst=0x40)),
        ]
        for i, (ts, pkt) in enumerate(pkts):
            findings = rule.feed(i, ts, pkt)
            assert findings == [], f"Unexpected finding at step {i}: {findings}"
        assert rule.finalize() == []

    def test_out_of_order_raises_error(self):
        rule = SpdmNegotiationSequenceRule()
        t = datetime(2026, 1, 1)
        # Skip GET_VERSION, go straight to GET_CAPABILITIES
        findings = rule.feed(0, t, _spdm_pkt(SpdmRequestCode.GET_CAPABILITIES))
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "out of order" in findings[0].message

    def test_operational_cmd_before_negotiation(self):
        rule = SpdmNegotiationSequenceRule()
        t = datetime(2026, 1, 1)
        # Only GET_VERSION done, then jump to GET_DIGESTS
        rule.feed(0, t, _spdm_pkt(SpdmRequestCode.GET_VERSION))
        findings = rule.feed(1, t, _spdm_pkt(SpdmRequestCode.GET_DIGESTS))
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "before negotiation" in findings[0].message

    def test_get_version_resets_session(self):
        rule = SpdmNegotiationSequenceRule()
        t = datetime(2026, 1, 1)
        rule.feed(0, t, _spdm_pkt(SpdmRequestCode.GET_VERSION))
        rule.feed(1, t, _spdm_pkt(SpdmRequestCode.GET_CAPABILITIES))
        # A second GET_VERSION should reset
        assert rule.feed(2, t, _spdm_pkt(SpdmRequestCode.GET_VERSION)) == []
        # Now GET_CAPABILITIES should work again (step 1)
        assert rule.feed(3, t, _spdm_pkt(SpdmRequestCode.GET_CAPABILITIES)) == []


class TestSpdmErrorResponseRule:
    def test_error_response_detected(self):
        rule = SpdmErrorResponseRule()
        t = datetime(2026, 1, 1)
        pkt = _spdm_pkt(SpdmResponseCode.ERROR, src=0x0C, dst=0x40, param1=SpdmErrorCode.BUSY)
        findings = rule.feed(0, t, pkt)
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARNING
        assert "BUSY" in findings[0].message

    def test_critical_error_elevated(self):
        rule = SpdmErrorResponseRule()
        t = datetime(2026, 1, 1)
        pkt = _spdm_pkt(SpdmResponseCode.ERROR, src=0x0C, dst=0x40, param1=SpdmErrorCode.UNEXPECTED_REQUEST)
        findings = rule.feed(0, t, pkt)
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR

    def test_non_error_ignored(self):
        rule = SpdmErrorResponseRule()
        t = datetime(2026, 1, 1)
        pkt = _spdm_pkt(SpdmResponseCode.VERSION, src=0x0C, dst=0x40)
        assert rule.feed(0, t, pkt) == []


class TestSpdmCertChainRule:
    def test_cert_without_digests_warns(self):
        rule = SpdmCertChainRule()
        t = datetime(2026, 1, 1)
        pkt = _spdm_pkt(SpdmRequestCode.GET_CERTIFICATE, param1=0)
        findings = rule.feed(0, t, pkt)
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARNING
        assert "without prior GET_DIGESTS" in findings[0].message

    def test_cert_after_digests_ok(self):
        rule = SpdmCertChainRule()
        t = datetime(2026, 1, 1)
        rule.feed(0, t, _spdm_pkt(SpdmRequestCode.GET_DIGESTS))
        rule.feed(1, t, _spdm_pkt(SpdmResponseCode.DIGESTS, src=0x0C, dst=0x40))
        findings = rule.feed(2, t, _spdm_pkt(SpdmRequestCode.GET_CERTIFICATE, param1=0))
        assert findings == []

    def test_slot_switch_detected(self):
        rule = SpdmCertChainRule()
        t = datetime(2026, 1, 1)
        rule.feed(0, t, _spdm_pkt(SpdmRequestCode.GET_DIGESTS))
        rule.feed(1, t, _spdm_pkt(SpdmRequestCode.GET_CERTIFICATE, param1=0))  # Slot 0
        findings = rule.feed(2, t, _spdm_pkt(SpdmRequestCode.GET_CERTIFICATE, param1=1))  # Slot 1
        # Should warn about slot not completed yet — but the CERTIFICATE response
        # clears in_cert_retrieval. Let's test without response.
        # Actually the first GET_CERT sets in_cert_retrieval=True, so second will detect switch.
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "Slot changed" in findings[0].message


class TestSpdmMeasurementsRule:
    def test_measurements_before_negotiation(self):
        rule = SpdmMeasurementsRule()
        t = datetime(2026, 1, 1)
        pkt = _spdm_pkt(SpdmRequestCode.GET_MEASUREMENTS, param1=0x01, param2=0x1C)
        findings = rule.feed(0, t, pkt)
        assert len(findings) == 1
        assert "before negotiation" in findings[0].message

    def test_measurements_after_negotiation_ok(self):
        rule = SpdmMeasurementsRule()
        t = datetime(2026, 1, 1)
        rule.feed(0, t, _spdm_pkt(SpdmRequestCode.GET_VERSION))
        rule.feed(1, t, _spdm_pkt(SpdmResponseCode.ALGORITHMS, src=0x0C, dst=0x40))
        findings = rule.feed(2, t, _spdm_pkt(SpdmRequestCode.GET_MEASUREMENTS))
        assert findings == []

    def test_missing_measurement_response(self):
        rule = SpdmMeasurementsRule()
        t = datetime(2026, 1, 1)
        rule.feed(0, t, _spdm_pkt(SpdmRequestCode.GET_VERSION))
        rule.feed(1, t, _spdm_pkt(SpdmResponseCode.ALGORITHMS, src=0x0C, dst=0x40))
        rule.feed(2, t, _spdm_pkt(SpdmRequestCode.GET_MEASUREMENTS, param1=0x01, param2=0x1C))
        findings = rule.finalize()
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR  # gen_sig=1 → ERROR
        assert "GenSig=1" in findings[0].message
