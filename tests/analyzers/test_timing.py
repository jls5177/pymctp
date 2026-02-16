# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for timing analysis rules."""

from datetime import datetime, timedelta

import pytest

from pymctp.analyzers.base import Severity
from pymctp.analyzers.timing import InterPacketGapRule, ResponseTimeoutRule
from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import MsgTypes


def _make_mctp_packet(src: int, dst: int, tag: int, to: int, msg_type: int = MsgTypes.CTRL) -> TransportHdrPacket:
    """Create a minimal MCTP transport packet for testing."""
    pkt = TransportHdr(
        src=src,
        dst=dst,
        som=1,
        eom=1,
        pkt_seq=0,
        to=to,
        tag=tag,
        msg_type=msg_type,
    )
    return pkt


class TestResponseTimeoutRule:
    def test_no_findings_for_normal_flow(self):
        rule = ResponseTimeoutRule(timeout=timedelta(seconds=5))
        t0 = datetime(2026, 1, 1, 12, 0, 0)
        t1 = t0 + timedelta(seconds=0.5)

        req = _make_mctp_packet(src=0x40, dst=0x0C, tag=1, to=1)
        rsp = _make_mctp_packet(src=0x0C, dst=0x40, tag=1, to=0)

        assert rule.feed(0, t0, req) == []
        assert rule.feed(1, t1, rsp) == []
        assert rule.finalize() == []

    def test_delayed_response(self):
        rule = ResponseTimeoutRule(timeout=timedelta(seconds=1))
        t0 = datetime(2026, 1, 1, 12, 0, 0)
        t1 = t0 + timedelta(seconds=3)

        req = _make_mctp_packet(src=0x40, dst=0x0C, tag=1, to=1)
        rsp = _make_mctp_packet(src=0x0C, dst=0x40, tag=1, to=0)

        assert rule.feed(0, t0, req) == []
        findings = rule.feed(1, t1, rsp)
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARNING
        assert "3.000s" in findings[0].message

    def test_missing_response(self):
        rule = ResponseTimeoutRule(timeout=timedelta(seconds=1))
        t0 = datetime(2026, 1, 1, 12, 0, 0)

        req = _make_mctp_packet(src=0x40, dst=0x0C, tag=1, to=1)
        assert rule.feed(0, t0, req) == []

        findings = rule.finalize()
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "No response" in findings[0].message

    def test_multiple_tags(self):
        rule = ResponseTimeoutRule(timeout=timedelta(seconds=5))
        t0 = datetime(2026, 1, 1, 12, 0, 0)
        t1 = t0 + timedelta(milliseconds=100)
        t2 = t0 + timedelta(milliseconds=200)
        t3 = t0 + timedelta(milliseconds=300)

        req1 = _make_mctp_packet(src=0x40, dst=0x0C, tag=1, to=1)
        req2 = _make_mctp_packet(src=0x40, dst=0x0C, tag=2, to=1)
        rsp1 = _make_mctp_packet(src=0x0C, dst=0x40, tag=1, to=0)
        rsp2 = _make_mctp_packet(src=0x0C, dst=0x40, tag=2, to=0)

        assert rule.feed(0, t0, req1) == []
        assert rule.feed(1, t1, req2) == []
        assert rule.feed(2, t2, rsp1) == []
        assert rule.feed(3, t3, rsp2) == []
        assert rule.finalize() == []

    def test_reset_clears_state(self):
        rule = ResponseTimeoutRule()
        t0 = datetime(2026, 1, 1)
        req = _make_mctp_packet(src=0x40, dst=0x0C, tag=1, to=1)
        rule.feed(0, t0, req)
        rule.reset()
        assert rule.finalize() == []


class TestInterPacketGapRule:
    def test_fast_response_no_findings(self):
        rule = InterPacketGapRule(threshold=timedelta(seconds=5))
        t0 = datetime(2026, 1, 1, 12, 0, 0)
        t1 = t0 + timedelta(seconds=1)

        req = _make_mctp_packet(src=0x40, dst=0x0C, tag=1, to=1)
        rsp = _make_mctp_packet(src=0x0C, dst=0x40, tag=1, to=0)
        assert rule.feed(0, t0, req) == []
        assert rule.feed(1, t1, rsp) == []

    def test_slow_response_detected(self):
        rule = InterPacketGapRule(threshold=timedelta(seconds=5))
        t0 = datetime(2026, 1, 1, 12, 0, 0)
        t1 = t0 + timedelta(seconds=15)

        req = _make_mctp_packet(src=0x40, dst=0x0C, tag=1, to=1)
        rsp = _make_mctp_packet(src=0x0C, dst=0x40, tag=1, to=0)
        assert rule.feed(0, t0, req) == []
        findings = rule.feed(1, t1, rsp)
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARNING
        assert "15.000s" in findings[0].message

    def test_gap_between_unrelated_transactions_ignored(self):
        """Idle gap between a response and a new unrelated request should NOT be flagged."""
        rule = InterPacketGapRule(threshold=timedelta(seconds=5))
        t0 = datetime(2026, 1, 1, 12, 0, 0)
        t1 = t0 + timedelta(seconds=1)
        t2 = t0 + timedelta(seconds=100)  # 99 s idle gap

        req1 = _make_mctp_packet(src=0x40, dst=0x0C, tag=1, to=1)
        rsp1 = _make_mctp_packet(src=0x0C, dst=0x40, tag=1, to=0)
        req2 = _make_mctp_packet(src=0x40, dst=0x0C, tag=2, to=1)

        assert rule.feed(0, t0, req1) == []
        assert rule.feed(1, t1, rsp1) == []
        # This new request 99 s later is a separate transaction — no finding
        assert rule.feed(2, t2, req2) == []

    def test_none_timestamps_skipped(self):
        rule = InterPacketGapRule(threshold=timedelta(seconds=5))
        req = _make_mctp_packet(src=0x40, dst=0x0C, tag=1, to=1)
        rsp = _make_mctp_packet(src=0x0C, dst=0x40, tag=1, to=0)
        assert rule.feed(0, None, req) == []
        assert rule.feed(1, None, rsp) == []

    def test_reset_clears_state(self):
        rule = InterPacketGapRule(threshold=timedelta(seconds=1))
        t0 = datetime(2026, 1, 1, 12, 0, 0)
        req = _make_mctp_packet(src=0x40, dst=0x0C, tag=1, to=1)
        rule.feed(0, t0, req)
        rule.reset()
        # After reset, a late response has no matching request — no finding
        t1 = t0 + timedelta(seconds=100)
        rsp = _make_mctp_packet(src=0x0C, dst=0x40, tag=1, to=0)
        assert rule.feed(1, t1, rsp) == []
