# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for MCTP transport-level analysis rules."""

from datetime import datetime, timedelta

import pytest

from pymctp.analyzers.base import Severity
from pymctp.analyzers.mctp import FragmentationRule, TagReuseRule
from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import MsgTypes


def _mctp_pkt(
    src: int = 0x40,
    dst: int = 0x0C,
    tag: int = 0,
    to: int = 1,
    som: int = 1,
    eom: int = 1,
    pkt_seq: int = 0,
) -> TransportHdrPacket:
    """Build a minimal MCTP transport packet."""
    return TransportHdr(
        src=src, dst=dst, tag=tag, to=to,
        som=som, eom=eom, pkt_seq=pkt_seq,
        msg_type=MsgTypes.CTRL,
    )


class TestFragmentationRule:
    def test_single_packet_no_findings(self):
        rule = FragmentationRule()
        t = datetime(2026, 1, 1)
        pkt = _mctp_pkt(som=1, eom=1)
        assert rule.feed(0, t, pkt) == []
        assert rule.finalize() == []

    def test_normal_fragmentation(self):
        rule = FragmentationRule()
        t = datetime(2026, 1, 1)
        # SOM fragment
        assert rule.feed(0, t, _mctp_pkt(som=1, eom=0, pkt_seq=0)) == []
        # Middle fragment
        assert rule.feed(1, t, _mctp_pkt(som=0, eom=0, pkt_seq=1)) == []
        # EOM fragment
        assert rule.feed(2, t, _mctp_pkt(som=0, eom=1, pkt_seq=2)) == []
        assert rule.finalize() == []

    def test_middle_without_som(self):
        rule = FragmentationRule()
        t = datetime(2026, 1, 1)
        findings = rule.feed(0, t, _mctp_pkt(som=0, eom=0, pkt_seq=1))
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "no preceding SOM" in findings[0].message.lower() or "no preceding SOM" in findings[0].message

    def test_eom_without_som(self):
        rule = FragmentationRule()
        t = datetime(2026, 1, 1)
        findings = rule.feed(0, t, _mctp_pkt(som=0, eom=1, pkt_seq=0))
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR

    def test_incomplete_at_end_of_capture(self):
        rule = FragmentationRule()
        t = datetime(2026, 1, 1)
        rule.feed(0, t, _mctp_pkt(som=1, eom=0, pkt_seq=0))
        findings = rule.finalize()
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "Incomplete" in findings[0].message

    def test_out_of_order_pkt_seq(self):
        rule = FragmentationRule()
        t = datetime(2026, 1, 1)
        rule.feed(0, t, _mctp_pkt(som=1, eom=0, pkt_seq=0))
        findings = rule.feed(1, t, _mctp_pkt(som=0, eom=0, pkt_seq=3))  # Expected 1
        assert len(findings) == 1
        assert "sequence out of order" in findings[0].message.lower() or "out of order" in findings[0].message

    def test_new_som_cancels_old(self):
        rule = FragmentationRule()
        t = datetime(2026, 1, 1)
        rule.feed(0, t, _mctp_pkt(som=1, eom=0, pkt_seq=0))
        findings = rule.feed(1, t, _mctp_pkt(som=1, eom=0, pkt_seq=0))
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "not completed" in findings[0].message

    def test_reset_clears_state(self):
        rule = FragmentationRule()
        t = datetime(2026, 1, 1)
        rule.feed(0, t, _mctp_pkt(som=1, eom=0, pkt_seq=0))
        rule.reset()
        assert rule.finalize() == []


class TestTagReuseRule:
    def test_normal_flow_no_findings(self):
        rule = TagReuseRule()
        t = datetime(2026, 1, 1)
        req = _mctp_pkt(src=0x40, dst=0x0C, tag=1, to=1)
        rsp = _mctp_pkt(src=0x0C, dst=0x40, tag=1, to=0)
        assert rule.feed(0, t, req) == []
        assert rule.feed(1, t, rsp) == []

    def test_tag_reuse_detected(self):
        rule = TagReuseRule()
        t = datetime(2026, 1, 1)
        req1 = _mctp_pkt(src=0x40, dst=0x0C, tag=1, to=1)
        req2 = _mctp_pkt(src=0x40, dst=0x0C, tag=1, to=1)
        assert rule.feed(0, t, req1) == []
        findings = rule.feed(1, t, req2)
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "never received a response" in findings[0].message

    def test_different_tags_ok(self):
        rule = TagReuseRule()
        t = datetime(2026, 1, 1)
        req1 = _mctp_pkt(src=0x40, dst=0x0C, tag=1, to=1)
        req2 = _mctp_pkt(src=0x40, dst=0x0C, tag=2, to=1)
        assert rule.feed(0, t, req1) == []
        assert rule.feed(1, t, req2) == []

    def test_different_sources_ok(self):
        rule = TagReuseRule()
        t = datetime(2026, 1, 1)
        req1 = _mctp_pkt(src=0x40, dst=0x0C, tag=1, to=1)
        req2 = _mctp_pkt(src=0x50, dst=0x0C, tag=1, to=1)
        assert rule.feed(0, t, req1) == []
        assert rule.feed(1, t, req2) == []

    def test_tag_freed_after_response(self):
        rule = TagReuseRule()
        t = datetime(2026, 1, 1)
        req = _mctp_pkt(src=0x40, dst=0x0C, tag=1, to=1)
        rsp = _mctp_pkt(src=0x0C, dst=0x40, tag=1, to=0)
        req2 = _mctp_pkt(src=0x40, dst=0x0C, tag=1, to=1)
        assert rule.feed(0, t, req) == []
        assert rule.feed(1, t, rsp) == []
        # Tag 1 is now free, reuse should be fine
        assert rule.feed(2, t, req2) == []

    def test_fragmented_response_clears_pending(self):
        """A multi-packet (fragmented) response should clear the pending tag.

        Real-world scenario: request (SOM+EOM) followed by a fragmented
        response (SOM-only start, middle fragments, EOM end).  The next
        request with the same tag must NOT be flagged.
        """
        rule = TagReuseRule()
        t = datetime(2026, 1, 1)
        # Request: SOM+EOM, tag=0, src=0x0A → dst=0x40
        req1 = _mctp_pkt(src=0x0A, dst=0x40, tag=0, to=1, som=1, eom=1)
        # Response starts: SOM only (fragmented), tag=0, src=0x40 → dst=0x0A
        rsp_som = _mctp_pkt(src=0x40, dst=0x0A, tag=0, to=0, som=1, eom=0, pkt_seq=0)
        # Middle fragments
        rsp_mid1 = _mctp_pkt(src=0x40, dst=0x0A, tag=0, to=0, som=0, eom=0, pkt_seq=1)
        rsp_mid2 = _mctp_pkt(src=0x40, dst=0x0A, tag=0, to=0, som=0, eom=0, pkt_seq=2)
        # EOM fragment
        rsp_eom = _mctp_pkt(src=0x40, dst=0x0A, tag=0, to=0, som=0, eom=1, pkt_seq=3)
        # Next request reusing the same tag should be fine
        req2 = _mctp_pkt(src=0x0A, dst=0x40, tag=0, to=1, som=1, eom=1)

        assert rule.feed(0, t, req1) == []
        assert rule.feed(1, t, rsp_som) == []   # SOM clears pending
        assert rule.feed(2, t, rsp_mid1) == []
        assert rule.feed(3, t, rsp_mid2) == []
        assert rule.feed(4, t, rsp_eom) == []
        # Tag 0 was freed by the SOM of the fragmented response
        assert rule.feed(5, t, req2) == []

    def test_fragment_only_packets_ignored_for_requests(self):
        """Middle/EOM-only request fragments should not start a new transaction."""
        rule = TagReuseRule()
        t = datetime(2026, 1, 1)
        # A middle fragment (no SOM, no EOM) with to=1 should be ignored
        mid = _mctp_pkt(src=0x0A, dst=0x40, tag=0, to=1, som=0, eom=0, pkt_seq=1)
        assert rule.feed(0, t, mid) == []
        # An EOM-only fragment with to=1 should also be ignored
        eom = _mctp_pkt(src=0x0A, dst=0x40, tag=0, to=1, som=0, eom=1, pkt_seq=2)
        assert rule.feed(1, t, eom) == []
        # No pending transactions should exist, so a real request is fine
        req = _mctp_pkt(src=0x0A, dst=0x40, tag=0, to=1, som=1, eom=1)
        assert rule.feed(2, t, req) == []
