# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the analysis engine and base classes."""

from datetime import datetime, timedelta

import pytest

from pymctp.analyzers import AnalysisEngine, AnalysisRule, Finding, Severity


# -- Helpers ------------------------------------------------------------------


class _AlwaysFindRule(AnalysisRule):
    """Trivial rule that emits a finding for every packet."""

    rule_id = "TEST-001"
    description = "Always emits a finding"

    def feed(self, index, timestamp, packet):
        return [
            Finding(
                rule_id=self.rule_id,
                severity=Severity.INFO,
                message=f"Packet {index}",
                packet_index=index,
                timestamp=timestamp,
            )
        ]


class _FinalizeRule(AnalysisRule):
    """Rule that only emits findings during finalize()."""

    rule_id = "TEST-002"
    description = "Emits findings at finalize"

    def __init__(self):
        self._count = 0

    def feed(self, index, timestamp, packet):
        self._count += 1
        return []

    def finalize(self):
        return [
            Finding(
                rule_id=self.rule_id,
                severity=Severity.WARNING,
                message=f"Processed {self._count} packets total",
            )
        ]

    def reset(self):
        self._count = 0


# -- Tests --------------------------------------------------------------------


class TestFinding:
    def test_str_with_timestamp(self):
        ts = datetime(2026, 1, 1, 12, 0, 0)
        f = Finding(rule_id="X-001", severity=Severity.ERROR, message="fail", timestamp=ts, packet_index=5)
        s = str(f)
        lines = s.split("\n")
        assert "[E]" in lines[0]
        assert "X-001" in lines[0]
        assert "pkt#5" in lines[0]
        assert "fail" in lines[0]
        # Timestamp is on the second line
        assert ts.isoformat() in lines[1]
        assert "\u21b3" in lines[1]

    def test_str_without_timestamp(self):
        f = Finding(rule_id="X-002", severity=Severity.INFO, message="ok")
        s = str(f)
        assert "???" in s

    def test_str_with_packet_summary(self):
        ts = datetime(2026, 1, 1, 12, 0, 0)
        f = Finding(
            rule_id="X-003", severity=Severity.WARNING, message="slow",
            timestamp=ts, packet_index=10, packet_summary="MCTP 0:7 SPDM",
        )
        s = str(f)
        lines = s.split("\n")
        assert len(lines) == 2
        assert "[W]" in lines[0]
        assert "slow" in lines[0]
        # Second line has timestamp + packet summary
        assert "\u21b3" in lines[1]
        assert ts.isoformat() in lines[1]
        assert "MCTP 0:7 SPDM" in lines[1]

    def test_str_with_multiline_packet_summary(self):
        ts = datetime(2026, 1, 1, 12, 0, 0)
        rsp_ts = "2026-01-01T12:00:03"
        combined = f"MCTP REQ summary\n{rsp_ts}: MCTP RSP summary"
        f = Finding(
            rule_id="X-004", severity=Severity.WARNING, message="slow",
            timestamp=ts, packet_index=10, packet_summary=combined,
        )
        s = str(f)
        lines = s.split("\n")
        assert len(lines) == 3
        # First line: header
        assert "[W]" in lines[0] and "slow" in lines[0]
        # Second line: request timestamp + request summary
        assert ts.isoformat() in lines[1]
        assert "MCTP REQ summary" in lines[1]
        # Third line: response timestamp + response summary
        assert rsp_ts in lines[2]
        assert "MCTP RSP summary" in lines[2]


class TestAnalysisEngine:
    def test_empty_engine_no_findings(self):
        engine = AnalysisEngine()
        findings = engine.analyze([])
        assert findings == []

    def test_single_rule(self):
        engine = AnalysisEngine([_AlwaysFindRule()])
        ts = datetime(2026, 1, 1)
        packets = [(ts, None), (ts, None), (ts, None)]
        findings = engine.analyze(packets)
        assert len(findings) == 3
        assert all(f.rule_id == "TEST-001" for f in findings)

    def test_finalize_called(self):
        engine = AnalysisEngine([_FinalizeRule()])
        ts = datetime(2026, 1, 1)
        packets = [(ts, None)] * 5
        findings = engine.analyze(packets)
        assert len(findings) == 1
        assert "5 packets" in findings[0].message

    def test_multiple_rules(self):
        engine = AnalysisEngine([_AlwaysFindRule(), _FinalizeRule()])
        ts = datetime(2026, 1, 1)
        packets = [(ts, None)] * 2
        findings = engine.analyze(packets)
        # 2 from AlwaysFindRule + 1 from FinalizeRule
        assert len(findings) == 3

    def test_reset_between_runs(self):
        engine = AnalysisEngine([_FinalizeRule()])
        ts = datetime(2026, 1, 1)
        engine.analyze([(ts, None)] * 3)
        assert "3 packets" in engine.findings[0].message

        engine.analyze([(ts, None)] * 7)
        assert "7 packets" in engine.findings[0].message

    def test_to_json(self):
        import json

        engine = AnalysisEngine([_AlwaysFindRule()])
        ts = datetime(2026, 1, 1)
        engine.analyze([(ts, None)])
        result = json.loads(engine.to_json())
        assert len(result) == 1
        assert result[0]["rule_id"] == "TEST-001"

    def test_to_json_severity_filter(self):
        import json

        engine = AnalysisEngine([_AlwaysFindRule(), _FinalizeRule()])
        ts = datetime(2026, 1, 1)
        engine.analyze([(ts, None)])
        # _AlwaysFindRule emits INFO, _FinalizeRule emits WARNING
        result = json.loads(engine.to_json(min_severity=Severity.WARNING))
        assert len(result) == 1
        assert result[0]["severity"] == "WARNING"
