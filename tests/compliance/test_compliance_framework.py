# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for compliance framework classes (not live endpoint tests)."""

import pytest

from pymctp.compliance.base import ComplianceResult, ComplianceTestCase, ComplianceTestSuite, TestResult


class TestTestResult:
    def test_str_format(self):
        r = TestResult(name="Test1", spec_ref="DSP0236 §12.3", result=ComplianceResult.PASS, message="OK")
        s = str(r)
        assert "[PASS]" in s
        assert "Test1" in s
        assert "DSP0236 §12.3" in s

    def test_fail_format(self):
        r = TestResult(name="Test2", spec_ref="X", result=ComplianceResult.FAIL, message="bad")
        assert "[FAIL]" in str(r)


class FakeTestCase(ComplianceTestCase):
    spec_ref = "TEST §1"
    description = "Fake test"

    def __init__(self, result: ComplianceResult, message: str = "ok"):
        self._result = result
        self._message = message

    def run(self, session, target_eid, *, timeout_s=5.0):
        return TestResult(self.description, self.spec_ref, self._result, self._message)


class ErrorTestCase(ComplianceTestCase):
    spec_ref = "TEST §2"
    description = "Error test"

    def run(self, session, target_eid, *, timeout_s=5.0):
        msg = "boom"
        raise RuntimeError(msg)


class TestComplianceTestSuite:
    def test_run_all_collects_results(self):
        suite = ComplianceTestSuite(session=None, target_eid=0x15)
        suite.add_test(FakeTestCase(ComplianceResult.PASS))
        suite.add_test(FakeTestCase(ComplianceResult.FAIL, "bad"))
        suite.add_test(FakeTestCase(ComplianceResult.WARN, "maybe"))

        results = suite.run_all()
        assert len(results) == 3
        assert results[0].result == ComplianceResult.PASS
        assert results[1].result == ComplianceResult.FAIL
        assert results[2].result == ComplianceResult.WARN

    def test_exception_handling(self):
        suite = ComplianceTestSuite(session=None, target_eid=0x15)
        suite.add_test(ErrorTestCase())

        results = suite.run_all()
        assert len(results) == 1
        assert results[0].result == ComplianceResult.FAIL
        assert "Exception" in results[0].message

    def test_report_format(self):
        suite = ComplianceTestSuite(session=None, target_eid=0x15)
        suite.add_tests([
            FakeTestCase(ComplianceResult.PASS),
            FakeTestCase(ComplianceResult.PASS),
            FakeTestCase(ComplianceResult.FAIL, "bad"),
        ])
        suite.run_all()

        report = suite.report()
        assert "Total: 3 tests" in report
        assert "2 PASS" in report
        assert "1 FAIL" in report

    def test_empty_suite(self):
        suite = ComplianceTestSuite(session=None, target_eid=0x15)
        results = suite.run_all()
        assert results == []
        assert "Total: 0 tests" in suite.report()

    def test_add_tests_bulk(self):
        suite = ComplianceTestSuite(session=None, target_eid=0x15)
        suite.add_tests([FakeTestCase(ComplianceResult.PASS), FakeTestCase(ComplianceResult.SKIP)])
        assert len(suite._tests) == 2


class TestAutoRegistration:
    """Tests for __init_subclass__ auto-registration of compliance tests."""

    def test_builtin_suites_registered(self):
        """Built-in mctp-base and mctp-bridge tests are auto-registered."""
        from pymctp.compliance.base import get_registered_suites, get_tests_for_suite

        # Force import of built-in modules
        from pymctp.compliance import mctp_base as _  # noqa: F401
        from pymctp.compliance import mctp_bridge as _b  # noqa: F401

        suites = get_registered_suites()
        assert "mctp-base" in suites
        assert "mctp-bridge" in suites

    def test_mctp_base_test_count(self):
        from pymctp.compliance.base import get_tests_for_suite
        from pymctp.compliance import mctp_base as _  # noqa: F401

        tests = get_tests_for_suite("mctp-base")
        assert len(tests) == 6

    def test_mctp_bridge_test_count(self):
        from pymctp.compliance.base import get_tests_for_suite
        from pymctp.compliance import mctp_bridge as _  # noqa: F401

        tests = get_tests_for_suite("mctp-bridge")
        assert len(tests) == 4

    def test_no_suite_not_registered(self):
        """Test cases without a suite attribute are not registered."""
        from pymctp.compliance.base import _test_registry

        # FakeTestCase has no suite (empty string) — should NOT be in registry
        for suite_tests in _test_registry.values():
            for cls in suite_tests:
                assert cls is not FakeTestCase
                assert cls is not ErrorTestCase

    def test_get_all_tests(self):
        from pymctp.compliance.base import get_all_tests
        from pymctp.compliance import mctp_base as _  # noqa: F401
        from pymctp.compliance import mctp_bridge as _b  # noqa: F401

        tests = get_all_tests()
        assert len(tests) >= 10  # 6 base + 4 bridge
