# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Compliance test framework for validating MCTP endpoint behavior."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..automaton.sessions import EndpointSession

log = logging.getLogger(__name__)


class ComplianceResult(str, Enum):
    """Outcome of a single compliance test."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


@dataclass
class TestResult:
    """Result of executing a single compliance test case."""

    __test__ = False  # prevent pytest from collecting this as a test class

    name: str
    spec_ref: str
    result: ComplianceResult
    message: str
    detail: str | None = None

    def __str__(self) -> str:
        status = self.result.value.ljust(4)
        return f"[{status}] {self.name} ({self.spec_ref}): {self.message}"


class ComplianceTestCase(ABC):
    """A single compliance test that can be executed against a live endpoint."""

    spec_ref: str = ""
    description: str = ""

    @abstractmethod
    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        """Execute the test against a live endpoint and return the result."""


class ComplianceTestSuite:
    """Runs a collection of compliance tests and reports results."""

    def __init__(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0):
        self.session = session
        self.target_eid = target_eid
        self.timeout_s = timeout_s
        self._tests: list[ComplianceTestCase] = []
        self._results: list[TestResult] = []

    def add_test(self, test: ComplianceTestCase) -> None:
        self._tests.append(test)

    def add_tests(self, tests: list[ComplianceTestCase]) -> None:
        self._tests.extend(tests)

    @property
    def results(self) -> list[TestResult]:
        return list(self._results)

    def run_all(self) -> list[TestResult]:
        """Execute all registered tests and return results."""
        self._results = []
        for test in self._tests:
            try:
                result = test.run(self.session, self.target_eid, timeout_s=self.timeout_s)
            except Exception as exc:
                log.exception("Test %s raised an exception", test.description)
                result = TestResult(
                    name=test.description,
                    spec_ref=test.spec_ref,
                    result=ComplianceResult.FAIL,
                    message=f"Exception: {exc}",
                )
            self._results.append(result)
        return self._results

    def report(self) -> str:
        """Generate a human-readable summary of test results."""
        lines = []
        counts = {r: 0 for r in ComplianceResult}
        for result in self._results:
            counts[result.result] += 1
            lines.append(str(result))

        lines.append("")
        total = len(self._results)
        summary_parts = [f"{counts[r]} {r.value}" for r in ComplianceResult if counts[r] > 0]
        lines.append(f"Total: {total} tests — {', '.join(summary_parts)}")
        return "\n".join(lines)
