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


# ---------------------------------------------------------------------------
# Auto-registration registry
# ---------------------------------------------------------------------------

# suite name → list of ComplianceTestCase *classes*
_test_registry: dict[str, list[type[ComplianceTestCase]]] = {}


class ComplianceTestCase(ABC):
    """A single compliance test that can be executed against a live endpoint.

    Subclasses are **automatically registered** into the compliance test
    registry when they define a ``suite`` class attribute::

        class TestGetEndpointID(ComplianceTestCase):
            suite = "mctp-base"
            spec_ref = "DSP0236 §12.3"
            description = "GetEndpointID returns a valid response"

    Tests without a ``suite`` attribute (including the ABC itself) are
    not registered.  This mirrors how pytest auto-discovers test classes.
    """

    suite: str = ""
    spec_ref: str = ""
    description: str = ""

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        suite_name = getattr(cls, "suite", "")
        # Only register concrete tests that declare a suite
        if suite_name and not getattr(cls, "__abstractmethods__", None):
            _test_registry.setdefault(suite_name, []).append(cls)

    @abstractmethod
    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        """Execute the test against a live endpoint and return the result."""


def get_registered_suites() -> list[str]:
    """Return the names of all registered compliance test suites."""
    _ensure_plugins_loaded()
    return sorted(_test_registry.keys())


def get_tests_for_suite(suite_name: str) -> list[ComplianceTestCase]:
    """Instantiate and return all tests registered under *suite_name*."""
    _ensure_plugins_loaded()
    classes = _test_registry.get(suite_name, [])
    return [cls() for cls in classes]


def get_all_tests() -> list[ComplianceTestCase]:
    """Instantiate and return all registered compliance tests."""
    _ensure_plugins_loaded()
    tests: list[ComplianceTestCase] = []
    for suite_name in sorted(_test_registry):
        tests.extend(cls() for cls in _test_registry[suite_name])
    return tests


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


# ---------------------------------------------------------------------------
# Plugin discovery for third-party compliance tests
# ---------------------------------------------------------------------------

import sys  # noqa: E402

if sys.version_info >= (3, 10):
    from importlib.metadata import entry_points as _entry_points
else:
    from importlib_metadata import entry_points as _entry_points  # type: ignore[no-redef]

ENTRY_POINT_GROUP = "pymctp.compliance_tests"

_plugins_loaded = False


def _ensure_plugins_loaded() -> None:
    """Load compliance test plugins from entry points (once)."""
    global _plugins_loaded  # noqa: PLW0603
    if _plugins_loaded:
        return
    _plugins_loaded = True

    try:
        eps = _entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:
        eps = _entry_points().get(ENTRY_POINT_GROUP, [])  # type: ignore[assignment]

    for ep in eps:
        try:
            # Loading the module triggers __init_subclass__ registration
            ep.load()
        except Exception:
            log.warning("Failed to load compliance test plugin '%s'", ep.name, exc_info=True)
