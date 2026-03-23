# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from .base import (
    ComplianceResult,
    ComplianceTestCase,
    ComplianceTestSuite,
    TestResult,
    get_all_tests,
    get_registered_suites,
    get_tests_for_suite,
)

# Import built-in test modules so their subclasses auto-register
from . import mctp_base as _mctp_base  # noqa: F401
from . import mctp_bridge as _mctp_bridge  # noqa: F401

__all__ = [
    "ComplianceResult",
    "ComplianceTestCase",
    "ComplianceTestSuite",
    "TestResult",
    "get_all_tests",
    "get_registered_suites",
    "get_tests_for_suite",
]
