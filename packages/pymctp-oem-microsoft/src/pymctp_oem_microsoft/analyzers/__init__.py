# SPDX-FileCopyrightText: 2024 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""IPMI-specific analysis rules for the pymctp triage engine."""

from pymctp_oem_microsoft.analyzers.ipmi_missing_response import IpmiMissingResponseRule
from pymctp_oem_microsoft.analyzers.ipmi_slow_response import IpmiSlowResponseRule

__all__ = [
    "IpmiMissingResponseRule",
    "IpmiSlowResponseRule",
]
