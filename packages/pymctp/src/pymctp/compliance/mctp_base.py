# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""MCTP Base Specification (DSP0236) compliance tests.

All ``ComplianceTestCase`` subclasses defined here are **automatically**
registered under the ``"mctp-base"`` suite via ``__init_subclass__``.
"""

from __future__ import annotations

from scapy.packet import Packet

from ..automaton.sessions import EndpointSession
from ..layers.mctp.control import (
    CompletionCodes,
    ControlHdrPacket,
    GetEndpointID,
    GetEndpointIDResponsePacket,
    GetEndpointUUID,
    GetEndpointUUIDResponsePacket,
    GetMctpVersionSupport,
    GetMctpVersionSupportResponsePacket,
    GetMessageTypeSupport,
    GetMessageTypeSupportResponsePacket,
)
from ..layers.mctp.types import MsgTypes
from .base import ComplianceResult, ComplianceTestCase, TestResult

_SUITE = "mctp-base"


class TestGetEndpointID(ComplianceTestCase):
    suite = _SUITE
    spec_ref = "DSP0236 §12.3"
    description = "GetEndpointID returns a valid response"

    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        rsp = session.sndrcv_control_msg(GetEndpointID(), target_eid, timeout_s=timeout_s)
        if rsp is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "No response received")

        ctrl = rsp.getlayer(ControlHdrPacket)
        if ctrl is None or ctrl.completion_code != CompletionCodes.SUCCESS:
            cc = ctrl.completion_code if ctrl else "missing"
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, f"Completion code: {cc}")

        return TestResult(self.description, self.spec_ref, ComplianceResult.PASS, "Valid response received")


class TestGetMessageTypeSupport(ComplianceTestCase):
    suite = _SUITE
    spec_ref = "DSP0236 §12.6"
    description = "GetMessageTypeSupport includes CTRL (0x00)"

    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        rsp = session.sndrcv_control_msg(GetMessageTypeSupport(), target_eid, timeout_s=timeout_s)
        if rsp is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "No response received")

        ctrl = rsp.getlayer(ControlHdrPacket)
        if ctrl is None or ctrl.completion_code != CompletionCodes.SUCCESS:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Non-success completion code")

        payload = rsp.getlayer(GetMessageTypeSupportResponsePacket)
        if payload is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Missing response payload")

        msg_types = list(payload.msg_types)
        if MsgTypes.CTRL.value not in msg_types:
            return TestResult(
                self.description,
                self.spec_ref,
                ComplianceResult.FAIL,
                f"CTRL (0x00) not in supported types: {msg_types}",
            )

        return TestResult(self.description, self.spec_ref, ComplianceResult.PASS, f"Supports {len(msg_types)} types")


class TestGetMCTPVersionSupport(ComplianceTestCase):
    suite = _SUITE
    spec_ref = "DSP0236 §12.5"
    description = "GetMCTPVersionSupport returns at least one version"

    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        rsp = session.sndrcv_control_msg(GetMctpVersionSupport(msg_type_number=0xFF), target_eid, timeout_s=timeout_s)
        if rsp is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "No response received")

        ctrl = rsp.getlayer(ControlHdrPacket)
        if ctrl is None or ctrl.completion_code != CompletionCodes.SUCCESS:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Non-success completion code")

        payload = rsp.getlayer(GetMctpVersionSupportResponsePacket)
        if payload is None or payload.version_count == 0:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "No versions returned")

        return TestResult(
            self.description,
            self.spec_ref,
            ComplianceResult.PASS,
            f"{payload.version_count} version(s) supported",
        )


class TestGetEndpointUUID(ComplianceTestCase):
    suite = _SUITE
    spec_ref = "DSP0236 §12.4"
    description = "GetEndpointUUID returns a valid UUID"

    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        rsp = session.sndrcv_control_msg(GetEndpointUUID(), target_eid, timeout_s=timeout_s)
        if rsp is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "No response received")

        ctrl = rsp.getlayer(ControlHdrPacket)
        if ctrl is None or ctrl.completion_code != CompletionCodes.SUCCESS:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Non-success completion code")

        payload = rsp.getlayer(GetEndpointUUIDResponsePacket)
        if payload is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Missing UUID payload")

        return TestResult(self.description, self.spec_ref, ComplianceResult.PASS, "UUID received")


class TestUnsupportedCommand(ComplianceTestCase):
    suite = _SUITE
    spec_ref = "DSP0236 §11.5"
    description = "Unsupported command returns ERROR_UNSUPPORTED_CMD"

    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        from ..layers.mctp.control import ControlHdr

        # Send a command with an invalid/unsupported command code (0xFF)
        pkt = ControlHdr(rq=True, cmd_code=0xFF)
        rsp = session.sndrcv_control_msg(pkt, target_eid, timeout_s=timeout_s)

        if rsp is None:
            return TestResult(
                self.description,
                self.spec_ref,
                ComplianceResult.WARN,
                "No response (endpoint may silently drop unsupported commands)",
            )

        ctrl = rsp.getlayer(ControlHdrPacket)
        if ctrl is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Malformed response")

        if ctrl.completion_code == CompletionCodes.ERROR_UNSUPPORTED_CMD:
            return TestResult(self.description, self.spec_ref, ComplianceResult.PASS, "Correct error code returned")

        return TestResult(
            self.description,
            self.spec_ref,
            ComplianceResult.FAIL,
            f"Expected ERROR_UNSUPPORTED_CMD (5), got {ctrl.completion_code}",
        )


class TestGetEndpointIDFormat(ComplianceTestCase):
    suite = _SUITE
    spec_ref = "DSP0236 §12.3"
    description = "GetEndpointID response fields are valid"

    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        rsp = session.sndrcv_control_msg(GetEndpointID(), target_eid, timeout_s=timeout_s)
        if rsp is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "No response received")

        ctrl = rsp.getlayer(ControlHdrPacket)
        if ctrl is None or ctrl.completion_code != CompletionCodes.SUCCESS:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Non-success completion code")

        payload = rsp.getlayer(GetEndpointIDResponsePacket)
        if payload is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Missing response payload")

        # Verify EID matches what we sent to
        if payload.eid != target_eid:
            return TestResult(
                self.description,
                self.spec_ref,
                ComplianceResult.WARN,
                f"Returned EID 0x{payload.eid:02X} != target 0x{target_eid:02X}",
            )

        # Verify endpoint_type is valid (0 or 1)
        if payload.endpoint_type not in (0, 1):
            return TestResult(
                self.description,
                self.spec_ref,
                ComplianceResult.FAIL,
                f"Invalid endpoint_type: {payload.endpoint_type}",
            )

        return TestResult(
            self.description,
            self.spec_ref,
            ComplianceResult.PASS,
            f"EID=0x{payload.eid:02X}, type={payload.endpoint_type}",
        )
