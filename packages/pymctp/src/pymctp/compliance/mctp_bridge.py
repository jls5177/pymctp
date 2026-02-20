# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""MCTP Bridge Specification compliance tests (DSP0236 bridging sections)."""

from __future__ import annotations

from ..automaton.sessions import EndpointSession
from ..layers.mctp.control import (
    CompletionCodes,
    ControlHdrPacket,
    GetRoutingTableEntries,
    GetRoutingTableEntriesResponsePacket,
    QueryHop,
    QueryHopResponsePacket,
)
from ..layers.mctp.control.allocate_eids import (
    AllocateEIDOperation,
    AllocateEndpointIDs,
    AllocateEndpointIDsResponsePacket,
)
from .base import ComplianceResult, ComplianceTestCase, TestResult


def all_tests() -> list[ComplianceTestCase]:
    """Return all MCTP bridge compliance tests."""
    return [
        TestGetRoutingTableEntries(),
        TestGetRoutingTablePagination(),
        TestQueryHop(),
        TestAllocateEndpointIDsInfo(),
    ]


class TestGetRoutingTableEntries(ComplianceTestCase):
    spec_ref = "DSP0236 §12.11"
    description = "GetRoutingTableEntries returns valid entries"

    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        rsp = session.sndrcv_control_msg(GetRoutingTableEntries(entry_handle=0), target_eid, timeout_s=timeout_s)
        if rsp is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "No response received")

        ctrl = rsp.getlayer(ControlHdrPacket)
        if ctrl is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Malformed response")

        if ctrl.completion_code == CompletionCodes.ERROR_UNSUPPORTED_CMD:
            return TestResult(
                self.description,
                self.spec_ref,
                ComplianceResult.SKIP,
                "Endpoint does not support GetRoutingTableEntries (not a bridge)",
            )

        if ctrl.completion_code == CompletionCodes.ERROR_NOT_READY:
            return TestResult(self.description, self.spec_ref, ComplianceResult.WARN, "Routing table not ready")

        if ctrl.completion_code != CompletionCodes.SUCCESS:
            return TestResult(
                self.description, self.spec_ref, ComplianceResult.FAIL, f"Completion code: {ctrl.completion_code}"
            )

        payload = rsp.getlayer(GetRoutingTableEntriesResponsePacket)
        if payload is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Missing response payload")

        return TestResult(
            self.description,
            self.spec_ref,
            ComplianceResult.PASS,
            f"{payload.entry_count} entries, next_handle=0x{payload.next_entry_handle:02X}",
        )


class TestGetRoutingTablePagination(ComplianceTestCase):
    spec_ref = "DSP0236 §12.11"
    description = "GetRoutingTableEntries pagination terminates with 0xFF"

    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        handle = 0
        total_entries = 0
        max_iterations = 64

        for _ in range(max_iterations):
            rsp = session.sndrcv_control_msg(
                GetRoutingTableEntries(entry_handle=handle), target_eid, timeout_s=timeout_s
            )
            if rsp is None:
                return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "No response mid-pagination")

            ctrl = rsp.getlayer(ControlHdrPacket)
            if ctrl is None or ctrl.completion_code != CompletionCodes.SUCCESS:
                if ctrl and ctrl.completion_code == CompletionCodes.ERROR_UNSUPPORTED_CMD:
                    return TestResult(self.description, self.spec_ref, ComplianceResult.SKIP, "Not a bridge endpoint")
                return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Error during pagination")

            payload = rsp.getlayer(GetRoutingTableEntriesResponsePacket)
            if payload is None:
                return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Missing payload")

            total_entries += payload.entry_count
            if payload.next_entry_handle == 0xFF:
                return TestResult(
                    self.description,
                    self.spec_ref,
                    ComplianceResult.PASS,
                    f"Pagination terminated correctly with {total_entries} total entries",
                )
            handle = payload.next_entry_handle

        return TestResult(
            self.description,
            self.spec_ref,
            ComplianceResult.FAIL,
            f"Pagination did not terminate within {max_iterations} requests",
        )


class TestQueryHop(ComplianceTestCase):
    spec_ref = "DSP0236 §12.16"
    description = "QueryHop returns valid response for known target"

    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        # Query hop for the bridge endpoint itself (should always succeed)
        rsp = session.sndrcv_control_msg(
            QueryHop(target_eid=target_eid, mctp_ctrl_msg_type=0), target_eid, timeout_s=timeout_s
        )
        if rsp is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "No response received")

        ctrl = rsp.getlayer(ControlHdrPacket)
        if ctrl is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Malformed response")

        if ctrl.completion_code == CompletionCodes.ERROR_UNSUPPORTED_CMD:
            return TestResult(self.description, self.spec_ref, ComplianceResult.SKIP, "Not a bridge endpoint")

        if ctrl.completion_code != CompletionCodes.SUCCESS:
            return TestResult(
                self.description, self.spec_ref, ComplianceResult.FAIL, f"Completion code: {ctrl.completion_code}"
            )

        payload = rsp.getlayer(QueryHopResponsePacket)
        if payload is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Missing response payload")

        return TestResult(
            self.description,
            self.spec_ref,
            ComplianceResult.PASS,
            f"next_bridge=0x{payload.next_bridge_eid:02X}, MTU={payload.max_incoming_unit_size}",
        )


class TestAllocateEndpointIDsInfo(ComplianceTestCase):
    spec_ref = "DSP0236 §12.9"
    description = "AllocateEndpointIDs GET_ALLOCATION_INFO returns pool info"

    def run(self, session: EndpointSession, target_eid: int, *, timeout_s: float = 5.0) -> TestResult:
        rsp = session.sndrcv_control_msg(
            AllocateEndpointIDs(op=AllocateEIDOperation.GET_ALLOCATION_INFO, allocated_pool_size=0, starting_eid=0),
            target_eid,
            timeout_s=timeout_s,
        )
        if rsp is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "No response received")

        ctrl = rsp.getlayer(ControlHdrPacket)
        if ctrl is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Malformed response")

        if ctrl.completion_code == CompletionCodes.ERROR_UNSUPPORTED_CMD:
            return TestResult(self.description, self.spec_ref, ComplianceResult.SKIP, "Not a bus owner endpoint")

        if ctrl.completion_code != CompletionCodes.SUCCESS:
            return TestResult(
                self.description, self.spec_ref, ComplianceResult.FAIL, f"Completion code: {ctrl.completion_code}"
            )

        payload = rsp.getlayer(AllocateEndpointIDsResponsePacket)
        if payload is None:
            return TestResult(self.description, self.spec_ref, ComplianceResult.FAIL, "Missing response payload")

        return TestResult(
            self.description,
            self.spec_ref,
            ComplianceResult.PASS,
            f"pool_size={payload.eid_pool_size}, first_eid=0x{payload.first_eid:02X}",
        )
