# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Bus-owner discovery behavior for DSP0236 endpoint assignment."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scapy.packet import Packet

from ...layers.mctp.control import (
    AllocateEIDAllocationStatus,
    AllocateEIDOperation,
    AllocateEndpointIDs,
    AllocateEndpointIDsResponsePacket,
    ControlHdrPacket,
    EndpointDiscovery,
    GetEndpointID,
    GetEndpointIDResponsePacket,
    GetMctpVersionSupport,
    GetMctpVersionSupportResponsePacket,
    GetMessageTypeSupport,
    GetMessageTypeSupportResponsePacket,
    GetRoutingTableEntries,
    GetRoutingTableEntriesResponsePacket,
    PrepareForEndpointDiscovery,
    RoutingTableEntryPacket,
    SetEndpointID,
    SetEndpointIDAllocationStatus,
    SetEndpointIDAssignmentStatus,
    SetEndpointIDOperation,
    SetEndpointIDResponsePacket,
)
from ...layers.mctp.control.types import CompletionCodes, ContrlCmdCodes
from ...layers.mctp.types import EndpointContext, RoutingTableEntry, Smbus7bitAddress
from ..sessions import HandlerResponse
from .base import Behavior

if TYPE_CHECKING:
    from ..role_endpoint import RoleBasedEndpointAM

logger = logging.getLogger(__name__)

_ROUTING_DONE_HANDLE = 0xFF
_MAX_ROUTING_TABLE_TRANSFERS = 16


@dataclass
class DiscoveryTarget:
    """One endpoint the bus owner is responsible for assigning."""

    name: str
    eid: int
    physical_address: int | None = None
    pool_start: int | None = None
    pool_size: int = 0
    is_bridge: bool = False


@dataclass
class DiscoveryStep:
    """One request/response in a discovery sweep."""

    name: str
    target: str
    ok: bool
    detail: str = ""
    response: Any = None


@dataclass
class DiscoveryReport:
    """Discovery sweep result."""

    steps: list[DiscoveryStep] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None

    @property
    def ok(self) -> bool:
        """True when every recorded discovery step succeeded."""
        return all(step.ok for step in self.steps)

    def failures(self) -> list[DiscoveryStep]:
        """Return failed discovery steps."""
        return [step for step in self.steps if not step.ok]

    def __str__(self) -> str:
        """Return a readable multi-line step summary."""
        return "\n".join(
            f"{'OK' if step.ok else 'FAIL'} {step.target}: {step.name}"
            f"{f' - {step.detail}' if step.detail else ''}"
            for step in self.steps
        )


class BusOwnerBehavior(Behavior):
    """Runs bus-owner endpoint discovery and assignment."""

    def __init__(
        self,
        *,
        targets: list[DiscoveryTarget] | list[dict] | None = None,
        auto_discover: bool = True,
        start_delay_s: float = 0.5,
        timeout_s: float = 2.0,
        retries: int = 1,
        prepare_for_discovery: bool = True,
        rediscover_on_notify: bool = True,
        verify_routing_table: bool = True,
    ) -> None:
        self._targets = [self._coerce_target(target) for target in (targets or [])]
        self.auto_discover = auto_discover
        self.start_delay_s = start_delay_s
        self.timeout_s = timeout_s
        self.retries = retries
        self.prepare_for_discovery = prepare_for_discovery
        self.rediscover_on_notify = rediscover_on_notify
        self.verify_routing_table = verify_routing_table

        self._am: RoleBasedEndpointAM | None = None
        self._ctx: EndpointContext | None = None
        self._report: DiscoveryReport | None = None
        self._shutdown_event = threading.Event()
        self._request_event = threading.Event()
        self._condition = threading.Condition()
        self._worker: threading.Thread | None = None
        self._sweep_generation = 0
        self._pending_timeout_s: float | None = None
        self._needs_start_delay = False

    @property
    def name(self) -> str:
        return "bus-owner"

    @property
    def report(self) -> DiscoveryReport | None:
        """Most recent discovery report, if a sweep has completed."""
        return self._report

    def add_target(self, target: DiscoveryTarget | dict) -> None:
        """Add a discovery target."""
        self._targets.append(self._coerce_target(target))

    def on_attach(self, ctx: EndpointContext) -> None:
        ctx.is_bus_owner = True
        self._ctx = ctx

    def on_bind(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        # Captured here rather than in on_start so rediscover() can run a
        # synchronous sweep against an endpoint whose sniffer was never started
        # (test harnesses, one-shot CLI invocations).
        self._am = am
        self._ctx = ctx

    def on_start(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        self._am = am
        self._ctx = ctx
        if self._worker and self._worker.is_alive():
            if self.auto_discover:
                self._request_event.set()
            return

        self._shutdown_event.clear()
        self._needs_start_delay = True
        self._worker = threading.Thread(target=self._worker_main, name=f"mctp-bus-owner-{ctx.eid}", daemon=True)
        self._worker.start()
        if self.auto_discover:
            self._request_event.set()

    def on_stop(self, am: RoleBasedEndpointAM, ctx: EndpointContext) -> None:
        self._shutdown_event.set()
        self._request_event.set()
        worker = self._worker
        if worker and worker.is_alive():
            worker.join(timeout=2.0)
        if worker and not worker.is_alive():
            self._worker = None

    def can_handle(self, pkt: Packet, ctx: EndpointContext) -> bool:
        if not pkt.haslayer(ControlHdrPacket):
            return False
        ctrl: ControlHdrPacket = pkt.getlayer(ControlHdrPacket)
        return ctrl.rq == 1 and ctrl.cmd_code == ContrlCmdCodes.DiscoveryNotify

    def handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse | None:
        if self.rediscover_on_notify and self._worker and self._worker.is_alive():
            self._request_worker_sweep()
        return HandlerResponse(stop_processing=False, reply=None)

    def rediscover(self, timeout_s: float | None = None, *, block: bool = True) -> DiscoveryReport:
        """Request a discovery sweep.

        With no running worker, blocking calls run synchronously and non-blocking
        calls only return the current report (or an empty queued report).
        """
        worker = self._worker
        if not worker or not worker.is_alive():
            if not block:
                return self._report or DiscoveryReport(steps=[], started_at=time.time(), finished_at=None)
            report = self._run_sweep(timeout_s=timeout_s)
            with self._condition:
                self._report = report
                self._sweep_generation += 1
                self._condition.notify_all()
            return report

        with self._condition:
            start_generation = self._sweep_generation
        self._request_worker_sweep(timeout_s=timeout_s)
        if not block:
            return self._report or DiscoveryReport(steps=[], started_at=time.time(), finished_at=None)

        with self._condition:
            while self._sweep_generation == start_generation and worker.is_alive() and not self._shutdown_event.is_set():
                self._condition.wait(timeout=0.1)
            return self._report or DiscoveryReport(steps=[], started_at=time.time(), finished_at=None)

    @staticmethod
    def _coerce_target(target: DiscoveryTarget | dict) -> DiscoveryTarget:
        if isinstance(target, DiscoveryTarget):
            return target
        return DiscoveryTarget(**target)

    def _request_worker_sweep(self, timeout_s: float | None = None) -> None:
        with self._condition:
            if timeout_s is not None:
                self._pending_timeout_s = timeout_s
        self._request_event.set()

    def _worker_main(self) -> None:
        while not self._shutdown_event.is_set():
            self._request_event.wait()
            if self._shutdown_event.is_set():
                break
            self._request_event.clear()

            if self._needs_start_delay:
                self._needs_start_delay = False
                if self.start_delay_s > 0 and self._shutdown_event.wait(timeout=self.start_delay_s):
                    break

            with self._condition:
                timeout_s = self._pending_timeout_s
                self._pending_timeout_s = None

            try:
                report = self._run_sweep(timeout_s=timeout_s)
            except Exception:
                logger.exception("Bus-owner discovery sweep failed")
                report = DiscoveryReport(
                    steps=[DiscoveryStep("discovery-sweep", "bus-owner", False, "unhandled exception")],
                    started_at=time.time(),
                    finished_at=time.time(),
                )

            with self._condition:
                self._report = report
                self._sweep_generation += 1
                self._condition.notify_all()

    def _run_sweep(self, timeout_s: float | None = None) -> DiscoveryReport:
        report = DiscoveryReport(started_at=time.time())
        timeout = self.timeout_s if timeout_s is None else timeout_s
        routing_table: list[RoutingTableEntry] = []

        try:
            for target in list(self._targets):
                if self._shutdown_event.is_set():
                    break
                try:
                    self._discover_target(target, report, routing_table, timeout)
                except Exception as exc:
                    logger.exception("Discovery failed for target %s", target.name)
                    report.steps.append(DiscoveryStep("target-discovery", target.name, False, str(exc)))
        finally:
            # Only publish a routing table we actually retrieved — a sweep that
            # failed early (or one with no bridge targets) must not wipe a
            # previously discovered or preconfigured table.
            if self._ctx is not None and routing_table:
                self._ctx.routing_table = routing_table
                self._ctx.routing_table_ready = True
            report.finished_at = time.time()

        return report

    def _discover_target(
        self,
        target: DiscoveryTarget,
        report: DiscoveryReport,
        routing_table: list[RoutingTableEntry],
        timeout_s: float,
    ) -> None:
        target_phy_addr = self._target_phy_addr(target)
        dst_eid = 0

        if self.prepare_for_discovery:
            self._optional_step(
                report,
                "prepare-for-endpoint-discovery",
                target,
                PrepareForEndpointDiscovery(),
                dst_eid=0,
                dst_phy_addr=target_phy_addr,
                timeout_s=timeout_s,
            )
            self._optional_step(
                report,
                "endpoint-discovery",
                target,
                EndpointDiscovery(),
                dst_eid=0,
                dst_phy_addr=target_phy_addr,
                timeout_s=timeout_s,
            )

        rsp = self._send(GetEndpointID(), dst_eid=dst_eid, dst_phy_addr=target_phy_addr, timeout_s=timeout_s)
        get_eid = self._payload(rsp, GetEndpointIDResponsePacket)
        if not rsp or not self._completion_ok(rsp) or not get_eid:
            report.steps.append(
                DiscoveryStep("get-endpoint-id", target.name, False, self._failure_detail(rsp), rsp)
            )
            return

        dst_eid = int(get_eid.eid)
        report.steps.append(
            DiscoveryStep(
                "get-endpoint-id",
                target.name,
                True,
                f"eid=0x{int(get_eid.eid):02X}",
                rsp,
            )
        )

        if int(get_eid.eid) == target.eid:
            report.steps.append(DiscoveryStep("set-endpoint-id", target.name, True, "already assigned", rsp))
            dst_eid = target.eid
        else:
            rsp = self._send(
                SetEndpointID(op=SetEndpointIDOperation.SetEID, eid=target.eid),
                dst_eid=dst_eid,
                dst_phy_addr=target_phy_addr,
                timeout_s=timeout_s,
            )
            set_eid = self._payload(rsp, SetEndpointIDResponsePacket)
            if not rsp or not self._completion_ok(rsp) or not set_eid:
                report.steps.append(
                    DiscoveryStep("set-endpoint-id", target.name, False, self._failure_detail(rsp), rsp)
                )
                return

            assignment_status = SetEndpointIDAssignmentStatus(int(set_eid.eid_assignment_status))
            allocation_status = SetEndpointIDAllocationStatus(int(set_eid.eid_allocation_status))
            set_ok = assignment_status == SetEndpointIDAssignmentStatus.ACCEPTED
            report.steps.append(
                DiscoveryStep(
                    "set-endpoint-id",
                    target.name,
                    set_ok,
                    "assignment=%s allocation=%s eid=0x%02X pool_size=%d"
                    % (assignment_status.name, allocation_status.name, int(set_eid.eid_setting), int(set_eid.eid_pool_size)),
                    rsp,
                )
            )
            if not set_ok:
                return
            dst_eid = target.eid

            if self._should_allocate_pool(target, allocation_status):
                if target.pool_start is None:
                    report.steps.append(
                        DiscoveryStep("allocate-endpoint-ids", target.name, False, "pool_start is required")
                    )
                    return
                self._allocate_endpoint_ids(report, target, target_phy_addr, dst_eid, timeout_s)

        self._informational_step(
            report,
            "get-mctp-version-support",
            target,
            GetMctpVersionSupport(msg_type_number=0),
            GetMctpVersionSupportResponsePacket,
            dst_eid=dst_eid,
            dst_phy_addr=target_phy_addr,
            timeout_s=timeout_s,
            detail_fn=lambda payload: "versions=[%s]"
            % ", ".join(f"0x{int(version):08X}" for version in payload.version_number_list),
        )
        self._informational_step(
            report,
            "get-message-type-support",
            target,
            GetMessageTypeSupport(),
            GetMessageTypeSupportResponsePacket,
            dst_eid=dst_eid,
            dst_phy_addr=target_phy_addr,
            timeout_s=timeout_s,
            detail_fn=lambda payload: "msg_types=[%s]"
            % ", ".join(f"0x{int(msg_type):02X}" for msg_type in payload.msg_type_list),
        )

        if target.is_bridge and self.verify_routing_table:
            self._get_routing_table(report, target, routing_table, target_phy_addr, dst_eid, timeout_s)

    def _optional_step(
        self,
        report: DiscoveryReport,
        name: str,
        target: DiscoveryTarget,
        pkt: Packet,
        *,
        dst_eid: int,
        dst_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
    ) -> None:
        rsp = self._send(pkt, dst_eid=dst_eid, dst_phy_addr=dst_phy_addr, timeout_s=timeout_s)
        if rsp is None:
            report.steps.append(DiscoveryStep(name, target.name, True, "no response (optional)", rsp))
            return
        ok = self._completion_ok(rsp)
        report.steps.append(DiscoveryStep(name, target.name, ok, self._success_or_failure_detail(rsp), rsp))

    def _informational_step(
        self,
        report: DiscoveryReport,
        name: str,
        target: DiscoveryTarget,
        pkt: Packet,
        payload_cls: type[Packet],
        *,
        dst_eid: int,
        dst_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
        detail_fn: Any,
    ) -> None:
        rsp = self._send(pkt, dst_eid=dst_eid, dst_phy_addr=dst_phy_addr, timeout_s=timeout_s)
        payload = self._payload(rsp, payload_cls)
        if rsp is None:
            report.steps.append(DiscoveryStep(name, target.name, True, "no response (informational)", rsp))
            return
        if not self._completion_ok(rsp) or payload is None:
            report.steps.append(DiscoveryStep(name, target.name, True, self._failure_detail(rsp), rsp))
            return
        report.steps.append(DiscoveryStep(name, target.name, True, detail_fn(payload), rsp))

    def _allocate_endpoint_ids(
        self,
        report: DiscoveryReport,
        target: DiscoveryTarget,
        dst_phy_addr: Smbus7bitAddress | None,
        dst_eid: int,
        timeout_s: float,
    ) -> None:
        rsp = self._send(
            AllocateEndpointIDs(
                op=AllocateEIDOperation.ALLOCATE_EIDS,
                allocated_pool_size=target.pool_size,
                starting_eid=target.pool_start or 0,
            ),
            dst_eid=dst_eid,
            dst_phy_addr=dst_phy_addr,
            timeout_s=timeout_s,
        )
        payload = self._payload(rsp, AllocateEndpointIDsResponsePacket)
        if not rsp or not self._completion_ok(rsp) or not payload:
            report.steps.append(DiscoveryStep("allocate-endpoint-ids", target.name, False, self._failure_detail(rsp), rsp))
            return

        status = AllocateEIDAllocationStatus(int(payload.status))
        report.steps.append(
            DiscoveryStep(
                "allocate-endpoint-ids",
                target.name,
                status == AllocateEIDAllocationStatus.ACCEPTED,
                f"status={status.name} pool_size={int(payload.eid_pool_size)} first_eid=0x{int(payload.first_eid):02X}",
                rsp,
            )
        )

    def _get_routing_table(
        self,
        report: DiscoveryReport,
        target: DiscoveryTarget,
        routing_table: list[RoutingTableEntry],
        dst_phy_addr: Smbus7bitAddress | None,
        dst_eid: int,
        timeout_s: float,
    ) -> None:
        entry_handle = 0
        for _ in range(_MAX_ROUTING_TABLE_TRANSFERS):
            rsp = self._send(
                GetRoutingTableEntries(entry_handle=entry_handle),
                dst_eid=dst_eid,
                dst_phy_addr=dst_phy_addr,
                timeout_s=timeout_s,
            )
            payload = self._payload(rsp, GetRoutingTableEntriesResponsePacket)
            if not rsp or not self._completion_ok(rsp) or not payload:
                report.steps.append(
                    DiscoveryStep("get-routing-table-entries", target.name, False, self._failure_detail(rsp), rsp)
                )
                return

            entries = [self._routing_entry_from_packet(entry) for entry in payload.entries]
            routing_table.extend(entries)
            next_handle = int(payload.next_entry_handle)
            report.steps.append(
                DiscoveryStep(
                    "get-routing-table-entries",
                    target.name,
                    True,
                    "handle=0x%02X entries=%d next=0x%02X" % (entry_handle, len(entries), next_handle),
                    rsp,
                )
            )
            if next_handle == _ROUTING_DONE_HANDLE:
                return
            entry_handle = next_handle

        report.steps.append(
            DiscoveryStep(
                "get-routing-table-entries",
                target.name,
                False,
                f"exceeded {_MAX_ROUTING_TABLE_TRANSFERS} transfers",
            )
        )

    def _send(
        self,
        pkt: Packet,
        *,
        dst_eid: int,
        dst_phy_addr: Smbus7bitAddress | None,
        timeout_s: float,
    ) -> Packet | None:
        if self._am is None:
            msg = "bus owner behavior is not attached to an answering machine"
            raise RuntimeError(msg)

        response: Packet | None = None
        for _ in range(self.retries + 1):
            if self._shutdown_event.is_set():
                return None
            response = self._am.session.sndrcv_control_msg(
                pkt,
                dst_eid=dst_eid,
                dst_phy_addr=dst_phy_addr,
                timeout_s=timeout_s,
                threaded=True,
            )
            if response is not None:
                return response
        return response

    @staticmethod
    def _target_phy_addr(target: DiscoveryTarget) -> Smbus7bitAddress | None:
        if target.physical_address is None:
            return None
        return Smbus7bitAddress(target.physical_address)

    @staticmethod
    def _payload(pkt: Packet | None, layer_cls: type[Packet]) -> Any | None:
        if pkt is None:
            return None
        if isinstance(pkt, layer_cls):
            return pkt
        if pkt.haslayer(layer_cls):
            return pkt.getlayer(layer_cls)
        return None

    @staticmethod
    def _completion_ok(pkt: Packet) -> bool:
        if not pkt.haslayer(ControlHdrPacket):
            return True
        ctrl: ControlHdrPacket = pkt.getlayer(ControlHdrPacket)
        return int(ctrl.completion_code) == int(CompletionCodes.SUCCESS)

    @staticmethod
    def _failure_detail(pkt: Packet | None) -> str:
        if pkt is None:
            return "timeout"
        if pkt.haslayer(ControlHdrPacket):
            ctrl: ControlHdrPacket = pkt.getlayer(ControlHdrPacket)
            try:
                return f"completion_code={CompletionCodes(int(ctrl.completion_code)).name}"
            except ValueError:
                return f"completion_code=0x{int(ctrl.completion_code):02X}"
        return "missing response payload"

    def _success_or_failure_detail(self, pkt: Packet) -> str:
        return "success" if self._completion_ok(pkt) else self._failure_detail(pkt)

    @staticmethod
    def _should_allocate_pool(target: DiscoveryTarget, allocation_status: SetEndpointIDAllocationStatus) -> bool:
        return (
            target.pool_size > 0
            and allocation_status == SetEndpointIDAllocationStatus.EID_POOL_REQUIRED
        )

    @staticmethod
    def _routing_entry_from_packet(entry: RoutingTableEntryPacket) -> RoutingTableEntry:
        return RoutingTableEntry(
            starting_eid=int(entry.starting_eid),
            port_number=int(entry.port_number),
            phy_address=[int(value) for value in entry.phy_address],
            phys_transport_binding_id=int(entry.phys_transport_binding_id),
            phy_media_type_id=int(entry.phy_media_type_id),
            entry_type=int(entry.entry_type),
            eid_range=int(entry.eid_range),
            static_eid=bool(entry.static_eid),
        )
