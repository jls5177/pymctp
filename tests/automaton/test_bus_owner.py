# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the bus-owner discovery behavior."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Callable

from scapy.packet import Packet

from pymctp.automaton.behaviors.bus_owner import BusOwnerBehavior, DiscoveryTarget
from pymctp.automaton.roles import create_endpoint
from pymctp.layers.mctp.control import (
    AllocateEIDAllocationStatus,
    AllocateEndpointIDsResponsePacket,
    ControlHdr,
    ControlHdrPacket,
    DiscoveryNotifyRequestPacket,
    GetEndpointIDResponsePacket,
    GetMctpVersionSupportResponsePacket,
    GetMessageTypeSupportResponsePacket,
    GetRoutingTableEntriesResponsePacket,
    RoutingTableEntryPacket,
    SetEndpointIDAllocationStatus,
    SetEndpointIDAssignmentStatus,
    SetEndpointIDResponsePacket,
)
from pymctp.layers.mctp.control.types import ContrlCmdCodes
from pymctp.layers.mctp.types import EndpointContext, Smbus7bitAddress


class FakeSession:
    def __init__(self, responder: Callable[[Packet], Packet | None]) -> None:
        self.sent: list[tuple[Packet, int, Smbus7bitAddress | None, bool]] = []
        self._responder = responder

    def sndrcv_control_msg(
        self,
        pkt: Packet,
        dst_eid: int,
        *,
        dst_phy_addr: Smbus7bitAddress | None = None,
        timeout_s: float | None = None,
        threaded: bool = False,
        instance_id: int | None = None,
    ) -> Packet | None:
        self.sent.append((pkt, dst_eid, dst_phy_addr, threaded))
        return self._responder(pkt)


class FakeAM:
    def __init__(self, session: FakeSession, context: EndpointContext) -> None:
        self.session = session
        self.context = context


def _response(cmd_code: ContrlCmdCodes, payload: Packet | None = None, completion_code: int = 0) -> Packet:
    hdr = ControlHdr(rq=False, cmd_code=cmd_code, completion_code=completion_code)
    return hdr / payload if payload is not None else hdr


def _set_rsp(
    allocation_status: SetEndpointIDAllocationStatus = SetEndpointIDAllocationStatus.NO_EID_POOL_REQUIRED,
    eid_setting: int = 0x0F,
    pool_size: int = 0,
) -> Packet:
    return _response(
        ContrlCmdCodes.SetEndpointID,
        SetEndpointIDResponsePacket(
            eid_assignment_status=SetEndpointIDAssignmentStatus.ACCEPTED,
            eid_allocation_status=allocation_status,
            eid_setting=eid_setting,
            eid_pool_size=pool_size,
        ),
    )


def _queue_responder(script: dict[ContrlCmdCodes, list[Packet | None]]) -> Callable[[Packet], Packet | None]:
    queues = {cmd: deque(values) for cmd, values in script.items()}

    def responder(pkt: Packet) -> Packet | None:
        queue = queues.get(ContrlCmdCodes(pkt.cmd_code))
        if not queue:
            return None
        return queue.popleft()

    return responder


def _behavior_with_fake_am(
    behavior: BusOwnerBehavior,
    responder: Callable[[Packet], Packet | None],
    ctx: EndpointContext | None = None,
) -> tuple[FakeSession, FakeAM, EndpointContext]:
    ctx = ctx or EndpointContext(physical_address=Smbus7bitAddress(0x20), assigned_eid=0x08)
    session = FakeSession(responder)
    am = FakeAM(session, ctx)
    behavior.on_attach(ctx)
    behavior._am = am
    behavior._ctx = ctx
    return session, am, ctx


def test_bus_owner_role_registration_sets_context_flag() -> None:
    ctx = EndpointContext(physical_address=Smbus7bitAddress(0x10), assigned_eid=0x08)
    am = create_endpoint("bus-owner", context=ctx)

    assert am.role == ["bus-owner"]
    assert ctx.is_bus_owner is True


def test_full_happy_path_bridge_sweep_records_expected_steps_and_routing_table() -> None:
    target = DiscoveryTarget(
        name="bmc",
        eid=0x0F,
        physical_address=0x10,
        pool_start=0x20,
        pool_size=0x10,
        is_bridge=True,
    )
    route_entry = RoutingTableEntryPacket(
        eid_range=0x10,
        starting_eid=0x20,
        entry_type=2,
        static_eid=0,
        port_number=1,
        phys_transport_binding_id=1,
        phy_media_type_id=3,
        phy_address=[0x10],
    )
    script = {
        ContrlCmdCodes.PrepareForEndpointDiscovery: [None],
        ContrlCmdCodes.EndpointDiscovery: [None],
        ContrlCmdCodes.GetEndpointID: [
            _response(ContrlCmdCodes.GetEndpointID, GetEndpointIDResponsePacket(eid=0))
        ],
        ContrlCmdCodes.SetEndpointID: [
            _set_rsp(SetEndpointIDAllocationStatus.EID_POOL_REQUIRED, eid_setting=0x0F, pool_size=0x10)
        ],
        ContrlCmdCodes.AllocateEndpointIDs: [
            _response(
                ContrlCmdCodes.AllocateEndpointIDs,
                AllocateEndpointIDsResponsePacket(
                    status=AllocateEIDAllocationStatus.ACCEPTED,
                    eid_pool_size=0x10,
                    first_eid=0x20,
                ),
            )
        ],
        ContrlCmdCodes.GetMCTPVersionSupport: [
            _response(
                ContrlCmdCodes.GetMCTPVersionSupport,
                GetMctpVersionSupportResponsePacket(version_number_entry_count=1, version_number_list=[0xF1F3F100]),
            )
        ],
        ContrlCmdCodes.GetMessageTypeSupport: [
            _response(
                ContrlCmdCodes.GetMessageTypeSupport,
                GetMessageTypeSupportResponsePacket(msg_type_cnt=1, msg_type_list=[0]),
            )
        ],
        ContrlCmdCodes.GetRoutingTableEntries: [
            _response(
                ContrlCmdCodes.GetRoutingTableEntries,
                GetRoutingTableEntriesResponsePacket(next_entry_handle=0xFF, entry_count=1, entries=[route_entry]),
            )
        ],
    }
    behavior = BusOwnerBehavior(targets=[target], start_delay_s=0)
    session, _, ctx = _behavior_with_fake_am(behavior, _queue_responder(script))

    report = behavior.rediscover()

    assert report.ok is True
    assert [step.name for step in report.steps] == [
        "prepare-for-endpoint-discovery",
        "endpoint-discovery",
        "get-endpoint-id",
        "set-endpoint-id",
        "allocate-endpoint-ids",
        "get-mctp-version-support",
        "get-message-type-support",
        "get-routing-table-entries",
    ]
    assert all(threaded for _, _, _, threaded in session.sent)
    assert ctx.routing_table[0].starting_eid == 0x20
    assert ctx.routing_table[0].eid_range == 0x10


def test_set_endpoint_id_timeout_fails_step_and_continues_to_next_target() -> None:
    targets = [
        DiscoveryTarget(name="off", eid=0x0A, physical_address=0x10),
        DiscoveryTarget(name="on", eid=0x0B, physical_address=0x11),
    ]
    script = {
        ContrlCmdCodes.GetEndpointID: [
            _response(ContrlCmdCodes.GetEndpointID, GetEndpointIDResponsePacket(eid=0)),
            _response(ContrlCmdCodes.GetEndpointID, GetEndpointIDResponsePacket(eid=0)),
        ],
        ContrlCmdCodes.SetEndpointID: [None, _set_rsp(eid_setting=0x0B)],
    }
    behavior = BusOwnerBehavior(
        targets=targets,
        start_delay_s=0,
        retries=0,
        prepare_for_discovery=False,
        verify_routing_table=False,
    )
    _behavior_with_fake_am(behavior, _queue_responder(script))

    report = behavior.rediscover()

    failures = report.failures()
    assert len(failures) == 1
    assert failures[0].name == "set-endpoint-id"
    assert failures[0].target == "off"
    assert any(step.target == "on" and step.name == "set-endpoint-id" and step.ok for step in report.steps)


def test_retries_retry_timeouts() -> None:
    attempts = 0

    def responder(pkt: Packet) -> Packet | None:
        nonlocal attempts
        if pkt.cmd_code == ContrlCmdCodes.GetEndpointID:
            attempts += 1
            if attempts < 3:
                return None
            return _response(ContrlCmdCodes.GetEndpointID, GetEndpointIDResponsePacket(eid=0x05))
        return None

    behavior = BusOwnerBehavior(
        targets=[DiscoveryTarget(name="ep", eid=0x05, physical_address=0x10)],
        start_delay_s=0,
        retries=2,
        prepare_for_discovery=False,
        verify_routing_table=False,
    )
    _behavior_with_fake_am(behavior, responder)

    report = behavior.rediscover()

    assert attempts == 3
    assert report.ok is True


def test_already_assigned_short_circuits_set_endpoint_id() -> None:
    behavior = BusOwnerBehavior(
        targets=[DiscoveryTarget(name="bmc", eid=0x0F, physical_address=0x10)],
        start_delay_s=0,
        prepare_for_discovery=False,
        verify_routing_table=False,
    )
    session, _, _ = _behavior_with_fake_am(
        behavior,
        _queue_responder(
            {
                ContrlCmdCodes.GetEndpointID: [
                    _response(ContrlCmdCodes.GetEndpointID, GetEndpointIDResponsePacket(eid=0x0F))
                ],
            }
        ),
    )

    report = behavior.rediscover()

    assert "already assigned" in [step.detail for step in report.steps if step.name == "set-endpoint-id"]
    assert ContrlCmdCodes.SetEndpointID not in [pkt.cmd_code for pkt, _, _, _ in session.sent]


def test_discovery_notify_requests_nonblocking_rediscovery_without_sending_inline() -> None:
    behavior = BusOwnerBehavior(targets=[DiscoveryTarget(name="bmc", eid=0x0F)], start_delay_s=0)
    called = False

    class AliveWorker:
        def is_alive(self) -> bool:
            return True

    def request_worker_sweep(timeout_s: float | None = None) -> None:
        nonlocal called
        called = True

    behavior._worker = AliveWorker()
    behavior._request_worker_sweep = request_worker_sweep
    pkt = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.DiscoveryNotify) / DiscoveryNotifyRequestPacket()

    started_at = time.perf_counter()
    response = behavior.handle(pkt, EndpointContext())

    assert time.perf_counter() - started_at < 0.01
    assert called is True
    assert response is not None
    assert response.stop_processing is False
    assert response.reply is None


def test_can_handle_claims_discovery_notify_requests_only() -> None:
    behavior = BusOwnerBehavior(start_delay_s=0)
    request = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.DiscoveryNotify) / DiscoveryNotifyRequestPacket()
    response = ControlHdr(rq=False, cmd_code=ContrlCmdCodes.DiscoveryNotify, completion_code=0)
    other_request = ControlHdr(rq=True, cmd_code=ContrlCmdCodes.GetEndpointID)

    assert behavior.can_handle(request, EndpointContext()) is True
    assert behavior.can_handle(response, EndpointContext()) is False
    assert behavior.can_handle(other_request, EndpointContext()) is False


def test_multi_part_routing_table_retrieval_terminates() -> None:
    route_entries = [
        RoutingTableEntryPacket(
            eid_range=1,
            starting_eid=0x20,
            entry_type=0,
            static_eid=0,
            port_number=1,
            phys_transport_binding_id=1,
            phy_media_type_id=3,
            phy_address=[0x20],
        ),
        RoutingTableEntryPacket(
            eid_range=1,
            starting_eid=0x21,
            entry_type=0,
            static_eid=0,
            port_number=1,
            phys_transport_binding_id=1,
            phy_media_type_id=3,
            phy_address=[0x21],
        ),
    ]
    script = {
        ContrlCmdCodes.GetEndpointID: [
            _response(ContrlCmdCodes.GetEndpointID, GetEndpointIDResponsePacket(eid=0)),
        ],
        ContrlCmdCodes.SetEndpointID: [_set_rsp(eid_setting=0x0F)],
        ContrlCmdCodes.GetRoutingTableEntries: [
            _response(
                ContrlCmdCodes.GetRoutingTableEntries,
                GetRoutingTableEntriesResponsePacket(next_entry_handle=1, entry_count=1, entries=[route_entries[0]]),
            ),
            _response(
                ContrlCmdCodes.GetRoutingTableEntries,
                GetRoutingTableEntriesResponsePacket(next_entry_handle=0xFF, entry_count=1, entries=[route_entries[1]]),
            ),
        ],
    }
    behavior = BusOwnerBehavior(
        targets=[DiscoveryTarget(name="bridge", eid=0x0F, physical_address=0x10, is_bridge=True)],
        start_delay_s=0,
        prepare_for_discovery=False,
    )
    session, _, ctx = _behavior_with_fake_am(behavior, _queue_responder(script))

    report = behavior.rediscover()

    route_requests = [
        pkt for pkt, _, _, _ in session.sent if pkt.cmd_code == ContrlCmdCodes.GetRoutingTableEntries
    ]
    assert [pkt.entry_handle for pkt in route_requests] == [0, 1]
    assert [step.name for step in report.steps].count("get-routing-table-entries") == 2
    assert [entry.starting_eid for entry in ctx.routing_table] == [0x20, 0x21]


def test_targets_accept_dicts() -> None:
    behavior = BusOwnerBehavior(
        targets=[{"name": "bmc", "eid": 0x0F, "physical_address": 0x10}],
        start_delay_s=0,
        prepare_for_discovery=False,
        verify_routing_table=False,
    )
    _behavior_with_fake_am(
        behavior,
        _queue_responder(
            {
                ContrlCmdCodes.GetEndpointID: [
                    _response(ContrlCmdCodes.GetEndpointID, GetEndpointIDResponsePacket(eid=0x0F))
                ],
            }
        ),
    )

    assert behavior.rediscover().ok is True


def test_rediscover_runs_synchronously_when_worker_was_never_started() -> None:
    calls_by_cmd: dict[ContrlCmdCodes, int] = defaultdict(int)

    def responder(pkt: Packet) -> Packet | None:
        calls_by_cmd[ContrlCmdCodes(pkt.cmd_code)] += 1
        if pkt.cmd_code == ContrlCmdCodes.GetEndpointID:
            return _response(ContrlCmdCodes.GetEndpointID, GetEndpointIDResponsePacket(eid=0x0F))
        return None

    ctx = EndpointContext(physical_address=Smbus7bitAddress(0x20), assigned_eid=0x08)
    session = FakeSession(responder)
    am = create_endpoint(
        (
            "bus-owner",
            {
                "targets": [{"name": "bmc", "eid": 0x0F, "physical_address": 0x10}],
                "start_delay_s": 0,
                "prepare_for_discovery": False,
                "verify_routing_table": False,
            },
        ),
        context=ctx,
        session=session,
    )
    behavior = am.get_behavior("bus-owner")

    assert isinstance(behavior, BusOwnerBehavior)
    report = behavior.rediscover()

    assert report.ok is True
    assert calls_by_cmd[ContrlCmdCodes.GetEndpointID] == 1
