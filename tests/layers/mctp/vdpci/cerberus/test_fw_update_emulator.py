# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import hashlib

from pymctp.layers.mctp import EndpointContext, MsgTypes, Smbus7bitAddress
from pymctp.layers.mctp.vdpci import VdPciHdr, VdPCIVendorIds
from pymctp.layers.mctp.vdpci.cerberus import (
    CerberusCmdCodes,
    CerberusErrorCodes,
    CerberusFwUpdateEmulator,
    CompleteFwUpdateRequestPacket,
    ErrorResponsePacket,
    ExtUpdateStatusResponsePacket,
    FwUpdateFaultControls,
    FwUpdateIssue,
    FwUpdatePhase,
    FwUpdateRequestPacket,
    GetExtUpdateStatusRequestPacket,
    GetUpdateStatusRequestPacket,
    InitFwUpdateRequestPacket,
)


class ExpectedImage:
    def __init__(self, data: bytes):
        self.data = data

    def __call__(self, offset: int, length: int) -> bytes:
        return self.data[offset : offset + length]

    def locate(self, data: bytes, cursor: int) -> int | None:
        offset = self.data.find(data)
        return offset if offset >= 0 else None


def _context(emulator: CerberusFwUpdateEmulator) -> EndpointContext:
    ctx = EndpointContext(
        physical_address=Smbus7bitAddress(0x20),
        supported_msg_types=[MsgTypes.CTRL, MsgTypes.VDPCI],
    )
    emulator.install(ctx)
    return ctx


def _reply(ctx: EndpointContext, command: CerberusCmdCodes, payload):
    req = VdPciHdr(rq=True, vendor_id=VdPCIVendorIds.Msft, vdm_cmd_code=command) / payload
    return req.make_reply(ctx)


def test_happy_path_tracks_bounded_evidence_hash_and_status():
    image = bytes(range(64))
    emulator = CerberusFwUpdateEmulator(expected_bytes=ExpectedImage(image), snapshot_bytes=8)
    ctx = _context(emulator)

    _reply(ctx, CerberusCmdCodes.INIT_FW_UPDATE, InitFwUpdateRequestPacket(size=len(image)))
    for offset in range(0, len(image), 16):
        _reply(ctx, CerberusCmdCodes.FW_UPDATE, FwUpdateRequestPacket() / image[offset : offset + 16])

    status = _reply(
        ctx,
        CerberusCmdCodes.GET_EXT_UPDATE_STATUS,
        GetExtUpdateStatusRequestPacket(update_type=0, port_id=0),
    )
    assert status.haslayer(ExtUpdateStatusResponsePacket)
    assert status.getlayer(ExtUpdateStatusResponsePacket).remaining_bytes == 0

    _reply(ctx, CerberusCmdCodes.COMPLETE_FW_UPDATE, CompleteFwUpdateRequestPacket())
    snapshot = emulator.snapshot()
    assert snapshot.phase == FwUpdatePhase.COMPLETED
    assert snapshot.cursor == len(image)
    assert snapshot.stream_sha256 == hashlib.sha256(image).hexdigest()
    assert snapshot.successful_completions == 1
    assert snapshot.prefix == image[:8]
    assert snapshot.suffix == image[-8:]


def test_dropped_data_response_retry_is_not_accumulated_twice():
    image = b"abcdefgh"
    faults = FwUpdateFaultControls(drop_responses={"data": {1}})
    emulator = CerberusFwUpdateEmulator(expected_bytes=ExpectedImage(image), faults=faults)
    ctx = _context(emulator)
    _reply(ctx, CerberusCmdCodes.INIT_FW_UPDATE, InitFwUpdateRequestPacket(size=len(image)))

    request = (
        VdPciHdr(rq=True, vendor_id=VdPCIVendorIds.Msft, vdm_cmd_code=CerberusCmdCodes.FW_UPDATE)
        / FwUpdateRequestPacket()
        / image
    )
    assert request.make_reply(ctx) is None
    request.make_reply(ctx)

    snapshot = emulator.snapshot()
    assert snapshot.cursor == len(image)
    assert snapshot.duplicate_count == 1
    assert FwUpdateIssue.DUPLICATE_DATA in snapshot.issues


def test_dropped_init_and_completion_responses_are_idempotent():
    image = b"firmware"
    faults = FwUpdateFaultControls(drop_responses={"init": {1}, "complete": {1}})
    emulator = CerberusFwUpdateEmulator(expected_bytes=ExpectedImage(image), faults=faults)
    ctx = _context(emulator)

    init = VdPciHdr(
        rq=True, vendor_id=VdPCIVendorIds.Msft, vdm_cmd_code=CerberusCmdCodes.INIT_FW_UPDATE
    ) / InitFwUpdateRequestPacket(size=len(image))
    assert init.make_reply(ctx) is None
    init.make_reply(ctx)
    assert FwUpdateIssue.DUPLICATE_INIT in emulator.snapshot().issues

    _reply(ctx, CerberusCmdCodes.FW_UPDATE, FwUpdateRequestPacket() / image)
    complete = (
        VdPciHdr(rq=True, vendor_id=VdPCIVendorIds.Msft, vdm_cmd_code=CerberusCmdCodes.COMPLETE_FW_UPDATE)
        / CompleteFwUpdateRequestPacket()
    )
    assert complete.make_reply(ctx) is None
    complete.make_reply(ctx)
    snapshot = emulator.snapshot()
    assert snapshot.successful_completions == 1
    assert snapshot.completion_attempts == 2
    assert FwUpdateIssue.DUPLICATE_COMPLETION in snapshot.issues


def test_fault_matrix_records_invalid_sequences_and_requires_reset():
    emulator = CerberusFwUpdateEmulator()
    ctx = _context(emulator)

    response = _reply(ctx, CerberusCmdCodes.FW_UPDATE, FwUpdateRequestPacket() / b"bad")
    assert response.haslayer(ErrorResponsePacket)
    assert response.getlayer(ErrorResponsePacket).code == CerberusErrorCodes.OUT_OF_ORDER_MSG
    assert emulator.snapshot().phase == FwUpdatePhase.IDLE

    emulator.reset()
    _reply(ctx, CerberusCmdCodes.INIT_FW_UPDATE, InitFwUpdateRequestPacket(size=4))
    response = _reply(ctx, CerberusCmdCodes.COMPLETE_FW_UPDATE, CompleteFwUpdateRequestPacket())
    assert response.getlayer(ErrorResponsePacket).code == CerberusErrorCodes.INVALID_PACKET_LEN
    assert FwUpdateIssue.TRUNCATION in emulator.snapshot().issues

    emulator.reset()
    response = _reply(ctx, CerberusCmdCodes.COMPLETE_FW_UPDATE, CompleteFwUpdateRequestPacket())
    assert response.getlayer(ErrorResponsePacket).code == CerberusErrorCodes.OUT_OF_ORDER_MSG
    assert FwUpdateIssue.EARLY_COMPLETION in emulator.snapshot().issues


def test_expected_provider_classifies_gap_overlap_reorder_and_corruption():
    image = b"AAAABBBBCCCCDDDD"
    cases = [
        (b"AAAA", b"CCCC", FwUpdateIssue.GAP),
        (b"AAAA", b"AABB", FwUpdateIssue.OVERLAP),
        (b"AAAABBBB", b"AAAA", FwUpdateIssue.REORDER),
        (b"AAAA", b"XXXX", FwUpdateIssue.CORRUPTION),
    ]
    for initial, data, issue in cases:
        emulator = CerberusFwUpdateEmulator(expected_bytes=ExpectedImage(image))
        emulator.init(len(image))
        emulator.data(initial)
        emulator.data(data)
        assert issue in emulator.snapshot().issues


def test_rejected_data_can_be_retried_without_losing_the_session():
    image = b"AAAABBBB"
    emulator = CerberusFwUpdateEmulator(expected_bytes=ExpectedImage(image))
    emulator.init(len(image))
    emulator.data(b"XXXX")
    emulator.data(image)
    emulator.complete()

    snapshot = emulator.snapshot()
    assert snapshot.phase == FwUpdatePhase.COMPLETED
    assert snapshot.cursor == len(image)
    assert snapshot.stream_sha256 == hashlib.sha256(image).hexdigest()


def test_duplicate_completion_post_completion_data_reinit_and_overflow():
    image = b"1234"
    emulator = CerberusFwUpdateEmulator(expected_bytes=ExpectedImage(image))
    emulator.init(4)
    emulator.data(image)
    emulator.complete()
    response = emulator.complete()
    assert response == b""
    assert FwUpdateIssue.DUPLICATE_COMPLETION in emulator.snapshot().issues
    assert emulator.snapshot().successful_completions == 1

    emulator.reset()
    emulator.init(4)
    emulator.data(image)
    emulator.complete()
    response = emulator.data(b"x")
    assert isinstance(response, ErrorResponsePacket)
    assert FwUpdateIssue.POST_COMPLETION_DATA in emulator.snapshot().issues

    emulator.reset()
    emulator.init(4)
    response = emulator.init(5)
    assert isinstance(response, ErrorResponsePacket)
    assert FwUpdateIssue.REINIT in emulator.snapshot().issues

    emulator.reset()
    emulator.init(3)
    response = emulator.data(image)
    assert isinstance(response, ErrorResponsePacket)
    assert FwUpdateIssue.DECLARED_SIZE_MISMATCH in emulator.snapshot().issues


def test_injected_fault_and_drop_are_deterministic():
    faults = FwUpdateFaultControls(
        drop_responses={"status": {1}},
        faults={"data": {1: CerberusErrorCodes.BUSY}},
    )
    emulator = CerberusFwUpdateEmulator(faults=faults)
    ctx = _context(emulator)
    _reply(ctx, CerberusCmdCodes.INIT_FW_UPDATE, InitFwUpdateRequestPacket(size=4))

    response = _reply(ctx, CerberusCmdCodes.FW_UPDATE, FwUpdateRequestPacket() / b"1234")
    assert response.getlayer(ErrorResponsePacket).code == CerberusErrorCodes.BUSY
    assert emulator.snapshot().cursor == 0
    _reply(ctx, CerberusCmdCodes.FW_UPDATE, FwUpdateRequestPacket() / b"1234")
    assert emulator.snapshot().cursor == 4

    status_request = VdPciHdr(
        rq=True, vendor_id=VdPCIVendorIds.Msft, vdm_cmd_code=CerberusCmdCodes.GET_UPDATE_STATUS
    ) / GetUpdateStatusRequestPacket(update_type=0, port_id=0)
    assert status_request.make_reply(ctx) is None
