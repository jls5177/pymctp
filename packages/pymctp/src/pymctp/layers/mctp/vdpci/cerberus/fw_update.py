# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import hashlib
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from scapy.fields import ByteEnumField, XByteField, XLEIntField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType, EndpointContext
from ..vdpci import DropResponse, VdPciHdr, VdPciHdrPacket
from ..types import VdPCIVendorIds
from .error import ErrorResponsePacket
from .types import CerberusCmdCodes, CerberusErrorCodes, CerberusUpdateType


FW_UPDATE_CONTEXT_KEY = "cerberus_fw_update"


class FwUpdatePhase(str, Enum):
    IDLE = "idle"
    RECEIVING = "receiving"
    COMPLETED = "completed"


class FwUpdateIssue(str, Enum):
    DATA_BEFORE_INIT = "data_before_init"
    REINIT = "reinit"
    DUPLICATE_INIT = "duplicate_init"
    DUPLICATE_DATA = "duplicate_data"
    GAP = "gap"
    OVERLAP = "overlap"
    REORDER = "reorder"
    CORRUPTION = "corruption"
    TRUNCATION = "truncation"
    EARLY_COMPLETION = "early_completion"
    DUPLICATE_COMPLETION = "duplicate_completion"
    POST_COMPLETION_DATA = "post_completion_data"
    DECLARED_SIZE_MISMATCH = "declared_size_mismatch"
    EMPTY_DATA = "empty_data"
    INJECTED_FAULT = "injected_fault"


@dataclass(frozen=True)
class FwUpdateVerification:
    accepted: bool
    issue: FwUpdateIssue | None = None
    detail: str = ""
    source_offset: int | None = None


class ExpectedByteProvider(Protocol):
    def __call__(self, offset: int, length: int) -> bytes: ...


VerifierHook = Callable[[int, bytes], FwUpdateVerification | bool | None]


@dataclass
class FwUpdateFaultControls:
    """Deterministic per-event response drops and injected protocol errors.

    Event occurrence numbers are one-based. Drops occur after normal state
    processing so a retry exercises duplicate/retry handling. Event names are
    ``init``, ``data``, ``complete``, ``status``, and ``ext_status``.
    """

    drop_responses: Mapping[str, set[int]] = field(default_factory=dict)
    faults: Mapping[str, Mapping[int, CerberusErrorCodes]] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    def next(self, event: str) -> tuple[bool, CerberusErrorCodes | None]:
        occurrence = self._counts.get(event, 0) + 1
        self._counts[event] = occurrence
        fault = self.faults.get(event, {}).get(occurrence)
        drop = occurrence in self.drop_responses.get(event, set())
        return drop, fault

    def reset(self) -> None:
        self._counts.clear()


@dataclass(frozen=True)
class FwUpdateSnapshot:
    phase: FwUpdatePhase
    declared_size: int | None
    cursor: int
    remaining_bytes: int
    stream_sha256: str
    completion_attempts: int
    successful_completions: int
    duplicate_count: int
    issue_count: int
    issues: tuple[FwUpdateIssue, ...]
    prefix: bytes
    suffix: bytes
    last_error: CerberusErrorCodes | None


@dataclass
class CerberusFwUpdateEmulator:
    expected_bytes: ExpectedByteProvider | None = None
    verifier: VerifierHook | None = None
    faults: FwUpdateFaultControls = field(default_factory=FwUpdateFaultControls)
    snapshot_bytes: int = 64
    issue_history: int = 32
    phase: FwUpdatePhase = field(default=FwUpdatePhase.IDLE, init=False)
    declared_size: int | None = field(default=None, init=False)
    cursor: int = field(default=0, init=False)
    completion_attempts: int = field(default=0, init=False)
    successful_completions: int = field(default=0, init=False)
    duplicate_count: int = field(default=0, init=False)
    issue_count: int = field(default=0, init=False)
    last_error: CerberusErrorCodes | None = field(default=None, init=False)
    _issues: deque[FwUpdateIssue] = field(init=False, repr=False)
    _hash: Any = field(init=False, repr=False)
    _prefix: bytearray = field(init=False, repr=False)
    _suffix: bytearray = field(init=False, repr=False)
    _last_chunk_sha256: bytes = field(default=b"", init=False, repr=False)
    _last_chunk_length: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.snapshot_bytes < 0 or self.issue_history < 1:
            msg = "snapshot_bytes must be non-negative and issue_history must be positive"
            raise ValueError(msg)
        self._issues = deque(maxlen=self.issue_history)
        self._hash = hashlib.sha256()
        self._prefix = bytearray()
        self._suffix = bytearray()

    def install(self, ctx: EndpointContext) -> "CerberusFwUpdateEmulator":
        ctx.msg_type_context[FW_UPDATE_CONTEXT_KEY] = self
        return self

    def reset(self, *, reset_faults: bool = False) -> None:
        self.phase = FwUpdatePhase.IDLE
        self.declared_size = None
        self.cursor = 0
        self.completion_attempts = 0
        self.successful_completions = 0
        self.duplicate_count = 0
        self.issue_count = 0
        self.last_error = None
        self._issues.clear()
        self._hash = hashlib.sha256()
        self._prefix.clear()
        self._suffix.clear()
        self._last_chunk_sha256 = b""
        self._last_chunk_length = 0
        if reset_faults:
            self.faults.reset()

    @property
    def remaining_bytes(self) -> int:
        if self.declared_size is None:
            return 0
        return max(self.declared_size - self.cursor, 0)

    @property
    def stream_sha256(self) -> str:
        return self._hash.copy().hexdigest()

    def snapshot(self) -> FwUpdateSnapshot:
        return FwUpdateSnapshot(
            phase=self.phase,
            declared_size=self.declared_size,
            cursor=self.cursor,
            remaining_bytes=self.remaining_bytes,
            stream_sha256=self.stream_sha256,
            completion_attempts=self.completion_attempts,
            successful_completions=self.successful_completions,
            duplicate_count=self.duplicate_count,
            issue_count=self.issue_count,
            issues=tuple(self._issues),
            prefix=bytes(self._prefix),
            suffix=bytes(self._suffix),
            last_error=self.last_error,
        )

    def _record(self, issue: FwUpdateIssue, code: CerberusErrorCodes) -> ErrorResponsePacket:
        self.issue_count += 1
        self._issues.append(issue)
        self.last_error = code
        return ErrorResponsePacket(code=code, data=0)

    def _event(self, event: str) -> bool:
        drop, fault = self.faults.next(event)
        if fault is not None:
            self._record(FwUpdateIssue.INJECTED_FAULT, fault)
            raise _InjectedFault(fault, drop)
        return drop

    def _finish(self, response: Packet | bytes, drop: bool) -> Packet | bytes:
        if drop:
            raise DropResponse
        return response

    def init(self, size: int) -> Packet | bytes:
        drop = self._event("init")
        if self.phase == FwUpdatePhase.RECEIVING:
            if self.declared_size == size and self.cursor == 0:
                self.duplicate_count += 1
                self.issue_count += 1
                self._issues.append(FwUpdateIssue.DUPLICATE_INIT)
                return self._finish(b"", drop)
            return self._finish(self._record(FwUpdateIssue.REINIT, CerberusErrorCodes.BUSY), drop)
        if self.phase == FwUpdatePhase.COMPLETED:
            return self._finish(self._record(FwUpdateIssue.REINIT, CerberusErrorCodes.BUSY), drop)
        if size <= 0:
            return self._finish(
                self._record(FwUpdateIssue.DECLARED_SIZE_MISMATCH, CerberusErrorCodes.INVALID_PACKET_LEN), drop
            )
        self.reset()
        self.declared_size = size
        self.phase = FwUpdatePhase.RECEIVING
        return self._finish(b"", drop)

    def _locate(self, data: bytes) -> int | None:
        locate = getattr(self.expected_bytes, "locate", None)
        return locate(data, self.cursor) if callable(locate) else None

    def _verify(self, data: bytes) -> FwUpdateVerification:
        if self.verifier:
            result = self.verifier(self.cursor, data)
            if isinstance(result, FwUpdateVerification):
                return result
            if result is False:
                return FwUpdateVerification(False, FwUpdateIssue.CORRUPTION)
        if self.expected_bytes:
            expected = self.expected_bytes(self.cursor, len(data))
            if data != expected:
                source_offset = self._locate(data)
                if source_offset is None:
                    issue = FwUpdateIssue.CORRUPTION
                elif source_offset > self.cursor:
                    issue = FwUpdateIssue.GAP
                elif source_offset + len(data) > self.cursor:
                    issue = FwUpdateIssue.OVERLAP
                else:
                    issue = FwUpdateIssue.REORDER
                return FwUpdateVerification(False, issue, source_offset=source_offset)
        return FwUpdateVerification(True)

    def _is_last_chunk(self, data: bytes) -> bool:
        return len(data) == self._last_chunk_length and hashlib.sha256(data).digest() == self._last_chunk_sha256

    def _accept_duplicate_data(self, drop: bool) -> Packet | bytes:
        self.duplicate_count += 1
        self.issue_count += 1
        self._issues.append(FwUpdateIssue.DUPLICATE_DATA)
        return self._finish(b"", drop)

    def data(self, data: bytes) -> Packet | bytes:
        drop = self._event("data")
        if self.phase == FwUpdatePhase.IDLE:
            return self._finish(self._record(FwUpdateIssue.DATA_BEFORE_INIT, CerberusErrorCodes.OUT_OF_ORDER_MSG), drop)
        if self.phase == FwUpdatePhase.COMPLETED:
            return self._finish(
                self._record(FwUpdateIssue.POST_COMPLETION_DATA, CerberusErrorCodes.OUT_OF_ORDER_MSG), drop
            )
        if not data:
            return self._finish(self._record(FwUpdateIssue.EMPTY_DATA, CerberusErrorCodes.INVALID_PACKET_LEN), drop)
        if self.declared_size is None or self.cursor + len(data) > self.declared_size:
            if self._is_last_chunk(data):
                return self._accept_duplicate_data(drop)
            return self._finish(
                self._record(FwUpdateIssue.DECLARED_SIZE_MISMATCH, CerberusErrorCodes.MSG_OVERFLOW), drop
            )
        verification = self._verify(data)
        if not verification.accepted:
            if self._is_last_chunk(data):
                return self._accept_duplicate_data(drop)
            issue = verification.issue or FwUpdateIssue.CORRUPTION
            code = CerberusErrorCodes.INVALID_CHECKSUM
            if issue in {FwUpdateIssue.GAP, FwUpdateIssue.OVERLAP, FwUpdateIssue.REORDER}:
                code = CerberusErrorCodes.OUT_OF_ORDER_MSG
            return self._finish(self._record(issue, code), drop)
        self._hash.update(data)
        if len(self._prefix) < self.snapshot_bytes:
            self._prefix.extend(data[: self.snapshot_bytes - len(self._prefix)])
        if self.snapshot_bytes:
            self._suffix = bytearray((bytes(self._suffix) + data)[-self.snapshot_bytes :])
        self.cursor += len(data)
        self._last_chunk_sha256 = hashlib.sha256(data).digest()
        self._last_chunk_length = len(data)
        self.last_error = None
        return self._finish(b"", drop)

    def complete(self) -> Packet | bytes:
        drop = self._event("complete")
        self.completion_attempts += 1
        if self.phase == FwUpdatePhase.COMPLETED:
            self.duplicate_count += 1
            self.issue_count += 1
            self._issues.append(FwUpdateIssue.DUPLICATE_COMPLETION)
            return self._finish(b"", drop)
        if self.phase == FwUpdatePhase.IDLE:
            return self._finish(self._record(FwUpdateIssue.EARLY_COMPLETION, CerberusErrorCodes.OUT_OF_ORDER_MSG), drop)
        if self.cursor != self.declared_size:
            issue = (
                FwUpdateIssue.TRUNCATION
                if self.cursor < (self.declared_size or 0)
                else FwUpdateIssue.DECLARED_SIZE_MISMATCH
            )
            return self._finish(self._record(issue, CerberusErrorCodes.INVALID_PACKET_LEN), drop)
        self.phase = FwUpdatePhase.COMPLETED
        self.successful_completions = 1
        self.last_error = None
        return self._finish(b"", drop)

    def status(self, *, extended: bool) -> Packet:
        drop = self._event("ext_status" if extended else "status")
        status = int(self.last_error or CerberusErrorCodes.NO_ERROR)
        response: Packet
        if extended:
            response = ExtUpdateStatusResponsePacket(status=status, remaining_bytes=self.remaining_bytes)
        else:
            response = UpdateStatusResponsePacket(status=status)
        return self._finish(response, drop)


class _InjectedFault(Exception):
    def __init__(self, code: CerberusErrorCodes, drop: bool):
        self.code = code
        self.drop = drop


def _get_emulator(ctx: EndpointContext) -> CerberusFwUpdateEmulator | None:
    emulator = ctx.msg_type_context.get(FW_UPDATE_CONTEXT_KEY)
    return emulator if isinstance(emulator, CerberusFwUpdateEmulator) else None


def _emulator_reply(
    ctx: EndpointContext, operation: Callable[[CerberusFwUpdateEmulator], Packet | bytes]
) -> Packet | bytes:
    emulator = _get_emulator(ctx)
    if emulator is None:
        return b""
    try:
        response = operation(emulator)
    except _InjectedFault as fault:
        if fault.drop:
            raise DropResponse from fault
        response = ErrorResponsePacket(code=fault.code, data=0)
    if isinstance(response, ErrorResponsePacket):
        return VdPciHdr(rq=False, vendor_id=VdPCIVendorIds.Msft, vdm_cmd_code=CerberusCmdCodes.ERROR) / response
    return response


# --- INIT_FW_UPDATE ---


class InitFwUpdateRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-InitFwUpdate-Req"
    fields_desc = [XLEIntField("size", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (size={self.size})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True

    def make_reply(self, ctx: EndpointContext) -> Packet | bytes:
        return _emulator_reply(ctx, lambda emulator: emulator.init(self.size))


bind_layers(
    VdPciHdrPacket,
    InitFwUpdateRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.INIT_FW_UPDATE,
)


# --- FW_UPDATE ---


class FwUpdateRequestPacket(AllowRawSummary, Packet):
    """Request to send FW update data. Payload follows as raw data."""

    name = "Cerberus-FwUpdate-Req"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        data_len = len(bytes(self.payload)) if self.payload else 0
        summary = f"{self.name} (len={data_len})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True

    def make_reply(self, ctx: EndpointContext) -> Packet | bytes:
        data = bytes(self.payload) if self.payload else b""
        return _emulator_reply(ctx, lambda emulator: emulator.data(data))


bind_layers(
    VdPciHdrPacket,
    FwUpdateRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.FW_UPDATE,
)


# --- COMPLETE_FW_UPDATE ---


class CompleteFwUpdateRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-CompleteFwUpdate-Req"
    fields_desc = []

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        return self.name, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True

    def make_reply(self, ctx: EndpointContext) -> Packet | bytes:
        return _emulator_reply(ctx, CerberusFwUpdateEmulator.complete)


bind_layers(
    VdPciHdrPacket,
    CompleteFwUpdateRequestPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.COMPLETE_FW_UPDATE,
)


# --- GET_UPDATE_STATUS ---


class GetUpdateStatusRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetUpdateStatus-Req"
    fields_desc = [
        ByteEnumField("update_type", 0, CerberusUpdateType),
        XByteField("port_id", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        try:
            type_name = CerberusUpdateType(self.update_type).name
        except ValueError:
            type_name = f"0x{self.update_type:02X}"
        summary = f"{self.name} (type={type_name}, port={self.port_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True

    def make_reply(self, ctx: EndpointContext) -> Packet | bytes:
        return _emulator_reply(ctx, lambda emulator: emulator.status(extended=False))


class UpdateStatusResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-UpdateStatus"
    fields_desc = [XLEIntField("status", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (status=0x{self.status:08X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class UpdateStatusCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 2:
            return GetUpdateStatusRequestPacket
        return UpdateStatusResponsePacket


bind_layers(
    VdPciHdrPacket,
    UpdateStatusCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_UPDATE_STATUS,
)


# --- GET_EXT_UPDATE_STATUS ---


class GetExtUpdateStatusRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-GetExtUpdateStatus-Req"
    fields_desc = [
        ByteEnumField("update_type", 0, CerberusUpdateType),
        XByteField("port_id", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        try:
            type_name = CerberusUpdateType(self.update_type).name
        except ValueError:
            type_name = f"0x{self.update_type:02X}"
        summary = f"{self.name} (type={type_name}, port={self.port_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True

    def make_reply(self, ctx: EndpointContext) -> Packet | bytes:
        return _emulator_reply(ctx, lambda emulator: emulator.status(extended=True))


class ExtUpdateStatusResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-ExtUpdateStatus"
    fields_desc = [
        XLEIntField("status", 0),
        XLEIntField("remaining_bytes", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (status=0x{self.status:08X}, remaining={self.remaining_bytes})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ExtUpdateStatusCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 2:
            return GetExtUpdateStatusRequestPacket
        return ExtUpdateStatusResponsePacket


bind_layers(
    VdPciHdrPacket,
    ExtUpdateStatusCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.GET_EXT_UPDATE_STATUS,
)
