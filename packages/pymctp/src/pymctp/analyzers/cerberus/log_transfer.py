# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Validate Cerberus log transfer completeness.

This rule observes the ``GET_LOG_INFO`` / ``READ_LOG`` command sequence
defined in the OCP Cerberus Challenge Protocol and validates that the
entire log is properly transferred for each log type.

Checks performed:

1. **ReadLog without LogInfo** — A ``READ_LOG`` request is seen before any
   ``GET_LOG_INFO`` response established the expected log sizes.
2. **Non-zero starting offset** — The very first ``READ_LOG`` request
   across all log types does not start at offset 0.
3. **Offset gap** — Within a single log type, the offset in a ``READ_LOG``
   request does not match the expected next offset (previous offset +
   previous response length).
4. **Offset overlap** — Within a single log type, the offset in a
   ``READ_LOG`` request is less than the expected next offset, meaning
   data would be re-read.
5. **Incomplete transfer** — At ``finalize()`` time, fewer bytes were
   transferred than the length reported by ``GET_LOG_INFO``.
6. **Over-read** — More bytes were transferred than the expected length.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.mctp import TransportHdrPacket
from pymctp.layers.mctp.vdpci.cerberus.log import (
    LogInfoResponsePacket,
    ReadLogRequestPacket,
    ReadLogResponsePacket,
)
from pymctp.layers.mctp.vdpci.cerberus.types import CerberusLogType


def _log_type_name(log_type: int) -> str:
    """Return a human-readable name for a Cerberus log type value."""
    try:
        return CerberusLogType(log_type).name
    except ValueError:
        return f"0x{log_type:02X}"


@dataclass
class _LogTypeState:
    """Track per-log-type offset continuity and byte accounting."""

    expected_length: int = 0
    next_offset: int = 0
    bytes_transferred: int = 0
    started: bool = False
    # location of the first READ_LOG request for this log type
    first_request_index: int | None = None
    first_request_ts: datetime | None = None
    first_request_summary: str = ""


@dataclass
class _FragmentState:
    """Track an in-progress fragmented READ_LOG response."""

    # MCTP message-flow key (tag, src, dst) to match continuation fragments
    key: tuple[int, int, int]
    log_type: int
    offset: int
    req_idx: int
    req_ts: datetime | None
    req_summary: str
    data_len: int  # accumulated payload bytes so far


class CerberusLogTransferRule(AnalysisRule):
    """Validate that Cerberus READ_LOG sequences transfer the complete log.

    The rule tracks:

    * ``GET_LOG_INFO`` responses to learn the expected byte count per log type.
    * ``READ_LOG`` request/response pairs to verify contiguous offsets and
      complete coverage.

    Cerberus uses a global offset space across all log types, but the
    host may interlace reads of different types.  Therefore, offset
    continuity (gap / overlap) is validated **per log type** while the
    "non-zero start" check applies only to the very first ``READ_LOG``
    across all types.
    """

    rule_id = "CERBERUS-LOG-001"  # type: ignore[assignment]
    description = "Validate Cerberus log transfer completeness"  # type: ignore[assignment]

    def __init__(self) -> None:
        self._log_info_seen: bool = False
        # expected total length per log type from GET_LOG_INFO
        self._expected: dict[int, int] = {}
        # per-log-type state (offset tracking + byte accounting)
        self._type_state: dict[int, _LogTypeState] = {}
        # Whether any READ_LOG has been seen (for non-zero start check)
        self._any_read_seen: bool = False
        # Track the last READ_LOG request so we can match its response
        # (log_type, offset, pkt_index, timestamp, summary)
        self._pending_read: tuple[int, int, int, datetime | None, str] | None = None
        # In-progress fragmented READ_LOG response
        self._frag: _FragmentState | None = None

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _get_state(self, log_type: int) -> _LogTypeState:
        if log_type not in self._type_state:
            self._type_state[log_type] = _LogTypeState(
                expected_length=self._expected.get(log_type, 0),
            )
        return self._type_state[log_type]

    def _complete_response(
        self,
        log_type: int,
        offset: int,
        req_idx: int,
        req_ts: datetime | None,
        req_summary: str,
        data_len: int,
    ) -> list[Finding]:
        """Process a fully-reassembled READ_LOG response."""
        findings: list[Finding] = []
        state = self._get_state(log_type)

        # Only count bytes beyond the current tracking point so that
        # retransmissions (offset overlap) don't inflate bytes_transferred.
        new_end = offset + data_len
        if new_end > state.next_offset:
            state.bytes_transferred += new_end - state.next_offset
            state.next_offset = new_end

        # Check for over-read
        if state.expected_length > 0 and state.bytes_transferred > state.expected_length:
            name = _log_type_name(log_type)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.INFO,
                    message=(
                        f"READ_LOG ({name}) over-read: transferred "
                        f"{state.bytes_transferred} bytes but expected "
                        f"{state.expected_length}"
                    ),
                    packet_index=req_idx,
                    timestamp=req_ts,
                    packet_summary=req_summary,
                )
            )
        return findings

    # ------------------------------------------------------------------
    # feed
    # ------------------------------------------------------------------

    def feed(
        self,
        index: int,
        timestamp: datetime | None,
        packet,
    ) -> Sequence[Finding]:
        findings: list[Finding] = []

        # --- GET_LOG_INFO response ---
        if packet.haslayer(LogInfoResponsePacket):
            resp = packet.getlayer(LogInfoResponsePacket)
            self._log_info_seen = True
            self._expected[CerberusLogType.DEBUG] = resp.debug_log_length
            self._expected[CerberusLogType.ATTESTATION] = resp.attestation_log_length
            self._expected[CerberusLogType.TAMPER] = resp.tamper_log_length
            # Reset transfer tracking when new log info arrives
            self._type_state.clear()
            self._any_read_seen = False
            return findings

        # --- READ_LOG request ---
        if packet.haslayer(ReadLogRequestPacket):
            req = packet.getlayer(ReadLogRequestPacket)
            log_type = req.log_type
            offset = req.offset
            name = _log_type_name(log_type)

            # Warn if no LogInfo has been seen yet
            if not self._log_info_seen:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.WARNING,
                        message=f"READ_LOG ({name}) without prior GET_LOG_INFO",
                        packet_index=index,
                        timestamp=timestamp,
                        packet_summary=packet.summary(),
                    )
                )

            state = self._get_state(log_type)

            # Record first request location for this log type (for finalize)
            if state.first_request_index is None:
                state.first_request_index = index
                state.first_request_ts = timestamp
                state.first_request_summary = packet.summary()

            if not self._any_read_seen:
                # Very first READ_LOG across all types
                self._any_read_seen = True
                if offset != 0:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.ERROR,
                            message=(f"READ_LOG ({name}) transfer starts at offset 0x{offset:X} instead of 0"),
                            packet_index=index,
                            timestamp=timestamp,
                            packet_summary=packet.summary(),
                        )
                    )

            if not state.started:
                # First request for this log type — accept offset as-is
                state.started = True
                state.next_offset = offset
            else:
                # Subsequent request for this type — validate per-type
                # offset continuity
                if offset > state.next_offset:
                    gap = offset - state.next_offset
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.ERROR,
                            message=(
                                f"READ_LOG ({name}) offset gap: expected "
                                f"0x{state.next_offset:X}, got 0x{offset:X} "
                                f"({gap} bytes missing)"
                            ),
                            packet_index=index,
                            timestamp=timestamp,
                            packet_summary=packet.summary(),
                        )
                    )
                    # Accept the new offset and continue tracking
                    state.next_offset = offset
                elif offset < state.next_offset:
                    overlap = state.next_offset - offset
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.WARNING,
                            message=(
                                f"READ_LOG ({name}) offset overlap: expected "
                                f"0x{state.next_offset:X}, got 0x{offset:X} "
                                f"({overlap} bytes re-read)"
                            ),
                            packet_index=index,
                            timestamp=timestamp,
                            packet_summary=packet.summary(),
                        )
                    )

            # Store pending request to match with the next response
            self._pending_read = (log_type, offset, index, timestamp, packet.summary())
            return findings

        # --- READ_LOG response (or continuation fragment) ---

        # Check for continuation/EOM fragments of a fragmented response
        if self._frag is not None and packet.haslayer(TransportHdrPacket):
            hdr = packet.getlayer(TransportHdrPacket)
            frag_key = (hdr.tag, hdr.src, hdr.dst)
            if frag_key == self._frag.key and not hdr.som:
                payload_len = len(bytes(hdr.payload)) if hdr.payload else 0
                self._frag.data_len += payload_len
                if hdr.eom:
                    # Fragmented response complete — process total
                    frag = self._frag
                    self._frag = None
                    findings.extend(
                        self._complete_response(
                            frag.log_type,
                            frag.offset,
                            frag.req_idx,
                            frag.req_ts,
                            frag.req_summary,
                            frag.data_len,
                        )
                    )
                return findings

        # SOM packet with ReadLogResponsePacket layer
        if packet.haslayer(ReadLogResponsePacket):
            if self._pending_read is not None:
                log_type, offset, req_idx, req_ts, req_summary = self._pending_read
                self._pending_read = None

                resp = packet.getlayer(ReadLogResponsePacket)
                data_len = len(bytes(resp.payload)) if resp.payload else 0

                # Check if the response is fragmented (SOM without EOM)
                if packet.haslayer(TransportHdrPacket):
                    hdr = packet.getlayer(TransportHdrPacket)
                    if hdr.som and not hdr.eom:
                        # Start fragment accumulation
                        self._frag = _FragmentState(
                            key=(hdr.tag, hdr.src, hdr.dst),
                            log_type=log_type,
                            offset=offset,
                            req_idx=req_idx,
                            req_ts=req_ts,
                            req_summary=req_summary,
                            data_len=data_len,
                        )
                        return findings

                # Unfragmented response (SOM+EOM) — process immediately
                findings.extend(
                    self._complete_response(
                        log_type,
                        offset,
                        req_idx,
                        req_ts,
                        req_summary,
                        data_len,
                    )
                )

            return findings

        return findings

    # ------------------------------------------------------------------
    # finalize
    # ------------------------------------------------------------------

    def finalize(self) -> Sequence[Finding]:
        findings: list[Finding] = []

        for log_type, state in self._type_state.items():
            if not state.started:
                continue

            name = _log_type_name(log_type)
            expected = state.expected_length

            if expected == 0:
                # No expected length known (no LogInfo or zero-length log)
                continue

            if state.bytes_transferred < expected:
                missing = expected - state.bytes_transferred
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.ERROR,
                        message=(
                            f"READ_LOG ({name}) incomplete: transferred "
                            f"{state.bytes_transferred}/{expected} bytes "
                            f"({missing} bytes missing)"
                        ),
                        packet_index=state.first_request_index,
                        timestamp=state.first_request_ts,
                        packet_summary=state.first_request_summary,
                    )
                )

        return findings

    def reset(self) -> None:
        self._log_info_seen = False
        self._expected.clear()
        self._type_state.clear()
        self._any_read_seen = False
        self._pending_read = None
        self._frag = None
