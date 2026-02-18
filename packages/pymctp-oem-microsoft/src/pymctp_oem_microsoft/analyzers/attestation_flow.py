# SPDX-FileCopyrightText: 2024 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Attestation flow milestone markers for triage reports.

These INFO-level rules annotate key events in the Microsoft attestation
protocol flow, making it easy to identify compstate reads, attestation
checks, forced attestations, and measurement requests in triage output.
"""

from __future__ import annotations

from datetime import datetime
from typing import Sequence

from pymctp.analyzers.base import AnalysisRule, Finding, Severity
from pymctp.layers.interfaces import AnyPacketType
from pymctp.layers.mctp import TransportHdrPacket
from pymctp.layers.mctp.spdm.get_measurements import GetMeasurementsPacket, MeasurementRequestAttributes
from pymctp.layers.mctp.spdm.spdm import SpdmHdrPacket
from pymctp.layers.mctp.vdpci.cerberus.log import (
    AttestationDataResponsePacket,
    GetAttestationDataRequestPacket,
    ReadLogRequestPacket,
    ReadLogResponsePacket,
    _decode_component_statuses_v1,
    _decode_component_statuses_v2,
)
from pymctp.layers.mctp.vdpci.cerberus.types import CerberusLogType

from pymctp_oem_microsoft.analyzers.tcg_log import decode_attestation_log, format_tcg_log_summary
from pymctp_oem_microsoft.layers.mctp.vdpci.cerberus.msft_cerberus import ForceAttestationRequestPacket
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.bmc import GetDeviceEidRequestPacket


class CompstateReadRule(AnalysisRule):
    """Marks compstate reads and decodes TCG attestation log entries from the response."""

    @property
    def rule_id(self) -> str:
        return "MSFT-ATTEST-001"

    @property
    def description(self) -> str:
        return "Marks compstate read start and decodes TCG attestation log"

    def __init__(self) -> None:
        self._pending_req: tuple[int, datetime | None, str] | None = None
        self._collecting = False
        self._resp_tag: int | None = None
        self._resp_src: int | None = None
        self._resp_dst: int | None = None
        self._log_data = bytearray()

    def feed(self, index: int, timestamp: datetime | None, packet: AnyPacketType) -> Sequence[Finding]:
        # Detect attestation log read request at offset 0
        if packet.haslayer(ReadLogRequestPacket):
            req = packet.getlayer(ReadLogRequestPacket)
            if req.log_type == CerberusLogType.ATTESTATION and req.offset == 0:
                self._pending_req = (index, timestamp, packet.summary())
                self._collecting = False
                self._log_data.clear()
                # Track the transport flow to match the response
                if packet.haslayer(TransportHdrPacket):
                    hdr = packet.getlayer(TransportHdrPacket)
                    self._resp_tag = hdr.tag
                    self._resp_src = hdr.dst
                    self._resp_dst = hdr.src
            return []

        # Collect response data
        if self._pending_req is None:
            return []

        if not packet.haslayer(TransportHdrPacket):
            return []

        hdr = packet.getlayer(TransportHdrPacket)

        # Match response flow (src/dst swapped from request)
        if self._resp_tag is not None:
            if hdr.tag != self._resp_tag:
                return []
            if self._resp_src is not None and hdr.src not in (self._resp_src, 0x00):
                return []
            if self._resp_dst is not None and hdr.dst not in (self._resp_dst, 0x00):
                return []

        if hdr.som:
            # First response fragment — get data from ReadLogResponsePacket payload
            if not packet.haslayer(ReadLogResponsePacket):
                return []
            self._collecting = True
            self._log_data.clear()
            resp = packet.getlayer(ReadLogResponsePacket)
            if resp.payload:
                self._log_data.extend(bytes(resp.payload))
        elif self._collecting:
            # Continuation fragment — raw payload data
            if hdr.payload:
                self._log_data.extend(bytes(hdr.payload))

        # Check if this is the last fragment
        if not hdr.eom or not self._collecting:
            return []

        # Complete — decode the TCG log
        req_idx, req_ts, req_summary = self._pending_req
        entries = decode_attestation_log(bytes(self._log_data))
        log_summary = format_tcg_log_summary(entries)

        finding = Finding(
            rule_id=self.rule_id,
            severity=Severity.INFO,
            message=f"Compstate read ({len(entries)} entries, {len(self._log_data)} bytes):\n{log_summary}",
            packet_index=req_idx,
            timestamp=req_ts,
            packet_summary=req_summary,
        )

        self._pending_req = None
        self._collecting = False
        self._log_data.clear()
        self._resp_tag = None
        self._resp_src = None
        self._resp_dst = None

        return [finding]

    def reset(self) -> None:
        self._pending_req = None
        self._collecting = False
        self._resp_tag = None
        self._resp_src = None
        self._resp_dst = None
        self._log_data.clear()


class AttestationCheckRule(AnalysisRule):
    """Marks the start of an attestation check via GetDeviceEid request."""

    @property
    def rule_id(self) -> str:
        return "MSFT-ATTEST-002"

    @property
    def description(self) -> str:
        return "Marks attestation check start (GetDeviceEid request)"

    def feed(self, index: int, timestamp: datetime | None, packet: AnyPacketType) -> Sequence[Finding]:
        if not packet.haslayer(GetDeviceEidRequestPacket):
            return []
        req = packet.getlayer(GetDeviceEidRequestPacket)
        return [
            Finding(
                rule_id=self.rule_id,
                severity=Severity.INFO,
                message=(
                    f"Attestation check started for device "
                    f"vid=0x{req.vendor_id:04X} did=0x{req.device_id:04X} inst={req.instance}"
                ),
                packet_index=index,
                timestamp=timestamp,
                packet_summary=packet.summary(),
            )
        ]

    def reset(self) -> None:
        pass


class ForceAttestRule(AnalysisRule):
    """Marks a user-forced attestation request."""

    @property
    def rule_id(self) -> str:
        return "MSFT-ATTEST-003"

    @property
    def description(self) -> str:
        return "Marks forced attestation request"

    def feed(self, index: int, timestamp: datetime | None, packet: AnyPacketType) -> Sequence[Finding]:
        if not packet.haslayer(ForceAttestationRequestPacket):
            return []
        req = packet.getlayer(ForceAttestationRequestPacket)
        return [
            Finding(
                rule_id=self.rule_id,
                severity=Severity.INFO,
                message=f"Forced attestation: mode={req.mode}, inst={req.instance_id}",
                packet_index=index,
                timestamp=timestamp,
                packet_summary=packet.summary(),
            )
        ]

    def reset(self) -> None:
        pass


class SpdmGetMeasurementsRule(AnalysisRule):
    """Marks SPDM GET_MEASUREMENTS requests (endpoint measurement retrieval)."""

    @property
    def rule_id(self) -> str:
        return "MSFT-ATTEST-004"

    @property
    def description(self) -> str:
        return "Marks SPDM GET_MEASUREMENTS request"

    def feed(self, index: int, timestamp: datetime | None, packet: AnyPacketType) -> Sequence[Finding]:
        if not packet.haslayer(GetMeasurementsPacket):
            return []
        # Read Attr and MeasOp from SPDM header (param1/param2)
        spdm_hdr = packet.getlayer(SpdmHdrPacket)
        if spdm_hdr is None:
            return []
        attr = spdm_hdr.getfieldval("param1")
        meas_op = spdm_hdr.getfieldval("param2")

        attr_parts = []
        if attr & MeasurementRequestAttributes.GENERATE_SIGNATURE:
            attr_parts.append("GenSig")
        if attr & MeasurementRequestAttributes.RAW_BIT_STREAM_REQUESTED:
            attr_parts.append("RawBitReq")
        attr_str = "|".join(attr_parts) if attr_parts else "0"

        if meas_op == 0:
            op_str = "TotalNum"
        elif meas_op == 0xFF:
            op_str = "All"
        else:
            op_str = f"Index({meas_op})"

        return [
            Finding(
                rule_id=self.rule_id,
                severity=Severity.INFO,
                message=f"GET_MEASUREMENTS (Attr={attr_str}, MeasOp={op_str})",
                packet_index=index,
                timestamp=timestamp,
                packet_summary=packet.summary(),
            )
        ]

    def reset(self) -> None:
        pass


class ComponentStatusRule(AnalysisRule):
    """Collects GET_ATTESTATION_DATA responses and decodes component attestation statuses.

    The utility reads component status via multiple GET_ATTESTATION_DATA requests
    at increasing offsets.  The first response carries a 5-byte header (event_data +
    status_version) followed by component status entries; subsequent responses are
    raw continuation data.  This rule reassembles across requests and emits an INFO
    finding once the full status payload has been collected.
    """

    @property
    def rule_id(self) -> str:
        return "MSFT-ATTEST-005"

    @property
    def description(self) -> str:
        return "Decodes component attestation status from GET_ATTESTATION_DATA responses"

    def __init__(self) -> None:
        self._first_idx: int | None = None
        self._first_ts: datetime | None = None
        self._first_summary: str | None = None
        self._version: int | None = None
        self._status_data = bytearray()
        # Track transport flow for response matching
        self._resp_tag: int | None = None
        self._resp_src: int | None = None
        self._resp_dst: int | None = None
        self._collecting = False
        self._frag_buf = bytearray()

    def feed(self, index: int, timestamp: datetime | None, packet: AnyPacketType) -> Sequence[Finding]:
        findings: list[Finding] = []

        # Detect a new GET_ATTESTATION_DATA request at offset 0 → start collection
        if packet.haslayer(GetAttestationDataRequestPacket):
            req = packet.getlayer(GetAttestationDataRequestPacket)
            if req.offset == 0:
                # Emit any previously collected data before starting a new sequence
                findings.extend(self._emit())
                self._first_idx = index
                self._first_ts = timestamp
                self._first_summary = packet.summary()
                self._version = None
                self._status_data.clear()
                self._collecting = True
                self._frag_buf.clear()
                if packet.haslayer(TransportHdrPacket):
                    hdr = packet.getlayer(TransportHdrPacket)
                    self._resp_tag = hdr.tag
                    self._resp_src = hdr.dst
                    self._resp_dst = hdr.src
            elif self._collecting:
                # Continuation request — track new tag for response matching
                if packet.haslayer(TransportHdrPacket):
                    hdr = packet.getlayer(TransportHdrPacket)
                    self._resp_tag = hdr.tag
                    self._resp_src = hdr.dst
                    self._resp_dst = hdr.src
                self._frag_buf.clear()
            return findings

        if not self._collecting:
            return findings

        # Collect response fragments
        if not packet.haslayer(TransportHdrPacket):
            return findings

        hdr = packet.getlayer(TransportHdrPacket)

        # Match response flow
        if self._resp_tag is not None and hdr.tag != self._resp_tag:
            return findings
        if self._resp_src is not None and hdr.src not in (self._resp_src, 0x00):
            return findings
        if self._resp_dst is not None and hdr.dst not in (self._resp_dst, 0x00):
            return findings

        if hdr.som:
            self._frag_buf.clear()
            if packet.haslayer(AttestationDataResponsePacket):
                resp = packet.getlayer(AttestationDataResponsePacket)
                if self._version is None:
                    self._version = resp.status_version
                if resp.payload:
                    self._frag_buf.extend(bytes(resp.payload))
            else:
                # Continuation reads don't have the 5-byte header — raw payload
                if hdr.payload:
                    self._frag_buf.extend(bytes(hdr.payload))
        elif hdr.payload:
            self._frag_buf.extend(bytes(hdr.payload))

        if not hdr.eom:
            return findings

        # Fragment complete — append to status data
        self._status_data.extend(self._frag_buf)
        self._frag_buf.clear()
        return findings

    def finalize(self) -> Sequence[Finding]:
        """Emit collected component status when analysis ends."""
        return self._emit()

    def _emit(self) -> list[Finding]:
        if not self._collecting or not self._status_data or self._version is None:
            return []

        version = self._version
        data = bytes(self._status_data)
        maps = AttestationDataResponsePacket.component_maps

        if version == 2:
            entries = _decode_component_statuses_v2(data, maps)
        elif version == 1:
            entries = _decode_component_statuses_v1(data)
        else:
            entries = []

        lines = []
        for comp_name, statuses in entries:
            status_str = ", ".join(statuses)
            lines.append(f"  {comp_name}: {status_str}")
        body = "\n".join(lines) if lines else "  (no components)"

        finding = Finding(
            rule_id=self.rule_id,
            severity=Severity.INFO,
            message=f"Component status (v{version}, {len(entries)} components):\n{body}",
            packet_index=self._first_idx or 0,
            timestamp=self._first_ts,
            packet_summary=self._first_summary or "",
        )

        self._reset_state()
        return [finding]

    def _reset_state(self) -> None:
        self._first_idx = None
        self._first_ts = None
        self._first_summary = None
        self._version = None
        self._status_data.clear()
        self._collecting = False
        self._frag_buf.clear()
        self._resp_tag = None
        self._resp_src = None
        self._resp_dst = None

    def reset(self) -> None:
        self._reset_state()


def get_attestation_rules() -> list[AnalysisRule]:
    """Factory function for entry point registration."""
    return [
        CompstateReadRule(),
        AttestationCheckRule(),
        ForceAttestRule(),
        SpdmGetMeasurementsRule(),
        ComponentStatusRule(),
    ]
