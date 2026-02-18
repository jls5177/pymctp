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
from pymctp.layers.mctp.vdpci.cerberus.log import ReadLogRequestPacket, ReadLogResponsePacket
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


def get_attestation_rules() -> list[AnalysisRule]:
    """Factory function for entry point registration."""
    return [
        CompstateReadRule(),
        AttestationCheckRule(),
        ForceAttestRule(),
        SpdmGetMeasurementsRule(),
    ]
