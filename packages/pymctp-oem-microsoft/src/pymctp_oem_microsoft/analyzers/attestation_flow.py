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
from pymctp.layers.mctp.spdm.get_measurements import GetMeasurementsPacket, MeasurementRequestAttributes
from pymctp.layers.mctp.spdm.spdm import SpdmHdrPacket
from pymctp.layers.mctp.vdpci.cerberus.log import ReadLogRequestPacket
from pymctp.layers.mctp.vdpci.cerberus.types import CerberusLogType

from pymctp_oem_microsoft.layers.mctp.vdpci.cerberus.msft_cerberus import ForceAttestationRequestPacket
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.bmc import GetDeviceEidRequestPacket


class CompstateReadRule(AnalysisRule):
    """Marks the start of a compstate read (Cerberus ReadLog ATTESTATION at offset 0)."""

    @property
    def rule_id(self) -> str:
        return "MSFT-ATTEST-001"

    @property
    def description(self) -> str:
        return "Marks compstate read start (Cerberus ReadLog ATTESTATION offset=0)"

    def feed(self, index: int, timestamp: datetime | None, packet: AnyPacketType) -> Sequence[Finding]:
        if not packet.haslayer(ReadLogRequestPacket):
            return []
        req = packet.getlayer(ReadLogRequestPacket)
        if req.log_type == CerberusLogType.ATTESTATION and req.offset == 0:
            return [
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.INFO,
                    message="Compstate read started",
                    packet_index=index,
                    timestamp=timestamp,
                    packet_summary=packet.summary(),
                )
            ]
        return []

    def reset(self) -> None:
        pass


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
