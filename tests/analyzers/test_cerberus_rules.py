# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the Cerberus log-transfer analyzer rule."""

from datetime import datetime, timedelta

import pytest
from scapy.packet import Raw

from pymctp.analyzers.base import Severity
from pymctp.analyzers.cerberus import CerberusLogTransferRule
from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import MsgTypes
from pymctp.layers.mctp.vdpci import RqBit, VdPciHdr, VdPCIVendorIds
from pymctp.layers.mctp.vdpci.cerberus import (
    CerberusCmdCodes,
    CerberusLogType,
)
from pymctp.layers.mctp.vdpci.cerberus.log import (
    GetLogInfoRequestPacket,
    LogInfoResponsePacket,
    ReadLogRequestPacket,
    ReadLogResponsePacket,
)


# ---------------------------------------------------------------------------
# Packet construction helpers
# ---------------------------------------------------------------------------

def _vdpci_hdr(cmd_code: int, rq: bool = True):
    return VdPciHdr(
        rq=RqBit.REQUEST if rq else RqBit.RESPONSE,
        vendor_id=VdPCIVendorIds.Msft,
        vdm_cmd_code=cmd_code,
    )


def _transport(rq: bool = True):
    return TransportHdr(
        msg_type=MsgTypes.VDPCI, dst=0x10, src=0x20,
        som=True, eom=True, to=rq,
    )


def _log_info_request():
    """GET_LOG_INFO request (empty payload)."""
    return _transport(rq=True) / _vdpci_hdr(CerberusCmdCodes.GET_LOG_INFO, rq=True) / GetLogInfoRequestPacket()


def _log_info_response(debug: int = 0, attestation: int = 0, tamper: int = 0):
    """GET_LOG_INFO response with the given log sizes."""
    return (
        _transport(rq=False)
        / _vdpci_hdr(CerberusCmdCodes.GET_LOG_INFO, rq=False)
        / LogInfoResponsePacket(
            debug_log_length=debug,
            attestation_log_length=attestation,
            tamper_log_length=tamper,
        )
    )


def _read_log_request(log_type: int, offset: int):
    return (
        _transport(rq=True)
        / _vdpci_hdr(CerberusCmdCodes.READ_LOG, rq=True)
        / ReadLogRequestPacket(log_type=log_type, offset=offset)
    )


def _read_log_response(data_len: int):
    """READ_LOG response with *data_len* bytes of dummy payload (unfragmented)."""
    return (
        _transport(rq=False)
        / _vdpci_hdr(CerberusCmdCodes.READ_LOG, rq=False)
        / ReadLogResponsePacket()
        / Raw(load=bytes(data_len))
    )


def _read_log_response_som(data_len: int, tag: int = 0, src: int = 0x20, dst: int = 0x10):
    """First fragment (SOM) of a fragmented READ_LOG response."""
    return (
        TransportHdr(
            msg_type=MsgTypes.VDPCI, dst=dst, src=src,
            som=True, eom=False, to=False, tag=tag, pkt_seq=0,
        )
        / _vdpci_hdr(CerberusCmdCodes.READ_LOG, rq=False)
        / ReadLogResponsePacket()
        / Raw(load=bytes(data_len))
    )


def _mctp_middle_fragment(data_len: int, tag: int = 0, src: int = 0x20, dst: int = 0x10, pkt_seq: int = 1):
    """Middle fragment (no SOM, no EOM)."""
    return (
        TransportHdr(
            dst=dst, src=src,
            som=False, eom=False, to=False, tag=tag, pkt_seq=pkt_seq,
        )
        / Raw(load=bytes(data_len))
    )


def _mctp_eom_fragment(data_len: int, tag: int = 0, src: int = 0x20, dst: int = 0x10, pkt_seq: int = 2):
    """Last fragment (EOM)."""
    return (
        TransportHdr(
            dst=dst, src=src,
            som=False, eom=True, to=False, tag=tag, pkt_seq=pkt_seq,
        )
        / Raw(load=bytes(data_len))
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

T0 = datetime(2026, 1, 1, 12, 0, 0)


class TestCerberusLogTransferRule:
    """Tests for CERBERUS-LOG-001."""

    # --- happy path: complete transfer ---

    def test_complete_transfer_no_findings(self):
        """Full transfer of a 100-byte debug log in two 50-byte chunks."""
        rule = CerberusLogTransferRule()
        t = T0

        # LogInfo says debug=100
        assert rule.feed(0, t, _log_info_response(debug=100)) == []

        # READ_LOG offset=0 → 50 bytes
        t += timedelta(milliseconds=10)
        assert rule.feed(1, t, _read_log_request(CerberusLogType.DEBUG, 0)) == []
        t += timedelta(milliseconds=5)
        assert rule.feed(2, t, _read_log_response(50)) == []

        # READ_LOG offset=50 → 50 bytes
        t += timedelta(milliseconds=10)
        assert rule.feed(3, t, _read_log_request(CerberusLogType.DEBUG, 50)) == []
        t += timedelta(milliseconds=5)
        assert rule.feed(4, t, _read_log_response(50)) == []

        # No issues at finalize
        assert rule.finalize() == []

    # --- ReadLog without prior LogInfo ---

    def test_read_log_without_log_info(self):
        rule = CerberusLogTransferRule()
        findings = rule.feed(0, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARNING
        assert "without prior GET_LOG_INFO" in findings[0].message

    # --- non-zero starting offset ---

    def test_non_zero_start_offset(self):
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=100))

        findings = rule.feed(1, T0, _read_log_request(CerberusLogType.DEBUG, 0x20))
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "starts at offset 0x20" in findings[0].message

    # --- offset gap ---

    def test_offset_gap_detected(self):
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=200))

        # First chunk: offset=0, 50 bytes → next expected=50
        rule.feed(1, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        rule.feed(2, T0, _read_log_response(50))

        # Second chunk skips to offset=100 (gap of 50)
        findings = rule.feed(3, T0, _read_log_request(CerberusLogType.DEBUG, 100))
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "offset gap" in findings[0].message
        assert "50 bytes missing" in findings[0].message

    # --- offset overlap ---

    def test_offset_overlap_detected(self):
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=200))

        # First chunk: offset=0, 50 bytes → next expected=50
        rule.feed(1, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        rule.feed(2, T0, _read_log_response(50))

        # Second chunk re-reads from offset=30 (overlap of 20)
        findings = rule.feed(3, T0, _read_log_request(CerberusLogType.DEBUG, 30))
        assert len(findings) == 1
        assert findings[0].severity == Severity.WARNING
        assert "offset overlap" in findings[0].message
        assert "20 bytes re-read" in findings[0].message

    # --- retransmission should not cause over-read ---

    def test_retransmission_does_not_cause_over_read(self):
        """An offset overlap (retransmission) should not inflate bytes_transferred."""
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=100))

        # First chunk: offset=0, 50 bytes
        rule.feed(1, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        rule.feed(2, T0, _read_log_response(50))

        # Retransmit: same offset=0, 50 bytes again (overlap warning)
        findings = rule.feed(3, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        assert len(findings) == 1
        assert "offset overlap" in findings[0].message
        # Response should NOT add to bytes_transferred
        assert rule.feed(4, T0, _read_log_response(50)) == []

        # Complete transfer: offset=50, 50 bytes
        assert rule.feed(5, T0, _read_log_request(CerberusLogType.DEBUG, 50)) == []
        assert rule.feed(6, T0, _read_log_response(50)) == []

        # No over-read, no incomplete — exactly 100 bytes transferred
        assert rule.finalize() == []

    # --- incomplete transfer at finalize ---

    def test_incomplete_transfer(self):
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(attestation=200))

        # Only transfer 80 of 200 bytes
        rule.feed(1, T0, _read_log_request(CerberusLogType.ATTESTATION, 0))
        rule.feed(2, T0, _read_log_response(80))

        findings = rule.finalize()
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "incomplete" in findings[0].message
        assert "80/200" in findings[0].message
        assert "120 bytes missing" in findings[0].message

    # --- over-read ---

    def test_over_read_detected(self):
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=50))

        rule.feed(1, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        findings = rule.feed(2, T0, _read_log_response(80))
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "over-read" in findings[0].message
        assert "80 bytes" in findings[0].message

    # --- independent tracking per log type ---

    def test_independent_log_types(self):
        """Debug and attestation logs tracked independently with per-type offsets."""
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=60, attestation=40))

        # Complete debug transfer: offset 0→60
        rule.feed(1, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        rule.feed(2, T0, _read_log_response(60))

        # Partial attestation transfer: starts at its own offset (0xFFB in
        # a global space, but per-type tracking accepts any first offset)
        rule.feed(3, T0, _read_log_request(CerberusLogType.ATTESTATION, 0))
        rule.feed(4, T0, _read_log_response(20))

        findings = rule.finalize()
        # Only attestation should be flagged as incomplete
        assert len(findings) == 1
        assert "ATTESTATION" in findings[0].message
        assert "20/40" in findings[0].message

    # --- global offset continuity across log types ---

    def test_cross_type_offset_continuity(self):
        """Interlaced reads across types should not cause false positives.

        Mirrors real-world behavior: TAMPER and ATTESTATION reads are
        interlaced in the capture.  Per-type offset tracking validates
        continuity within each type independently.
        """
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(tamper=4091, attestation=1000))

        # First TAMPER read at offset 0, fragmented response = 4091 bytes
        assert rule.feed(1, T0, _read_log_request(CerberusLogType.TAMPER, 0)) == []
        assert rule.feed(2, T0, _read_log_response_som(242)) == []
        for i in range(15):
            assert rule.feed(3 + i, T0, _mctp_middle_fragment(247, pkt_seq=(i + 1) % 4)) == []
        assert rule.feed(18, T0, _mctp_eom_fragment(144, pkt_seq=0)) == []

        # Interlaced ATTESTATION read at its own offset 0xFFB — no false positive
        assert rule.feed(19, T0, _read_log_request(CerberusLogType.ATTESTATION, 0xFFB)) == []
        assert rule.feed(20, T0, _read_log_response(500)) == []

        # Back to TAMPER at offset 4091 (continues from where TAMPER left off)
        assert rule.feed(21, T0, _read_log_request(CerberusLogType.TAMPER, 4091)) == []

        # Back to ATTESTATION continuing from 0xFFB + 500 = 0x11EF
        assert rule.feed(22, T0, _read_log_request(CerberusLogType.ATTESTATION, 0xFFB + 500)) == []

    # --- reset clears all state ---

    def test_reset_clears_state(self):
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=100))
        rule.feed(1, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        rule.feed(2, T0, _read_log_response(50))

        rule.reset()

        # After reset, a ReadLog without LogInfo triggers a warning
        findings = rule.feed(3, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        assert any("without prior GET_LOG_INFO" in f.message for f in findings)

        # No incomplete-transfer findings since state was cleared
        assert rule.finalize() == []

    # --- new LogInfo resets transfer tracking ---

    def test_new_log_info_resets_transfers(self):
        """A second GET_LOG_INFO response resets all transfer state."""
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=100))

        # Partial transfer
        rule.feed(1, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        rule.feed(2, T0, _read_log_response(30))

        # New LogInfo with different sizes
        rule.feed(3, T0, _log_info_response(debug=40))

        # Complete transfer of the new size
        rule.feed(4, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        rule.feed(5, T0, _read_log_response(40))

        assert rule.finalize() == []

    # --- zero-length log is not flagged ---

    def test_zero_length_log_not_flagged(self):
        """A log type with length=0 should not produce incomplete findings."""
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=0, tamper=0))
        assert rule.finalize() == []

    # --- packet_summary is populated ---

    def test_finding_has_packet_summary(self):
        """Findings should include a packet_summary string."""
        rule = CerberusLogTransferRule()
        findings = rule.feed(0, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        assert len(findings) == 1
        assert findings[0].packet_summary is not None
        assert len(findings[0].packet_summary) > 0

    # --- contiguous offset after response updates correctly ---

    def test_next_offset_tracks_response_length(self):
        """Verify next_offset = previous offset + response data length."""
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=300))

        # 3 chunks: 100 + 100 + 100
        for i, offset in enumerate([0, 100, 200]):
            req_idx = 1 + i * 2
            rsp_idx = req_idx + 1
            assert rule.feed(req_idx, T0, _read_log_request(CerberusLogType.DEBUG, offset)) == []
            assert rule.feed(rsp_idx, T0, _read_log_response(100)) == []

        assert rule.finalize() == []

    # --- fragmented responses ---

    def test_fragmented_response_complete_transfer(self):
        """A fragmented response (SOM + middles + EOM) should sum all fragments."""
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=4091))

        # Request at offset 0
        assert rule.feed(1, T0, _read_log_request(CerberusLogType.DEBUG, 0)) == []

        # Fragmented response: 242 + 15*247 + 144 = 4091
        assert rule.feed(2, T0, _read_log_response_som(242)) == []
        for i in range(15):
            assert rule.feed(3 + i, T0, _mctp_middle_fragment(247, pkt_seq=(i + 1) % 4)) == []
        assert rule.feed(18, T0, _mctp_eom_fragment(144, pkt_seq=0)) == []

        # Transfer is complete
        assert rule.finalize() == []

    def test_fragmented_response_continues_offset_tracking(self):
        """After a fragmented response, the next request offset should be validated correctly."""
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(tamper=500))

        # First request: offset=0, fragmented response totaling 300 bytes
        assert rule.feed(1, T0, _read_log_request(CerberusLogType.TAMPER, 0)) == []
        assert rule.feed(2, T0, _read_log_response_som(100)) == []
        assert rule.feed(3, T0, _mctp_eom_fragment(200, pkt_seq=1)) == []

        # Second request at offset=300 (correct continuation)
        assert rule.feed(4, T0, _read_log_request(CerberusLogType.TAMPER, 300)) == []
        assert rule.feed(5, T0, _read_log_response(200)) == []

        assert rule.finalize() == []

    def test_fragmented_response_gap_after_fragment(self):
        """An offset gap after a fragmented response should be detected."""
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=1000))

        # First request: offset=0, fragmented response totaling 200 bytes
        rule.feed(1, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        rule.feed(2, T0, _read_log_response_som(100))
        rule.feed(3, T0, _mctp_eom_fragment(100, pkt_seq=1))

        # Second request skips to offset=500 (gap of 300)
        findings = rule.feed(4, T0, _read_log_request(CerberusLogType.DEBUG, 500))
        assert len(findings) == 1
        assert findings[0].severity == Severity.ERROR
        assert "offset gap" in findings[0].message
        assert "300 bytes missing" in findings[0].message

    def test_fragmented_response_incomplete_at_finalize(self):
        """If fragment accumulation never completes (no EOM), finalize flags incomplete."""
        rule = CerberusLogTransferRule()
        rule.feed(0, T0, _log_info_response(debug=500))

        # Request + fragmented response that never gets EOM
        rule.feed(1, T0, _read_log_request(CerberusLogType.DEBUG, 0))
        rule.feed(2, T0, _read_log_response_som(100))
        rule.feed(3, T0, _mctp_middle_fragment(100, pkt_seq=1))
        # No EOM ever arrives → next_offset never updated → incomplete

        findings = rule.finalize()
        assert len(findings) == 1
        assert "incomplete" in findings[0].message