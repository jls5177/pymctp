# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import pytest

from pymctp.layers.mctp.spdm import (
    GetVersion,
    GetVersionPacket,
    SpdmHdrPacket,
    VersionPacket,
    VersionResponse,
)
from pymctp.layers.mctp.spdm.types import SpdmRequestCode, SpdmResponseCode
from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import MsgTypes


class TestGetVersion:
    def test_request_fn_creates_empty_payload(self):
        pkt = GetVersion()
        data = bytes(pkt)
        assert len(data) == 0

    def test_request_summary(self):
        pkt = GetVersion()
        summary = pkt.summary()
        assert "SPDM_GET_VERSION ()" in summary

    def test_request_code_is_correct(self):
        hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmRequestCode.GET_VERSION,
        )
        assert hdr.request_response_code == SpdmRequestCode.GET_VERSION


class TestVersion:
    def test_response_fn_without_args_has_default_values(self):
        pkt = VersionResponse()
        assert pkt.version_number_list == []

    def test_response_with_version_list(self):
        # 1.0.0.0 = 0x1000, 1.1.0.0 = 0x1100
        pkt = VersionResponse(version_number_list=[0x1000, 0x1100])
        assert len(pkt.version_number_list) == 2
        assert pkt.version_number_list[0] == 0x1000
        assert pkt.version_number_list[1] == 0x1100

    def test_response_summary(self):
        pkt = VersionResponse(version_number_list=[0x1000, 0x1100, 0x1200])
        summary = pkt.summary()
        assert "SPDM_VERSION" in summary
        assert "1.0.0.0" in summary
        assert "1.1.0.0" in summary
        assert "1.2.0.0" in summary

    def test_response_from_bytes(self):
        # reserved=0, count=2, versions: 0x1000 (LE: 00 10), 0x1100 (LE: 00 11)
        raw = bytes([0x00, 0x02, 0x00, 0x10, 0x00, 0x11])
        hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmResponseCode.VERSION,
        )
        pkt = VersionPacket(raw, _underlayer=hdr)
        assert pkt.version_number_entry_count == 2
        assert pkt.version_number_list[0] == 0x1000
        assert pkt.version_number_list[1] == 0x1100

    def test_response_serialization_roundtrip(self):
        pkt = VersionResponse(version_number_list=[0x1000, 0x1100])
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmResponseCode.VERSION,
        )
        pkt2 = VersionPacket(raw, _underlayer=hdr)
        assert pkt2.version_number_entry_count == 2
        assert pkt2.version_number_list == [0x1000, 0x1100]


class TestSpdmTransportBinding:
    def test_spdm_packet_dissected_from_transport(self):
        # Build a full MCTP transport + SPDM GET_VERSION
        transport = TransportHdr(
            msg_type=MsgTypes.SPDM,
            dst=0x10,
            src=0x20,
            som=True,
            eom=True,
        )
        spdm_hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmRequestCode.GET_VERSION,
            param1=0,
            param2=0,
        )
        pkt = transport / spdm_hdr
        raw_data = bytes(pkt)
        # Re-dissect from raw
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(SpdmHdrPacket)
        spdm = parsed.getlayer(SpdmHdrPacket)
        assert spdm.request_response_code == SpdmRequestCode.GET_VERSION

    def test_spdm_version_response_dissected_from_transport(self):
        transport = TransportHdr(
            msg_type=MsgTypes.SPDM,
            dst=0x20,
            src=0x10,
            som=True,
            eom=True,
            to=False,
        )
        spdm_hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmResponseCode.VERSION,
            param1=0,
            param2=0,
        )
        version_data = VersionResponse(version_number_list=[0x1000, 0x1100])
        pkt = transport / spdm_hdr / version_data
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(SpdmHdrPacket)
        assert parsed.haslayer(VersionPacket)
        ver = parsed.getlayer(VersionPacket)
        assert ver.version_number_entry_count == 2
        assert ver.version_number_list == [0x1000, 0x1100]

    def test_spdm_header_summary_request(self):
        hdr = SpdmHdrPacket(
            spdm_version=0x12,
            request_response_code=SpdmRequestCode.GET_VERSION,
        )
        summary, _ = hdr.mysummary()
        assert "REQ" in summary
        assert "1.2" in summary
        assert "0x84" in summary

    def test_spdm_header_summary_response(self):
        hdr = SpdmHdrPacket(
            spdm_version=0x11,
            request_response_code=SpdmResponseCode.VERSION,
        )
        summary, _ = hdr.mysummary()
        assert "RSP" in summary
        assert "1.1" in summary
        assert "0x04" in summary

    def test_spdm_is_request(self):
        hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmRequestCode.GET_VERSION,
        )
        assert hdr.is_request()

    def test_spdm_is_not_request(self):
        hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmResponseCode.VERSION,
        )
        assert not hdr.is_request()
