# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import pytest

from pymctp.layers.mctp.spdm import (
    SPDM_VERSION_10,
    SPDM_VERSION_11,
    SPDM_VERSION_12,
    CapabilitiesPacket,
    CapabilitiesResponse,
    GetCapabilities,
    GetCapabilitiesPacket,
    RequesterCapabilityFlags,
    ResponderCapabilityFlags,
    SpdmHdrPacket,
)
from pymctp.layers.mctp.spdm.types import SpdmRequestCode, SpdmResponseCode
from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import MsgTypes


# ---------------------------------------------------------------------------
# GET_CAPABILITIES request – version-varying format
# ---------------------------------------------------------------------------
class TestGetCapabilitiesV10:
    def test_v10_request_has_no_payload(self):
        pkt = GetCapabilities(spdm_version=SPDM_VERSION_10)
        raw = bytes(pkt)
        assert len(raw) == 0

    def test_v10_request_summary_is_empty(self):
        pkt = GetCapabilities(spdm_version=SPDM_VERSION_10)
        summary = pkt.summary()
        assert "SPDM_GET_CAPABILITIES ()" in summary


class TestGetCapabilitiesV11:
    def test_v11_request_has_8_byte_payload(self):
        pkt = GetCapabilities(spdm_version=SPDM_VERSION_11, ct_exponent=0x0A, flags=0x000000FE)
        raw = bytes(pkt)
        # reserved(1) + ct_exponent(1) + reserved2(2) + flags(4) = 8
        assert len(raw) == 8

    def test_v11_request_fields(self):
        pkt = GetCapabilities(spdm_version=SPDM_VERSION_11, ct_exponent=0x0A, flags=0x000000FE)
        assert pkt.ct_exponent == 0x0A
        assert pkt.flags == 0x000000FE

    def test_v11_request_summary(self):
        pkt = GetCapabilities(spdm_version=SPDM_VERSION_11, ct_exponent=0x0A, flags=0x000000FE)
        summary = pkt.summary()
        assert "Flags=0x000000FE" in summary
        assert "CTExponent=0x0A" in summary
        assert "DataTransSize" not in summary

    def test_v11_request_from_bytes(self):
        # reserved=0, ct_exponent=0x0A, reserved2=0x0000, flags=0xFE000000 (LE)
        raw = bytes([0x00, 0x0A, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x00])
        pkt = GetCapabilities(raw, spdm_version=SPDM_VERSION_11)
        assert pkt.ct_exponent == 0x0A
        assert pkt.flags == 0x000000FE

    def test_v11_request_roundtrip(self):
        pkt = GetCapabilities(spdm_version=SPDM_VERSION_11, ct_exponent=0x0C, flags=0x0000FFFE)
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(spdm_version=SPDM_VERSION_11, request_response_code=SpdmRequestCode.GET_CAPABILITIES)
        pkt2 = GetCapabilitiesPacket(raw, _underlayer=hdr)
        assert pkt2.ct_exponent == 0x0C
        assert pkt2.flags == 0x0000FFFE


class TestGetCapabilitiesV12:
    def test_v12_request_has_16_byte_payload(self):
        pkt = GetCapabilities(
            spdm_version=SPDM_VERSION_12,
            ct_exponent=0x0C,
            flags=0x000000FE,
            data_transfer_size=0x1000,
            max_spdm_msg_size=0x1000,
        )
        raw = bytes(pkt)
        # 8 base + 4 data_transfer_size + 4 max_spdm_msg_size = 16
        assert len(raw) == 16

    def test_v12_request_fields(self):
        pkt = GetCapabilities(
            spdm_version=SPDM_VERSION_12,
            ct_exponent=0x0C,
            flags=0x000000FE,
            data_transfer_size=0x00001000,
            max_spdm_msg_size=0x00002000,
        )
        assert pkt.ct_exponent == 0x0C
        assert pkt.flags == 0x000000FE
        assert pkt.data_transfer_size == 0x1000
        assert pkt.max_spdm_msg_size == 0x2000

    def test_v12_request_summary(self):
        pkt = GetCapabilities(
            spdm_version=SPDM_VERSION_12,
            ct_exponent=0x0C,
            flags=0x000000FE,
            data_transfer_size=0x00001000,
            max_spdm_msg_size=0x00001000,
        )
        summary = pkt.summary()
        assert "Flags=0x000000FE" in summary
        assert "CTExponent=0x0C" in summary
        assert "DataTransSize=0x00001000" in summary
        assert "MaxSpdmMsgSize=0x00001000" in summary

    def test_v12_request_roundtrip(self):
        pkt = GetCapabilities(
            spdm_version=SPDM_VERSION_12,
            ct_exponent=0x0C,
            flags=0x000000FE,
            data_transfer_size=0x1000,
            max_spdm_msg_size=0x2000,
        )
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(spdm_version=SPDM_VERSION_12, request_response_code=SpdmRequestCode.GET_CAPABILITIES)
        pkt2 = GetCapabilitiesPacket(raw, _underlayer=hdr)
        assert pkt2.ct_exponent == 0x0C
        assert pkt2.flags == 0x000000FE
        assert pkt2.data_transfer_size == 0x1000
        assert pkt2.max_spdm_msg_size == 0x2000


# ---------------------------------------------------------------------------
# CAPABILITIES response – version-varying format
# ---------------------------------------------------------------------------
class TestCapabilitiesV10:
    def test_v10_response_has_8_byte_payload(self):
        pkt = CapabilitiesResponse(spdm_version=SPDM_VERSION_10, ct_exponent=0x0C, flags=0x0000003F)
        raw = bytes(pkt)
        assert len(raw) == 8

    def test_v10_response_summary_no_transfer_fields(self):
        pkt = CapabilitiesResponse(spdm_version=SPDM_VERSION_10, ct_exponent=0x0C, flags=0x0000003F)
        summary = pkt.summary()
        assert "Flags=0x0000003F" in summary
        assert "CTExponent=0x0C" in summary
        assert "DataTransSize" not in summary


class TestCapabilitiesV11:
    def test_v11_response_fields(self):
        pkt = CapabilitiesResponse(spdm_version=SPDM_VERSION_11, ct_exponent=0x0C, flags=0x0000FFFE)
        assert pkt.ct_exponent == 0x0C
        assert pkt.flags == 0x0000FFFE

    def test_v11_response_summary(self):
        pkt = CapabilitiesResponse(spdm_version=SPDM_VERSION_11, ct_exponent=0x0C, flags=0x0000FFFE)
        summary = pkt.summary()
        assert "SPDM_CAPABILITIES" in summary
        assert "Flags=0x0000FFFE" in summary
        assert "CTExponent=0x0C" in summary

    def test_v11_response_from_bytes(self):
        raw = bytes([0x00, 0x0C, 0x00, 0x00, 0xFE, 0xFF, 0x00, 0x00])
        hdr = SpdmHdrPacket(spdm_version=SPDM_VERSION_11, request_response_code=SpdmResponseCode.CAPABILITIES)
        pkt = CapabilitiesPacket(raw, _underlayer=hdr)
        assert pkt.ct_exponent == 0x0C
        assert pkt.flags == 0x0000FFFE

    def test_v11_response_roundtrip(self):
        pkt = CapabilitiesResponse(spdm_version=SPDM_VERSION_11, ct_exponent=0x0C, flags=0x0000FFFE)
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(spdm_version=SPDM_VERSION_11, request_response_code=SpdmResponseCode.CAPABILITIES)
        pkt2 = CapabilitiesPacket(raw, _underlayer=hdr)
        assert pkt2.ct_exponent == 0x0C
        assert pkt2.flags == 0x0000FFFE


class TestCapabilitiesV12:
    def test_v12_response_has_16_byte_payload(self):
        pkt = CapabilitiesResponse(
            spdm_version=SPDM_VERSION_12,
            ct_exponent=0x0C,
            flags=0x0000FFFE,
            data_transfer_size=0x1000,
            max_spdm_msg_size=0x2000,
        )
        raw = bytes(pkt)
        assert len(raw) == 16

    def test_v12_response_fields(self):
        pkt = CapabilitiesResponse(
            spdm_version=SPDM_VERSION_12,
            ct_exponent=0x0C,
            flags=0x0000FFFE,
            data_transfer_size=0x00001000,
            max_spdm_msg_size=0x00002000,
        )
        assert pkt.ct_exponent == 0x0C
        assert pkt.flags == 0x0000FFFE
        assert pkt.data_transfer_size == 0x1000
        assert pkt.max_spdm_msg_size == 0x2000

    def test_v12_response_summary(self):
        pkt = CapabilitiesResponse(
            spdm_version=SPDM_VERSION_12,
            ct_exponent=0x0C,
            flags=0x0000FFFE,
            data_transfer_size=0x00001000,
            max_spdm_msg_size=0x00002000,
        )
        summary = pkt.summary()
        assert "Flags=0x0000FFFE" in summary
        assert "DataTransSize=0x00001000" in summary
        assert "MaxSpdmMsgSize=0x00002000" in summary

    def test_v12_response_roundtrip(self):
        pkt = CapabilitiesResponse(
            spdm_version=SPDM_VERSION_12,
            ct_exponent=0x0C,
            flags=0x0000FFFE,
            data_transfer_size=0x1000,
            max_spdm_msg_size=0x2000,
        )
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(spdm_version=SPDM_VERSION_12, request_response_code=SpdmResponseCode.CAPABILITIES)
        pkt2 = CapabilitiesPacket(raw, _underlayer=hdr)
        assert pkt2.ct_exponent == 0x0C
        assert pkt2.flags == 0x0000FFFE
        assert pkt2.data_transfer_size == 0x1000
        assert pkt2.max_spdm_msg_size == 0x2000


# ---------------------------------------------------------------------------
# Capability flag enums
# ---------------------------------------------------------------------------
class TestCapabilitiesFlags:
    def test_requester_flags_v11(self):
        assert RequesterCapabilityFlags.CERT_CAP == 0x0000_0002
        assert RequesterCapabilityFlags.CHAL_CAP == 0x0000_0004
        assert RequesterCapabilityFlags.ENCRYPT_CAP == 0x0000_0040
        assert RequesterCapabilityFlags.KEY_EX_CAP == 0x0000_0200
        assert RequesterCapabilityFlags.PSK_CAP == 0x0000_0400
        assert RequesterCapabilityFlags.PUB_KEY_ID_CAP == 0x0001_0000

    def test_requester_flags_v12(self):
        assert RequesterCapabilityFlags.CHUNK_CAP == 0x0002_0000

    def test_requester_flags_v13(self):
        assert RequesterCapabilityFlags.EP_INFO_CAP_NO_SIG == 0x0040_0000
        assert RequesterCapabilityFlags.EP_INFO_CAP_SIG == 0x0080_0000
        assert RequesterCapabilityFlags.EVENT_CAP == 0x0200_0000
        assert RequesterCapabilityFlags.MULTI_KEY_CAP_ONLY == 0x0400_0000
        assert RequesterCapabilityFlags.MULTI_KEY_CAP_NEG == 0x0800_0000

    def test_requester_flags_v14(self):
        assert RequesterCapabilityFlags.LARGE_RESP_CAP == 0x8000_0000

    def test_responder_flags_v10(self):
        assert ResponderCapabilityFlags.CACHE_CAP == 0x0000_0001
        assert ResponderCapabilityFlags.CERT_CAP == 0x0000_0002
        assert ResponderCapabilityFlags.MEAS_CAP_NO_SIG == 0x0000_0008
        assert ResponderCapabilityFlags.MEAS_CAP_SIG == 0x0000_0010
        assert ResponderCapabilityFlags.MEAS_FRESH_CAP == 0x0000_0020

    def test_responder_flags_v11(self):
        assert ResponderCapabilityFlags.ENCRYPT_CAP == 0x0000_0040
        assert ResponderCapabilityFlags.PSK_CAP == 0x0000_0400
        assert ResponderCapabilityFlags.PSK_CAP_WITH_CONTEXT == 0x0000_0800
        assert ResponderCapabilityFlags.ENCAP_CAP == 0x0000_1000
        assert ResponderCapabilityFlags.PUB_KEY_ID_CAP == 0x0001_0000

    def test_responder_flags_v12(self):
        assert ResponderCapabilityFlags.CHUNK_CAP == 0x0002_0000
        assert ResponderCapabilityFlags.ALIAS_CERT_CAP == 0x0004_0000
        assert ResponderCapabilityFlags.SET_CERT_CAP == 0x0008_0000
        assert ResponderCapabilityFlags.CSR_CAP == 0x0010_0000
        assert ResponderCapabilityFlags.CERT_INSTALL_RESET_CAP == 0x0020_0000

    def test_responder_flags_v13(self):
        assert ResponderCapabilityFlags.EP_INFO_CAP_NO_SIG == 0x0040_0000
        assert ResponderCapabilityFlags.MEL_CAP == 0x0100_0000
        assert ResponderCapabilityFlags.GET_KEY_PAIR_INFO_CAP == 0x1000_0000
        assert ResponderCapabilityFlags.SET_KEY_PAIR_INFO_CAP == 0x2000_0000

    def test_responder_flags_v14(self):
        assert ResponderCapabilityFlags.SET_KEY_PAIR_RESET_CAP == 0x4000_0000
        assert ResponderCapabilityFlags.LARGE_RESP_CAP == 0x8000_0000

    def test_flag_composition(self):
        flags = RequesterCapabilityFlags.CERT_CAP | RequesterCapabilityFlags.CHAL_CAP
        assert flags & RequesterCapabilityFlags.CERT_CAP
        assert flags & RequesterCapabilityFlags.CHAL_CAP
        assert not (flags & RequesterCapabilityFlags.ENCRYPT_CAP)


# ---------------------------------------------------------------------------
# Transport binding – end-to-end dissection
# ---------------------------------------------------------------------------
class TestCapabilitiesTransportBinding:
    def test_v11_capabilities_dissected_from_transport(self):
        transport = TransportHdr(
            msg_type=MsgTypes.SPDM, dst=0x10, src=0x20, som=True, eom=True, to=False,
        )
        spdm_hdr = SpdmHdrPacket(
            spdm_version=SPDM_VERSION_11,
            request_response_code=SpdmResponseCode.CAPABILITIES,
        )
        caps = CapabilitiesResponse(spdm_version=SPDM_VERSION_11, ct_exponent=0x0C, flags=0x0000FFFE)
        pkt = transport / spdm_hdr / caps
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(SpdmHdrPacket)
        assert parsed.haslayer(CapabilitiesPacket)
        cap = parsed.getlayer(CapabilitiesPacket)
        assert cap.ct_exponent == 0x0C
        assert cap.flags == 0x0000FFFE

    def test_v12_capabilities_dissected_from_transport(self):
        transport = TransportHdr(
            msg_type=MsgTypes.SPDM, dst=0x10, src=0x20, som=True, eom=True, to=False,
        )
        spdm_hdr = SpdmHdrPacket(
            spdm_version=SPDM_VERSION_12,
            request_response_code=SpdmResponseCode.CAPABILITIES,
        )
        caps = CapabilitiesResponse(
            spdm_version=SPDM_VERSION_12,
            ct_exponent=0x0C,
            flags=0x0000FFFE,
            data_transfer_size=0x1000,
            max_spdm_msg_size=0x2000,
        )
        pkt = transport / spdm_hdr / caps
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(CapabilitiesPacket)
        cap = parsed.getlayer(CapabilitiesPacket)
        assert cap.ct_exponent == 0x0C
        assert cap.flags == 0x0000FFFE
        assert cap.data_transfer_size == 0x1000
        assert cap.max_spdm_msg_size == 0x2000
