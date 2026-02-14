# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from pymctp.layers.mctp.spdm import (
    CertificatePacket,
    CertificateResponse,
    GetCertificate,
    GetCertificatePacket,
    SpdmHdrPacket,
)
from pymctp.layers.mctp.spdm.types import SpdmRequestCode, SpdmResponseCode
from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import MsgTypes


class TestGetCertificate:
    def test_request_fields(self):
        pkt = GetCertificate(slot_id=1, offset=0x100, length=0x400)
        assert pkt.offset == 0x100
        assert pkt.length == 0x400

    def test_request_summary(self):
        pkt = GetCertificate(slot_id=2, offset=0x100, length=0x400)
        summary = pkt.summary()
        assert "SlotID=0x02" in summary
        assert "Offset=0x0100" in summary
        assert "Length=0x0400" in summary

    def test_request_has_4_byte_payload(self):
        pkt = GetCertificate(slot_id=0, offset=0, length=0x400)
        raw = bytes(pkt)
        assert len(raw) == 4

    def test_request_roundtrip(self):
        pkt = GetCertificate(slot_id=3, offset=0x200, length=0x300)
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmRequestCode.GET_CERTIFICATE,
            param1=3,
        )
        pkt2 = GetCertificatePacket(raw, _underlayer=hdr)
        assert pkt2.offset == 0x200
        assert pkt2.length == 0x300


class TestCertificate:
    def test_response_fields(self):
        pkt = CertificateResponse(slot_id=0, portion_length=0x400, remainder_length=0x100)
        assert pkt.portion_length == 0x400
        assert pkt.remainder_length == 0x100

    def test_response_summary(self):
        pkt = CertificateResponse(slot_id=1, portion_length=0x400, remainder_length=0x100)
        summary = pkt.summary()
        assert "SlotID=0x01" in summary
        assert "PortLen=0x0400" in summary
        assert "RemLen=0x0100" in summary

    def test_response_roundtrip(self):
        pkt = CertificateResponse(slot_id=0, portion_length=0x200, remainder_length=0x300)
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmResponseCode.CERTIFICATE,
            param1=0,
        )
        pkt2 = CertificatePacket(raw, _underlayer=hdr)
        assert pkt2.portion_length == 0x200
        assert pkt2.remainder_length == 0x300


class TestCertificateTransportBinding:
    def test_get_certificate_dissected(self):
        transport = TransportHdr(msg_type=MsgTypes.SPDM, dst=0x10, src=0x20, som=True, eom=True)
        spdm_hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmRequestCode.GET_CERTIFICATE,
            param1=0,
        )
        cert = GetCertificate(slot_id=0, offset=0, length=0x400)
        pkt = transport / spdm_hdr / cert
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(GetCertificatePacket)
        c = parsed.getlayer(GetCertificatePacket)
        assert c.offset == 0
        assert c.length == 0x400

    def test_certificate_response_dissected(self):
        transport = TransportHdr(msg_type=MsgTypes.SPDM, dst=0x20, src=0x10, som=True, eom=True, to=False)
        spdm_hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmResponseCode.CERTIFICATE,
            param1=0,
        )
        cert = CertificateResponse(slot_id=0, portion_length=0x400, remainder_length=0x0)
        pkt = transport / spdm_hdr / cert
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(CertificatePacket)
        c = parsed.getlayer(CertificatePacket)
        assert c.portion_length == 0x400
        assert c.remainder_length == 0x0
