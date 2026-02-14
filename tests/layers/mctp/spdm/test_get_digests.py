# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from pymctp.layers.mctp.spdm import (
    DigestsPacket,
    DigestsResponse,
    GetDigests,
    GetDigestsPacket,
    SpdmHdrPacket,
)
from pymctp.layers.mctp.spdm.types import SpdmRequestCode, SpdmResponseCode
from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import MsgTypes


class TestGetDigests:
    def test_request_has_no_payload(self):
        pkt = GetDigests()
        assert len(bytes(pkt)) == 0

    def test_request_summary(self):
        pkt = GetDigests()
        assert "SPDM_GET_DIGESTS ()" in pkt.summary()


class TestDigests:
    def test_response_summary_v10(self):
        pkt = DigestsResponse(spdm_version=0x10, slot_mask=0x03)
        summary = pkt.summary()
        assert "ProvisionedSlotMask=0x03" in summary
        assert "SupportedSlotMask" not in summary

    def test_response_summary_v13(self):
        pkt = DigestsResponse(spdm_version=0x13, slot_mask=0x03, supported_slot_mask=0x0F)
        summary = pkt.summary()
        assert "SupportedSlotMask=0x0F" in summary
        assert "ProvisionedSlotMask=0x03" in summary


class TestDigestsTransportBinding:
    def test_get_digests_dissected_from_transport(self):
        transport = TransportHdr(msg_type=MsgTypes.SPDM, dst=0x10, src=0x20, som=True, eom=True)
        spdm_hdr = SpdmHdrPacket(spdm_version=0x10, request_response_code=SpdmRequestCode.GET_DIGESTS)
        pkt = transport / spdm_hdr
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(SpdmHdrPacket)
        spdm = parsed.getlayer(SpdmHdrPacket)
        assert spdm.request_response_code == SpdmRequestCode.GET_DIGESTS

    def test_digests_response_dissected_from_transport(self):
        transport = TransportHdr(msg_type=MsgTypes.SPDM, dst=0x20, src=0x10, som=True, eom=True, to=False)
        spdm_hdr = SpdmHdrPacket(
            spdm_version=0x10, request_response_code=SpdmResponseCode.DIGESTS, param2=0x03,
        )
        pkt = transport / spdm_hdr
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(SpdmHdrPacket)
        spdm = parsed.getlayer(SpdmHdrPacket)
        assert spdm.param2 == 0x03
