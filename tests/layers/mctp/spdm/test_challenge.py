# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from pymctp.layers.mctp.spdm import (
    Challenge,
    ChallengeAuthPacket,
    ChallengeAuthResponse,
    ChallengePacket,
    MeasurementSummaryHashType,
    SpdmHdrPacket,
)
from pymctp.layers.mctp.spdm.types import SpdmRequestCode, SpdmResponseCode
from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import MsgTypes


class TestChallenge:
    def test_request_has_32_byte_nonce(self):
        pkt = Challenge(slot_id=0, hash_type=MeasurementSummaryHashType.NO_HASH)
        raw = bytes(pkt)
        assert len(raw) == 32

    def test_request_nonce_custom(self):
        nonce = bytes(range(32))
        pkt = Challenge(slot_id=0, hash_type=MeasurementSummaryHashType.NO_HASH, nonce=nonce)
        assert pkt.nonce == nonce

    def test_request_summary_no_hash(self):
        pkt = Challenge(slot_id=0, hash_type=MeasurementSummaryHashType.NO_HASH)
        summary = pkt.summary()
        assert "SlotID=0x00" in summary
        assert "HashType=0x00(NoHash)" in summary

    def test_request_summary_tcb_hash(self):
        pkt = Challenge(slot_id=1, hash_type=MeasurementSummaryHashType.TCB_HASH)
        summary = pkt.summary()
        assert "SlotID=0x01" in summary
        assert "HashType=0x01(TcbHash)" in summary

    def test_request_summary_all_hash(self):
        pkt = Challenge(slot_id=0, hash_type=MeasurementSummaryHashType.ALL_HASH)
        summary = pkt.summary()
        assert "HashType=0xFF(AllHash)" in summary

    def test_request_roundtrip(self):
        nonce = bytes(range(32))
        pkt = Challenge(slot_id=2, hash_type=MeasurementSummaryHashType.TCB_HASH, nonce=nonce)
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmRequestCode.CHALLENGE,
            param1=2,
            param2=MeasurementSummaryHashType.TCB_HASH,
        )
        pkt2 = ChallengePacket(raw, _underlayer=hdr)
        assert pkt2.nonce == nonce


class TestChallengeAuth:
    def test_response_summary(self):
        pkt = ChallengeAuthResponse(slot_id=0, slot_mask=0x01)
        summary = pkt.summary()
        assert "SlotID=0x00" in summary
        assert "SlotMask=0x01" in summary

    def test_response_slot_id_masked(self):
        pkt = ChallengeAuthResponse(slot_id=0x83, slot_mask=0x0F)
        summary = pkt.summary()
        # slot_id should be masked to lower 4 bits
        assert "SlotID=0x03" in summary


class TestChallengeTransportBinding:
    def test_challenge_dissected_from_transport(self):
        transport = TransportHdr(msg_type=MsgTypes.SPDM, dst=0x10, src=0x20, som=True, eom=True)
        spdm_hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmRequestCode.CHALLENGE,
            param1=0,
            param2=MeasurementSummaryHashType.NO_HASH,
        )
        chal = Challenge(slot_id=0, hash_type=MeasurementSummaryHashType.NO_HASH)
        pkt = transport / spdm_hdr / chal
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(ChallengePacket)
        c = parsed.getlayer(ChallengePacket)
        assert len(c.nonce) == 32
