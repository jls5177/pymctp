# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from pymctp.layers.mctp.spdm import (
    GetMeasurements,
    GetMeasurementsPacket,
    MeasurementRequestAttributes,
    MeasurementsPacket,
    MeasurementsResponse,
    SpdmHdrPacket,
)
from pymctp.layers.mctp.spdm.types import SpdmRequestCode, SpdmResponseCode
from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import MsgTypes


class TestGetMeasurements:
    def test_request_no_sig_no_payload(self):
        pkt = GetMeasurements(attributes=0, measurement_operation=0)
        raw = bytes(pkt)
        # No GENERATE_SIGNATURE → no nonce or slot_id_param
        assert len(raw) == 0

    def test_request_with_sig_v10_has_nonce_only(self):
        pkt = GetMeasurements(
            spdm_version=0x10,
            attributes=MeasurementRequestAttributes.GENERATE_SIGNATURE,
            measurement_operation=0xFF,
        )
        raw = bytes(pkt)
        # nonce(32), no slot_id_param in v1.0
        assert len(raw) == 32

    def test_request_with_sig_v11_has_nonce_and_slot(self):
        pkt = GetMeasurements(
            spdm_version=0x11,
            attributes=MeasurementRequestAttributes.GENERATE_SIGNATURE,
            measurement_operation=0xFF,
            slot_id=2,
        )
        raw = bytes(pkt)
        # nonce(32) + slot_id_param(1)
        assert len(raw) == 33
        assert pkt.slot_id_param == 2

    def test_request_summary_total_num(self):
        pkt = GetMeasurements(attributes=0, measurement_operation=0)
        summary = pkt.summary()
        assert "MeasOp=0x00(TotalNum)" in summary

    def test_request_summary_all(self):
        pkt = GetMeasurements(
            spdm_version=0x11,
            attributes=MeasurementRequestAttributes.GENERATE_SIGNATURE,
            measurement_operation=0xFF,
            slot_id=0,
        )
        summary = pkt.summary()
        assert "Attr=0x01(GenSig)" in summary
        assert "MeasOp=0xFF(All)" in summary
        assert "SlotID=0x00" in summary

    def test_request_summary_index(self):
        pkt = GetMeasurements(attributes=0, measurement_operation=5)
        summary = pkt.summary()
        assert "MeasOp=0x05(Index(5))" in summary

    def test_request_roundtrip_with_sig(self):
        nonce = bytes(range(32))
        pkt = GetMeasurements(
            spdm_version=0x11,
            attributes=MeasurementRequestAttributes.GENERATE_SIGNATURE,
            measurement_operation=0xFF,
            nonce=nonce,
            slot_id=3,
        )
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(
            spdm_version=0x11,
            request_response_code=SpdmRequestCode.GET_MEASUREMENTS,
            param1=MeasurementRequestAttributes.GENERATE_SIGNATURE,
            param2=0xFF,
        )
        pkt2 = GetMeasurementsPacket(raw, _underlayer=hdr)
        assert pkt2.nonce == nonce
        assert pkt2.slot_id_param == 3


class TestMeasurements:
    def test_response_fields(self):
        pkt = MeasurementsResponse(number_of_blocks=5, measurement_record_length=0x200)
        assert pkt.number_of_blocks == 5
        assert pkt.measurement_record_length == 0x200

    def test_response_has_4_byte_header(self):
        pkt = MeasurementsResponse(number_of_blocks=1, measurement_record_length=0x30)
        raw = bytes(pkt)
        # number_of_blocks(1) + measurement_record_length(3) = 4
        assert len(raw) == 4

    def test_response_summary(self):
        pkt = MeasurementsResponse(number_of_blocks=3, measurement_record_length=0x120)
        summary = pkt.summary()
        assert "NumBlocks=3" in summary
        assert "MeasRecordLen=0x000120" in summary

    def test_response_roundtrip(self):
        pkt = MeasurementsResponse(number_of_blocks=4, measurement_record_length=0xABCDEF)
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmResponseCode.MEASUREMENTS,
        )
        pkt2 = MeasurementsPacket(raw, _underlayer=hdr)
        assert pkt2.number_of_blocks == 4
        assert pkt2.measurement_record_length == 0xABCDEF


class TestMeasurementsTransportBinding:
    def test_get_measurements_dissected_from_transport(self):
        transport = TransportHdr(msg_type=MsgTypes.SPDM, dst=0x10, src=0x20, som=True, eom=True)
        spdm_hdr = SpdmHdrPacket(
            spdm_version=0x11,
            request_response_code=SpdmRequestCode.GET_MEASUREMENTS,
            param1=MeasurementRequestAttributes.GENERATE_SIGNATURE,
            param2=0xFF,
        )
        meas = GetMeasurements(
            spdm_version=0x11,
            attributes=MeasurementRequestAttributes.GENERATE_SIGNATURE,
            measurement_operation=0xFF,
        )
        pkt = transport / spdm_hdr / meas
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(GetMeasurementsPacket)
        m = parsed.getlayer(GetMeasurementsPacket)
        assert len(m.nonce) == 32

    def test_measurements_response_dissected_from_transport(self):
        transport = TransportHdr(msg_type=MsgTypes.SPDM, dst=0x20, src=0x10, som=True, eom=True, to=False)
        spdm_hdr = SpdmHdrPacket(
            spdm_version=0x10,
            request_response_code=SpdmResponseCode.MEASUREMENTS,
        )
        meas = MeasurementsResponse(number_of_blocks=2, measurement_record_length=0x100)
        pkt = transport / spdm_hdr / meas
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(MeasurementsPacket)
        m = parsed.getlayer(MeasurementsPacket)
        assert m.number_of_blocks == 2
        assert m.measurement_record_length == 0x100
