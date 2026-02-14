# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from pymctp.layers.mctp.spdm import (
    AlgorithmsPacket,
    AlgorithmsResponse,
    BaseAsymAlgo,
    BaseHashAlgo,
    MeasurementHashAlgo,
    MeasurementSpecification,
    NegotiateAlgorithms,
    NegotiateAlgorithmsPacket,
    SpdmHdrPacket,
)
from pymctp.layers.mctp.spdm.types import SpdmRequestCode, SpdmResponseCode
from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import MsgTypes


class TestNegotiateAlgorithms:
    def test_request_fields(self):
        pkt = NegotiateAlgorithms(
            base_hash_algo=BaseHashAlgo.SHA_256,
            base_asym_algo=BaseAsymAlgo.ECDSA_P256,
            measurement_specification=MeasurementSpecification.DMTF,
        )
        assert pkt.base_hash_algo == BaseHashAlgo.SHA_256
        assert pkt.base_asym_algo == BaseAsymAlgo.ECDSA_P256
        assert pkt.measurement_specification == MeasurementSpecification.DMTF

    def test_request_summary(self):
        pkt = NegotiateAlgorithms(
            base_hash_algo=BaseHashAlgo.SHA_256,
            base_asym_algo=BaseAsymAlgo.ECDSA_P256,
        )
        summary = pkt.summary()
        assert "SPDM_NEGOTIATE_ALGORITHMS" in summary
        assert "SHA_256" in summary
        assert "ECDSA_P256" in summary

    def test_request_roundtrip(self):
        pkt = NegotiateAlgorithms(
            base_hash_algo=BaseHashAlgo.SHA_256 | BaseHashAlgo.SHA_384,
            base_asym_algo=BaseAsymAlgo.ECDSA_P256,
        )
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(spdm_version=0x11, request_response_code=SpdmRequestCode.NEGOTIATE_ALGORITHMS)
        pkt2 = NegotiateAlgorithmsPacket(raw, _underlayer=hdr)
        assert pkt2.base_hash_algo == BaseHashAlgo.SHA_256 | BaseHashAlgo.SHA_384
        assert pkt2.base_asym_algo == BaseAsymAlgo.ECDSA_P256

    def test_multiple_flags_summary(self):
        pkt = NegotiateAlgorithms(
            base_hash_algo=BaseHashAlgo.SHA_256 | BaseHashAlgo.SHA_384,
            base_asym_algo=BaseAsymAlgo.ECDSA_P256 | BaseAsymAlgo.ECDSA_P384,
        )
        summary = pkt.summary()
        assert "SHA_256" in summary
        assert "SHA_384" in summary
        assert "ECDSA_P256" in summary
        assert "ECDSA_P384" in summary


class TestAlgorithms:
    def test_response_fields(self):
        pkt = AlgorithmsResponse(
            base_hash_sel=BaseHashAlgo.SHA_256,
            base_asym_sel=BaseAsymAlgo.ECDSA_P256,
            measurement_hash_algo=MeasurementHashAlgo.SHA_256,
        )
        assert pkt.base_hash_sel == BaseHashAlgo.SHA_256
        assert pkt.base_asym_sel == BaseAsymAlgo.ECDSA_P256
        assert pkt.measurement_hash_algo == MeasurementHashAlgo.SHA_256

    def test_response_summary(self):
        pkt = AlgorithmsResponse(
            base_hash_sel=BaseHashAlgo.SHA_256,
            base_asym_sel=BaseAsymAlgo.ECDSA_P256,
            measurement_hash_algo=MeasurementHashAlgo.SHA_256,
        )
        summary = pkt.summary()
        assert "SPDM_ALGORITHMS" in summary
        assert "MeasHash=" in summary
        assert "SHA_256" in summary
        assert "ECDSA_P256" in summary

    def test_response_roundtrip(self):
        pkt = AlgorithmsResponse(
            base_hash_sel=BaseHashAlgo.SHA_384,
            base_asym_sel=BaseAsymAlgo.ECDSA_P384,
            measurement_hash_algo=MeasurementHashAlgo.SHA_384,
        )
        raw = bytes(pkt)
        hdr = SpdmHdrPacket(spdm_version=0x11, request_response_code=SpdmResponseCode.ALGORITHMS)
        pkt2 = AlgorithmsPacket(raw, _underlayer=hdr)
        assert pkt2.base_hash_sel == BaseHashAlgo.SHA_384
        assert pkt2.base_asym_sel == BaseAsymAlgo.ECDSA_P384
        assert pkt2.measurement_hash_algo == MeasurementHashAlgo.SHA_384


class TestAlgorithmsTransportBinding:
    def test_negotiate_algorithms_dissected_from_transport(self):
        transport = TransportHdr(msg_type=MsgTypes.SPDM, dst=0x10, src=0x20, som=True, eom=True)
        spdm_hdr = SpdmHdrPacket(
            spdm_version=0x11, request_response_code=SpdmRequestCode.NEGOTIATE_ALGORITHMS,
        )
        alg = NegotiateAlgorithms(base_hash_algo=BaseHashAlgo.SHA_256, base_asym_algo=BaseAsymAlgo.ECDSA_P256)
        pkt = transport / spdm_hdr / alg
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(NegotiateAlgorithmsPacket)
        neg = parsed.getlayer(NegotiateAlgorithmsPacket)
        assert neg.base_hash_algo == BaseHashAlgo.SHA_256

    def test_algorithms_response_dissected_from_transport(self):
        transport = TransportHdr(msg_type=MsgTypes.SPDM, dst=0x20, src=0x10, som=True, eom=True, to=False)
        spdm_hdr = SpdmHdrPacket(
            spdm_version=0x11, request_response_code=SpdmResponseCode.ALGORITHMS,
        )
        alg = AlgorithmsResponse(
            base_hash_sel=BaseHashAlgo.SHA_256,
            base_asym_sel=BaseAsymAlgo.ECDSA_P256,
            measurement_hash_algo=MeasurementHashAlgo.SHA_256,
        )
        pkt = transport / spdm_hdr / alg
        raw_data = bytes(pkt)
        parsed = TransportHdrPacket(raw_data)
        assert parsed.haslayer(AlgorithmsPacket)
        a = parsed.getlayer(AlgorithmsPacket)
        assert a.base_hash_sel == BaseHashAlgo.SHA_256
        assert a.measurement_hash_algo == MeasurementHashAlgo.SHA_256


class TestAlgorithmEnums:
    def test_base_asym_algo_values(self):
        assert BaseAsymAlgo.RSASSA_2048 == 0x01
        assert BaseAsymAlgo.ECDSA_P256 == 0x10
        assert BaseAsymAlgo.ECDSA_P384 == 0x80
        assert BaseAsymAlgo.ECDSA_P521 == 0x100
        assert BaseAsymAlgo.EDDSA_25519 == 0x400
        assert BaseAsymAlgo.EDDSA_448 == 0x800

    def test_base_hash_algo_values(self):
        assert BaseHashAlgo.SHA_256 == 0x01
        assert BaseHashAlgo.SHA_384 == 0x02
        assert BaseHashAlgo.SHA_512 == 0x04
        assert BaseHashAlgo.SM3_256 == 0x40

    def test_measurement_hash_algo_values(self):
        assert MeasurementHashAlgo.RAW_BIT_STREAM == 0x01
        assert MeasurementHashAlgo.SHA_256 == 0x02
        assert MeasurementHashAlgo.SM3_256 == 0x80
