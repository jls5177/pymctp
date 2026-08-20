# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the SPDM responder behavior."""

from __future__ import annotations

import hashlib

from scapy.plist import PacketList

from pymctp.automaton.behaviors.spdm_responder import SpdmResponderBehavior, SpdmResponderProfile
from pymctp.automaton.roles import create_endpoint
from pymctp.layers.mctp.spdm import (
    AlgorithmsPacket,
    BaseAsymAlgo,
    BaseHashAlgo,
    CapabilitiesPacket,
    CertificatePacket,
    Challenge,
    ChallengeAuthPacket,
    DigestsPacket,
    GetCapabilitiesPacket,
    GetCertificatePacket,
    GetMeasurements,
    MeasurementHashAlgo,
    MeasurementRequestAttributes,
    MeasurementSpecification,
    MeasurementSummaryHashType,
    MeasurementsPacket,
    NegotiateAlgorithmsPacket,
    ResponderCapabilityFlags,
    SpdmHdr,
    SpdmHdrPacket,
    VersionPacket,
)
from pymctp.layers.mctp.spdm.types import SpdmErrorCode, SpdmRequestCode, SpdmResponseCode
from pymctp.layers.mctp.transport import SmbusTransport, TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import EndpointContext, MsgTypes, Smbus7bitAddress


def _ctx(*, mtu_size: int = 240 - (4 + 5), supported_spdm: bool = True) -> EndpointContext:
    supported = [MsgTypes.CTRL, MsgTypes.SPDM] if supported_spdm else [MsgTypes.CTRL]
    return EndpointContext(
        physical_address=Smbus7bitAddress(0x10),
        assigned_eid=0x10,
        mtu_size=mtu_size,
        supported_msg_types=supported,
    )


def _request(
    request_code: int,
    payload=None,
    *,
    spdm_version: int = 0x10,
    param1: int = 0,
    param2: int = 0,
    to: bool = True,
):
    transport = TransportHdr(
        msg_type=MsgTypes.SPDM,
        dst=0x10,
        src=0x20,
        som=True,
        eom=True,
        to=to,
        tag=3,
    )
    spdm = SpdmHdr(spdm_version=spdm_version, request_response_code=request_code, param1=param1, param2=param2)
    spdm_payload = spdm / payload if payload is not None else spdm
    pkt = SmbusTransport(dst_addr=Smbus7bitAddress(0x10), src_addr=Smbus7bitAddress(0x20), load=transport / spdm_payload)
    return SmbusTransport(bytes(pkt))


def _get_reply(behavior: SpdmResponderBehavior, pkt, ctx: EndpointContext) -> PacketList:
    response = behavior.handle(pkt, ctx)
    assert response is not None
    assert response.stop_processing is True
    assert isinstance(response.reply, PacketList)
    return response.reply


def _single_spdm(reply: PacketList) -> SpdmHdrPacket:
    assert len(reply) == 1
    pkt = SmbusTransport(bytes(reply[0]))
    spdm = pkt.getlayer(SpdmHdrPacket)
    assert spdm is not None
    return spdm


def _spdm_payload_bytes(reply: PacketList) -> bytes:
    chunks = []
    for fragment in reply:
        pkt = SmbusTransport(bytes(fragment))
        transport = pkt.getlayer(TransportHdrPacket)
        assert transport is not None
        chunks.append(bytes(transport.payload))
    return b"".join(chunks)


def _challenge_body(spdm: SpdmHdrPacket) -> bytes:
    auth = spdm.getlayer(ChallengeAuthPacket)
    assert auth is not None
    return bytes(auth.payload)


def _measurements_body(spdm: SpdmHdrPacket) -> bytes:
    measurements = spdm.getlayer(MeasurementsPacket)
    assert measurements is not None
    return bytes(measurements.payload)


def _measurement_block(index: int, value: bytes, measurement_specification: int = MeasurementSpecification.DMTF) -> bytes:
    return bytes([index, int(measurement_specification)]) + len(value).to_bytes(2, "little") + value


def _negotiate_spdm(
    behavior: SpdmResponderBehavior,
    ctx: EndpointContext,
    *,
    spdm_version: int = 0x12,
    certificate: bytes = b"slot-zero-cert",
) -> None:
    _get_reply(behavior, _request(SpdmRequestCode.GET_VERSION), ctx)
    _get_reply(
        behavior,
        _request(
            SpdmRequestCode.GET_CAPABILITIES,
            GetCapabilitiesPacket(ct_exponent=1, flags=0xAA, data_transfer_size=0x80, max_spdm_msg_size=0x90),
            spdm_version=spdm_version,
        ),
        ctx,
    )
    _get_reply(
        behavior,
        _request(
            SpdmRequestCode.NEGOTIATE_ALGORITHMS,
            NegotiateAlgorithmsPacket(
                measurement_specification=MeasurementSpecification.DMTF,
                base_asym_algo=BaseAsymAlgo.ECDSA_P384,
                base_hash_algo=BaseHashAlgo.SHA_384,
            ),
            spdm_version=spdm_version,
        ),
        ctx,
    )
    _get_reply(behavior, _request(SpdmRequestCode.GET_DIGESTS, spdm_version=spdm_version), ctx)
    _get_reply(
        behavior,
        _request(
            SpdmRequestCode.GET_CERTIFICATE,
            GetCertificatePacket(offset=0, length=len(certificate)),
            spdm_version=spdm_version,
            param1=0,
        ),
        ctx,
    )


def test_role_registration_create_endpoint_and_options() -> None:
    ctx = _ctx()
    am = create_endpoint(
        (
            "spdm-responder",
            {
                "profile": {"versions": [0x12], "slot_mask": 0x02},
                "ct_exponent": 3,
            },
        ),
        context=ctx,
    )

    behavior = am.get_behavior("spdm-responder")

    assert am.role == ["spdm-responder"]
    assert isinstance(behavior, SpdmResponderBehavior)
    assert behavior.profile.versions == [0x12]
    assert behavior.profile.slot_mask == 0x02
    assert behavior.profile.ct_exponent == 3


def test_can_handle_claims_only_supported_spdm_requests() -> None:
    behavior = SpdmResponderBehavior()
    request = _request(SpdmRequestCode.GET_VERSION)
    response = _request(SpdmResponseCode.VERSION, to=False)

    assert behavior.can_handle(request, _ctx()) is True
    assert behavior.can_handle(response, _ctx()) is False
    assert behavior.can_handle(request, _ctx(supported_spdm=False)) is False


def test_get_version_returns_configured_version_list_and_resets_state() -> None:
    ctx = _ctx()
    behavior = SpdmResponderBehavior(profile={"versions": [0x10, 0x12]})
    ctx.msg_type_context[behavior.name]["negotiated"] = {"version": 0x12}
    pkt = _request(SpdmRequestCode.GET_VERSION)

    spdm = _single_spdm(_get_reply(behavior, pkt, ctx))
    version = spdm.getlayer(VersionPacket)

    assert spdm.spdm_version == 0x10
    assert spdm.request_response_code == SpdmResponseCode.VERSION
    assert version.version_number_list == [0x1000, 0x1200]
    assert ctx.msg_type_context[behavior.name]["negotiated"] == {}


def test_get_capabilities_returns_profile_fields_for_v10_and_v12() -> None:
    flags = int(ResponderCapabilityFlags.CERT_CAP | ResponderCapabilityFlags.CHUNK_CAP)
    behavior = SpdmResponderBehavior(ct_exponent=0x0C, flags=flags, data_transfer_size=0x1000, max_spdm_msg_size=0x2000)
    ctx = _ctx()

    v12_request = _request(
        SpdmRequestCode.GET_CAPABILITIES,
        GetCapabilitiesPacket(ct_exponent=1, flags=0xAA, data_transfer_size=0x80, max_spdm_msg_size=0x90),
        spdm_version=0x12,
    )
    v12_spdm = _single_spdm(_get_reply(behavior, v12_request, ctx))
    v12_caps = v12_spdm.getlayer(CapabilitiesPacket)

    v10_request = _request(SpdmRequestCode.GET_CAPABILITIES, GetCapabilitiesPacket(), spdm_version=0x10)
    v10_spdm = _single_spdm(_get_reply(behavior, v10_request, ctx))
    v10_caps = v10_spdm.getlayer(CapabilitiesPacket)

    assert v12_caps.ct_exponent == 0x0C
    assert v12_caps.flags == flags
    assert v12_caps.data_transfer_size == 0x1000
    assert v12_caps.max_spdm_msg_size == 0x2000
    assert v10_caps.ct_exponent == 0x0C
    assert v10_caps.flags == flags
    assert v10_caps.data_transfer_size is None
    assert v10_caps.max_spdm_msg_size is None


def test_negotiate_algorithms_returns_profile_and_records_negotiated_state() -> None:
    behavior = SpdmResponderBehavior(
        measurement_specification=MeasurementSpecification.DMTF,
        measurement_hash_algo=MeasurementHashAlgo.SHA_256,
        base_asym_algo=BaseAsymAlgo.ECDSA_P256,
        base_hash_algo=BaseHashAlgo.SHA_256,
        hash_size=32,
    )
    ctx = _ctx()
    pkt = _request(
        SpdmRequestCode.NEGOTIATE_ALGORITHMS,
        NegotiateAlgorithmsPacket(
            measurement_specification=MeasurementSpecification.DMTF,
            base_asym_algo=BaseAsymAlgo.ECDSA_P256 | BaseAsymAlgo.ECDSA_P384,
            base_hash_algo=BaseHashAlgo.SHA_256 | BaseHashAlgo.SHA_384,
        ),
        spdm_version=0x12,
    )

    spdm = _single_spdm(_get_reply(behavior, pkt, ctx))
    algorithms = spdm.getlayer(AlgorithmsPacket)

    assert spdm.request_response_code == SpdmResponseCode.ALGORITHMS
    assert algorithms.measurement_specification_sel == MeasurementSpecification.DMTF
    assert algorithms.measurement_hash_algo == MeasurementHashAlgo.SHA_256
    assert algorithms.base_asym_sel == BaseAsymAlgo.ECDSA_P256
    assert algorithms.base_hash_sel == BaseHashAlgo.SHA_256
    assert behavior.negotiated == {
        "version": 0x12,
        "measurement_specification": int(MeasurementSpecification.DMTF),
        "measurement_hash_algo": int(MeasurementHashAlgo.SHA_256),
        "base_asym_algo": int(BaseAsymAlgo.ECDSA_P256),
        "base_hash_algo": int(BaseHashAlgo.SHA_256),
    }


def test_get_digests_returns_slot_mask_and_concatenated_digest_payload() -> None:
    chain0 = b"slot-zero-cert"
    chain2 = b"slot-two-cert"
    behavior = SpdmResponderBehavior(profile=SpdmResponderProfile(slot_mask=0x05, cert_chains={0: chain0, 2: chain2}))
    pkt = _request(SpdmRequestCode.GET_DIGESTS)

    spdm = _single_spdm(_get_reply(behavior, pkt, _ctx()))
    digests = spdm.getlayer(DigestsPacket)
    payload = bytes(digests.payload)

    assert spdm.request_response_code == SpdmResponseCode.DIGESTS
    assert spdm.param2 == 0x05
    assert len(payload) == 2 * behavior.profile.hash_size
    assert payload == hashlib.sha384(chain0).digest() + hashlib.sha384(chain2).digest()


def test_get_certificate_returns_full_chain_and_unknown_slot_error() -> None:
    chain = bytes(range(128))
    behavior = SpdmResponderBehavior(profile=SpdmResponderProfile(slot_mask=0x01, cert_chains={0: chain}))
    ctx = _ctx()

    pkt = _request(
        SpdmRequestCode.GET_CERTIFICATE,
        GetCertificatePacket(offset=0, length=len(chain)),
        param1=0,
    )
    spdm = _single_spdm(_get_reply(behavior, pkt, ctx))
    certificate = spdm.getlayer(CertificatePacket)

    unknown_slot = _request(
        SpdmRequestCode.GET_CERTIFICATE,
        GetCertificatePacket(offset=0, length=1),
        param1=1,
    )
    error = _single_spdm(_get_reply(behavior, unknown_slot, ctx))

    assert spdm.request_response_code == SpdmResponseCode.CERTIFICATE
    assert spdm.param1 == 0
    assert certificate.portion_length == len(chain)
    assert certificate.remainder_length == 0
    assert bytes(certificate.payload) == chain
    assert error.request_response_code == SpdmResponseCode.ERROR
    assert error.param1 == SpdmErrorCode.INVALID_REQUEST
    assert error.param2 == 0


def test_get_certificate_chunked_transfer_reassembles_and_remainder_decreases() -> None:
    chain = bytes(range(256)) * 3
    behavior = SpdmResponderBehavior(
        profile=SpdmResponderProfile(slot_mask=0x01, cert_chains={0: chain}, max_portion_length=100)
    )
    ctx = _ctx()
    offset = 0
    chunks = []
    remainders = []

    while offset < len(chain):
        pkt = _request(
            SpdmRequestCode.GET_CERTIFICATE,
            GetCertificatePacket(offset=offset, length=500),
            param1=0,
        )
        spdm = _single_spdm(_get_reply(behavior, pkt, ctx))
        certificate = spdm.getlayer(CertificatePacket)
        portion = bytes(certificate.payload)
        chunks.append(portion)
        remainders.append(certificate.remainder_length)
        offset += certificate.portion_length

    assert b"".join(chunks) == chain
    assert remainders == sorted(remainders, reverse=True)
    assert remainders[-1] == 0


def test_large_certificate_response_is_fragmented_and_reassembles_to_spdm_payload() -> None:
    chain = bytes(range(256)) * 8
    behavior = SpdmResponderBehavior(profile=SpdmResponderProfile(slot_mask=0x01, cert_chains={0: chain}))
    ctx = _ctx(mtu_size=128)
    pkt = _request(
        SpdmRequestCode.GET_CERTIFICATE,
        GetCertificatePacket(offset=0, length=len(chain)),
        param1=0,
    )

    reply = _get_reply(behavior, pkt, ctx)
    reassembled = SpdmHdrPacket(_spdm_payload_bytes(reply))
    certificate = reassembled.getlayer(CertificatePacket)

    assert isinstance(reply, PacketList)
    assert len(reply) > 1
    assert reassembled.request_response_code == SpdmResponseCode.CERTIFICATE
    assert certificate.portion_length == len(chain)
    assert certificate.remainder_length == 0
    assert bytes(certificate.payload) == chain


def test_challenge_and_get_measurements_before_negotiation_return_unexpected_request_error() -> None:
    behavior = SpdmResponderBehavior()
    ctx = _ctx()
    challenge = _request(SpdmRequestCode.CHALLENGE, Challenge(slot_id=0), param1=0)
    measurements = _request(
        SpdmRequestCode.GET_MEASUREMENTS,
        GetMeasurements(attributes=MeasurementRequestAttributes.GENERATE_SIGNATURE, measurement_operation=0xFF),
        spdm_version=0x11,
        param1=MeasurementRequestAttributes.GENERATE_SIGNATURE,
        param2=0xFF,
    )

    challenge_error = _single_spdm(_get_reply(behavior, challenge, ctx))
    measurements_error = _single_spdm(_get_reply(behavior, measurements, ctx))

    assert challenge_error.request_response_code == SpdmResponseCode.ERROR
    assert challenge_error.param1 == SpdmErrorCode.UNEXPECTED_REQUEST
    assert challenge_error.param2 == SpdmRequestCode.CHALLENGE
    assert measurements_error.request_response_code == SpdmResponseCode.ERROR
    assert measurements_error.param1 == SpdmErrorCode.UNEXPECTED_REQUEST
    assert measurements_error.param2 == SpdmRequestCode.GET_MEASUREMENTS & 0xFF


class TestSpdmResponderChallenge:
    def test_full_negotiation_then_challenge_succeeds_with_signature(self) -> None:
        certificate = b"slot-zero-cert"
        behavior = SpdmResponderBehavior(
            profile=SpdmResponderProfile(
                slot_mask=0x01,
                cert_chains={0: certificate},
                nonce_provider=lambda: b"N" * 32,
            )
        )
        ctx = _ctx()
        _negotiate_spdm(behavior, ctx, certificate=certificate)

        spdm = _single_spdm(
            _get_reply(
                behavior,
                _request(
                    SpdmRequestCode.CHALLENGE,
                    Challenge(nonce=b"C" * 32),
                    spdm_version=0x12,
                    param1=0,
                    param2=MeasurementSummaryHashType.NO_HASH,
                ),
                ctx,
            )
        )
        body = _challenge_body(spdm)

        assert spdm.request_response_code == SpdmResponseCode.CHALLENGE_AUTH
        assert spdm.param1 == 0
        assert spdm.param2 == 0x01
        assert body[: behavior.profile.hash_size] == hashlib.sha384(certificate).digest()
        assert body[behavior.profile.hash_size : behavior.profile.hash_size + 32] == b"N" * 32
        assert ctx.msg_type_context[behavior.name]["challenge_nonce"] == b"N" * 32
        assert len(body[-behavior.profile.signature_size :]) == behavior.profile.signature_size

    def test_challenge_with_unprovisioned_slot_returns_invalid_request(self) -> None:
        behavior = SpdmResponderBehavior(slot_mask=0x01, cert_chains={0: b"cert"}, nonce_provider=lambda: b"N" * 32)
        ctx = _ctx()
        _negotiate_spdm(behavior, ctx, certificate=b"cert")

        spdm = _single_spdm(
            _get_reply(
                behavior,
                _request(
                    SpdmRequestCode.CHALLENGE,
                    Challenge(slot_id=1),
                    spdm_version=0x12,
                    param1=1,
                ),
                ctx,
            )
        )

        assert spdm.request_response_code == SpdmResponseCode.ERROR
        assert spdm.param1 == SpdmErrorCode.INVALID_REQUEST

    def test_challenge_default_signer_is_deterministic_and_nonce_sensitive(self) -> None:
        certificate = b"slot-zero-cert"

        def challenge_response(nonce: bytes) -> bytes:
            behavior = SpdmResponderBehavior(
                slot_mask=0x01,
                cert_chains={0: certificate},
                nonce_provider=lambda: nonce,
            )
            ctx = _ctx()
            _negotiate_spdm(behavior, ctx, certificate=certificate)
            reply = _get_reply(
                behavior,
                _request(
                    SpdmRequestCode.CHALLENGE,
                    Challenge(nonce=b"C" * 32),
                    spdm_version=0x12,
                    param1=0,
                ),
                ctx,
            )
            return bytes(_single_spdm(reply))

        assert challenge_response(b"N" * 32) == challenge_response(b"N" * 32)
        assert challenge_response(b"N" * 32) != challenge_response(b"M" * 32)

    def test_challenge_custom_signer_is_invoked_and_returned(self) -> None:
        signer_inputs: list[bytes] = []
        signature = b"S" * 96

        def signer(transcript_hash: bytes) -> bytes:
            signer_inputs.append(transcript_hash)
            return signature

        behavior = SpdmResponderBehavior(
            slot_mask=0x01,
            cert_chains={0: b"cert"},
            nonce_provider=lambda: b"N" * 32,
            signer=signer,
            signature_size=len(signature),
        )
        ctx = _ctx()
        _negotiate_spdm(behavior, ctx, certificate=b"cert")

        spdm = _single_spdm(
            _get_reply(
                behavior,
                _request(SpdmRequestCode.CHALLENGE, Challenge(nonce=b"C" * 32), spdm_version=0x12),
                ctx,
            )
        )

        assert len(signer_inputs) == 1
        assert len(signer_inputs[0]) == behavior.profile.hash_size
        assert _challenge_body(spdm).endswith(signature)


class TestSpdmResponderMeasurements:
    def test_get_measurements_count_specific_index_and_all_blocks(self) -> None:
        measurements = {1: b"one", 3: b"three"}
        behavior = SpdmResponderBehavior(measurements=measurements)
        ctx = _ctx()
        _negotiate_spdm(behavior, ctx)

        count_spdm = _single_spdm(
            _get_reply(
                behavior,
                _request(
                    SpdmRequestCode.GET_MEASUREMENTS,
                    GetMeasurements(measurement_operation=0),
                    spdm_version=0x12,
                    param2=0,
                ),
                ctx,
            )
        )
        count_packet = count_spdm.getlayer(MeasurementsPacket)
        assert count_spdm.request_response_code == SpdmResponseCode.MEASUREMENTS
        assert count_spdm.param1 == 2
        assert count_packet.number_of_blocks == 0
        assert count_packet.measurement_record_length == 0

        index_spdm = _single_spdm(
            _get_reply(
                behavior,
                _request(
                    SpdmRequestCode.GET_MEASUREMENTS,
                    GetMeasurements(measurement_operation=3),
                    spdm_version=0x12,
                    param2=3,
                ),
                ctx,
            )
        )
        index_packet = index_spdm.getlayer(MeasurementsPacket)
        assert index_packet.number_of_blocks == 1
        assert index_packet.measurement_record_length == len(_measurement_block(3, b"three"))
        assert _measurements_body(index_spdm) == _measurement_block(3, b"three")

        all_spdm = _single_spdm(
            _get_reply(
                behavior,
                _request(
                    SpdmRequestCode.GET_MEASUREMENTS,
                    GetMeasurements(measurement_operation=0xFF),
                    spdm_version=0x12,
                    param2=0xFF,
                ),
                ctx,
            )
        )
        all_record = _measurement_block(1, b"one") + _measurement_block(3, b"three")
        all_packet = all_spdm.getlayer(MeasurementsPacket)
        assert all_packet.number_of_blocks == 2
        assert all_packet.measurement_record_length == len(all_record)
        assert _measurements_body(all_spdm) == all_record

    def test_get_measurements_signature_requested_bit_is_honoured(self) -> None:
        measurements = {1: b"one"}
        signature_size = 96
        behavior = SpdmResponderBehavior(
            measurements=measurements,
            cert_chains={0: b"cert"},
            nonce_provider=lambda: b"N" * 32,
            signature_size=signature_size,
        )
        ctx = _ctx()
        _negotiate_spdm(behavior, ctx, certificate=b"cert")
        record = _measurement_block(1, b"one")

        unsigned_spdm = _single_spdm(
            _get_reply(
                behavior,
                _request(
                    SpdmRequestCode.GET_MEASUREMENTS,
                    GetMeasurements(measurement_operation=1),
                    spdm_version=0x12,
                    param2=1,
                ),
                ctx,
            )
        )
        signed_spdm = _single_spdm(
            _get_reply(
                behavior,
                _request(
                    SpdmRequestCode.GET_MEASUREMENTS,
                    GetMeasurements(
                        attributes=MeasurementRequestAttributes.GENERATE_SIGNATURE,
                        measurement_operation=1,
                        nonce=b"R" * 32,
                        slot_id=0,
                        spdm_version=0x12,
                    ),
                    spdm_version=0x12,
                    param1=MeasurementRequestAttributes.GENERATE_SIGNATURE,
                    param2=1,
                ),
                ctx,
            )
        )

        assert _measurements_body(unsigned_spdm) == record
        assert _measurements_body(signed_spdm)[: len(record)] == record
        assert _measurements_body(signed_spdm)[len(record) : len(record) + 32] == b"N" * 32
        assert len(_measurements_body(signed_spdm)) == len(record) + 32 + signature_size

    def test_get_measurements_unknown_index_returns_invalid_request(self) -> None:
        behavior = SpdmResponderBehavior(measurements={1: b"one"})
        ctx = _ctx()
        _negotiate_spdm(behavior, ctx)

        spdm = _single_spdm(
            _get_reply(
                behavior,
                _request(
                    SpdmRequestCode.GET_MEASUREMENTS,
                    GetMeasurements(measurement_operation=2),
                    spdm_version=0x12,
                    param2=2,
                ),
                ctx,
            )
        )

        assert spdm.request_response_code == SpdmResponseCode.ERROR
        assert spdm.param1 == SpdmErrorCode.INVALID_REQUEST

    def test_large_measurements_response_is_fragmented_and_reassembles(self) -> None:
        measurements = {index: bytes([index]) * 96 for index in range(1, 8)}
        behavior = SpdmResponderBehavior(measurements=measurements)
        ctx = _ctx(mtu_size=128)
        _negotiate_spdm(behavior, ctx)

        reply = _get_reply(
            behavior,
            _request(
                SpdmRequestCode.GET_MEASUREMENTS,
                GetMeasurements(measurement_operation=0xFF),
                spdm_version=0x12,
                param2=0xFF,
            ),
            ctx,
        )
        reassembled = SpdmHdrPacket(_spdm_payload_bytes(reply))
        measurements_packet = reassembled.getlayer(MeasurementsPacket)
        expected_record = b"".join(_measurement_block(index, measurements[index]) for index in sorted(measurements))

        assert isinstance(reply, PacketList)
        assert len(reply) > 1
        assert reassembled.request_response_code == SpdmResponseCode.MEASUREMENTS
        assert measurements_packet.number_of_blocks == len(measurements)
        assert measurements_packet.measurement_record_length == len(expected_record)
        assert _measurements_body(reassembled) == expected_record


def test_spdm_transcripts_are_isolated_per_endpoint_context() -> None:
    certificate = b"slot-zero-cert"

    def run_sequence(behavior: SpdmResponderBehavior, ctx: EndpointContext, spdm_version: int) -> bytes:
        _negotiate_spdm(behavior, ctx, spdm_version=spdm_version, certificate=certificate)
        spdm = _single_spdm(
            _get_reply(
                behavior,
                _request(
                    SpdmRequestCode.CHALLENGE,
                    Challenge(nonce=b"C" * 32),
                    spdm_version=spdm_version,
                    param1=0,
                ),
                ctx,
            )
        )
        return _challenge_body(spdm)[-behavior.profile.signature_size :]

    shared_behavior = SpdmResponderBehavior(
        slot_mask=0x01,
        cert_chains={0: certificate},
        nonce_provider=lambda: b"N" * 32,
    )
    ctx11 = _ctx()
    ctx12 = _ctx()
    signature11 = run_sequence(shared_behavior, ctx11, 0x11)
    signature12 = run_sequence(shared_behavior, ctx12, 0x12)

    control_behavior = SpdmResponderBehavior(
        slot_mask=0x01,
        cert_chains={0: certificate},
        nonce_provider=lambda: b"N" * 32,
    )
    control_signature11 = run_sequence(control_behavior, _ctx(), 0x11)

    assert signature11 == control_signature11
    assert signature11 != signature12


def test_state_is_per_context_for_one_behavior_instance() -> None:
    behavior = SpdmResponderBehavior()
    ctx11 = _ctx()
    ctx12 = _ctx()
    request11 = _request(SpdmRequestCode.GET_CAPABILITIES, GetCapabilitiesPacket(), spdm_version=0x11)
    request12 = _request(SpdmRequestCode.GET_CAPABILITIES, GetCapabilitiesPacket(), spdm_version=0x12)

    _get_reply(behavior, request11, ctx11)
    _get_reply(behavior, request12, ctx12)

    assert ctx11.msg_type_context[behavior.name]["negotiated"]["version"] == 0x11
    assert ctx12.msg_type_context[behavior.name]["negotiated"]["version"] == 0x12
