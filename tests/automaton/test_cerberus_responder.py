# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the Cerberus Challenge Protocol responder behavior."""

from __future__ import annotations

import hashlib

from scapy.plist import PacketList

from pymctp.automaton.behaviors.cerberus_responder import (
    CerberusChallengeBehavior,
    CerberusResponderProfile,
    ComponentAttestation,
)
from pymctp.automaton.roles import create_endpoint, get_behaviors_for_roles
from pymctp.layers.mctp.transport import SmbusTransport, TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import EndpointContext, MsgTypes, Smbus7bitAddress
from pymctp.layers.mctp.vdpci import VdPCIVendorIds
from pymctp.layers.mctp.vdpci.cerberus import (
    AttestationChallengeRequestPacket,
    AttestationChallengeResponsePacket,
    AttestationDataResponsePacket,
    CerberusCmdCodes,
    CerberusErrorCodes,
    CerberusLogType,
    CertificateResponsePacket,
    ClearLogRequestPacket,
    ComponentAttestStatus,
    DeviceCapsRequestPacket,
    DeviceCapsResponsePacket,
    DeviceIdResponsePacket,
    DeviceInfoResponsePacket,
    DigestResponsePacket,
    ErrorResponsePacket,
    ExportCsrRequestPacket,
    FwVersionRequestPacket,
    FwVersionResponsePacket,
    GetCertificateRequestPacket,
    GetAttestationDataRequestPacket,
    GetDeviceIdRequestPacket,
    GetDeviceInfoRequestPacket,
    GetDigestRequestPacket,
    GetLogInfoRequestPacket,
    GetManifestIdRequestPacket,
    LogInfoResponsePacket,
    ManifestIdResponsePacket,
    ReadLogRequestPacket,
)
from pymctp.layers.mctp.vdpci.vdpci import RqBit, VdPciHdr, VdPciHdrPacket


def _ctx(*, mtu_size: int = 240 - (4 + 5), supported_vdpci: bool = True) -> EndpointContext:
    supported = [MsgTypes.CTRL, MsgTypes.VDPCI] if supported_vdpci else [MsgTypes.CTRL]
    return EndpointContext(
        physical_address=Smbus7bitAddress(0x10),
        assigned_eid=0x10,
        mtu_size=mtu_size,
        supported_msg_types=supported,
    )


def _request(
    cmd_code: int,
    payload=None,
    *,
    rq: bool = True,
    vendor_id: int = VdPCIVendorIds.Msft,
    to: bool = True,
):
    transport = TransportHdr(
        msg_type=MsgTypes.VDPCI,
        dst=0x10,
        src=0x20,
        som=True,
        eom=True,
        to=to,
        tag=3,
    )
    vdpci = VdPciHdr(
        rq=RqBit.REQUEST if rq else RqBit.RESPONSE,
        vendor_id=vendor_id,
        vdm_cmd_code=cmd_code,
    )
    vdpci_payload = vdpci / payload if payload is not None else vdpci
    pkt = SmbusTransport(dst_addr=Smbus7bitAddress(0x10), src_addr=Smbus7bitAddress(0x20), load=transport / vdpci_payload)
    return SmbusTransport(bytes(pkt))


def _get_reply(behavior: CerberusChallengeBehavior, pkt, ctx: EndpointContext) -> PacketList:
    response = behavior.handle(pkt, ctx)
    assert response is not None
    assert response.stop_processing is True
    assert isinstance(response.reply, PacketList)
    return response.reply


def _single_vdpci(reply: PacketList) -> VdPciHdrPacket:
    assert len(reply) == 1
    pkt = SmbusTransport(bytes(reply[0]))
    vdpci = pkt.getlayer(VdPciHdrPacket)
    assert vdpci is not None
    return vdpci


def _vdpci_payload_bytes(reply: PacketList) -> bytes:
    chunks = []
    for fragment in reply:
        pkt = SmbusTransport(bytes(fragment))
        transport = pkt.getlayer(TransportHdrPacket)
        assert transport is not None
        chunks.append(bytes(transport.payload))
    return b"".join(chunks)


def _reassembled_vdpci(reply: PacketList) -> VdPciHdrPacket:
    return VdPciHdrPacket(_vdpci_payload_bytes(reply))


def _response_payload(reply: PacketList) -> bytes:
    return bytes(_reassembled_vdpci(reply).payload)


def _raw_response_payload(reply: PacketList) -> bytes:
    return _vdpci_payload_bytes(reply)[4:]


def test_role_registration_create_endpoint_and_options() -> None:
    ctx = _ctx()
    behaviors = get_behaviors_for_roles("cerberus-rot")
    am = create_endpoint(
        (
            "cerberus-rot",
            {
                "profile": {"fw_versions": {0: "factory"}},
                "max_message_size": 0x2000,
            },
        ),
        context=ctx,
    )

    behavior = am.get_behavior("cerberus-rot")

    assert len(behaviors) == 1
    assert isinstance(behaviors[0], CerberusChallengeBehavior)
    assert am.role == ["cerberus-rot"]
    assert isinstance(behavior, CerberusChallengeBehavior)
    assert behavior.profile.fw_versions == {0: "factory"}
    assert behavior.profile.max_message_size == 0x2000


def test_can_handle_claims_only_supported_cerberus_requests() -> None:
    behavior = CerberusChallengeBehavior()
    request = _request(CerberusCmdCodes.GET_DEVICE_ID, GetDeviceIdRequestPacket())
    response = _request(CerberusCmdCodes.GET_DEVICE_ID, DeviceIdResponsePacket(), rq=False, to=False)
    other_vendor = _request(CerberusCmdCodes.GET_DEVICE_ID, GetDeviceIdRequestPacket(), vendor_id=VdPCIVendorIds.Intel)

    assert behavior.can_handle(request, _ctx()) is True
    assert behavior.can_handle(response, _ctx()) is False
    assert behavior.can_handle(other_vendor, _ctx()) is False
    assert behavior.can_handle(request, _ctx(supported_vdpci=False)) is False


def test_get_device_capabilities_returns_profile_fields() -> None:
    behavior = CerberusChallengeBehavior(
        max_message_size=0x1234,
        max_packet_size=0x00F7,
        device_info_flags=0x26,
        features=0xA0,
        pk_key_strength=0xD7,
        enc_key_strength=0x02,
        message_timeout=0x64,
        crypto_timeout=0x0A,
    )
    pkt = _request(
        CerberusCmdCodes.GET_DEVICE_CAPABILITIES,
        DeviceCapsRequestPacket(max_message=4096, max_packet=247),
    )

    vdpci = _single_vdpci(_get_reply(behavior, pkt, _ctx()))
    caps = vdpci.getlayer(DeviceCapsResponsePacket)

    assert vdpci.vendor_id == VdPCIVendorIds.Msft
    assert vdpci.vdm_cmd_code == CerberusCmdCodes.GET_DEVICE_CAPABILITIES
    assert caps.max_message == 0x1234
    assert caps.max_packet == 0x00F7
    assert caps.device_info == 0x26
    assert caps.features == 0xA0
    assert caps.pk_key_strength == 0xD7
    assert caps.enc_key_strength == 0x02
    assert caps.message_timeout == 0x64
    assert caps.crypto_timeout == 0x0A


def test_get_device_id_device_info_and_fw_version_return_configured_values() -> None:
    behavior = CerberusChallengeBehavior(
        profile=CerberusResponderProfile(
            device_id={
                "vendor_id": 0x1414,
                "device_id": 0x1001,
                "subsystem_vid": 0x1AF4,
                "subsystem_id": 0x2002,
            },
            device_info={0: "GPU iRoT", 1: b"Azure HSM"},
            fw_versions={0: "1.2.3", 2: "recovery"},
        )
    )
    ctx = _ctx()

    dev_id = _single_vdpci(
        _get_reply(behavior, _request(CerberusCmdCodes.GET_DEVICE_ID, GetDeviceIdRequestPacket()), ctx)
    ).getlayer(DeviceIdResponsePacket)
    info = _single_vdpci(
        _get_reply(behavior, _request(CerberusCmdCodes.GET_DEVICE_INFO, GetDeviceInfoRequestPacket(info_index=1)), ctx)
    ).getlayer(DeviceInfoResponsePacket)
    fw = _single_vdpci(
        _get_reply(behavior, _request(CerberusCmdCodes.GET_FW_VERSION, FwVersionRequestPacket(area_index=2)), ctx)
    ).getlayer(FwVersionResponsePacket)

    assert dev_id.vendor_id == 0x1414
    assert dev_id.device_id == 0x1001
    assert dev_id.subsystem_vid == 0x1AF4
    assert dev_id.subsystem_id == 0x2002
    assert bytes(info.payload) == b"Azure HSM"
    assert fw.version.rstrip(b"\x00") == b"recovery"


def test_get_digest_returns_configured_and_derived_digest() -> None:
    chain = b"certificate-chain"
    configured_digest = b"\xAB" * 48
    behavior = CerberusChallengeBehavior(
        profile=CerberusResponderProfile(slot_mask=0x03, cert_chains={0: chain}, digests={1: configured_digest})
    )
    ctx = _ctx()

    derived = _single_vdpci(
        _get_reply(behavior, _request(CerberusCmdCodes.GET_DIGEST, GetDigestRequestPacket(slot_num=0)), ctx)
    ).getlayer(DigestResponsePacket)
    configured = _single_vdpci(
        _get_reply(behavior, _request(CerberusCmdCodes.GET_DIGEST, GetDigestRequestPacket(slot_num=1)), ctx)
    ).getlayer(DigestResponsePacket)

    assert derived.num_digests == 1
    assert bytes(derived.payload) == hashlib.sha384(chain).digest()
    assert configured.num_digests == 1
    assert bytes(configured.payload) == configured_digest


def test_get_certificate_chunked_transfer_reassembles_to_original_chain() -> None:
    chain = bytes(range(256)) * 3
    behavior = CerberusChallengeBehavior(
        profile=CerberusResponderProfile(slot_mask=0x01, cert_chains={0: chain}, max_cert_chunk_size=100)
    )
    ctx = _ctx()
    offset = 0
    chunks = []

    while offset < len(chain):
        pkt = _request(
            CerberusCmdCodes.GET_CERTIFICATE,
            GetCertificateRequestPacket(slot_num=0, cert_num=1, offset=offset, length=500),
        )
        certificate = _single_vdpci(_get_reply(behavior, pkt, ctx)).getlayer(CertificateResponsePacket)
        chunk = bytes(certificate.payload)
        chunks.append(chunk)
        offset += len(chunk)

    assert b"".join(chunks) == chain
    assert len(chunks[-1]) == len(chain) % 100
    assert ctx.msg_type_context[behavior.name]["cert_transfer"]["remainder_length"] == 0


def test_large_certificate_response_is_fragmented_and_reassembles_to_cerberus_payload() -> None:
    chain = bytes(range(256)) * 8
    behavior = CerberusChallengeBehavior(profile=CerberusResponderProfile(slot_mask=0x01, cert_chains={0: chain}))
    ctx = _ctx(mtu_size=128)
    pkt = _request(
        CerberusCmdCodes.GET_CERTIFICATE,
        GetCertificateRequestPacket(slot_num=0, cert_num=0, offset=0, length=len(chain)),
    )

    reply = _get_reply(behavior, pkt, ctx)
    reassembled = VdPciHdrPacket(_vdpci_payload_bytes(reply))
    certificate = reassembled.getlayer(CertificateResponsePacket)

    assert isinstance(reply, PacketList)
    assert len(reply) > 1
    assert reassembled.vdm_cmd_code == CerberusCmdCodes.GET_CERTIFICATE
    assert certificate.slot_num == 0
    assert certificate.cert_num == 0
    assert bytes(certificate.payload) == chain


def test_attestation_challenge_is_deterministic_and_nonce_dependent() -> None:
    behavior = CerberusChallengeBehavior(profile=CerberusResponderProfile(slot_mask=0x01, cert_chains={0: b"chain"}))
    ctx = _ctx()
    nonce_a = b"\xAA" * 32
    nonce_b = b"\xBB" * 32

    first = _single_vdpci(
        _get_reply(
            behavior,
            _request(CerberusCmdCodes.ATTESTATION_CHALLENGE, AttestationChallengeRequestPacket(slot_num=0, nonce=nonce_a)),
            ctx,
        )
    ).getlayer(AttestationChallengeResponsePacket)
    second = _single_vdpci(
        _get_reply(
            behavior,
            _request(CerberusCmdCodes.ATTESTATION_CHALLENGE, AttestationChallengeRequestPacket(slot_num=0, nonce=nonce_a)),
            ctx,
        )
    ).getlayer(AttestationChallengeResponsePacket)
    different = _single_vdpci(
        _get_reply(
            behavior,
            _request(CerberusCmdCodes.ATTESTATION_CHALLENGE, AttestationChallengeRequestPacket(slot_num=0, nonce=nonce_b)),
            ctx,
        )
    ).getlayer(AttestationChallengeResponsePacket)

    assert first.nonce == nonce_a
    assert bytes(first.payload) == bytes(second.payload)
    assert bytes(first.payload) != bytes(different.payload)


def test_unsupported_command_returns_error_and_endpoint_recovers() -> None:
    behavior = CerberusChallengeBehavior(fw_versions={0: "ok"})
    ctx = _ctx()
    unsupported = _request(CerberusCmdCodes.EXPORT_CSR, ExportCsrRequestPacket(csr_index=0))

    error_vdpci = _single_vdpci(_get_reply(behavior, unsupported, ctx))
    error = error_vdpci.getlayer(ErrorResponsePacket)
    fw = _single_vdpci(
        _get_reply(behavior, _request(CerberusCmdCodes.GET_FW_VERSION, FwVersionRequestPacket(area_index=0)), ctx)
    ).getlayer(FwVersionResponsePacket)

    assert error_vdpci.vdm_cmd_code == CerberusCmdCodes.ERROR
    assert error.code == CerberusErrorCodes.INVALID_REQ
    assert fw.version.rstrip(b"\x00") == b"ok"


def test_state_is_per_context_for_one_behavior_instance() -> None:
    behavior = CerberusChallengeBehavior(fw_versions={1: "ctx1", 2: "ctx2"})
    ctx1 = _ctx()
    ctx2 = _ctx()

    _get_reply(behavior, _request(CerberusCmdCodes.GET_FW_VERSION, FwVersionRequestPacket(area_index=1)), ctx1)
    _get_reply(behavior, _request(CerberusCmdCodes.GET_FW_VERSION, FwVersionRequestPacket(area_index=2)), ctx2)

    assert ctx1.msg_type_context[behavior.name]["last_fw_area"] == 1
    assert ctx2.msg_type_context[behavior.name]["last_fw_area"] == 2


def _utility_components() -> list[ComponentAttestation]:
    return [
        ComponentAttestation(component_id=0x100, status=ComponentAttestStatus.INTERRUPTED),
        ComponentAttestation(component_id=0x101, status=0x0A),
        ComponentAttestation(component_id=0x102, status=ComponentAttestStatus.AUTHENTICATED),
        ComponentAttestation(component_id=0x103, status=ComponentAttestStatus.AUTHENTICATED),
        ComponentAttestation(component_id=0x104, status=ComponentAttestStatus.AUTHENTICATED),
    ]


def _decoded_v2_statuses(response: AttestationDataResponsePacket) -> list[tuple[int, list[int]]]:
    data = bytes(response.status_data)
    decoded: list[tuple[int, list[int]]] = []
    pos = 0
    while pos + 5 <= len(data):
        component_id = int.from_bytes(data[pos : pos + 4], "little")
        count = data[pos + 4]
        statuses = list(data[pos + 5 : pos + 5 + count])
        decoded.append((component_id, statuses))
        pos += 5 + count
    return decoded


class TestCerberusUtilityFlow:
    def test_get_log_info_returns_configured_lengths(self) -> None:
        behavior = CerberusChallengeBehavior(
            profile=CerberusResponderProfile(
                debug_log=b"D" * 35000,
                attestation_log=b"A" * 5082,
                tamper_log=b"",
            )
        )

        info = _single_vdpci(
            _get_reply(behavior, _request(CerberusCmdCodes.GET_LOG_INFO, GetLogInfoRequestPacket()), _ctx())
        ).getlayer(LogInfoResponsePacket)

        assert info.debug_log_length == 35000
        assert info.attestation_log_length == 5082
        assert info.tamper_log_length == 0

    def test_read_log_slices_offsets_empty_and_errors_unknown_type(self) -> None:
        log = bytes(i % 256 for i in range(600))
        behavior = CerberusChallengeBehavior(profile=CerberusResponderProfile(attestation_log=log, max_log_chunk=242))
        ctx = _ctx()

        first = _raw_response_payload(
            _get_reply(
                behavior,
                _request(
                    CerberusCmdCodes.READ_LOG,
                    ReadLogRequestPacket(log_type=CerberusLogType.ATTESTATION, offset=0),
                ),
                ctx,
            )
        )
        middle = _raw_response_payload(
            _get_reply(
                behavior,
                _request(
                    CerberusCmdCodes.READ_LOG,
                    ReadLogRequestPacket(log_type=CerberusLogType.ATTESTATION, offset=123),
                ),
                ctx,
            )
        )
        past_end = _raw_response_payload(
            _get_reply(
                behavior,
                _request(
                    CerberusCmdCodes.READ_LOG,
                    ReadLogRequestPacket(log_type=CerberusLogType.ATTESTATION, offset=len(log) + 1),
                ),
                ctx,
            )
        )
        error = _single_vdpci(
            _get_reply(
                behavior,
                _request(CerberusCmdCodes.READ_LOG, ReadLogRequestPacket(log_type=0xFE, offset=0)),
                ctx,
            )
        ).getlayer(ErrorResponsePacket)

        assert first == log[:242]
        assert middle == log[123 : 123 + 242]
        assert past_end == b""
        assert error.code == CerberusErrorCodes.INVALID_REQ

    def test_read_log_large_chunk_fragments_and_reassembles(self) -> None:
        log = bytes(i % 256 for i in range(512))
        behavior = CerberusChallengeBehavior(profile=CerberusResponderProfile(debug_log=log, max_log_chunk=242))
        ctx = _ctx(mtu_size=128)

        reply = _get_reply(
            behavior,
            _request(CerberusCmdCodes.READ_LOG, ReadLogRequestPacket(log_type=CerberusLogType.DEBUG, offset=0)),
            ctx,
        )

        assert isinstance(reply, PacketList)
        assert len(reply) > 1
        assert _reassembled_vdpci(reply).vdm_cmd_code == CerberusCmdCodes.READ_LOG
        assert _raw_response_payload(reply) == log[:242]

    def test_clear_log_is_per_context_and_updates_log_info(self) -> None:
        behavior = CerberusChallengeBehavior(profile=CerberusResponderProfile(debug_log=b"debug"))
        ctx1 = _ctx()
        ctx2 = _ctx()

        clear = _single_vdpci(
            _get_reply(
                behavior,
                _request(CerberusCmdCodes.CLEAR_LOG, ClearLogRequestPacket(log_type=CerberusLogType.DEBUG)),
                ctx1,
            )
        )
        info1 = _single_vdpci(
            _get_reply(behavior, _request(CerberusCmdCodes.GET_LOG_INFO, GetLogInfoRequestPacket()), ctx1)
        ).getlayer(LogInfoResponsePacket)
        info2 = _single_vdpci(
            _get_reply(behavior, _request(CerberusCmdCodes.GET_LOG_INFO, GetLogInfoRequestPacket()), ctx2)
        ).getlayer(LogInfoResponsePacket)

        assert clear.vdm_cmd_code == CerberusCmdCodes.CLEAR_LOG
        assert info1.debug_log_length == 0
        assert info2.debug_log_length == len(b"debug")

    def test_get_attestation_data_v2_round_trips_statuses_and_summary(self) -> None:
        behavior = CerberusChallengeBehavior(profile=CerberusResponderProfile(components=_utility_components()))
        response = _reassembled_vdpci(
            _get_reply(
                behavior,
                _request(
                    CerberusCmdCodes.GET_ATTESTATION_DATA,
                    GetAttestationDataRequestPacket(pmr_id=1, entry_id=4, offset=0),
                ),
                _ctx(),
            )
        ).getlayer(AttestationDataResponsePacket)
        summary = response.mysummary()[0]

        assert response.event_data == 0xE000002F
        assert response.status_version == 2
        assert _decoded_v2_statuses(response) == [
            (0x100, [ComponentAttestStatus.INTERRUPTED]),
            (0x101, [0x0A]),
            (0x102, [ComponentAttestStatus.AUTHENTICATED]),
            (0x103, [ComponentAttestStatus.AUTHENTICATED]),
            (0x104, [ComponentAttestStatus.AUTHENTICATED]),
        ]
        assert "Component-256=INTERRUPTED" in summary
        assert "Component-257=0x0A" in summary
        assert "Component-258=AUTHENTICATED" in summary

    def test_get_attestation_data_honors_offset_and_status_version_1(self) -> None:
        components = _utility_components()[:3]
        behavior_v2 = CerberusChallengeBehavior(profile=CerberusResponderProfile(components=components))
        full_v2 = _raw_response_payload(
            _get_reply(
                behavior_v2,
                _request(CerberusCmdCodes.GET_ATTESTATION_DATA, GetAttestationDataRequestPacket(offset=0)),
                _ctx(),
            )
        )
        offset_v2 = _raw_response_payload(
            _get_reply(
                behavior_v2,
                _request(CerberusCmdCodes.GET_ATTESTATION_DATA, GetAttestationDataRequestPacket(offset=6)),
                _ctx(),
            )
        )

        behavior_v1 = CerberusChallengeBehavior(
            profile=CerberusResponderProfile(attestation_status_version=1, components=components)
        )
        response_v1 = _reassembled_vdpci(
            _get_reply(
                behavior_v1,
                _request(CerberusCmdCodes.GET_ATTESTATION_DATA, GetAttestationDataRequestPacket(offset=0)),
                _ctx(),
            )
        ).getlayer(AttestationDataResponsePacket)
        offset_v1 = _raw_response_payload(
            _get_reply(
                behavior_v1,
                _request(CerberusCmdCodes.GET_ATTESTATION_DATA, GetAttestationDataRequestPacket(offset=6)),
                _ctx(),
            )
        )

        assert offset_v2 == full_v2[6 : 6 + 242]
        assert response_v1.status_version == 1
        assert bytes(response_v1.status_data) == bytes([ComponentAttestStatus.INTERRUPTED, 0x0A, 0x00])
        assert offset_v1 == bytes([0x0A, 0x00])

    def test_get_attestation_data_rejects_unknown_status_version(self) -> None:
        behavior = CerberusChallengeBehavior(
            profile=CerberusResponderProfile(attestation_status_version=3, components=_utility_components())
        )

        error = _single_vdpci(
            _get_reply(
                behavior,
                _request(CerberusCmdCodes.GET_ATTESTATION_DATA, GetAttestationDataRequestPacket(offset=0)),
                _ctx(),
            )
        ).getlayer(ErrorResponsePacket)

        assert error.code == CerberusErrorCodes.INVALID_REQ

    def test_get_pcd_id_returns_configured_manifest_and_unknown_type_errors(self) -> None:
        behavior = CerberusChallengeBehavior(
            profile=CerberusResponderProfile(manifest_ids={CerberusCmdCodes.GET_PCD_ID: (True, 0x00000007)})
        )
        ctx = _ctx()

        manifest = _single_vdpci(
            _get_reply(
                behavior,
                _request(CerberusCmdCodes.GET_PCD_ID, GetManifestIdRequestPacket(id_type=0)),
                ctx,
            )
        ).getlayer(ManifestIdResponsePacket)
        error = _single_vdpci(
            _get_reply(
                behavior,
                _request(CerberusCmdCodes.GET_PCD_ID, GetManifestIdRequestPacket(id_type=0xFF)),
                ctx,
            )
        ).getlayer(ErrorResponsePacket)

        assert manifest.valid == 1
        assert manifest.manifest_id == 0x00000007
        assert error.code == CerberusErrorCodes.INVALID_REQ

    def test_full_captured_utility_sequence_succeeds(self) -> None:
        attestation_log = bytes(i % 256 for i in range(5082))
        behavior = CerberusChallengeBehavior(
            profile=CerberusResponderProfile(
                device_id={
                    "vendor_id": 0x1414,
                    "device_id": 0x0006,
                    "subsystem_vid": 0x1414,
                    "subsystem_id": 0x0003,
                },
                debug_log=b"D" * 35000,
                attestation_log=attestation_log,
                tamper_log=b"",
                components=_utility_components(),
                manifest_ids={CerberusCmdCodes.GET_PCD_ID: (True, 0x00000007)},
            )
        )
        ctx = _ctx()

        caps = _single_vdpci(
            _get_reply(
                behavior,
                _request(
                    CerberusCmdCodes.GET_DEVICE_CAPABILITIES,
                    DeviceCapsRequestPacket(max_message=4096, max_packet=247),
                ),
                ctx,
            )
        ).getlayer(DeviceCapsResponsePacket)
        dev_id = _single_vdpci(
            _get_reply(behavior, _request(CerberusCmdCodes.GET_DEVICE_ID, GetDeviceIdRequestPacket()), ctx)
        ).getlayer(DeviceIdResponsePacket)
        pcd = _single_vdpci(
            _get_reply(behavior, _request(CerberusCmdCodes.GET_PCD_ID, GetManifestIdRequestPacket(id_type=0)), ctx)
        ).getlayer(ManifestIdResponsePacket)
        logs = _single_vdpci(
            _get_reply(behavior, _request(CerberusCmdCodes.GET_LOG_INFO, GetLogInfoRequestPacket()), ctx)
        ).getlayer(LogInfoResponsePacket)
        first_log = _raw_response_payload(
            _get_reply(
                behavior,
                _request(
                    CerberusCmdCodes.READ_LOG,
                    ReadLogRequestPacket(log_type=CerberusLogType.ATTESTATION, offset=0),
                ),
                ctx,
            )
        )
        second_log = _raw_response_payload(
            _get_reply(
                behavior,
                _request(
                    CerberusCmdCodes.READ_LOG,
                    ReadLogRequestPacket(log_type=CerberusLogType.ATTESTATION, offset=0x00000FFB),
                ),
                ctx,
            )
        )
        attest = _reassembled_vdpci(
            _get_reply(
                behavior,
                _request(
                    CerberusCmdCodes.GET_ATTESTATION_DATA,
                    GetAttestationDataRequestPacket(pmr_id=1, entry_id=4, offset=0),
                ),
                ctx,
            )
        ).getlayer(AttestationDataResponsePacket)

        assert caps.max_message == 4096
        assert dev_id.vendor_id == 0x1414
        assert dev_id.device_id == 0x0006
        assert dev_id.subsystem_vid == 0x1414
        assert dev_id.subsystem_id == 0x0003
        assert pcd.valid == 1
        assert pcd.manifest_id == 0x00000007
        assert logs.debug_log_length == 35000
        assert logs.attestation_log_length == 5082
        assert logs.tamper_log_length == 0
        assert first_log == attestation_log[:242]
        assert second_log == attestation_log[0x00000FFB : 0x00000FFB + 242]
        assert attest.event_data == 0xE000002F
        assert len(_decoded_v2_statuses(attest)) == 5


class TestRequestDetectionMatchesRealHardware:
    """The Cerberus Utility leaves the VDPCI rq bit CLEAR.

    Requests are marked by the MCTP TO bit; the utility's own writes look like
    ``0x7e 0x14 0x14 0x00 0x02 ...`` — note the ``0x00`` flags byte. Gating
    ``can_handle`` on ``rq`` alone rejected every real request, so the endpoint
    fell through to the default reply path and answered with a bare VDPCI header
    and no payload:

        Failed to connect to Cerberus device:
        [cerberus_get_device_capabilities] Unexpected response length: Expected 10 but got 0.
    """

    #: Exactly what the utility wrote (minus the leading MCTP message type).
    CAPTURED_GET_DEV_CAPS = bytes.fromhex("141400020010f7008200df02")

    def _packet(self, body: bytes, *, to: bool = True):
        pkt = SmbusTransport(
            dst_addr=Smbus7bitAddress(0x41),
            src_addr=Smbus7bitAddress(0x10),
            load=TransportHdr(
                src=0x0F, dst=0x20, som=1, eom=1, to=1 if to else 0, tag=0, msg_type=MsgTypes.VDPCI
            )
            / body,
        )
        return SmbusTransport(bytes(pkt))

    def _ctx(self):
        return EndpointContext(
            physical_address=Smbus7bitAddress(0x41),
            assigned_eid=0x20,
            supported_msg_types=[MsgTypes.CTRL, MsgTypes.VDPCI],
        )

    def test_claims_a_request_with_the_rq_bit_clear(self):
        behavior = CerberusChallengeBehavior()
        pkt = self._packet(self.CAPTURED_GET_DEV_CAPS)

        assert pkt.getlayer(VdPciHdrPacket).rq == 0, "fixture must mirror the utility's clear rq bit"
        assert behavior.can_handle(pkt, self._ctx()) is True

    def test_captured_request_gets_a_full_device_caps_body(self):
        behavior = CerberusChallengeBehavior()
        ctx = self._ctx()
        pkt = self._packet(self.CAPTURED_GET_DEV_CAPS)

        reply = behavior.handle(pkt, ctx).reply
        reply = reply[0] if isinstance(reply, (PacketList, list)) else reply

        assert reply.haslayer(DeviceCapsResponsePacket), reply.summary()
        body = bytes(reply.getlayer(DeviceCapsResponsePacket))
        # The utility requires exactly 10 bytes of DevCaps payload.
        assert len(body) == 10

    def test_still_claims_a_request_with_the_rq_bit_set(self):
        behavior = CerberusChallengeBehavior()
        body = bytes(VdPciHdr(rq=RqBit.REQUEST, vendor_id=VdPCIVendorIds.Msft,
                              vdm_cmd_code=CerberusCmdCodes.GET_DEVICE_CAPABILITIES) / DeviceCapsRequestPacket())
        assert behavior.can_handle(self._packet(body), self._ctx()) is True

    def test_does_not_claim_a_response(self):
        """A reply travelling the other way must never be claimed."""
        behavior = CerberusChallengeBehavior()
        body = bytes(
            VdPciHdr(rq=RqBit.RESPONSE, vendor_id=VdPCIVendorIds.Msft,
                     vdm_cmd_code=CerberusCmdCodes.GET_DEVICE_CAPABILITIES)
            / DeviceCapsResponsePacket()
        )
        assert behavior.can_handle(self._packet(body, to=False), self._ctx()) is False
