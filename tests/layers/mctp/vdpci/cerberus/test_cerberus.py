# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from pymctp.layers.mctp.transport import TransportHdr, TransportHdrPacket, MsgTypes
from pymctp.layers.mctp.vdpci import VdPciHdrPacket, VdPciHdr, RqBit, VdPCIVendorIds
from pymctp.layers.mctp.vdpci.cerberus import (
    CerberusCmdCodes,
    CerberusErrorCodes,
    CerberusLogType,
    CerberusUpdateType,
    CerberusResetConfig,
    ErrorResponsePacket,
    FwVersionCmdPacket,
    FwVersionRequestPacket,
    FwVersionResponsePacket,
    DeviceCapsCmdPacket,
    DeviceCapsRequestPacket,
    DeviceCapsResponsePacket,
    DeviceIdCmdPacket,
    GetDeviceIdRequestPacket,
    DeviceIdResponsePacket,
    DeviceInfoCmdPacket,
    GetDeviceInfoRequestPacket,
    DeviceInfoResponsePacket,
    ExportCsrCmdPacket,
    ExportCsrRequestPacket,
    ImportCertRequestPacket,
    GetSignedCertStateRequestPacket,
    SignedCertStateResponsePacket,
    GetHostStateRequestPacket,
    HostStateResponsePacket,
    GetLogInfoRequestPacket,
    LogInfoResponsePacket,
    ReadLogRequestPacket,
    ReadLogResponsePacket,
    ClearLogRequestPacket,
    GetAttestationDataRequestPacket,
    AttestationDataResponsePacket,
    InitFwUpdateRequestPacket,
    FwUpdateRequestPacket,
    CompleteFwUpdateRequestPacket,
    GetUpdateStatusRequestPacket,
    UpdateStatusResponsePacket,
    GetExtUpdateStatusRequestPacket,
    ExtUpdateStatusResponsePacket,
    ResetConfigRequestPacket,
    GetConfigIdRequestPacket,
    ConfigIdResponsePacket,
    TriggerFwRecoveryRequestPacket,
    PrepareRecoveryImageRequestPacket,
    UpdateRecoveryImageRequestPacket,
    ActivateRecoveryImageRequestPacket,
    GetRecoveryImageVersionRequestPacket,
    RecoveryImageVersionResponsePacket,
    GetPmrRequestPacket,
    PmrResponsePacket,
    GetDigestRequestPacket,
    DigestResponsePacket,
    GetCertificateRequestPacket,
    CertificateResponsePacket,
    AttestationChallengeRequestPacket,
    AttestationChallengeResponsePacket,
    UnsealMessageRequestPacket,
    UnsealMessageResultRequestPacket,
    UnsealMessageResultResponsePacket,
    ResetCounterRequestPacket,
    ResetCounterResponsePacket,
    GetManifestIdRequestPacket,
    ManifestIdResponsePacket,
    InitManifestUpdateRequestPacket,
    ManifestUpdateRequestPacket,
    CompleteManifestUpdateRequestPacket,
    UpdatePmrRequestPacket,
    UpdatePmrResponsePacket,
)


def _make_vdpci_hdr(cmd_code: int, rq: bool = True) -> VdPciHdrPacket:
    return VdPciHdr(
        rq=RqBit.REQUEST if rq else RqBit.RESPONSE,
        vendor_id=VdPCIVendorIds.Msft,
        vdm_cmd_code=cmd_code,
    )


def _make_transport_packet(cmd_code: int, rq: bool, payload_bytes: bytes) -> bytes:
    transport = TransportHdr(msg_type=MsgTypes.VDPCI, dst=0x10, src=0x20, som=True, eom=True, to=rq)
    vdpci = _make_vdpci_hdr(cmd_code, rq)
    pkt = transport / vdpci / payload_bytes
    return bytes(pkt)


class TestTypes:
    def test_cmd_codes_have_expected_values(self):
        assert CerberusCmdCodes.GET_FW_VERSION == 0x01
        assert CerberusCmdCodes.ERROR == 0x7F
        assert CerberusCmdCodes.ATTESTATION_CHALLENGE == 0x83
        assert CerberusCmdCodes.GET_EXT_UPDATE_STATUS == 0x8E

    def test_error_codes(self):
        assert CerberusErrorCodes.NO_ERROR == 0x00
        assert CerberusErrorCodes.BUSY == 0x03
        assert CerberusErrorCodes.MSG_OVERFLOW == 0xF5


class TestError:
    def test_error_response_fields(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.ERROR, rq=False)
        pkt = hdr / ErrorResponsePacket(code=0x04, data=0x12345678)
        err = pkt.getlayer(ErrorResponsePacket)
        assert err.code == 0x04
        assert err.data == 0x12345678

    def test_error_response_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.ERROR, rq=False)
        pkt = hdr / ErrorResponsePacket(code=CerberusErrorCodes.UNSPECIFIED, data=0)
        summary, _ = pkt.getlayer(ErrorResponsePacket).mysummary()
        assert "UNSPECIFIED" in summary

    def test_error_dissected_from_transport(self):
        raw = _make_transport_packet(CerberusCmdCodes.ERROR, False, bytes([0x04, 0x00, 0x00, 0x00, 0x00]))
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(ErrorResponsePacket)


class TestFwVersion:
    def test_request_fields(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_FW_VERSION)
        pkt = hdr / FwVersionRequestPacket(area_index=1)
        assert pkt.getlayer(FwVersionRequestPacket).area_index == 1

    def test_request_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_FW_VERSION)
        pkt = hdr / FwVersionRequestPacket(area_index=0)
        summary, _ = pkt.getlayer(FwVersionRequestPacket).mysummary()
        assert "area=0" in summary

    def test_response_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_FW_VERSION, rq=False)
        pkt = hdr / FwVersionResponsePacket(version=b"1.2.3\x00" + b"\x00" * 27)
        summary, _ = pkt.getlayer(FwVersionResponsePacket).mysummary()
        assert "1.2.3" in summary

    def test_request_dissected_from_transport(self):
        raw = _make_transport_packet(CerberusCmdCodes.GET_FW_VERSION, True, bytes([0x00]))
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(FwVersionRequestPacket)

    def test_response_dissected_from_transport(self):
        raw = _make_transport_packet(CerberusCmdCodes.GET_FW_VERSION, False, b"v1.0.0" + b"\x00" * 26)
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(FwVersionResponsePacket)


class TestDeviceCapabilities:
    def test_request_fields(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_DEVICE_CAPABILITIES)
        pkt = hdr / DeviceCapsRequestPacket(max_message=4096, max_packet=256)
        req = pkt.getlayer(DeviceCapsRequestPacket)
        assert req.max_message == 4096
        assert req.max_packet == 256

    def test_response_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_DEVICE_CAPABILITIES, rq=False)
        pkt = hdr / DeviceCapsResponsePacket(
            max_message=4096, max_packet=256, device_info=0x40,
            features=0x03, pk_key_strength=0x50, enc_key_strength=0x81,
            message_timeout=10, crypto_timeout=20,
        )
        summary, _ = pkt.getlayer(DeviceCapsResponsePacket).mysummary()
        assert "max_msg=4096" in summary
        assert "crypto_to=20" in summary

    def test_dispatch_request(self):
        raw = _make_transport_packet(CerberusCmdCodes.GET_DEVICE_CAPABILITIES, True, bytes(8))
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(DeviceCapsRequestPacket)


class TestDeviceId:
    def test_response_fields(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_DEVICE_ID, rq=False)
        pkt = hdr / DeviceIdResponsePacket(
            vendor_id=0x1414, device_id=0x0001, subsystem_vid=0x1414, subsystem_id=0x0002,
        )
        rsp = pkt.getlayer(DeviceIdResponsePacket)
        assert rsp.vendor_id == 0x1414
        assert rsp.device_id == 0x0001

    def test_response_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_DEVICE_ID, rq=False)
        pkt = hdr / DeviceIdResponsePacket(vendor_id=0x1414, device_id=0x0001)
        summary, _ = pkt.getlayer(DeviceIdResponsePacket).mysummary()
        assert "vid=0x1414" in summary
        assert "did=0x0001" in summary


class TestDeviceInfo:
    def test_request_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_DEVICE_INFO)
        pkt = hdr / GetDeviceInfoRequestPacket(info_index=0)
        summary, _ = pkt.getlayer(GetDeviceInfoRequestPacket).mysummary()
        assert "index=0" in summary


class TestCertificate:
    def test_export_csr_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.EXPORT_CSR)
        pkt = hdr / ExportCsrRequestPacket(csr_index=1)
        summary, _ = pkt.getlayer(ExportCsrRequestPacket).mysummary()
        assert "index=1" in summary

    def test_import_cert_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.IMPORT_CA_SIGNED_CERT)
        pkt = hdr / ImportCertRequestPacket(cert_index=0, cert_length=256)
        summary, _ = pkt.getlayer(ImportCertRequestPacket).mysummary()
        assert "index=0" in summary
        assert "len=256" in summary

    def test_signed_cert_state_response(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_SIGNED_CERT_STATE, rq=False)
        pkt = hdr / SignedCertStateResponsePacket(cert_state=0)
        summary, _ = pkt.getlayer(SignedCertStateResponsePacket).mysummary()
        assert "state=0" in summary


class TestHostState:
    def test_request_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_HOST_STATE)
        pkt = hdr / GetHostStateRequestPacket(port_id=1)
        summary, _ = pkt.getlayer(GetHostStateRequestPacket).mysummary()
        assert "port=1" in summary

    def test_response_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_HOST_STATE, rq=False)
        pkt = hdr / HostStateResponsePacket(host_state=0x01)
        summary, _ = pkt.getlayer(HostStateResponsePacket).mysummary()
        assert "0x01" in summary


class TestLog:
    def test_log_info_response_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_LOG_INFO, rq=False)
        pkt = hdr / LogInfoResponsePacket(debug_log_length=100, attestation_log_length=200, tamper_log_length=50)
        summary, _ = pkt.getlayer(LogInfoResponsePacket).mysummary()
        assert "debug=100" in summary
        assert "attest=200" in summary
        assert "tamper=50" in summary

    def test_read_log_request_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.READ_LOG)
        pkt = hdr / ReadLogRequestPacket(log_type=CerberusLogType.ATTESTATION, offset=0x100)
        summary, _ = pkt.getlayer(ReadLogRequestPacket).mysummary()
        assert "ATTESTATION" in summary
        assert "0x00000100" in summary

    def test_clear_log_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.CLEAR_LOG)
        pkt = hdr / ClearLogRequestPacket(log_type=CerberusLogType.DEBUG)
        summary, _ = pkt.getlayer(ClearLogRequestPacket).mysummary()
        assert "DEBUG" in summary

    def test_get_attestation_data_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_ATTESTATION_DATA)
        pkt = hdr / GetAttestationDataRequestPacket(pmr_id=0, entry_id=1, offset=0)
        summary, _ = pkt.getlayer(GetAttestationDataRequestPacket).mysummary()
        assert "pmr=0" in summary
        assert "entry=1" in summary

    def test_log_info_dissected_from_transport(self):
        raw = _make_transport_packet(CerberusCmdCodes.GET_LOG_INFO, False, bytes(12))
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(LogInfoResponsePacket)

    def test_read_log_dissected_from_transport(self):
        raw = _make_transport_packet(CerberusCmdCodes.READ_LOG, True, bytes([0x01, 0x00, 0x01, 0x00, 0x00]))
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(ReadLogRequestPacket)


class TestFwUpdate:
    def test_init_fw_update_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.INIT_FW_UPDATE)
        pkt = hdr / InitFwUpdateRequestPacket(size=0x10000)
        summary, _ = pkt.getlayer(InitFwUpdateRequestPacket).mysummary()
        assert "size=65536" in summary

    def test_get_update_status_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_UPDATE_STATUS)
        pkt = hdr / GetUpdateStatusRequestPacket(update_type=CerberusUpdateType.FW_UPDATE, port_id=0)
        summary, _ = pkt.getlayer(GetUpdateStatusRequestPacket).mysummary()
        assert "FW_UPDATE" in summary

    def test_update_status_response(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_UPDATE_STATUS, rq=False)
        pkt = hdr / UpdateStatusResponsePacket(status=0x00000000)
        summary, _ = pkt.getlayer(UpdateStatusResponsePacket).mysummary()
        assert "status=0x00000000" in summary

    def test_ext_update_status_response(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_EXT_UPDATE_STATUS, rq=False)
        pkt = hdr / ExtUpdateStatusResponsePacket(status=0x01, remaining_bytes=1024)
        summary, _ = pkt.getlayer(ExtUpdateStatusResponsePacket).mysummary()
        assert "remaining=1024" in summary

    def test_update_status_dissected(self):
        raw = _make_transport_packet(CerberusCmdCodes.GET_UPDATE_STATUS, True, bytes([0x00, 0x01]))
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(GetUpdateStatusRequestPacket)


class TestConfig:
    def test_reset_config_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.RESET_CONFIG)
        pkt = hdr / ResetConfigRequestPacket(reset_type=CerberusResetConfig.RESTORE_DEFAULTS)
        summary, _ = pkt.getlayer(ResetConfigRequestPacket).mysummary()
        assert "RESTORE_DEFAULTS" in summary

    def test_get_config_id_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_CONFIG_ID)
        pkt = hdr / GetConfigIdRequestPacket(config_type=0)
        summary, _ = pkt.getlayer(GetConfigIdRequestPacket).mysummary()
        assert "type=0" in summary


class TestRecovery:
    def test_trigger_fw_recovery(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.TRIGGER_FW_RECOVERY)
        pkt = hdr / TriggerFwRecoveryRequestPacket(port_id=1)
        summary, _ = pkt.getlayer(TriggerFwRecoveryRequestPacket).mysummary()
        assert "port=1" in summary

    def test_prepare_recovery_image(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.PREPARE_RECOVERY_IMAGE)
        pkt = hdr / PrepareRecoveryImageRequestPacket(port_id=0, size=0x8000)
        summary, _ = pkt.getlayer(PrepareRecoveryImageRequestPacket).mysummary()
        assert "size=32768" in summary


class TestAttestation:
    def test_get_pmr_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_PMR)
        pkt = hdr / GetPmrRequestPacket(pmr_id=0)
        summary, _ = pkt.getlayer(GetPmrRequestPacket).mysummary()
        assert "pmr=0" in summary

    def test_get_digest_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_DIGEST)
        pkt = hdr / GetDigestRequestPacket(slot_num=0, key_algorithm=0x01)
        summary, _ = pkt.getlayer(GetDigestRequestPacket).mysummary()
        assert "slot=0" in summary
        assert "algo=0x01" in summary

    def test_get_certificate_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_CERTIFICATE)
        pkt = hdr / GetCertificateRequestPacket(slot_num=0, cert_num=1, offset=0, length=512)
        summary, _ = pkt.getlayer(GetCertificateRequestPacket).mysummary()
        assert "slot=0" in summary
        assert "cert=1" in summary
        assert "len=512" in summary

    def test_challenge_request_has_nonce(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.ATTESTATION_CHALLENGE)
        pkt = hdr / AttestationChallengeRequestPacket(slot_num=0, nonce=b"\xAB" * 32)
        req = pkt.getlayer(AttestationChallengeRequestPacket)
        assert len(req.nonce) == 32
        assert req.nonce == b"\xAB" * 32

    def test_challenge_response_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.ATTESTATION_CHALLENGE, rq=False)
        pkt = hdr / AttestationChallengeResponsePacket(
            slot_num=0, slot_mask=0x01,
            min_protocol_version=1, max_protocol_version=4,
        )
        summary, _ = pkt.getlayer(AttestationChallengeResponsePacket).mysummary()
        assert "slot=0" in summary
        assert "mask=0x01" in summary
        assert "proto=1-4" in summary

    def test_challenge_dissected_from_transport(self):
        # 34 bytes = 1 (slot) + 1 (reserved) + 32 (nonce)
        payload = bytes([0x00, 0x00]) + b"\x00" * 32
        raw = _make_transport_packet(CerberusCmdCodes.ATTESTATION_CHALLENGE, True, payload)
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(AttestationChallengeRequestPacket)


class TestMeasurements:
    def test_update_pmr_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.UPDATE_PMR)
        pkt = hdr / UpdatePmrRequestPacket(pmr_id=0)
        summary, _ = pkt.getlayer(UpdatePmrRequestPacket).mysummary()
        assert "pmr=0" in summary

    def test_reset_counter_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.RESET_COUNTER)
        pkt = hdr / ResetCounterRequestPacket(counter_type=0, port_id=1)
        summary, _ = pkt.getlayer(ResetCounterRequestPacket).mysummary()
        assert "type=0" in summary
        assert "port=1" in summary

    def test_reset_counter_response(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.RESET_COUNTER, rq=False)
        pkt = hdr / ResetCounterResponsePacket(counter=5)
        summary, _ = pkt.getlayer(ResetCounterResponsePacket).mysummary()
        assert "count=5" in summary

    def test_reset_counter_dissected(self):
        raw = _make_transport_packet(CerberusCmdCodes.RESET_COUNTER, True, bytes([0x00, 0x01]))
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(ResetCounterRequestPacket)


class TestUnseal:
    def test_unseal_request_summary(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.UNSEAL_MESSAGE)
        pkt = hdr / UnsealMessageRequestPacket(seed_type=0x01, seed_params=0x00, seed_length=64)
        summary, _ = pkt.getlayer(UnsealMessageRequestPacket).mysummary()
        assert "seed_type=0x01" in summary
        assert "seed_len=64" in summary

    def test_unseal_result_response(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.UNSEAL_MESSAGE_RESULT, rq=False)
        pkt = hdr / UnsealMessageResultResponsePacket(unseal_status=0x00)
        summary, _ = pkt.getlayer(UnsealMessageResultResponsePacket).mysummary()
        assert "status=0x00" in summary


class TestManifest:
    def test_get_pfm_id_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_PFM_ID)
        pkt = hdr / GetManifestIdRequestPacket(port_id=0, id_type=0)
        summary, _ = pkt.getlayer(GetManifestIdRequestPacket).mysummary()
        assert "PFM" in summary
        assert "port=0" in summary

    def test_get_cfm_id_request(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_CFM_ID)
        pkt = hdr / GetManifestIdRequestPacket(id_type=1)
        summary, _ = pkt.getlayer(GetManifestIdRequestPacket).mysummary()
        assert "CFM" in summary

    def test_manifest_id_response(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.GET_PFM_ID, rq=False)
        pkt = hdr / ManifestIdResponsePacket(valid=1, manifest_id=0xDEADBEEF)
        summary, _ = pkt.getlayer(ManifestIdResponsePacket).mysummary()
        assert "PFM" in summary
        assert "valid=1" in summary
        assert "0xDEADBEEF" in summary

    def test_init_pfm_update_has_port_id(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.INIT_PFM_UPDATE)
        pkt = hdr / InitManifestUpdateRequestPacket(port_id=1, size=0x1000)
        summary, _ = pkt.getlayer(InitManifestUpdateRequestPacket).mysummary()
        assert "PFM" in summary
        assert "port=1" in summary
        assert "size=4096" in summary

    def test_init_cfm_update_no_port_id(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.INIT_CFM_UPDATE)
        pkt = hdr / InitManifestUpdateRequestPacket(size=0x2000)
        raw = bytes(pkt.getlayer(InitManifestUpdateRequestPacket))
        # CFM has no port_id, so should be 4 bytes (size only)
        assert len(raw) == 4

    def test_complete_pfm_update_has_activation(self):
        hdr = _make_vdpci_hdr(CerberusCmdCodes.COMPLETE_PFM_UPDATE)
        pkt = hdr / CompleteManifestUpdateRequestPacket(port_id=0, activation=1)
        summary, _ = pkt.getlayer(CompleteManifestUpdateRequestPacket).mysummary()
        assert "PFM" in summary
        assert "activation=1" in summary


class TestWireDataDissection:
    """Tests using actual captured wire data to verify end-to-end dissection."""

    def test_get_device_capabilities_request_from_wire(self):
        # 0140 0ac8 7e14 1400 0200 10f7 0082 00df 02
        raw = bytes.fromhex("01400ac87e1414000200 10f7008200df02".replace(" ", ""))
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(VdPciHdrPacket)
        assert parsed.haslayer(DeviceCapsRequestPacket)
        vdpci = parsed.getlayer(VdPciHdrPacket)
        assert vdpci.vendor_id == VdPCIVendorIds.Msft
        assert vdpci.vdm_cmd_code == CerberusCmdCodes.GET_DEVICE_CAPABILITIES
        caps = parsed.getlayer(DeviceCapsRequestPacket)
        assert caps.max_message == 4096
        assert caps.max_packet == 247
        assert caps.device_info == 0x82
        assert caps.pk_key_strength == 0xDF
        assert caps.enc_key_strength == 0x02

    def test_get_device_capabilities_response_from_wire(self):
        # 010a 40c0 7e14 1400 0200 10f7 0026 a0d7 0264 0a
        raw = bytes.fromhex("010a40c07e1414000200 10f70026a0d702640a".replace(" ", ""))
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(DeviceCapsResponsePacket)
        caps = parsed.getlayer(DeviceCapsResponsePacket)
        assert caps.max_message == 4096
        assert caps.max_packet == 247
        assert caps.device_info == 0x26
        assert caps.features == 0xA0
        assert caps.pk_key_strength == 0xD7
        assert caps.enc_key_strength == 0x02
        assert caps.message_timeout == 100
        assert caps.crypto_timeout == 10

    def test_get_device_id_request_from_wire(self):
        # 0140 0ac8 7e14 1400 03
        raw = bytes.fromhex("01400ac87e14140003")
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(VdPciHdrPacket)
        assert parsed.haslayer(GetDeviceIdRequestPacket)
        vdpci = parsed.getlayer(VdPciHdrPacket)
        assert vdpci.vdm_cmd_code == CerberusCmdCodes.GET_DEVICE_ID

    def test_get_device_id_response_from_wire(self):
        # 010a 40c0 7e14 1400 0314 1402 0014 1403 00
        raw = bytes.fromhex("010a40c07e141400031414020014140300")
        parsed = TransportHdrPacket(raw)
        assert parsed.haslayer(DeviceIdResponsePacket)
        dev_id = parsed.getlayer(DeviceIdResponsePacket)
        assert dev_id.vendor_id == 0x1414
        assert dev_id.device_id == 0x0002
        assert dev_id.subsystem_vid == 0x1414
        assert dev_id.subsystem_id == 0x0003
