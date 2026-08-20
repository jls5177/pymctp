# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Cerberus Challenge Protocol responder behavior for mocked RoT endpoints.

This module intentionally does not perform real attestation cryptography.  The
default signer is a deterministic SHA-384-based mock over the request nonce and
emulated transcript data so tests and demos can assert stable responses.  Supply
``CerberusResponderProfile.signer`` to plug in different signing behavior.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, fields
import hashlib
import logging
import struct
from typing import Any

from scapy.packet import Packet

from ...layers.mctp.types import EndpointContext, MsgTypes
from ...layers.mctp.vdpci import VdPCIVendorIds
from ...layers.mctp.vdpci.cerberus import (
    AttestationChallengeRequestPacket,
    AttestationChallengeResponsePacket,
    AttestationDataResponsePacket,
    CerberusCmdCodes,
    CerberusErrorCodes,
    CerberusLogType,
    CertificateResponsePacket,
    ClearLogRequestPacket,
    ComponentAttestStatus,
    DeviceCapsResponsePacket,
    DeviceIdResponsePacket,
    DeviceInfoResponsePacket,
    DigestResponsePacket,
    ErrorResponsePacket,
    FwVersionResponsePacket,
    GetCertificateRequestPacket,
    GetAttestationDataRequestPacket,
    GetDeviceInfoRequestPacket,
    GetDigestRequestPacket,
    GetManifestIdRequestPacket,
    FwVersionRequestPacket,
    LogInfoResponsePacket,
    ManifestIdResponsePacket,
    ReadLogRequestPacket,
)
from ...layers.mctp.vdpci.vdpci import RqBit, VdPciHdr, VdPciHdrPacket
from ..sessions import HandlerResponse
from .base import Behavior
from .replies import build_layered_reply

logger = logging.getLogger(__name__)

_HASH_BY_SIZE = {
    32: hashlib.sha256,
    48: hashlib.sha384,
    64: hashlib.sha512,
}
_MOCK_SIGNATURE_CONTEXT = b"pymctp-cerberus-mock-attestation-v1"
TCG_SHA256_ALG_ID = 0x000B
TCG_SHA384_ALG_ID = 0x000C
TCG_SHA512_ALG_ID = 0x000D
_DIGEST_SIZE_BY_ALG_ID = {
    TCG_SHA256_ALG_ID: 32,
    TCG_SHA384_ALG_ID: 48,
    TCG_SHA512_ALG_ID: 64,
}
_HASH_BY_ALG_ID = {
    TCG_SHA256_ALG_ID: hashlib.sha256,
    TCG_SHA384_ALG_ID: hashlib.sha384,
    TCG_SHA512_ALG_ID: hashlib.sha512,
}


def _digest_size_for_algorithm(digest_algorithm_id: int) -> int:
    digest_size = _DIGEST_SIZE_BY_ALG_ID.get(int(digest_algorithm_id))
    if digest_size is None:
        msg = f"Unsupported TCG digest algorithm id: 0x{int(digest_algorithm_id):04x}"
        raise ValueError(msg)
    return digest_size


def _hash_factory_for_algorithm(digest_algorithm_id: int) -> Callable[[bytes], Any]:
    hash_factory = _HASH_BY_ALG_ID.get(int(digest_algorithm_id))
    if hash_factory is None:
        msg = f"Unsupported TCG digest algorithm id: 0x{int(digest_algorithm_id):04x}"
        raise ValueError(msg)
    return hash_factory


@dataclass
class AttestationLogEntry:
    """A single Cerberus attestation log entry."""

    entry_id: int
    event_type: int
    pcr_bank: int = 0
    pcr_measurement: int = 0
    measurement_index: int = 0
    digest: bytes = b""
    measurement: bytes = b""
    digest_algorithm_id: int = TCG_SHA384_ALG_ID

    def __post_init__(self) -> None:
        digest_size = _digest_size_for_algorithm(self.digest_algorithm_id)
        self.entry_id = int(self.entry_id)
        self.event_type = int(self.event_type)
        self.pcr_bank = int(self.pcr_bank)
        self.pcr_measurement = int(self.pcr_measurement)
        self.measurement_index = int(self.measurement_index)
        self.digest_algorithm_id = int(self.digest_algorithm_id)
        self.digest = _resize_bytes(bytes(self.digest), digest_size)
        self.measurement = _resize_bytes(bytes(self.measurement), digest_size)

    @property
    def measurement_type(self) -> int:
        """Packed TCG measurement type."""
        return ((self.measurement_index & 0xFFFF) << 16) | ((self.pcr_bank & 0xFF) << 8) | (
            self.pcr_measurement & 0xFF
        )

    def to_bytes(self) -> bytes:
        """Encode this entry using the Cerberus TCG log framing."""
        digest_size = _digest_size_for_algorithm(self.digest_algorithm_id)
        digest = _resize_bytes(self.digest, digest_size)
        measurement = _resize_bytes(self.measurement, digest_size)
        body = (
            struct.pack(
                "<IIIH",
                self.event_type & 0xFFFFFFFF,
                self.measurement_type & 0xFFFFFFFF,
                1,
                self.digest_algorithm_id & 0xFFFF,
            )
            + digest
            + struct.pack("<I", digest_size)
            + measurement
        )

        if self.digest_algorithm_id == TCG_SHA256_ALG_ID:
            return b"\xCA" + struct.pack("<I", self.entry_id & 0xFFFFFFFF) + body

        entry_length = 7 + len(body)
        return b"\xCB" + struct.pack("<HI", entry_length, self.entry_id & 0xFFFFFFFF) + body


class AttestationLogBuilder:
    """Builds a Cerberus attestation log, extending measurements like a PCR."""

    def __init__(self, *, digest_algorithm_id: int = TCG_SHA384_ALG_ID) -> None:
        self.digest_algorithm_id = int(digest_algorithm_id)
        _digest_size_for_algorithm(self.digest_algorithm_id)
        self._entries: list[AttestationLogEntry] = []
        self._pcr_values: dict[int, bytes] = {}

    def add_entry(
        self,
        *,
        event_type: int,
        digest: bytes,
        pcr_bank: int = 0,
        pcr_measurement: int = 0,
        measurement_index: int = 0,
        measurement: bytes | None = None,
    ) -> AttestationLogEntry:
        """Append and return an attestation log entry."""
        digest_size = _digest_size_for_algorithm(self.digest_algorithm_id)
        normalized_digest = _resize_bytes(bytes(digest), digest_size)
        normalized_measurement = (
            self.extend(pcr_bank, normalized_digest)
            if measurement is None
            else _resize_bytes(bytes(measurement), digest_size)
        )
        if measurement is not None:
            self._pcr_values[int(pcr_bank)] = normalized_measurement

        entry = AttestationLogEntry(
            entry_id=len(self._entries),
            event_type=int(event_type),
            pcr_bank=int(pcr_bank),
            pcr_measurement=int(pcr_measurement),
            measurement_index=int(measurement_index),
            digest=normalized_digest,
            measurement=normalized_measurement,
            digest_algorithm_id=self.digest_algorithm_id,
        )
        self._entries.append(entry)
        return entry

    def extend(self, pcr_bank: int, digest: bytes) -> bytes:
        """PCR extend: H(current || digest), starting from all-zero."""
        digest_size = _digest_size_for_algorithm(self.digest_algorithm_id)
        normalized_digest = _resize_bytes(bytes(digest), digest_size)
        pcr_key = int(pcr_bank)
        current = self._pcr_values.get(pcr_key, b"\x00" * digest_size)
        extended = _hash_factory_for_algorithm(self.digest_algorithm_id)(current + normalized_digest).digest()
        self._pcr_values[pcr_key] = extended
        return extended

    def to_bytes(self) -> bytes:
        """Encode all entries into a Cerberus attestation log blob."""
        return b"".join(entry.to_bytes() for entry in self._entries)

    def clear(self) -> None:
        """Remove all entries and reset PCR values."""
        self._entries.clear()
        self._pcr_values.clear()

    @property
    def entries(self) -> list[AttestationLogEntry]:
        """Return a copy of the currently built entries."""
        return list(self._entries)


@dataclass
class CerberusDeviceId:
    """PCI identifiers returned by GET_DEVICE_ID."""

    vendor_id: int = 0x1414
    device_id: int = 0x0001
    subsystem_vid: int = 0x1414
    subsystem_id: int = 0x0002


@dataclass
class ComponentAttestation:
    """Attestation status for a Cerberus component."""

    component_id: int
    status: int = ComponentAttestStatus.AUTHENTICATED
    instances: int = 1
    statuses: list[int] | None = None


@dataclass
class CerberusResponderProfile:
    """What this Cerberus RoT reports."""

    device_id: CerberusDeviceId | dict[str, int] = field(default_factory=CerberusDeviceId)
    fw_versions: dict[int, str] = field(default_factory=lambda: {0: "pymctp-cerberus"})
    device_info: dict[int, str | bytes] = field(default_factory=lambda: {0: "PyMCTP Cerberus RoT"})
    cert_chains: dict[int, bytes] = field(default_factory=dict)
    digests: dict[int, bytes] = field(default_factory=dict)
    digest_size: int = 48
    max_message_size: int = 4096
    max_packet_size: int = 247
    device_info_flags: int = 0x00
    features: int = 0x00
    pk_key_strength: int = 0x00
    enc_key_strength: int = 0x00
    message_timeout: int = 100
    crypto_timeout: int = 10
    slot_mask: int = 0x01
    min_protocol_version: int = 1
    max_protocol_version: int = 4
    measurements: bytes = b""
    max_cert_chunk_size: int | None = None
    signer: Callable[[bytes], bytes] | None = None
    attestation_event_data: int = 0xE000002F
    default_event_type: int = 0xE000002F
    attestation_status_version: int = 2
    components: list[ComponentAttestation] = field(default_factory=list)
    debug_log: bytes = b""
    attestation_log: bytes = b""
    attestation_log_builder: AttestationLogBuilder = field(default_factory=AttestationLogBuilder)
    tamper_log: bytes = b""
    manifest_ids: dict[int, tuple[bool, int]] = field(default_factory=dict)
    max_log_chunk: int = 242

    def __post_init__(self) -> None:
        if isinstance(self.device_id, dict):
            self.device_id = CerberusDeviceId(**self.device_id)
        self.fw_versions = {int(area): str(version) for area, version in self.fw_versions.items()}
        self.device_info = {int(index): value for index, value in self.device_info.items()}
        self.cert_chains = {int(slot): bytes(chain) for slot, chain in self.cert_chains.items()}
        self.digests = {int(slot): bytes(digest) for slot, digest in self.digests.items()}
        self.digest_size = int(self.digest_size)
        self.slot_mask = int(self.slot_mask)
        self.attestation_event_data = int(self.attestation_event_data)
        self.default_event_type = int(self.default_event_type)
        self.attestation_status_version = int(self.attestation_status_version)
        self.components = [
            component if isinstance(component, ComponentAttestation) else ComponentAttestation(**component)
            for component in self.components
        ]
        self.debug_log = bytes(self.debug_log)
        self.attestation_log = bytes(self.attestation_log)
        if isinstance(self.attestation_log_builder, dict):
            self.attestation_log_builder = AttestationLogBuilder(**self.attestation_log_builder)
        self.tamper_log = bytes(self.tamper_log)
        self.manifest_ids = {
            int(cmd): (bool(valid), int(manifest_id)) for cmd, (valid, manifest_id) in self.manifest_ids.items()
        }
        self.max_log_chunk = int(self.max_log_chunk)

    def digest_for(self, slot: int) -> bytes:
        """Return the configured or certificate-derived digest for *slot*."""
        slot = int(slot)
        if slot in self.digests:
            return _resize_bytes(self.digests[slot], self.digest_size)

        hash_factory = _HASH_BY_SIZE.get(self.digest_size, hashlib.sha384)
        return _resize_bytes(hash_factory(self.cert_chain_for(slot)).digest(), self.digest_size)

    def cert_chain_for(self, slot: int) -> bytes:
        """Return the configured certificate chain bytes for *slot*."""
        return self.cert_chains.get(int(slot), b"")

    def sign(self, transcript: bytes) -> bytes:
        """Return a signature over *transcript* using the configured or mock signer."""
        if self.signer is not None:
            return bytes(self.signer(transcript))
        return hashlib.sha384(_MOCK_SIGNATURE_CONTEXT + transcript).digest()


class CerberusChallengeBehavior(Behavior):
    """Answers basic Cerberus Challenge Protocol requests for a mocked RoT."""

    def __init__(
        self,
        *,
        profile: CerberusResponderProfile | dict[str, Any] | None = None,
        **overrides: Any,
    ) -> None:
        base_profile = self._coerce_profile(profile)
        if overrides:
            profile_fields = {item.name for item in fields(CerberusResponderProfile)}
            unknown = sorted(set(overrides) - profile_fields)
            if unknown:
                msg = f"Unknown Cerberus responder profile option(s): {', '.join(unknown)}"
                raise TypeError(msg)
            data = {item.name: getattr(base_profile, item.name) for item in fields(CerberusResponderProfile)}
            data.update(overrides)
            base_profile = CerberusResponderProfile(**data)
        self.profile = base_profile
        self._ctx: EndpointContext | None = None

    @property
    def name(self) -> str:
        return "cerberus-rot"

    def record_attestation(
        self,
        component_id: int,
        *,
        instance: int = 1,
        status: int = ComponentAttestStatus.AUTHENTICATED,
        measurements: Iterable[bytes] = (),
        event_type: int | None = None,
        ctx: EndpointContext | None = None,
    ) -> None:
        """Record component attestation status and append measurements to the context log."""
        target_ctx = ctx or self._ctx
        selected_event_type = self.profile.default_event_type if event_type is None else int(event_type)
        if target_ctx is None:
            _record_component_status(self.profile.components, component_id, instance=instance, status=status)
            builder = self.profile.attestation_log_builder
        else:
            state = self._state(target_ctx)
            _record_component_status(state["components"], component_id, instance=instance, status=status)
            builder = state["attestation_log_builder"]

        entries = [bytes(measurement) for measurement in measurements]
        if not entries:
            entries = [_hash_factory_for_algorithm(builder.digest_algorithm_id)(int(component_id).to_bytes(4, "little")).digest()]
        for measurement_index, digest in enumerate(entries):
            builder.add_entry(
                event_type=selected_event_type,
                digest=digest,
                pcr_bank=int(component_id) & 0xFF,
                pcr_measurement=max(0, int(instance) - 1) & 0xFF,
                measurement_index=measurement_index,
            )

    def on_bind(self, am: Any, ctx: EndpointContext) -> None:
        self._ctx = ctx
        self._state(ctx)

    def on_attach(self, ctx: EndpointContext) -> None:
        self._ctx = ctx
        self._state(ctx)

    def can_handle(self, pkt: Packet, ctx: EndpointContext) -> bool:
        if MsgTypes.VDPCI not in ctx.supported_msg_types:
            return False

        vdpci = pkt.getlayer(VdPciHdrPacket)
        if vdpci is None or int(vdpci.vendor_id) != int(VdPCIVendorIds.Msft):
            return False
        # The real Cerberus Utility sends its requests with the VDPCI rq bit
        # CLEAR, relying on the MCTP TO bit to mark them as requests. Testing
        # ``rq`` alone silently rejected every real request and fell through to
        # the default reply path, which emits a bare header with no payload.
        # ``is_request()`` is the same check the dissector uses for its
        # REQ/RSP rendering: rq bit, or the payload type, or the transport TO bit.
        if not vdpci.is_request():
            return False
        try:
            CerberusCmdCodes(int(vdpci.vdm_cmd_code))
        except ValueError:
            return False
        return True

    def handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse | None:
        self._ctx = ctx
        try:
            return self._handle(pkt, ctx)
        except Exception:
            logger.exception("Failed to handle Cerberus request")
            return self._reply(pkt, ctx, self._error_response(pkt, CerberusErrorCodes.UNSPECIFIED))

    def _handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        vdpci = pkt.getlayer(VdPciHdrPacket)
        if vdpci is None:
            return self._reply(pkt, ctx, self._error_response(pkt, CerberusErrorCodes.INVALID_REQ))

        cmd = CerberusCmdCodes(int(vdpci.vdm_cmd_code))
        handlers = {
            CerberusCmdCodes.GET_DEVICE_CAPABILITIES: self._get_device_capabilities,
            CerberusCmdCodes.GET_DEVICE_ID: self._get_device_id,
            CerberusCmdCodes.GET_DEVICE_INFO: self._get_device_info,
            CerberusCmdCodes.GET_FW_VERSION: self._get_fw_version,
            CerberusCmdCodes.GET_DIGEST: self._get_digest,
            CerberusCmdCodes.GET_CERTIFICATE: self._get_certificate,
            CerberusCmdCodes.ATTESTATION_CHALLENGE: self._attestation_challenge,
            CerberusCmdCodes.GET_LOG_INFO: self._get_log_info,
            CerberusCmdCodes.READ_LOG: self._read_log,
            CerberusCmdCodes.CLEAR_LOG: self._clear_log,
            CerberusCmdCodes.GET_ATTESTATION_DATA: self._get_attestation_data,
            CerberusCmdCodes.GET_PFM_ID: self._get_manifest_id,
            CerberusCmdCodes.GET_CFM_ID: self._get_manifest_id,
            CerberusCmdCodes.GET_PCD_ID: self._get_manifest_id,
        }
        handler = handlers.get(cmd)
        if handler is None:
            return self._reply(pkt, ctx, self._error_response(pkt, CerberusErrorCodes.INVALID_REQ))
        return self._reply(pkt, ctx, handler(pkt, ctx))

    def _get_device_capabilities(self, pkt: Packet, ctx: EndpointContext) -> Packet:
        self._state(ctx)["capabilities_requested"] = True
        return DeviceCapsResponsePacket(
            max_message=self.profile.max_message_size,
            max_packet=self.profile.max_packet_size,
            device_info=self.profile.device_info_flags,
            features=self.profile.features,
            pk_key_strength=self.profile.pk_key_strength,
            enc_key_strength=self.profile.enc_key_strength,
            message_timeout=self.profile.message_timeout,
            crypto_timeout=self.profile.crypto_timeout,
        )

    def _get_device_id(self, pkt: Packet, ctx: EndpointContext) -> Packet:
        self._state(ctx)["device_id_requested"] = True
        device_id = self.profile.device_id
        if isinstance(device_id, dict):
            device_id = CerberusDeviceId(**device_id)
        return DeviceIdResponsePacket(
            vendor_id=device_id.vendor_id,
            device_id=device_id.device_id,
            subsystem_vid=device_id.subsystem_vid,
            subsystem_id=device_id.subsystem_id,
        )

    def _get_device_info(self, pkt: Packet, ctx: EndpointContext) -> Packet:
        request = pkt.getlayer(GetDeviceInfoRequestPacket)
        index = _field_int(request, "info_index")
        value = self.profile.device_info.get(index, b"")
        info = value if isinstance(value, bytes) else value.encode()
        if len(info) == 1:
            info += b"\x00"
        self._state(ctx)["last_device_info_index"] = index
        payload = DeviceInfoResponsePacket()
        return payload / info if info else payload

    def _get_fw_version(self, pkt: Packet, ctx: EndpointContext) -> Packet:
        request = pkt.getlayer(FwVersionRequestPacket)
        area = _field_int(request, "area_index")
        self._state(ctx)["last_fw_area"] = area
        return FwVersionResponsePacket(version=_version_bytes(self.profile.fw_versions.get(area, "")))

    def _get_digest(self, pkt: Packet, ctx: EndpointContext) -> Packet:
        request = pkt.getlayer(GetDigestRequestPacket)
        slot = _field_int(request, "slot_num")
        if not self._slot_provisioned(slot):
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        digest = self.profile.digest_for(slot)
        self._state(ctx)["last_digest"] = {"slot": slot, "digest": digest}
        return DigestResponsePacket(num_digests=1) / digest

    def _get_certificate(self, pkt: Packet, ctx: EndpointContext) -> Packet:
        request = pkt.getlayer(GetCertificateRequestPacket)
        if request is None:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        slot = int(request.slot_num)
        cert_num = int(request.cert_num)
        if not self._slot_provisioned(slot):
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        chain = self.profile.cert_chain_for(slot)
        offset = min(max(0, int(request.offset)), len(chain))
        requested_length = max(0, int(request.length))
        remaining = len(chain) - offset
        portion_length = min(requested_length, remaining)
        if self.profile.max_cert_chunk_size is not None:
            portion_length = min(portion_length, max(0, int(self.profile.max_cert_chunk_size)))
        portion_length = _avoid_certificate_request_wire_length(portion_length)
        end = offset + portion_length
        cert_portion = chain[offset:end]

        self._state(ctx)["cert_transfer"] = {
            "slot": slot,
            "cert_num": cert_num,
            "offset": offset,
            "requested_length": requested_length,
            "portion_length": portion_length,
            "remainder_length": max(0, len(chain) - end),
        }

        payload = CertificateResponsePacket(slot_num=slot, cert_num=cert_num)
        return payload / cert_portion if cert_portion else payload

    def _attestation_challenge(self, pkt: Packet, ctx: EndpointContext) -> Packet:
        request = pkt.getlayer(AttestationChallengeRequestPacket)
        if request is None:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        slot = int(request.slot_num)
        if not self._slot_provisioned(slot):
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        nonce = bytes(request.nonce)
        digest = self.profile.digest_for(slot)
        transcript = b"".join(
            [
                bytes([slot & 0xFF]),
                nonce,
                digest,
                bytes(self.profile.measurements),
            ]
        )
        signature = self.profile.sign(transcript)
        self._state(ctx)["last_challenge"] = {
            "slot": slot,
            "nonce": nonce,
            "signature": signature,
        }

        payload = AttestationChallengeResponsePacket(
            slot_num=slot,
            slot_mask=self.profile.slot_mask,
            min_protocol_version=self.profile.min_protocol_version,
            max_protocol_version=self.profile.max_protocol_version,
            nonce=nonce,
        )
        body = bytes(self.profile.measurements) + signature
        return payload / body if body else payload

    def _get_log_info(self, pkt: Packet, ctx: EndpointContext) -> Packet:
        return LogInfoResponsePacket(
            debug_log_length=len(self._get_log(ctx, int(CerberusLogType.DEBUG)) or b""),
            attestation_log_length=len(self._get_log(ctx, int(CerberusLogType.ATTESTATION)) or b""),
            tamper_log_length=len(self._get_log(ctx, int(CerberusLogType.TAMPER)) or b""),
        )

    def _read_log(self, pkt: Packet, ctx: EndpointContext) -> Packet | bytes:
        request = pkt.getlayer(ReadLogRequestPacket)
        if request is None:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        log = self._get_log(ctx, int(request.log_type))
        if log is None:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        offset = min(max(0, int(request.offset)), len(log))
        chunk = log[offset : offset + self._max_log_chunk()]
        self._state(ctx)["last_log_read"] = {
            "log_type": int(request.log_type),
            "offset": offset,
            "length": len(chunk),
        }
        return chunk

    def _clear_log(self, pkt: Packet, ctx: EndpointContext) -> Packet | bytes:
        request = pkt.getlayer(ClearLogRequestPacket)
        if request is None:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        log_type = int(request.log_type)
        if self._get_log(ctx, log_type) is None:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        self._state(ctx)["logs"][log_type] = b""
        if log_type == int(CerberusLogType.ATTESTATION):
            self._state(ctx)["attestation_log_builder"].clear()
        self._state(ctx)["last_cleared_log_type"] = log_type
        return b""

    def _get_attestation_data(self, pkt: Packet, ctx: EndpointContext) -> Packet | bytes:
        request = pkt.getlayer(GetAttestationDataRequestPacket)
        if request is None:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)
        if int(self.profile.attestation_status_version) not in {1, 2}:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        payload = self._attestation_data_payload(ctx)
        offset = min(max(0, int(request.offset)), len(payload))
        chunk = payload[offset : offset + self._max_log_chunk()]
        self._state(ctx)["last_attestation_data"] = {
            "pmr_id": int(request.pmr_id),
            "entry_id": int(request.entry_id),
            "offset": offset,
            "length": len(chunk),
        }
        return chunk

    def _get_manifest_id(self, pkt: Packet, ctx: EndpointContext) -> Packet:
        request = pkt.getlayer(GetManifestIdRequestPacket)
        if request is None:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)
        if int(request.id_type) != 0:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        vdpci = pkt.getlayer(VdPciHdrPacket)
        if vdpci is None:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        cmd_code = int(vdpci.vdm_cmd_code)
        if cmd_code not in {
            int(CerberusCmdCodes.GET_PFM_ID),
            int(CerberusCmdCodes.GET_CFM_ID),
            int(CerberusCmdCodes.GET_PCD_ID),
        }:
            return self._error_body(CerberusErrorCodes.INVALID_REQ)

        valid, manifest_id = self.profile.manifest_ids.get(cmd_code, (True, 0))
        self._state(ctx)["last_manifest_id"] = {
            "cmd_code": cmd_code,
            "id_type": int(request.id_type),
            "valid": valid,
            "manifest_id": manifest_id,
        }
        return ManifestIdResponsePacket(valid=1 if valid else 0, manifest_id=manifest_id)

    def _reply(self, pkt: Packet, ctx: EndpointContext, payload: Packet | bytes | None) -> HandlerResponse:
        vdpci_req = pkt.getlayer(VdPciHdrPacket)
        if isinstance(payload, Packet) and payload.haslayer(ErrorResponsePacket):
            cmd_code = CerberusCmdCodes.ERROR
        else:
            cmd_code = vdpci_req.vdm_cmd_code if vdpci_req is not None else CerberusCmdCodes.ERROR
        response = VdPciHdr(
            rq=False,
            vendor_id=vdpci_req.vendor_id if vdpci_req is not None else VdPCIVendorIds.Msft,
            vdm_cmd_code=cmd_code,
        )
        if payload:
            response /= payload
        return HandlerResponse(stop_processing=True, reply=build_layered_reply(pkt, ctx, response))

    def _error_response(self, pkt: Packet, code: CerberusErrorCodes, data: int = 0) -> Packet:
        return self._error_body(code, data)

    def _error_body(self, code: CerberusErrorCodes, data: int = 0) -> Packet:
        return ErrorResponsePacket(code=int(code), data=data & 0xFFFFFFFF)

    def _slot_provisioned(self, slot: int) -> bool:
        return bool(self.profile.slot_mask & (1 << int(slot)))

    def _max_log_chunk(self) -> int:
        return max(0, int(self.profile.max_log_chunk))

    def _get_log(self, ctx: EndpointContext, log_type: int) -> bytes | None:
        state = self._state(ctx)
        log_type = int(log_type)
        log = state["logs"].get(log_type)
        if log_type == int(CerberusLogType.ATTESTATION) and log == b"":
            return state["attestation_log_builder"].to_bytes()
        return log

    def _attestation_data_payload(self, ctx: EndpointContext) -> bytes:
        components = self._state(ctx)["components"]
        status_version = int(self.profile.attestation_status_version)
        if status_version == 1:
            status_data = bytes(_first_component_status(component) for component in components)
        else:
            status_data = b"".join(_component_attestation_v2_bytes(component) for component in components)

        return bytes(
            AttestationDataResponsePacket(
                event_data=self.profile.attestation_event_data,
                status_version=status_version,
                status_data=status_data,
            )
        )

    def _state(self, ctx: EndpointContext) -> dict[str, Any]:
        state = ctx.msg_type_context[self.name]
        if not state:
            state.update(self._new_state())
        return state

    def _new_state(self) -> dict[str, Any]:
        return {
            "capabilities_requested": False,
            "device_id_requested": False,
            "last_device_info_index": None,
            "last_fw_area": None,
            "last_digest": {},
            "last_challenge": {},
            "cert_transfer": {},
            "logs": {
                int(CerberusLogType.DEBUG): bytes(self.profile.debug_log),
                int(CerberusLogType.ATTESTATION): bytes(self.profile.attestation_log),
                int(CerberusLogType.TAMPER): bytes(self.profile.tamper_log),
            },
            "attestation_log_builder": _clone_attestation_log_builder(self.profile.attestation_log_builder),
            "components": _clone_components(self.profile.components),
            "last_log_read": {},
            "last_cleared_log_type": None,
            "last_attestation_data": {},
            "last_manifest_id": {},
        }

    @staticmethod
    def _coerce_profile(profile: CerberusResponderProfile | dict[str, Any] | None) -> CerberusResponderProfile:
        if profile is None:
            return CerberusResponderProfile()
        if isinstance(profile, CerberusResponderProfile):
            return profile
        return CerberusResponderProfile(**profile)


def _resize_bytes(data: bytes, size: int) -> bytes:
    return data[:size].ljust(size, b"\x00")


def _clone_attestation_log_builder(builder: AttestationLogBuilder) -> AttestationLogBuilder:
    cloned = AttestationLogBuilder(digest_algorithm_id=builder.digest_algorithm_id)
    cloned._entries = [
        AttestationLogEntry(
            entry_id=entry.entry_id,
            event_type=entry.event_type,
            pcr_bank=entry.pcr_bank,
            pcr_measurement=entry.pcr_measurement,
            measurement_index=entry.measurement_index,
            digest=entry.digest,
            measurement=entry.measurement,
            digest_algorithm_id=entry.digest_algorithm_id,
        )
        for entry in builder.entries
    ]
    cloned._pcr_values = dict(builder._pcr_values)
    return cloned


def _clone_components(components: list[ComponentAttestation]) -> list[ComponentAttestation]:
    return [
        ComponentAttestation(
            component_id=component.component_id,
            status=component.status,
            instances=component.instances,
            statuses=list(component.statuses) if component.statuses is not None else None,
        )
        for component in components
    ]


def _record_component_status(
    components: list[ComponentAttestation],
    component_id: int,
    *,
    instance: int,
    status: int,
) -> None:
    component_id = int(component_id)
    instance = max(1, int(instance))
    status = int(status)
    for component in components:
        if int(component.component_id) == component_id:
            component.instances = max(int(component.instances), instance)
            if component.statuses is None and instance == 1:
                component.status = status
                return

            statuses = list(_component_status_bytes(component))
            if len(statuses) < instance:
                statuses.extend([int(component.status) & 0xFF] * (instance - len(statuses)))
            statuses[instance - 1] = status & 0xFF
            component.statuses = statuses
            return

    if instance == 1:
        components.append(ComponentAttestation(component_id=component_id, status=status, instances=1))
        return

    statuses = [int(ComponentAttestStatus.AUTHENTICATED) & 0xFF] * instance
    statuses[instance - 1] = status & 0xFF
    components.append(
        ComponentAttestation(component_id=component_id, status=status, instances=instance, statuses=statuses)
    )


def _version_bytes(version: str | bytes) -> bytes:
    data = version if isinstance(version, bytes) else version.encode()
    return _resize_bytes(data, 32)


def _field_int(pkt: Packet | None, name: str) -> int:
    value = getattr(pkt, name, 0)
    return 0 if value is None else int(value)


def _component_status_bytes(component: ComponentAttestation) -> bytes:
    if component.statuses is not None:
        return bytes(int(status) & 0xFF for status in component.statuses)
    return bytes([int(component.status) & 0xFF]) * max(0, int(component.instances))


def _first_component_status(component: ComponentAttestation) -> int:
    statuses = _component_status_bytes(component)
    return statuses[0] if statuses else 0


def _component_attestation_v2_bytes(component: ComponentAttestation) -> bytes:
    statuses = _component_status_bytes(component)[:0xFF]
    return int(component.component_id).to_bytes(4, "little") + bytes([len(statuses)]) + statuses


def _avoid_certificate_request_wire_length(portion_length: int) -> int:
    if portion_length != 4:
        return portion_length
    return 3
