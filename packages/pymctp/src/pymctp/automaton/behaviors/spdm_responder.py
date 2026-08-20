# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Basic stateless-ish SPDM responder behavior.

The CHALLENGE_AUTH and MEASUREMENTS signatures produced by this emulator are
deterministic mock signatures by default.  They are not cryptographically
meaningful and exist only so a requester's SPDM state machine can be exercised
end to end.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, fields
import hashlib
import logging
import os
from typing import Any

from scapy.packet import Packet

from ...layers.mctp.spdm import (
    AlgorithmsPacket,
    BaseAsymAlgo,
    BaseHashAlgo,
    CapabilitiesPacket,
    CertificatePacket,
    ChallengeAuthPacket,
    ChallengePacket,
    DigestsPacket,
    GetCapabilitiesPacket,
    GetCertificatePacket,
    GetMeasurementsPacket,
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
from ...layers.mctp.spdm.types import SpdmErrorCode, SpdmRequestCode, SpdmResponseCode
from ...layers.mctp.types import EndpointContext, MsgTypes
from ..sessions import HandlerResponse
from .base import Behavior
from .replies import build_layered_reply

logger = logging.getLogger(__name__)

_DEFAULT_RESPONDER_FLAGS = (
    ResponderCapabilityFlags.CERT_CAP | ResponderCapabilityFlags.CHAL_CAP | ResponderCapabilityFlags.MEAS_CAP_SIG
)
_HASH_BY_SIZE = {
    32: hashlib.sha256,
    48: hashlib.sha384,
    64: hashlib.sha512,
}
_HASH_BY_ALGO = {
    int(BaseHashAlgo.SHA_256): hashlib.sha256,
    int(BaseHashAlgo.SHA_384): hashlib.sha384,
    int(BaseHashAlgo.SHA_512): hashlib.sha512,
}
_SPDM_NONCE_SIZE = 32


@dataclass
class SpdmResponderProfile:
    """What this responder advertises and returns."""

    versions: list[int] = field(default_factory=lambda: [0x10, 0x11, 0x12])
    ct_exponent: int = 0
    flags: int = int(_DEFAULT_RESPONDER_FLAGS)
    data_transfer_size: int = 4096
    max_spdm_msg_size: int = 4096
    measurement_specification: int = int(MeasurementSpecification.DMTF)
    base_asym_algo: int = int(BaseAsymAlgo.ECDSA_P384)
    base_hash_algo: int = int(BaseHashAlgo.SHA_384)
    measurement_hash_algo: int = int(MeasurementHashAlgo.SHA_384)
    hash_size: int = 48
    slot_mask: int = 0x01
    cert_chains: dict[int, bytes] = field(default_factory=dict)
    digests: dict[int, bytes] = field(default_factory=dict)
    measurements: dict[int, bytes] = field(default_factory=dict)
    opaque_data: bytes = b""
    signer: Callable[[bytes], bytes] | None = None
    signature_size: int = 96
    nonce_provider: Callable[[], bytes] | None = None
    max_portion_length: int | None = None

    def __post_init__(self) -> None:
        self.versions = [int(version) for version in self.versions]
        self.cert_chains = {int(slot): bytes(chain) for slot, chain in self.cert_chains.items()}
        self.digests = {int(slot): bytes(digest) for slot, digest in self.digests.items()}
        self.measurements = {int(index): bytes(value) for index, value in self.measurements.items()}
        self.opaque_data = bytes(self.opaque_data)
        self.signature_size = int(self.signature_size)

    def digest_for(self, slot: int) -> bytes:
        """Return the configured or derived digest for a certificate slot."""
        if slot in self.digests:
            digest = self.digests[slot]
            if len(digest) == self.hash_size:
                return digest
            return digest[: self.hash_size].ljust(self.hash_size, b"\x00")

        hash_factory = _HASH_BY_SIZE.get(self.hash_size, hashlib.sha384)
        digest = hash_factory(self.cert_chain_for(slot)).digest()
        if len(digest) == self.hash_size:
            return digest
        return digest[: self.hash_size].ljust(self.hash_size, b"\x00")

    def cert_chain_for(self, slot: int) -> bytes:
        """Return the configured DER certificate chain bytes for a slot."""
        return self.cert_chains.get(slot, b"")

    @property
    def version_number_list(self) -> list[int]:
        """Return GET_VERSION entries in SPDM's 16-bit version-number encoding."""
        return [_version_number_entry(version) for version in self.versions]


class SpdmResponderBehavior(Behavior):
    """Answers basic SPDM requester commands for a mocked RoT endpoint."""

    def __init__(self, *, profile: SpdmResponderProfile | dict[str, Any] | None = None, **overrides: Any) -> None:
        base_profile = self._coerce_profile(profile)
        if overrides:
            profile_fields = {item.name for item in fields(SpdmResponderProfile)}
            unknown = sorted(set(overrides) - profile_fields)
            if unknown:
                msg = f"Unknown SPDM responder profile option(s): {', '.join(unknown)}"
                raise TypeError(msg)
            data = {item.name: getattr(base_profile, item.name) for item in fields(SpdmResponderProfile)}
            data.update(overrides)
            base_profile = SpdmResponderProfile(**data)
        self.profile = base_profile
        self._ctx: EndpointContext | None = None

    @property
    def name(self) -> str:
        return "spdm-responder"

    @property
    def negotiated(self) -> dict[str, Any]:
        """Return the negotiated state for the currently attached endpoint context."""
        if self._ctx is None:
            return {}
        state = self._state(self._ctx)
        return dict(state.get("negotiated", {}))

    def on_bind(self, am: Any, ctx: EndpointContext) -> None:
        self._ctx = ctx
        self._state(ctx)

    def on_attach(self, ctx: EndpointContext) -> None:
        self._ctx = ctx
        self._state(ctx)

    def can_handle(self, pkt: Packet, ctx: EndpointContext) -> bool:
        if MsgTypes.SPDM not in ctx.supported_msg_types:
            return False
        spdm = pkt.getlayer(SpdmHdrPacket)
        return bool(spdm is not None and spdm.is_request())

    def handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse | None:
        self._ctx = ctx
        try:
            return self._handle(pkt, ctx)
        except Exception:
            logger.exception("Failed to handle SPDM request")
            spdm = pkt.getlayer(SpdmHdrPacket)
            request_code = int(spdm.request_response_code) if spdm is not None else 0
            return self._reply(pkt, ctx, self._error_response(0x10, SpdmErrorCode.UNSPECIFIED, request_code))

    def _handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        spdm = pkt.getlayer(SpdmHdrPacket)
        if spdm is None:
            return self._reply(pkt, ctx, self._error_response(0x10, SpdmErrorCode.INVALID_REQUEST))

        try:
            request_code = SpdmRequestCode(spdm.request_response_code)
        except ValueError:
            return self._reply(
                pkt,
                ctx,
                self._error_response(spdm.spdm_version, SpdmErrorCode.UNSUPPORTED_REQUEST, spdm.request_response_code),
            )

        handlers = {
            SpdmRequestCode.GET_VERSION: self._get_version,
            SpdmRequestCode.GET_CAPABILITIES: self._get_capabilities,
            SpdmRequestCode.NEGOTIATE_ALGORITHMS: self._negotiate_algorithms,
            SpdmRequestCode.GET_DIGESTS: self._get_digests,
            SpdmRequestCode.GET_CERTIFICATE: self._get_certificate,
            SpdmRequestCode.CHALLENGE: self._challenge,
            SpdmRequestCode.GET_MEASUREMENTS: self._get_measurements,
        }
        handler = handlers.get(request_code)
        if handler is None:
            return self._reply(
                pkt,
                ctx,
                self._error_response(spdm.spdm_version, SpdmErrorCode.UNSUPPORTED_REQUEST, int(request_code)),
            )
        return self._reply(pkt, ctx, handler(pkt, ctx, spdm))

    def _get_version(self, pkt: Packet, ctx: EndpointContext, spdm: SpdmHdrPacket) -> Packet:
        ctx.msg_type_context[self.name] = self._new_state()
        state = self._state(ctx)
        payload = (
            SpdmHdr(spdm_version=0x10, request_response_code=SpdmResponseCode.VERSION)
            / VersionPacket(version_number_list=self.profile.version_number_list)
        )
        self._record_transcript(state, bytes(spdm), bytes(payload))
        return payload

    def _get_capabilities(self, pkt: Packet, ctx: EndpointContext, spdm: SpdmHdrPacket) -> Packet:
        state = self._state(ctx)
        request = pkt.getlayer(GetCapabilitiesPacket)
        state["requester_capabilities"] = {
            "ct_exponent": _field_int(request, "ct_exponent"),
            "flags": _field_int(request, "flags"),
            "data_transfer_size": _field_int(request, "data_transfer_size"),
            "max_spdm_msg_size": _field_int(request, "max_spdm_msg_size"),
        }
        state["negotiated"]["version"] = int(spdm.spdm_version)

        hdr = SpdmHdr(spdm_version=spdm.spdm_version, request_response_code=SpdmResponseCode.CAPABILITIES)
        payload = hdr / CapabilitiesPacket(
            ct_exponent=self.profile.ct_exponent,
            flags=self.profile.flags,
            data_transfer_size=self.profile.data_transfer_size,
            max_spdm_msg_size=self.profile.max_spdm_msg_size,
        )
        self._record_transcript(state, bytes(spdm), bytes(payload))
        return payload

    def _negotiate_algorithms(self, pkt: Packet, ctx: EndpointContext, spdm: SpdmHdrPacket) -> Packet:
        state = self._state(ctx)
        request = pkt.getlayer(NegotiateAlgorithmsPacket)
        state["requester_algorithms"] = {
            "measurement_specification": _field_int(request, "measurement_specification"),
            "base_asym_algo": _field_int(request, "base_asym_algo"),
            "base_hash_algo": _field_int(request, "base_hash_algo"),
        }
        negotiated = state["negotiated"]
        negotiated.update(
            {
                "version": int(spdm.spdm_version),
                "measurement_specification": self.profile.measurement_specification,
                "measurement_hash_algo": self.profile.measurement_hash_algo,
                "base_asym_algo": self.profile.base_asym_algo,
                "base_hash_algo": self.profile.base_hash_algo,
            }
        )

        payload = (
            SpdmHdr(spdm_version=spdm.spdm_version, request_response_code=SpdmResponseCode.ALGORITHMS)
            / AlgorithmsPacket(
                length=32,
                measurement_specification_sel=self.profile.measurement_specification,
                measurement_hash_algo=self.profile.measurement_hash_algo,
                base_asym_sel=self.profile.base_asym_algo,
                base_hash_sel=self.profile.base_hash_algo,
            )
        )
        self._record_transcript(state, bytes(spdm), bytes(payload))
        return payload

    def _get_digests(self, pkt: Packet, ctx: EndpointContext, spdm: SpdmHdrPacket) -> Packet:
        state = self._state(ctx)
        digest_bytes = b"".join(self.profile.digest_for(slot) for slot in _slots_from_mask(self.profile.slot_mask))
        supported_slot_mask = self.profile.slot_mask if spdm.spdm_version >= 0x13 else 0
        payload = (
            SpdmHdr(
                spdm_version=spdm.spdm_version,
                request_response_code=SpdmResponseCode.DIGESTS,
                param1=supported_slot_mask,
                param2=self.profile.slot_mask,
            )
            / DigestsPacket()
        )
        payload = payload / digest_bytes if digest_bytes else payload
        self._record_transcript(state, bytes(spdm), bytes(payload))
        return payload

    def _get_certificate(self, pkt: Packet, ctx: EndpointContext, spdm: SpdmHdrPacket) -> Packet:
        request = pkt.getlayer(GetCertificatePacket)
        if request is None:
            return self._error_response(spdm.spdm_version, SpdmErrorCode.INVALID_REQUEST)

        slot = int(spdm.param1) & 0x0F
        if not self._slot_provisioned(slot):
            return self._error_response(spdm.spdm_version, SpdmErrorCode.INVALID_REQUEST)

        chain = self.profile.cert_chain_for(slot)
        offset = min(int(request.offset), len(chain))
        requested_length = max(0, int(request.length))
        remaining = len(chain) - offset
        portion_length = min(requested_length, remaining)
        if self.profile.max_portion_length is not None:
            portion_length = min(portion_length, max(0, int(self.profile.max_portion_length)))
        end = offset + portion_length
        remainder_length = max(0, len(chain) - end)
        cert_portion = chain[offset:end]

        self._state(ctx)["cert_transfer"] = {
            "slot": slot,
            "offset": offset,
            "requested_length": requested_length,
            "portion_length": portion_length,
            "remainder_length": remainder_length,
        }

        payload = (
            SpdmHdr(
                spdm_version=spdm.spdm_version,
                request_response_code=SpdmResponseCode.CERTIFICATE,
                param1=slot,
            )
            / CertificatePacket(portion_length=portion_length, remainder_length=remainder_length)
        )
        payload = payload / cert_portion if cert_portion else payload
        self._record_transcript(self._state(ctx), bytes(spdm), bytes(payload))
        return payload

    def _challenge(self, pkt: Packet, ctx: EndpointContext, spdm: SpdmHdrPacket) -> Packet:
        state = self._state(ctx)
        if not self._algorithms_negotiated(state):
            return self._error_response(spdm.spdm_version, SpdmErrorCode.UNEXPECTED_REQUEST, int(SpdmRequestCode.CHALLENGE))
        if pkt.getlayer(ChallengePacket) is None:
            return self._error_response(spdm.spdm_version, SpdmErrorCode.INVALID_REQUEST)

        slot = int(spdm.param1) & 0x0F
        if not self._slot_provisioned(slot):
            return self._error_response(spdm.spdm_version, SpdmErrorCode.INVALID_REQUEST)

        try:
            hash_type = MeasurementSummaryHashType(int(spdm.param2))
        except ValueError:
            return self._error_response(spdm.spdm_version, SpdmErrorCode.INVALID_REQUEST)

        nonce = self._nonce()
        state["challenge_nonce"] = nonce

        body_without_signature = (
            self.profile.digest_for(slot)
            + nonce
            + self._measurement_summary_hash(hash_type, state)
            + self.profile.opaque_data
        )
        payload_without_signature = (
            SpdmHdr(
                spdm_version=spdm.spdm_version,
                request_response_code=SpdmResponseCode.CHALLENGE_AUTH,
                param1=slot,
                param2=self.profile.slot_mask,
            )
            / ChallengeAuthPacket()
            / body_without_signature
        )
        transcript_hash = self._transcript_hash(state, bytes(spdm), bytes(payload_without_signature))
        signature = self._sign(transcript_hash)
        state["challenge_transcript_hash"] = transcript_hash

        return (
            SpdmHdr(
                spdm_version=spdm.spdm_version,
                request_response_code=SpdmResponseCode.CHALLENGE_AUTH,
                param1=slot,
                param2=self.profile.slot_mask,
            )
            / ChallengeAuthPacket()
            / (body_without_signature + signature)
        )

    def _get_measurements(self, pkt: Packet, ctx: EndpointContext, spdm: SpdmHdrPacket) -> Packet:
        state = self._state(ctx)
        if not self._algorithms_negotiated(state):
            return self._error_response(
                spdm.spdm_version,
                SpdmErrorCode.UNEXPECTED_REQUEST,
                int(SpdmRequestCode.GET_MEASUREMENTS) & 0xFF,
            )
        request = pkt.getlayer(GetMeasurementsPacket)
        if request is None:
            return self._error_response(spdm.spdm_version, SpdmErrorCode.INVALID_REQUEST)

        operation = int(spdm.param2)
        if operation == 0:
            return SpdmHdr(
                spdm_version=spdm.spdm_version,
                request_response_code=SpdmResponseCode.MEASUREMENTS,
                param1=len(self.profile.measurements),
            ) / MeasurementsPacket(number_of_blocks=0, measurement_record_length=0)

        if operation == 0xFF:
            block_indexes = sorted(self.profile.measurements)
        elif operation in self.profile.measurements:
            block_indexes = [operation]
        else:
            return self._error_response(spdm.spdm_version, SpdmErrorCode.INVALID_REQUEST)

        record = b"".join(self._measurement_block(index) for index in block_indexes)
        body_without_signature = record
        slot = 0
        if self._measurements_signature_requested(spdm):
            slot = _field_int(request, "slot_id_param") & 0x0F
            if spdm.spdm_version >= 0x11 and not self._slot_provisioned(slot):
                return self._error_response(spdm.spdm_version, SpdmErrorCode.INVALID_REQUEST)
            nonce = self._nonce()
            state["measurements_nonce"] = nonce
            body_without_signature += nonce + self.profile.opaque_data

        payload_without_signature = (
            SpdmHdr(
                spdm_version=spdm.spdm_version,
                request_response_code=SpdmResponseCode.MEASUREMENTS,
                param2=slot,
            )
            / MeasurementsPacket(number_of_blocks=len(block_indexes), measurement_record_length=len(record))
            / body_without_signature
        )
        if self._measurements_signature_requested(spdm):
            transcript_hash = self._transcript_hash(state, bytes(spdm), bytes(payload_without_signature))
            signature = self._sign(transcript_hash)
            state["measurements_transcript_hash"] = transcript_hash
            body = body_without_signature + signature
        else:
            body = body_without_signature

        return (
            SpdmHdr(
                spdm_version=spdm.spdm_version,
                request_response_code=SpdmResponseCode.MEASUREMENTS,
                param2=slot,
            )
            / MeasurementsPacket(number_of_blocks=len(block_indexes), measurement_record_length=len(record))
            / body
        )

    def _reply(self, pkt: Packet, ctx: EndpointContext, payload: Packet) -> HandlerResponse:
        return HandlerResponse(stop_processing=True, reply=build_layered_reply(pkt, ctx, payload))

    def _error_response(
        self,
        spdm_version: int,
        error_code: SpdmErrorCode,
        error_data: int = 0,
    ) -> Packet:
        return SpdmHdr(
            spdm_version=spdm_version,
            request_response_code=SpdmResponseCode.ERROR,
            param1=int(error_code),
            param2=error_data & 0xFF,
        )

    def _slot_provisioned(self, slot: int) -> bool:
        return bool(self.profile.slot_mask & (1 << slot))

    @staticmethod
    def _record_transcript(state: dict[str, Any], request_bytes: bytes, response_bytes: bytes) -> None:
        state["transcript"].extend(request_bytes)
        state["transcript"].extend(response_bytes)

    def _transcript_hash(self, state: dict[str, Any], request_bytes: bytes = b"", response_bytes: bytes = b"") -> bytes:
        hash_factory = self._hash_factory(state)
        digest = hash_factory(bytes(state["transcript"]) + request_bytes + response_bytes).digest()
        return digest[: self.profile.hash_size].ljust(self.profile.hash_size, b"\x00")

    def _hash_factory(self, state: dict[str, Any]) -> Callable[[bytes], Any]:
        negotiated_algo = int(state.get("negotiated", {}).get("base_hash_algo", self.profile.base_hash_algo))
        return _HASH_BY_ALGO.get(negotiated_algo, _HASH_BY_SIZE.get(self.profile.hash_size, hashlib.sha384))

    def _measurement_summary_hash(self, hash_type: MeasurementSummaryHashType, state: dict[str, Any]) -> bytes:
        if hash_type == MeasurementSummaryHashType.NO_HASH:
            return b""
        record = b"".join(self._measurement_block(index) for index in sorted(self.profile.measurements))
        digest = self._hash_factory(state)(record).digest()
        return digest[: self.profile.hash_size].ljust(self.profile.hash_size, b"\x00")

    def _measurement_block(self, index: int) -> bytes:
        value = self.profile.measurements[index]
        return (
            bytes([index & 0xFF, self.profile.measurement_specification & 0xFF])
            + len(value).to_bytes(2, "little")
            + value
        )

    def _nonce(self) -> bytes:
        provider = self.profile.nonce_provider
        nonce = os.urandom(_SPDM_NONCE_SIZE) if provider is None else bytes(provider())
        return nonce[:_SPDM_NONCE_SIZE].ljust(_SPDM_NONCE_SIZE, b"\x00")

    def _sign(self, transcript_hash: bytes) -> bytes:
        if self.profile.signer is not None:
            return bytes(self.profile.signer(transcript_hash))
        return _expand_mock_signature(transcript_hash, self.profile.signature_size)

    @staticmethod
    def _algorithms_negotiated(state: dict[str, Any]) -> bool:
        return "base_hash_algo" in state.get("negotiated", {})

    @staticmethod
    def _measurements_signature_requested(spdm: SpdmHdrPacket) -> bool:
        return bool(int(spdm.param1) & int(MeasurementRequestAttributes.GENERATE_SIGNATURE))

    def _state(self, ctx: EndpointContext) -> dict[str, Any]:
        state = ctx.msg_type_context[self.name]
        if not state:
            state.update(self._new_state())
        return state

    @staticmethod
    def _new_state() -> dict[str, Any]:
        return {
            "negotiated": {},
            "requester_capabilities": {},
            "requester_algorithms": {},
            "cert_transfer": {},
            "transcript": bytearray(),
        }

    @staticmethod
    def _coerce_profile(profile: SpdmResponderProfile | dict[str, Any] | None) -> SpdmResponderProfile:
        if profile is None:
            return SpdmResponderProfile()
        if isinstance(profile, SpdmResponderProfile):
            return profile
        return SpdmResponderProfile(**profile)


def _version_number_entry(version: int) -> int:
    if version <= 0xFF:
        return (((version >> 4) & 0x0F) << 12) | ((version & 0x0F) << 8)
    return version


def _slots_from_mask(slot_mask: int) -> list[int]:
    return [slot for slot in range(8) if slot_mask & (1 << slot)]


def _field_int(pkt: Packet | None, name: str) -> int:
    value = getattr(pkt, name, 0)
    return 0 if value is None else int(value)


def _expand_mock_signature(seed: bytes, size: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(hashlib.sha512(seed + counter.to_bytes(4, "little")).digest())
        counter += 1
    return bytes(output[:size])
