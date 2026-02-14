# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from enum import IntEnum


class SpdmRequestCode(IntEnum):
    """SPDM request message codes (DSP0274)."""

    GET_DIGESTS = 0x81
    GET_CERTIFICATE = 0x82
    CHALLENGE = 0x83
    GET_VERSION = 0x84
    GET_MEASUREMENTS = 0xE0
    GET_CAPABILITIES = 0xE1
    NEGOTIATE_ALGORITHMS = 0xE3
    KEY_EXCHANGE = 0xE4
    FINISH = 0xE5
    PSK_EXCHANGE = 0xE6
    PSK_FINISH = 0xE7
    HEARTBEAT = 0xE8
    KEY_UPDATE = 0xE9
    GET_ENCAPSULATED_REQUEST = 0xEA
    DELIVER_ENCAPSULATED_RESPONSE = 0xEB
    END_SESSION = 0xEC
    GET_CSR = 0xED
    SET_CERTIFICATE = 0xEE
    CHUNK_SEND = 0xEF
    CHUNK_GET = 0xF0
    GET_SUPPORTED_EVENT_TYPES = 0xF1
    SUBSCRIBE_EVENT_TYPES = 0xF2
    VENDOR_DEFINED_REQUEST = 0xFE
    RESPOND_IF_READY = 0xFF


class SpdmResponseCode(IntEnum):
    """SPDM response message codes (DSP0274)."""

    DIGESTS = 0x01
    CERTIFICATE = 0x02
    CHALLENGE_AUTH = 0x03
    VERSION = 0x04
    MEASUREMENTS = 0x60
    CAPABILITIES = 0x61
    ALGORITHMS = 0x63
    KEY_EXCHANGE_RSP = 0x64
    FINISH_RSP = 0x65
    PSK_EXCHANGE_RSP = 0x66
    PSK_FINISH_RSP = 0x67
    HEARTBEAT_ACK = 0x68
    KEY_UPDATE_ACK = 0x69
    ENCAPSULATED_REQUEST = 0x6A
    ENCAPSULATED_RESPONSE_ACK = 0x6B
    END_SESSION_ACK = 0x6C
    CSR = 0x6D
    SET_CERTIFICATE_RSP = 0x6E
    CHUNK_SEND_ACK = 0x6F
    CHUNK_RESPONSE = 0x70
    SUPPORTED_EVENT_TYPES = 0x71
    SUBSCRIBE_EVENT_TYPES_ACK = 0x72
    VENDOR_DEFINED_RESPONSE = 0x7E
    ERROR = 0x7F


# Combined lookup for all SPDM message codes (for display purposes)
SpdmMessageCode = {}
SpdmMessageCode.update({e.value: e.name for e in SpdmRequestCode})
SpdmMessageCode.update({e.value: e.name for e in SpdmResponseCode})


class SpdmErrorCode(IntEnum):
    """SPDM error codes (DSP0274)."""

    INVALID_REQUEST = 0x01
    BUSY = 0x03
    UNEXPECTED_REQUEST = 0x04
    UNSPECIFIED = 0x05
    UNSUPPORTED_REQUEST = 0x07
    VERSION_MISMATCH = 0x41
    RESPONSE_NOT_READY = 0x42
    REQUEST_RESYNCH = 0x43
    VENDOR_DEFINED = 0xFF


# Map request codes to their corresponding response codes
SPDM_REQUEST_RESPONSE_MAP = {
    SpdmRequestCode.GET_VERSION: SpdmResponseCode.VERSION,
    SpdmRequestCode.GET_CAPABILITIES: SpdmResponseCode.CAPABILITIES,
    SpdmRequestCode.NEGOTIATE_ALGORITHMS: SpdmResponseCode.ALGORITHMS,
    SpdmRequestCode.GET_DIGESTS: SpdmResponseCode.DIGESTS,
    SpdmRequestCode.GET_CERTIFICATE: SpdmResponseCode.CERTIFICATE,
    SpdmRequestCode.CHALLENGE: SpdmResponseCode.CHALLENGE_AUTH,
    SpdmRequestCode.GET_MEASUREMENTS: SpdmResponseCode.MEASUREMENTS,
    SpdmRequestCode.KEY_EXCHANGE: SpdmResponseCode.KEY_EXCHANGE_RSP,
    SpdmRequestCode.FINISH: SpdmResponseCode.FINISH_RSP,
    SpdmRequestCode.PSK_EXCHANGE: SpdmResponseCode.PSK_EXCHANGE_RSP,
    SpdmRequestCode.PSK_FINISH: SpdmResponseCode.PSK_FINISH_RSP,
    SpdmRequestCode.HEARTBEAT: SpdmResponseCode.HEARTBEAT_ACK,
    SpdmRequestCode.KEY_UPDATE: SpdmResponseCode.KEY_UPDATE_ACK,
    SpdmRequestCode.END_SESSION: SpdmResponseCode.END_SESSION_ACK,
    SpdmRequestCode.VENDOR_DEFINED_REQUEST: SpdmResponseCode.VENDOR_DEFINED_RESPONSE,
}
