# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from enum import IntEnum


class CerberusCmdCodes(IntEnum):
    """Open-source Cerberus Challenge Protocol command codes.

    Defined in the OCP Project Cerberus Challenge Protocol specification.
    """

    GET_FW_VERSION = 0x01
    GET_DEVICE_CAPABILITIES = 0x02
    GET_DEVICE_ID = 0x03
    GET_DEVICE_INFO = 0x04

    EXPORT_CSR = 0x20
    IMPORT_CA_SIGNED_CERT = 0x21
    GET_SIGNED_CERT_STATE = 0x22

    GET_HOST_STATE = 0x40

    GET_LOG_INFO = 0x4F
    READ_LOG = 0x50
    CLEAR_LOG = 0x51
    GET_ATTESTATION_DATA = 0x52

    GET_PFM_ID = 0x59
    GET_PFM_SUPPORTED_FW = 0x5A
    INIT_PFM_UPDATE = 0x5B
    PFM_UPDATE = 0x5C
    COMPLETE_PFM_UPDATE = 0x5D

    GET_CFM_ID = 0x5E
    INIT_CFM_UPDATE = 0x5F
    CFM_UPDATE = 0x60
    COMPLETE_CFM_UPDATE = 0x61

    GET_PCD_ID = 0x62
    INIT_PCD_UPDATE = 0x63
    PCD_UPDATE = 0x64
    COMPLETE_PCD_UPDATE = 0x65

    INIT_FW_UPDATE = 0x66
    FW_UPDATE = 0x67
    GET_UPDATE_STATUS = 0x68
    COMPLETE_FW_UPDATE = 0x69
    RESET_CONFIG = 0x6A

    GET_CONFIG_ID = 0x70
    TRIGGER_FW_RECOVERY = 0x71
    PREPARE_RECOVERY_IMAGE = 0x72
    UPDATE_RECOVERY_IMAGE = 0x73
    ACTIVATE_RECOVERY_IMAGE = 0x74
    GET_RECOVERY_IMAGE_VERSION = 0x75

    ERROR = 0x7F

    GET_PMR = 0x80
    GET_DIGEST = 0x81
    GET_CERTIFICATE = 0x82
    ATTESTATION_CHALLENGE = 0x83
    EXCHANGE_KEYS = 0x84
    SESSION_SYNC = 0x85
    UPDATE_PMR = 0x86
    RESET_COUNTER = 0x87

    UNSEAL_MESSAGE = 0x89
    UNSEAL_MESSAGE_RESULT = 0x8A

    GET_PCD_SUPPORTED_COMPONENT_IDS = 0x8C
    GET_CFM_SUPPORTED_COMPONENT_IDS = 0x8D
    GET_EXT_UPDATE_STATUS = 0x8E


class CerberusErrorCodes(IntEnum):
    """Cerberus protocol error codes."""

    NO_ERROR = 0x00
    INVALID_REQ = 0x01
    BUSY = 0x03
    UNSPECIFIED = 0x04
    INVALID_CHECKSUM = 0xF0
    OUT_OF_ORDER_MSG = 0xF1
    AUTHENTICATION = 0xF2
    OUT_OF_SEQ_WINDOW = 0xF3
    INVALID_PACKET_LEN = 0xF4
    MSG_OVERFLOW = 0xF5


class CerberusLogType(IntEnum):
    """Cerberus log types for READ_LOG command."""

    DEBUG = 1
    ATTESTATION = 2
    TAMPER = 3


class CerberusUpdateType(IntEnum):
    """Cerberus update status types."""

    FW_UPDATE = 0
    PFM_UPDATE = 1
    CFM_UPDATE = 2
    PCD_UPDATE = 3
    HOST_FW_NEXT_RESET = 4
    RECOVERY_UPDATE = 5
    CONFIG_RESET = 6


class CerberusResetConfig(IntEnum):
    """Reset configuration types."""

    RESTORE_BYPASS = 0
    RESTORE_DEFAULTS = 1
    CLEAR_PLATFORM_CONFIG = 2
    CLEAR_COMPONENT_MANIFESTS = 3
    RESET_INTRUSION = 4
