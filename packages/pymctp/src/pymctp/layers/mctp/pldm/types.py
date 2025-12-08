# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from enum import IntEnum


class PldmTypeCodes(IntEnum):
    CONTROL = 0x00
    SMBIOS = 0x01
    PLATFORM_MONITORING = 0x02
    BIOS = 0x03
    FRU = 0x04
    FIRMWARE_UPDATES = 0x05
    RDE = 0x06
    OEM = 0x3F


class PldmControlCmdCodes(IntEnum):
    Reserved = 0x00
    SetTID = 0x01
    GetTID = 0x02
    GetPLDMVersion = 0x03
    GetPLDMTypes = 0x04
    GetPLDMCommands = 0x05
    SelectPLDMVersion = 0x06
    NegotiateTransferParameters = 0x07
    MultipartSend = 0x08
    MultipartReceive = 0x09


class CompletionCodes(IntEnum):
    SUCCESS = 0
    """The Request was accepted and completed normally."""

    ERROR = 1
    """This is a generic failure message. (It should not be used
    when a more specific result code applies.)"""

    ERROR_INVALID_DATA = 2
    """The packet payload contained invalid data or an illegal
    parameter value."""

    ERROR_INVALID_LENGTH = 3
    """The message length was invalid. (The Message body
    was larger or smaller than expected for the particular
    request.)"""

    ERROR_NOT_READY = 4
    """The Receiver is in a transient state where it is not ready
    to receive the corresponding message."""

    ERROR_UNSUPPORTED_CMD = 5
    """The command field in the control type of the received
    message is unspecified or not supported on this
    endpoint. This completion code shall be returned for any
    unsupported command values received in MCTP control
    Request messages."""

    ERROR_INVALID_PLDM_TYPE = 32
    """The PLDM Type field value in the PLDM request
    message is invalid or unsupported."""
