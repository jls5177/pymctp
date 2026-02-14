from enum import IntEnum


class MsftVdmCommandSets(IntEnum):
    BASE = 0
    BMC = 1
    ROT = 2
    LION = 3
    BMC_1P = 4
    FIPS = 5
    TIP = 6


class CompletionCodes(IntEnum):
    SUCCESS = 0
    """Command completed successfully."""

    FAILURE = 0xFF
    """General command processing failure."""

    ERROR_INVALID_COMMAND = 0xFE
    """The command is unknown."""

    ERROR_UNSUPPORTED_CMD = 0xFD
    """The command is a known command but is not supported by this device."""

    ERROR_MALFORMED_CMD = 0xFC
    """A supported command is not structured correctly."""

    ERROR_UNSUPPORTED_PARAMETER = 0xFB
    """An argument provided with the request is not valid for the device."""

    ERROR_RESOURCE_UNAVAILABLE = 0xFA
    """The requested operation uses a resource that is currently not available."""

    ERROR_UNSUPPORTED_PROTOCOL_VER = 0xF9
    """The message protocol version is not supported by the device."""
