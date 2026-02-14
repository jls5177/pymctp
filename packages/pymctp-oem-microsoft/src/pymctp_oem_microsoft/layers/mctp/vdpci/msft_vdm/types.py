from enum import IntEnum


class MsftVdmBaseCmdCodes(IntEnum):
    STATUS = 0
    CMD_SET_SUPPORT = 1
    CAP_NEGOTIATION = 2
    GET_TEMP = 3
    HEARTBEAT_CTRL = 4
    HEARTBEAT = 5


class MsftVdmBmcCmdCodes(IntEnum):
    BMC_GET_SYSTEM_DEVICES = 0x13
    BMC_GET_DEVICE_STRING = 0x14
    BMC_GET_DEVICE_EID = 0x15
