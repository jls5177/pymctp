# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from enum import IntEnum

from scapy.fields import FieldListField, XByteEnumField, XByteField, XLEIntField
from scapy.packet import Packet

from ..transport import TransportHdrPacket
from ..types import AnyPacketType
from .pldm import AutobindPLDMMsg, PldmHdrPacket, set_pldm_fields
from .types import (
    PldmControlCmdCodes,
    PldmTypeCodes,
)


@AutobindPLDMMsg(PldmTypeCodes.CONTROL, PldmControlCmdCodes.SetTID)
class SetTIDPacket(Packet):
    fields_desc = set_pldm_fields(
        rq_fields=[
            XByteField("tid", 0),
        ],
        rsp_fields=[],
    )

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"SETTID (tid: {self.tid})"
        return summary, [PldmHdrPacket, TransportHdrPacket]


@AutobindPLDMMsg(PldmTypeCodes.CONTROL, PldmControlCmdCodes.GetTID)
class GetTIDPacket(Packet):
    fields_desc = set_pldm_fields(
        rq_fields=[],
        rsp_fields=[
            XByteField("tid", 0),
        ],
    )

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"GETTID (tid: {self.tid})"
        return summary, [PldmHdrPacket, TransportHdrPacket]


class GetPLDMVersionOperation(IntEnum):
    GET_NEXT_PART = 0
    GET_FIRST_PART = 1


class GetPLDMVersionTransferFlag(IntEnum):
    START = 1
    MIDDLE = 2
    END = 4
    START_AND_END = 5


@AutobindPLDMMsg(PldmTypeCodes.CONTROL, PldmControlCmdCodes.GetPLDMVersion)
class GetPLDMVersionPacket(Packet):
    fields_desc = set_pldm_fields(
        rq_fields=[
            XLEIntField("DataTransferHandle", 0),
            XByteEnumField("TransferOperationFlag", 0, GetPLDMVersionOperation),
            XByteField("PLDMType", 0),
        ],
        rsp_fields=[
            XLEIntField("NextDataTransferHandle", 0),
            XByteEnumField("TransferFlag", 0, GetPLDMVersionTransferFlag),
        ],
    )

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = "GetPLDMVER ("
        if self.underlayer.getfieldval("rq") == 1:
            summary += f"hdl={self.DataTransferHandle}, op={self.TransferOperationFlag}, type={self.PLDMType})"
        else:
            summary += f"nextHdl={self.NextDataTransferHandle}, transferFlag={self.TransferFlag})"
        return summary, [PldmHdrPacket, TransportHdrPacket]


class PLDMTypesByte1(IntEnum):
    CONTROL = 1 << 0x00
    SMBIOS = 1 << 0x01
    PLATFORM_MONITORING = 1 << 0x02
    BIOS = 1 << 0x03
    FRU = 1 << 0x04
    FIRMWARE_UPDATES = 1 << 0x05
    RDE = 1 << 0x06


@AutobindPLDMMsg(PldmTypeCodes.CONTROL, PldmControlCmdCodes.GetPLDMTypes)
class GetPLDMTypesPacket(Packet):
    fields_desc = set_pldm_fields(
        rq_fields=[],
        rsp_fields=[
            XByteEnumField("PLDMTypes1", 0, PLDMTypesByte1),
            XByteField("PLDMTypes2", 0),
            XByteField("PLDMTypes3", 0),
            XByteField("PLDMTypes4", 0),
            XByteField("PLDMTypes5", 0),
            XByteField("PLDMTypes6", 0),
            XByteField("PLDMTypes7", 0),
            XByteField("PLDMTypes8", 0),
        ],
    )

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = "GetPLDMTypes ("
        if self.underlayer.getfieldval("rq") == 1:
            summary += ")"
            return summary, [PldmHdrPacket, TransportHdrPacket]

        if self.PLDMTypes1 != 0:
            if self.PLDMTypes1 & PLDMTypesByte1.CONTROL != 0:
                summary += "CTRL "
            if self.PLDMTypes1 & PLDMTypesByte1.SMBIOS != 0:
                summary += "SMBIOS "
            if self.PLDMTypes1 & PLDMTypesByte1.PLATFORM_MONITORING != 0:
                summary += "M&C "
            if self.PLDMTypes1 & PLDMTypesByte1.BIOS != 0:
                summary += "BIOS "
            if self.PLDMTypes1 & PLDMTypesByte1.FRU != 0:
                summary += "FRU "
            if self.PLDMTypes1 & PLDMTypesByte1.FIRMWARE_UPDATES != 0:
                summary += "FUP "
            if self.PLDMTypes1 & PLDMTypesByte1.RDE != 0:
                summary += "RDE "
            summary = summary.rstrip()
        if self.PLDMTypes2 != 0:
            summary += f"PLDMTypes[2]=0x{self.PLDMTypes2:02X}"
        if self.PLDMTypes3 != 0:
            summary += f"PLDMTypes[3]=0x{self.PLDMTypes3:02X}"
        if self.PLDMTypes4 != 0:
            summary += f"PLDMTypes[4]=0x{self.PLDMTypes4:02X}"
        if self.PLDMTypes5 != 0:
            summary += f"PLDMTypes[5]=0x{self.PLDMTypes5:02X}"
        if self.PLDMTypes6 != 0:
            summary += f"PLDMTypes[6]=0x{self.PLDMTypes6:02X}"
        if self.PLDMTypes7 != 0:
            summary += f"PLDMTypes[7]=0x{self.PLDMTypes7:02X}"
        if self.PLDMTypes8 != 0:
            summary += f"PLDMTypes[8]=0x{self.PLDMTypes8:02X}"

        summary += ")"
        return summary, [PldmHdrPacket, TransportHdrPacket]


@AutobindPLDMMsg(PldmTypeCodes.CONTROL, PldmControlCmdCodes.GetPLDMCommands)
class GetPLDMCommandsPacket(Packet):
    fields_desc = set_pldm_fields(
        rq_fields=[
            XByteField("PLDMType", 0),
            XLEIntField("Version", 0),
        ],
        rsp_fields=[
            FieldListField("cmds", [], XByteField("", 0), length_from=lambda pkt: 32),
        ],
    )

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = "GetPLDMTypes ("
        if self.underlayer.getfieldval("rq") == 0:
            summary += f"{self.cmds}"
        summary += ")"
        return summary, [PldmHdrPacket, TransportHdrPacket]
