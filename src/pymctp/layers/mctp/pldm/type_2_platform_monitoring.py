# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from enum import IntEnum

from scapy.fields import (
    ConditionalField,
    FieldLenField,
    FieldListField,
    XByteEnumField,
    XByteField,
    XLEIntField,
    XLEShortField,
)
from scapy.packet import Packet, bind_layers

from ...helpers import AllowRawSummary
from .. import TransportHdrPacket
from ..types import AnyPacketType
from .pldm import AutobindPLDMMsg, PldmHdrPacket, set_pldm_fields
from .types import (
    PldmTypeCodes,
)


class PldmPlatformMonitoringCmdCodes(IntEnum):
    Reserved = 0x00

    # Terminus commands
    SetTID = 0x01
    GetTID = 0x02
    GetTerminusUID = 0x03
    SetEventReceiver = 0x04
    GetEventReceiver = 0x05
    PlatformEventMessage = 0x0A
    PollForPlatformEventMessage = 0x0B
    EventMessageSupported = 0x0C
    EventMessageBufferSize = 0x0D

    # Numeric Sensor commands
    SetNumericSensorEnable = 0x10
    GetSensorReading = 0x11
    GetSensorThresholds = 0x12
    SetSensorThresholds = 0x13
    RestoreSensorThresholds = 0x14
    GetSensorHysteresis = 0x15
    SetSensorHysteresis = 0x16
    InitNumericSensor = 0x17

    # State Sensor commands
    SetStateSensorEnables = 0x20
    GetStateSensorReadings = 0x21
    InitStateSensor = 0x22

    # PLDM Effecter commands
    SetNumericEffecterEnable = 0x30
    SetNumericEffecterValue = 0x31
    GetNumericEffecterValue = 0x32
    SetStateEffecterEnables = 0x38
    SetStateEffecterStates = 0x39
    GetStateEffecterStates = 0x3A

    # PLDM Event Log commands
    GetPLDMEventLogInfo = 0x40
    EnablePLDMEventLogging = 0x41
    ClearPLDMEventLog = 0x42
    GetPLDMEventLogTimestamp = 0x43
    SetPLDMEventLogTimestamp = 0x44
    ReadPLDMEventLog = 0x45
    GetPLDMEventLogPolicyInfo = 0x46
    SetPLDMEventLogPolicy = 0x47
    FindPLDMEventLogEntry = 0x48

    # PDR Repository commands
    GetPDRRepositoryInfo = 0x50
    GetPDR = 0x51
    FindPDR = 0x52
    RunInitAgent = 0x58
    GetPDRRepositorySignature = 0x53


class GetPDRPacket(Packet):
    pass
    # fields_desc =


class PlatformEventMsgStatus(IntEnum):
    NO_LOGGING = 0
    LOGGING_DISABLED = 1
    LOG_FULL = 2
    ACCEPTED_FOR_LOGGING = 3
    LOGGED = 4
    LOGGING_REJECTED = 5


class PlatformEventMsgClasses(IntEnum):
    PLDM_SENSOR_EVENT = 0x00
    PLDM_EFFECTER_EVENT = 0x01
    PLDM_REDFISH_TASK_EXECUTED_EVENT = 0x02
    PLDM_REDFISH_MESSAGE_EVENT = 0x03
    PLDM_PDR_REPOSITORY_CHG_EVENT = 0x04
    PLDM_MESSAGE_POLL_EVENT = 0x05
    PLDM_HEARTBEAT_TIMER_ELAPSED_EVENT = 0x06
    PLDM_OEM_CRASH_DUMP_EVENT = 0xF0
    PLDM_OEM_SEL_EVENT = 0xF1
    PLDM_OEM_BMC_EVENT = 0xF2


class PldmMessagePollEventDataPacket(Packet):
    fields_desc = [
        XByteField("formatVersion", 0x01),
        XLEShortField("eventID", 0),
        XLEIntField("DataTransferHandle", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"MsgPollEventData (fmtVer={self.formatVersion}, eventID={self.eventID}, "
            f"DataTransferHandle={self.DataTransferHandle})"
        )
        return summary, [PollForPlatformEventMsgPacket, PldmHdrPacket, TransportHdrPacket]


class PldmSELEventDataPacket(Packet):
    fields_desc = [
        XLEShortField("record_id", 0x01),
        XByteField("record_type", 0),
        XLEIntField("timestamp", 0),
        XLEShortField("generator_id", 0x01),
        XByteField("event_msg_rev", 0),
        XByteField("sensor_type", 0),
        XByteField("sensor_num", 0),
        XByteField("event_dir_type", 0),
        XByteField("event_data_1", 0),
        XByteField("event_data_2", 0),
        XByteField("event_data_3", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"SELEvent (record_id={self.record_id}, record_type={self.record_type}, "
            f"sensor_num={self.sensor_num}, sensor_type={self.sensor_type})"
        )
        return summary, [PollForPlatformEventMsgPacket, PldmHdrPacket, TransportHdrPacket]


@AutobindPLDMMsg(PldmTypeCodes.PLATFORM_MONITORING, PldmPlatformMonitoringCmdCodes.PlatformEventMessage)
class PlatformEventMsgPacket(Packet):
    fields_desc = set_pldm_fields(
        rq_fields=[
            XByteField("formatVersion", 0x01),
            XByteField("tid", 0),
            XByteEnumField("eventClass", 0, PlatformEventMsgClasses),
        ],
        rsp_fields=[
            XByteEnumField("status", 0, PlatformEventMsgStatus),
        ],
    )

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = "PlatformEventMsg ("
        if self.underlayer.getfieldval("rq") == 1:
            summary += f"ver={self.formatVersion}, tid={self.tid}, eventClass=0x{self.eventClass:02X}"
        else:
            summary += f"status={self.status}"
        summary += ")"
        # TODO: decode eventData based on eventClass
        return summary, [PldmHdrPacket, TransportHdrPacket]


bind_layers(
    PlatformEventMsgPacket,
    PldmMessagePollEventDataPacket,
    eventClass=PlatformEventMsgClasses.PLDM_MESSAGE_POLL_EVENT.value,
)
bind_layers(PlatformEventMsgPacket, PldmSELEventDataPacket, eventClass=PlatformEventMsgClasses.PLDM_OEM_SEL_EVENT.value)


class PollForPlatformEventOperation(IntEnum):
    GET_NEXT_PART = 0
    GET_FIRST_PART = 1
    ACK_ONLY = 2


class PollForPlatformEventTransferFlag(IntEnum):
    START = 0
    MIDDLE = 1
    END = 4
    START_AND_END = 5


@AutobindPLDMMsg(PldmTypeCodes.PLATFORM_MONITORING, PldmPlatformMonitoringCmdCodes.PollForPlatformEventMessage)
class PollForPlatformEventMsgPacket(Packet):
    fields_desc = set_pldm_fields(
        rq_fields=[
            XByteField("formatVersion", 0x01),
            XByteEnumField("TransferOperationFlag", 0, PollForPlatformEventOperation),
            XLEIntField("DataTransferHandle", 0),
            XLEShortField("eventIDToAcknowledge", 0),
        ],
        rsp_fields=[
            XByteField("tid", 0),
            XLEShortField("eventID", 0),
            ConditionalField(XLEIntField("NextDataTransferHandle", 0), lambda pkt: pkt.eventID != 0),
            ConditionalField(
                XByteEnumField("TransferFlag", 0, PollForPlatformEventTransferFlag), lambda pkt: pkt.eventID != 0
            ),
            ConditionalField(XByteEnumField("eventClass", 0, PlatformEventMsgClasses), lambda pkt: pkt.eventID != 0),
            ConditionalField(
                FieldLenField("eventDataSize", None, fmt="<I", count_of="eventData"), lambda pkt: pkt.eventID != 0
            ),
            ConditionalField(
                FieldListField("eventData", [], XByteField("", 0), count_from=lambda pkt: pkt.eventDataSize),
                lambda pkt: pkt.eventID != 0,
            ),
            # XLEIntField('NextDataTransferHandle', 0),
            # XByteEnumField("TransferFlag", 0, PollForPlatformEventTransferFlag),
            # XByteEnumField("eventClass", 0, PlatformEventMsgClasses),
            # FieldLenField('eventDataSize', None, fmt='I', count_of='eventData'),
            # FieldListField('eventData', [], XByteField('', 0),
            #                count_from=lambda pkt: pkt.eventDataSize),
            ConditionalField(
                XLEIntField("eventDataIntegrityChecksum", 0),
                lambda pkt: pkt.eventID != 0 and pkt.TransferFlag == PollForPlatformEventTransferFlag.END.value,
            ),
        ],
    )

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = "PPE ("
        if self.underlayer.getfieldval("rq") == 1:
            summary += (
                f"ver={self.formatVersion}, op={self.TransferOperationFlag}, "
                f"hdl=0x{self.DataTransferHandle:02X}, eventIDToAck=0x{self.eventIDToAcknowledge:04X}"
            )
        else:
            summary += f"tid={self.tid}, eventID=0x{self.eventID:04X}"
            if self.eventID != 0:
                summary += (
                    f", nextHdl=0x{self.NextDataTransferHandle:08x}, "
                    f"transferFlag={self.TransferFlag}, eventClass=0x{self.eventClass:02X}, "
                    f"eventDataSize={self.eventDataSize}"
                )
            if self.TransferFlag == PollForPlatformEventTransferFlag.END.value:
                summary += f", eventDataIntegrityChecksum={self.eventDataIntegrityChecksum}"
        summary += ")"
        # TODO: decode eventData based on eventClass
        return summary, [PldmHdrPacket, TransportHdrPacket]


class GetSensorReadingDataSizeEnum(IntEnum):
    UINT8 = 0
    SINT8 = 1
    UINT16 = 2
    SINT16 = 3
    UINT32 = 4
    SINT32 = 5


class GetSensorReadingOperationalStateEnum(IntEnum):
    ENABLED = 0
    DISABLED = 1
    UNAVAILABLE = 2
    UNKNOWN = 3
    FAILED = 4
    INITIALIZING = 5
    SHUTTING_DOWN = 6
    IN_TEST = 7


class GetSensorReadingEventMsgEnableEnum(IntEnum):
    NO_EVENT_GENERATION = 0
    EVENTS_DISABLED = 1
    EVENTS_ENABLED = 2
    OP_EVENTS_ONLY_ENABLED = 3
    STATE_EVENTS_ONLY_ENABLED = 4


class GetSensorReadingPresentEnum(IntEnum):
    UNKNOWN = 0x0
    NORMAL = 0x01
    WARNING = 0x02
    CRITICAL = 0x03
    FATAL = 0x04
    LOWERWARNING = 0x05
    LOWERCRITICAL = 0x06
    LOWERFATAL = 0x07
    UPPERWARNING = 0x08
    UPPERCRITICAL = 0x09
    UPPERFATAL = 0x0A


@AutobindPLDMMsg(PldmTypeCodes.PLATFORM_MONITORING, PldmPlatformMonitoringCmdCodes.GetSensorReading)
class GetSensorReadingPacket(AllowRawSummary, Packet):
    fields_desc = set_pldm_fields(
        rq_fields=[
            XLEShortField("sensorID", 0),
            XByteField("rearmEventState", 0),
        ],
        rsp_fields=[
            XByteEnumField("sensorDataSize", 0, GetSensorReadingDataSizeEnum),
            XByteEnumField("sensorOperationalState", 0, GetSensorReadingOperationalStateEnum),
            XByteEnumField("sensorEventMessageEnable", 0, GetSensorReadingEventMsgEnableEnum),
            XByteEnumField("presentState", 0, GetSensorReadingPresentEnum),
            XByteEnumField("previousState", 0, GetSensorReadingPresentEnum),
            XByteEnumField("eventState", 0, GetSensorReadingPresentEnum),
            ConditionalField(
                XByteField("presentReading8", 0),
                lambda pkt: pkt.sensorDataSize
                in [GetSensorReadingDataSizeEnum.UINT8.value, GetSensorReadingDataSizeEnum.SINT8.value],
            ),
            ConditionalField(
                XLEShortField("presentReading16", 0),
                lambda pkt: pkt.sensorDataSize
                in [GetSensorReadingDataSizeEnum.UINT16.value, GetSensorReadingDataSizeEnum.SINT16.value],
            ),
            ConditionalField(
                XLEIntField("presentReading32", 0),
                lambda pkt: pkt.sensorDataSize
                in [GetSensorReadingDataSizeEnum.UINT32.value, GetSensorReadingDataSizeEnum.SINT32.value],
            ),
        ],
    )

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = "GetSensorReading ("
        if self.underlayer.getfieldval("rq") == 1:
            summary += f"sensorID=0x{self.sensorID:04X}, rearmEventState=0x{self.rearmEventState:02X}"
        else:
            summary += (
                f"sensorDataSize={self.sensorDataSize}, opState=0x{self.sensorOperationalState:02X}, "
                f"eventMsgEnabled=0x{self.sensorEventMessageEnable:02x}, "
                f"presentState={self.presentState}, "
                f"previousState={self.presentState}, "
                f"eventState={self.presentState}"
            )
            if self.sensorDataSize in [
                GetSensorReadingDataSizeEnum.UINT8.value,
                GetSensorReadingDataSizeEnum.SINT8.value,
            ]:
                summary += f", presentReading=0x{self.presentReading8:02X}"
            elif self.sensorDataSize in [
                GetSensorReadingDataSizeEnum.UINT16.value,
                GetSensorReadingDataSizeEnum.SINT16.value,
            ]:
                summary += f", presentReading=0x{self.presentReading16:04X}"
            elif self.sensorDataSize in [
                GetSensorReadingDataSizeEnum.UINT32.value,
                GetSensorReadingDataSizeEnum.SINT32.value,
            ]:
                summary += f", presentReading=0x{self.presentReading32:08X}"
        summary += ")"
        # TODO: decode eventData based on eventClass
        return summary, [PldmHdrPacket, TransportHdrPacket]
