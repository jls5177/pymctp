# SPDX-FileCopyrightText: 2025 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import time
from enum import IntEnum

from scapy.config import conf
from scapy.fields import BitEnumField, BitField, ShortEnumField, XByteField
from scapy.packet import Packet, Raw, bind_layers, ConditionalField

from .types import NvmeMIMessageType
from ..transport import (
    AutobindMessageType,
    MsgTypes,
    SmbusTransportPacket,
    TransportHdrPacket,
    TrimmedSmbusTransportPacket,
)
from ..types import AnyPacketType
from ...interfaces import ICanSetMySummaryClasses


class RqBit(IntEnum):
    RESPONSE = 1
    REQUEST = 0


@AutobindMessageType(MsgTypes.NVMeMgmtMsg)
class NvmeMIHdrPacket(Packet):
    name = "NVMe-MI"
    fields_desc = [
        BitEnumField("ror", 0, 1, RqBit),
        BitEnumField("nmimt", 0, 4, NvmeMIMessageType),
        BitField("rsv", 0, 2),
        BitField("csi", 0, 1),
        XByteField("unused2", 0),
        XByteField("unused3", 0),
        # TODO: move to separate packet
        ConditionalField(
            XByteField("opcode", 0),
            lambda pkt: pkt.nmimt in [NvmeMIMessageType.CMD.value, NvmeMIMessageType.ADMIN_CMD.value],
        ),
        ConditionalField(
            XByteField("unused5", 0),
            lambda pkt: pkt.nmimt in [NvmeMIMessageType.CMD.value, NvmeMIMessageType.ADMIN_CMD.value],
        ),
        ConditionalField(
            XByteField("unused6", 0),
            lambda pkt: pkt.nmimt in [NvmeMIMessageType.CMD.value, NvmeMIMessageType.ADMIN_CMD.value],
        ),
        ConditionalField(
            XByteField("unused7", 0),
            lambda pkt: pkt.nmimt in [NvmeMIMessageType.CMD.value, NvmeMIMessageType.ADMIN_CMD.value],
        ),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        rqType = "REQ" if self.is_request() else "RSP"
        nmint_field = self.get_field("nmimt")
        nmint_value = self.nmimt
        nmimt_str = nmint_field.i2s[nmint_value] if nmint_field and nmint_value in nmint_field.i2s else "UNKNOWN"
        summary = f"{self.name} {rqType} (nmimt: 0x{self.nmimt:02X}, csi: 0x{self.csi:02X}"
        if self.nmimt in [NvmeMIMessageType.CMD.value, NvmeMIMessageType.ADMIN_CMD.value]:
            summary += f", opcode: 0x{self.opcode:02X}"
        summary += f") {nmimt_str}"
        return summary, [TransportHdrPacket, SmbusTransportPacket, TrimmedSmbusTransportPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return any(
            [
                self.ror == RqBit.REQUEST.value,
            ]
        )

    def do_dissect_payload(self, s: bytes) -> None:
        if not s:
            return
        cls = self.guess_payload_class(s)
        try:
            p = cls(s, _internal=1, _underlayer=self)
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector and cls is not None:
                raise
            p = conf.raw_layer(s, _internal=1, _underlayer=self)
        self.add_payload(p)
        if isinstance(p, ICanSetMySummaryClasses):
            p.set_mysummary_classes([NvmeMIHdrPacket, TransportHdrPacket])
