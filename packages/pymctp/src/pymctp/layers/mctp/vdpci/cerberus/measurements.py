# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import XByteField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes


# --- UPDATE_PMR ---


class UpdatePmrRequestPacket(AllowRawSummary, Packet):
    """Request to extend a PMR. Contains pmr_id followed by variable-length measurement data."""

    name = "Cerberus-UpdatePMR-Req"
    fields_desc = [XByteField("pmr_id", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        data_len = len(bytes(self.payload)) if self.payload else 0
        summary = f"{self.name} (pmr={self.pmr_id}, len={data_len})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class UpdatePmrResponsePacket(AllowRawSummary, Packet):
    """Response contains the updated PMR value as raw payload."""

    name = "Cerberus-UpdatePMR"
    fields_desc = [XByteField("pmr_length", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (len={self.pmr_length})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class UpdatePmrCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        # Request has pmr_id (1 byte) + measurement data (variable, > 0)
        # Response has pmr_length (1 byte) + PMR value
        # Disambiguate via rq bit in VdPci header at runtime
        return cls


bind_layers(
    VdPciHdrPacket,
    UpdatePmrCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.UPDATE_PMR,
)


# --- RESET_COUNTER ---


class ResetCounterRequestPacket(AllowRawSummary, Packet):
    name = "Cerberus-ResetCounter-Req"
    fields_desc = [
        XByteField("counter_type", 0),
        XByteField("port_id", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (type={self.counter_type}, port={self.port_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ResetCounterResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-ResetCounter"
    fields_desc = [XByteField("counter", 0)]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = f"{self.name} (count={self.counter})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ResetCounterCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is None:
            return cls
        if len(_pkt) == 2:
            return ResetCounterRequestPacket
        return ResetCounterResponsePacket


bind_layers(
    VdPciHdrPacket,
    ResetCounterCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.RESET_COUNTER,
)
