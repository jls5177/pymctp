# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""
SPDM GET_MEASUREMENTS / MEASUREMENTS message packets (DSP0274).

GET_MEASUREMENTS request:
  param1 = Attributes (GenSig, RawBitReq, NewMeasReq)
  param2 = measurement_operation (0=TotalNum, 1-0xFE=index, 0xFF=All)
  nonce(32) — present when GENERATE_SIGNATURE is set
  slot_id_param(1) — added in v1.1, present when GENERATE_SIGNATURE is set

MEASUREMENTS response:
  param1 = TotalNumberOfMeasurement (when op==TotalNum) / RSVD
  param2[3:0] = slot_id, param2[5:4] = content_changed
  number_of_blocks(1), measurement_record_length(3 LE)
  followed by variable measurement_record, nonce, opaque data, signature

spdm-dump style output:
  SPDM_GET_MEASUREMENTS (Attr=0x01(GenSig), MeasOp=0xFF(All), SlotID=0x00)
  SPDM_MEASUREMENTS (NumBlocks=3, MeasRecordLen=0x000120)
"""

from enum import IntFlag

from scapy.fields import (
    ConditionalField,
    StrFixedLenField,
    ThreeBytesField,
    XByteField,
)
from scapy.packet import Packet

from ..transport import TransportHdrPacket
from ..types import AnyPacketType
from .spdm import AutobindSPDMMsg, SpdmHdrPacket
from .types import SpdmRequestCode, SpdmResponseCode

SPDM_NONCE_SIZE = 32
SPDM_VERSION_11 = 0x11


class MeasurementRequestAttributes(IntFlag):
    GENERATE_SIGNATURE = 0x01
    RAW_BIT_STREAM_REQUESTED = 0x02
    NEW_MEASUREMENT_REQUESTED = 0x04


_ATTR_NAMES = {
    MeasurementRequestAttributes.GENERATE_SIGNATURE: "GenSig",
    MeasurementRequestAttributes.RAW_BIT_STREAM_REQUESTED: "RawBitReq",
    MeasurementRequestAttributes.NEW_MEASUREMENT_REQUESTED: "NewMeasReq",
}


def _format_meas_attr(attr: int) -> str:
    names = [v for k, v in _ATTR_NAMES.items() if attr & k]
    return "|".join(names) if names else "0"


def _format_meas_op(op: int) -> str:
    if op == 0:
        return "TotalNum"
    if op == 0xFF:
        return "All"
    return f"Index({op})"


def _has_sig(pkt: Packet) -> bool:
    """Check if the request includes a signature (GENERATE_SIGNATURE set in param1)."""
    if pkt.underlayer is not None:
        return bool(pkt.underlayer.getfieldval("param1") & MeasurementRequestAttributes.GENERATE_SIGNATURE)
    return False


def _spdm_version_from_pkt(pkt: Packet) -> int:
    if pkt.underlayer is not None:
        return pkt.underlayer.getfieldval("spdm_version")
    return 0x10


# ---------------------------------------------------------------------------
# GET_MEASUREMENTS request
# ---------------------------------------------------------------------------
@AutobindSPDMMsg(SpdmRequestCode.GET_MEASUREMENTS)
class GetMeasurementsPacket(Packet):
    name = "SPDM_GET_MEASUREMENTS"
    fields_desc = [
        # nonce is only present when GENERATE_SIGNATURE is set in param1
        ConditionalField(
            StrFixedLenField("nonce", b"\x00" * SPDM_NONCE_SIZE, length=SPDM_NONCE_SIZE),
            lambda pkt: _has_sig(pkt),
        ),
        # slot_id_param added in v1.1, only when GENERATE_SIGNATURE set
        ConditionalField(
            XByteField("slot_id_param", 0),
            lambda pkt: _has_sig(pkt) and _spdm_version_from_pkt(pkt) >= SPDM_VERSION_11,
        ),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        attr = 0
        meas_op = 0
        ver = 0x10
        if self.underlayer is not None:
            attr = self.underlayer.getfieldval("param1")
            meas_op = self.underlayer.getfieldval("param2")
            ver = self.underlayer.getfieldval("spdm_version")

        summary = (
            f"SPDM_GET_MEASUREMENTS ("
            f"Attr=0x{attr:02X}({_format_meas_attr(attr)})"
            f", MeasOp=0x{meas_op:02X}({_format_meas_op(meas_op)})"
        )
        if (attr & MeasurementRequestAttributes.GENERATE_SIGNATURE) and ver >= SPDM_VERSION_11:
            slot_id = getattr(self, "slot_id_param", 0) or 0
            summary += f", SlotID=0x{slot_id:02X}"
        summary += ")"
        return summary, [SpdmHdrPacket, TransportHdrPacket]


# ---------------------------------------------------------------------------
# MEASUREMENTS response
# ---------------------------------------------------------------------------
@AutobindSPDMMsg(SpdmResponseCode.MEASUREMENTS)
class MeasurementsPacket(Packet):
    name = "SPDM_MEASUREMENTS"
    fields_desc = [
        XByteField("number_of_blocks", 0),
        ThreeBytesField("measurement_record_length", 0),
    ]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        summary = (
            f"SPDM_MEASUREMENTS ("
            f"NumBlocks={self.number_of_blocks}"
            f", MeasRecordLen=0x{self.measurement_record_length:06X})"
        )
        return summary, [SpdmHdrPacket, TransportHdrPacket]


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------
def GetMeasurements(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    spdm_version: int = 0x10,
    attributes: int = 0,
    measurement_operation: int = 0xFF,
    nonce: bytes = b"\x00" * SPDM_NONCE_SIZE,
    slot_id: int = 0,
) -> GetMeasurementsPacket:
    """Create a GET_MEASUREMENTS request packet."""
    hdr = SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=SpdmRequestCode.GET_MEASUREMENTS,
        param1=attributes,
        param2=measurement_operation,
    )
    if _pkt:
        return GetMeasurementsPacket(_pkt, _underlayer=hdr)
    kwargs: dict = {}
    if attributes & MeasurementRequestAttributes.GENERATE_SIGNATURE:
        kwargs["nonce"] = nonce
        if spdm_version >= SPDM_VERSION_11:
            kwargs["slot_id_param"] = slot_id
    return GetMeasurementsPacket(_underlayer=hdr, **kwargs)


def MeasurementsResponse(
    _pkt: bytes | bytearray = b"",
    /,
    *,
    spdm_version: int = 0x10,
    slot_id: int = 0,
    number_of_blocks: int = 0,
    measurement_record_length: int = 0,
) -> MeasurementsPacket:
    """Create a MEASUREMENTS response packet."""
    hdr = SpdmHdrPacket(
        spdm_version=spdm_version,
        request_response_code=SpdmResponseCode.MEASUREMENTS,
        param1=0,
        param2=slot_id & 0x0F,
    )
    if _pkt:
        return MeasurementsPacket(_pkt, _underlayer=hdr)
    return MeasurementsPacket(
        number_of_blocks=number_of_blocks,
        measurement_record_length=measurement_record_length,
        _underlayer=hdr,
    )
