# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.fields import XByteEnumField, XByteField, XLEIntField
from scapy.packet import Packet, bind_layers

from ....helpers import AllowRawSummary
from ...types import AnyPacketType
from ..vdpci import VdPciHdrPacket
from ..types import VdPCIVendorIds
from .types import CerberusCmdCodes, CerberusErrorCodes
from .rot_errors import ROT_ERROR_TABLE_PUBLIC, RotErrorTable, rot_is_error


class ErrorResponsePacket(AllowRawSummary, Packet):
    name = "Cerberus-Error"
    fields_desc = [
        XByteEnumField("code", 0, CerberusErrorCodes),
        XLEIntField("data", 0),
    ]

    # Error tables used to decode the data field. Additional tables (e.g. for
    # private modules) can be appended at runtime.
    rot_error_tables: list[RotErrorTable] = [ROT_ERROR_TABLE_PUBLIC]

    def mysummary(self) -> str | tuple[str, list[AnyPacketType]]:
        try:
            code_name = CerberusErrorCodes(self.code).name
        except ValueError:
            code_name = f"0x{self.code:02X}"

        data_str = f"0x{self.data:08X}"
        if rot_is_error(self.data):
            for table in self.rot_error_tables:
                info = table.decode(self.data)
                if info is not None and info.error_name is not None:
                    data_str = f"{info.module_name}::{info.error_name}"
                    break
                elif info is not None:
                    data_str = f"{info.module_name}::0x{info.error_code:02X}"
                    break

        summary = f"{self.name} (code={code_name}, data={data_str})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


bind_layers(
    VdPciHdrPacket,
    ErrorResponsePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=CerberusCmdCodes.ERROR,
)
