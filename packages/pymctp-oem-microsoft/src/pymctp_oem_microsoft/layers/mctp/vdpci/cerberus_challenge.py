from enum import IntEnum
from typing import Tuple, Union, List

from scapy.fields import XByteField, XLEIntField, XLEShortField, StrFixedLenField, ConditionalField
from scapy.packet import Packet, bind_layers

from pymctp.layers.helpers import AllowRawSummary
from pymctp.layers.mctp import VdPciHdrPacket
from pymctp.layers.mctp.types import AnyPacketType
from pymctp.layers.mctp.vdpci import VdPCIVendorIds


class ChallengeCmdCodes(IntEnum):
    CERBERUS_PROTOCOL_GET_FW_VERSION = 0x01  # Get FW version
    CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES = 2  # Get device capabilities
    CERBERUS_PROTOCOL_GET_DEVICE_ID = 3  # Get device ID
    CERBERUS_PROTOCOL_GET_DEVICE_INFO = 4  # Get device information
    CERBERUS_PROTOCOL_EXPORT_CSR = 0x20  # Export CSR
    CERBERUS_PROTOCOL_IMPORT_CA_SIGNED_CERT = 0x21  # Import CA signed certificate
    CERBERUS_PROTOCOL_GET_SIGNED_CERT_STATE = 0x22  # Get state of the signed certificates
    CERBERUS_PROTOCOL_GET_HOST_STATE = 0x40  # Get Host reset state
    CERBERUS_PROTOCOL_GET_LOG_INFO = 0x4F  # Get log info
    CERBERUS_PROTOCOL_READ_LOG = 0x50  # Read back log
    CERBERUS_PROTOCOL_CLEAR_LOG = 0x51  # Clear log
    CERBERUS_PROTOCOL_GET_ATTESTATION_DATA = 0x52  # Retrieve raw data for log measurements
    CERBERUS_PROTOCOL_GET_PFM_ID = 0x59  # Get PFM ID
    CERBERUS_PROTOCOL_GET_PFM_SUPPORTED_FW = 0x5A  # Get PFM supported FW versions
    CERBERUS_PROTOCOL_INIT_PFM_UPDATE = 0x5B  # Initialize PFM update process
    CERBERUS_PROTOCOL_PFM_UPDATE = 0x5C  # Send PFM update data
    CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE = 0x5D  # Trigger Cerberus to verify PFM update
    CERBERUS_PROTOCOL_GET_CFM_ID = 0x5E  # Get CFM ID
    CERBERUS_PROTOCOL_INIT_CFM_UPDATE = 0x5F  # Initialize CFM update process
    CERBERUS_PROTOCOL_CFM_UPDATE = 0x60  # Send CFM update data
    CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE = 0x61  # Trigger Cerberus to verify CFM update
    CERBERUS_PROTOCOL_GET_PCD_ID = 0x62  # Get PCD ID
    CERBERUS_PROTOCOL_INIT_PCD_UPDATE = 0x63  # Initialize PCD update process
    CERBERUS_PROTOCOL_PCD_UPDATE = 0x64  # Send PCD update data
    CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE = 0x65  # Trigger Cerberus to verify PCD update
    CERBERUS_PROTOCOL_INIT_FW_UPDATE = 0x66  # Initialize FW update process
    CERBERUS_PROTOCOL_FW_UPDATE = 0x67  # Send FW update data
    CERBERUS_PROTOCOL_GET_UPDATE_STATUS = 0x68  # Get update status
    CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE = 0x69  # Trigger Cerberus to start FW update
    CERBERUS_PROTOCOL_RESET_CONFIG = 0x6A  # Erase configuration from the device.
    CERBERUS_PROTOCOL_GET_CONFIG_ID = 0x70  # Get configuration IDs
    CERBERUS_PROTOCOL_TRIGGER_FW_RECOVERY = 0x71  # Trigger Cerberus FW recovery
    CERBERUS_PROTOCOL_PREPARE_RECOVERY_IMAGE = 0x72  # Prepare to receive host recovery data
    CERBERUS_PROTOCOL_UPDATE_RECOVERY_IMAGE = 0x73  # Send host recovery image data
    CERBERUS_PROTOCOL_ACTIVATE_RECOVERY_IMAGE = 0x74  # Activate host recovery image
    CERBERUS_PROTOCOL_GET_RECOVERY_IMAGE_VERSION = 0x75  # Get active host recovery image version ID
    CERBERUS_PROTOCOL_ERROR = 0x7F  # Error response message
    CERBERUS_PROTOCOL_GET_PMR = 0x80  # Get a Platform Measurement Register
    CERBERUS_PROTOCOL_GET_DIGEST = 0x81  # Get certificate digest
    CERBERUS_PROTOCOL_GET_CERTIFICATE = 0x82  # Get certificate
    CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE = 0x83  # Attestation challenge
    CERBERUS_PROTOCOL_EXCHANGE_KEYS = 0x84  # Exchange pre-master session keys
    CERBERUS_PROTOCOL_SESSION_SYNC = 0x85  # Session sync
    CERBERUS_PROTOCOL_UPDATE_PMR = 0x86  # Extend a Platform Measurement Register
    CERBERUS_PROTOCOL_RESET_COUNTER = 0x87  # Reset counter
    CERBERUS_PROTOCOL_UNSEAL_MESSAGE = 0x89  # Start unsealing message
    CERBERUS_PROTOCOL_UNSEAL_MESSAGE_RESULT = 0x8A  # Get unsealing result*/
    CERBERUS_PROTOCOL_GET_CFM_SUPPORTED_COMPONENT_IDS = 0x8D  # Get CFM supported component IDs
    CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS = 0x8E  # Get extended update status

    OVERLAKE_PROTOCOL_GET_STORAGE = 0xA1  # Get blob storage */
    OVERLAKE_PROTOCOL_SET_STORAGE = 0xA2  # Set blob storage */
    OVERLAKE_PROTOCOL_GET_COUNTER = 0xA3  # Get tamper counter */
    OVERLAKE_PROTOCOL_INCREMENT_COUNTER = 0xA4  # Increment tamper counter */
    OVERLAKE_PROTOCOL_READ_DATA = 0xA5  # Read data from internal storage */
    OVERLAKE_PROTOCOL_CLEAR_DATA = 0xA6  # Clear internal storage data */
    OVERLAKE_PROTOCOL_STORE_DATA = 0xA7  # Store data to internal storage */
    OVERLAKE_PROTOCOL_SIGN_DATA = 0xA8  # Sign object data */
    OVERLAKE_PROTOCOL_GET_FPGA_BOOT_MODE = 0xB0  # Get cached FPGA boot mode */
    OVERLAKE_PROTOCOL_SET_FPGA_BOOT_MODE = 0xB1  # Set FPGA boot mode in flash and update cache */
    OVERLAKE_PROTOCOL_GET_SOC_FW_HEADER = 0xB3  # Get the extended header of the port. */
    OVERLAKE_PROTOCOL_SOC_RESET = 0xE0  # Reset SoC */
    OVERLAKE_PROTOCOL_SOC_INIT_FW_UPDATE = 0xE1  # Init SoC FW update process */
    OVERLAKE_PROTOCOL_SOC_UPDATE_FW = 0xE2  # Send SoC FW update data */
    OVERLAKE_PROTOCOL_TRIGGER_NMI = 0xE3  # Trigger SoC NMI */
    OVERLAKE_PROTOCOL_GET_BOOT_DEVICE = 0xE4  # Get SoC boot device */
    OVERLAKE_PROTOCOL_SET_BOOT_DEVICE = 0xE5  # Change SoC boot device */
    OVERLAKE_PROTOCOL_GET_MAC_ADDRESS = 0xE6  # Get SoC MAC Address */
    OVERLAKE_PROTOCOL_GET_DEBUG_LOG_INFO = 0xE7  # Get SoC firmware debug Log info */
    OVERLAKE_PROTOCOL_GET_DEBUG_LOG = 0xE8  # Get SoC debug log data */
    OVERLAKE_PROTOCOL_GET_SOC_UPDATE_STATUS = 0xE9  # Get SoC update status */
    OVERLAKE_PROTOCOL_TPM_CLEAR = 0xEA  # TPM clear */
    OVERLAKE_PROTOCOL_GET_PUBLIC_KEY = 0xEB  # Get public key */
    OVERLAKE_PROTOCOL_DECRYPT_PAYLOAD = 0xEC  # Decrypt payload */
    OVERLAKE_PROTOCOL_SET_DEBUG_VERBOSITY = 0xED  # Set SoC debug verbose level */
    OVERLAKE_PROTOCOL_GET_DEBUG_VERBOSITY = 0xEE  # Get SoC debug verbose level */
    OVERLAKE_PROTOCOL_GET_SOC_FWVERSION = 0xEF  # Get the SoC FW Version */

    # Special diagnostic commands to query for device health or other debug information.
    CERBERUS_PROTOCOL_DIAG_HEAP_USAGE = 0xD0  # Diagnostic command to get heap usage

    # Utilize the reserved command space for debugging.  Must be disabled in production.
    CERBERUS_PROTOCOL_DEBUG_START_ATTESTATION = 0xF0  # Debug command to start attestation
    CERBERUS_PROTOCOL_DEBUG_GET_ATTESTATION_STATE = 0xF1  # Debug command to get attestation status
    CERBERUS_PROTOCOL_DEBUG_FILL_LOG = 0xF2  # Debug command to fill up debug log
    CERBERUS_PROTOCOL_DEBUG_RESERVED = 0xFF  # Not available to use as a debug command.


class ErrorResponsePacket(AllowRawSummary, Packet):
    name = "ERR RSP"
    fields_desc = [XByteField("code", 0), XLEIntField("data", 0)]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (code: 0x{self.code:02X}, data: 0x{self.data:02X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


bind_layers(
    VdPciHdrPacket,
    ErrorResponsePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_ERROR.value,
)


class FwVersionRequestPacket(AllowRawSummary, Packet):
    name = "FW-Version REQ"
    fields_desc = [XByteField("area_index", 0)]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (area_index: {self.area_index:02X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class FwVersionResponsePacket(AllowRawSummary, Packet):
    name = "FW-Version RSP"
    fields_desc = [StrFixedLenField("version", "", 32)]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        version_str = self.version.rstrip(b"\0")
        summary = f"{self.name} (ver: {version_str.decode()})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class FwVersionCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if not _pkt:
            return cls
        if len(_pkt) == 1:
            return FwVersionRequestPacket
        return FwVersionResponsePacket


bind_layers(
    VdPciHdrPacket,
    FwVersionCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_GET_FW_VERSION.value,
)
bind_layers(
    VdPciHdrPacket,
    FwVersionCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.OVERLAKE_PROTOCOL_GET_SOC_FWVERSION.value,
)


class DeviceCapsRequestPacket(AllowRawSummary, Packet):
    name = "Dev-Caps REQ"
    fields_desc = [
        XLEShortField("max_message", 0),
        XLEShortField("max_packet", 0),
        XByteField("device_info", 0),
        XByteField("features", 0),
        XByteField("pk_key_strength", 0),
        XByteField("enc_key_strength", 0),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = (
            f"{self.name} (max_msg: {self.max_message}, max_pkt: {self.max_packet}, "
            f"info: 0x{self.device_info:02X},"
            f"ft: 0x{self.features:02X}, "
            f"pk_str: 0x{self.pk_key_strength:02X}, "
            f"enc_str: 0x{self.enc_key_strength:02X})"
        )
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class DeviceCapsResponsePacket(AllowRawSummary, Packet):
    name = "Dev-Caps RSP"
    fields_desc = [
        XLEShortField("max_message", 0),
        XLEShortField("max_packet", 0),
        XByteField("device_info", 0),
        XByteField("features", 0),
        XByteField("pk_key_strength", 0),
        XByteField("enc_key_strength", 0),
        XByteField("message_timeout", 0),
        XByteField("crypto_timeout", 0),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = (
            f"{self.name} (max_msg: {self.max_message}, max_pkt: {self.max_packet}, "
            f"info: 0x{self.device_info:02X},"
            f"ft: 0x{self.features:02X}, "
            f"pk_str: 0x{self.pk_key_strength:02X}, "
            f"enc_str: 0x{self.enc_key_strength:02X}, "
            f"msg_to: 0x{self.message_timeout:02X}, "
            f"crypt_to: 0x{self.crypto_timeout:02X})"
        )
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class DeviceCapsCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if not _pkt:
            return cls
        if len(_pkt) == 8:
            return DeviceCapsRequestPacket
        return DeviceCapsResponsePacket


bind_layers(
    VdPciHdrPacket,
    DeviceCapsCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES.value,
)


class GetLogRequestPacket(AllowRawSummary, Packet):
    name = "Get-Log-Info REQ"
    fields_desc = []

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name}"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class GetLogResponsePacket(AllowRawSummary, Packet):
    name = "Get-Log-Info RSP"
    fields_desc = [
        XLEIntField("debug_log_length", 0),
        XLEIntField("attestation_log_length", 0),
        XLEIntField("tamper_log_length", 0),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = (
            f"{self.name} (debug: 0x{self.debug_log_length:02X}, "
            f"attest: 0x{self.attestation_log_length:02X}, "
            f"tamper: 0x{self.tamper_log_length:02X})"
        )
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class GetLogInfoCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if not _pkt:
            return cls
        if len(_pkt) == 0:
            return GetLogRequestPacket
        return GetLogResponsePacket


bind_layers(
    VdPciHdrPacket,
    GetLogInfoCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_GET_LOG_INFO.value,
)


class ReadLogRequestPacket(AllowRawSummary, Packet):
    name = "Read-Log REQ"
    fields_desc = [XByteField("log_type", 0), XLEIntField("offset", 0)]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (type: {self.log_type}, offset: 0x{self.offset:02X})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ReadLogResponsePacket(AllowRawSummary, Packet):
    name = "Read-Log RSP"
    fields_desc = []

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name}"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return False


class ReadLogCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if not _pkt:
            return cls
        if len(_pkt) == 5:
            return ReadLogRequestPacket
        return ReadLogResponsePacket


bind_layers(
    VdPciHdrPacket,
    ReadLogCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_READ_LOG.value,
)


class ExtendedUpdateStatusRequestPacket(AllowRawSummary, Packet):
    name = "xUpdateStatus REQ"
    fields_desc = [
        XByteField("update_type", 0),
        XByteField("port_id", 0),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (type: {self.update_type}, port_id: {self.port_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ExtendedUpdateStatusResponsePacket(AllowRawSummary, Packet):
    name = "xUpdateStatus RSP"
    fields_desc = [
        XLEIntField("status", 0),
        XLEIntField("remaining_bytes", 0),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        summary = f"{self.name} (status: 0x{self.status:08X}, remaining: {self.remaining_bytes})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


class ExtendedUpdateCmdPacket(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if not _pkt:
            return cls
        if len(_pkt) == 2:
            return ExtendedUpdateStatusRequestPacket
        return ExtendedUpdateStatusResponsePacket


bind_layers(
    VdPciHdrPacket,
    ExtendedUpdateCmdPacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_GET_EXT_UPDATE_STATUS.value,
)


def _get_update_type_name(cmd_code: int) -> str:
    if (
        ChallengeCmdCodes.CERBERUS_PROTOCOL_INIT_FW_UPDATE.value
        <= cmd_code
        <= ChallengeCmdCodes.CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE.value
    ):
        return "FW"
    if (
        ChallengeCmdCodes.CERBERUS_PROTOCOL_INIT_PCD_UPDATE.value
        <= cmd_code
        <= ChallengeCmdCodes.CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE.value
    ):
        return "PCD"
    if (
        ChallengeCmdCodes.CERBERUS_PROTOCOL_INIT_PFM_UPDATE.value
        <= cmd_code
        <= ChallengeCmdCodes.CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE.value
    ):
        return "PFM"
    if (
        ChallengeCmdCodes.CERBERUS_PROTOCOL_INIT_CFM_UPDATE.value
        <= cmd_code
        <= ChallengeCmdCodes.CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE.value
    ):
        return "CFM"
    if (
        ChallengeCmdCodes.OVERLAKE_PROTOCOL_SOC_INIT_FW_UPDATE.value
        <= cmd_code
        <= ChallengeCmdCodes.OVERLAKE_PROTOCOL_SOC_UPDATE_FW.value
    ):
        return "SOC"


class PrepareUpdatePacket(AllowRawSummary, Packet):
    name = "Init-Update REQ"
    fields_desc = [
        ConditionalField(
            XByteField("port_id", 0),
            lambda pkt: pkt.underlayer.getfieldval("vdm_cmd_code")
            == ChallengeCmdCodes.CERBERUS_PROTOCOL_INIT_PFM_UPDATE.value,
        ),
        XLEIntField("size", 0),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        fw_type = _get_update_type_name(self.underlayer.getfieldval("vdm_cmd_code"))
        summary = f"{self.name} {fw_type} (size: {self.size}"
        if "port_id" in self.fields:
            summary += f", port_id: {self.port_id}"
        summary += ")"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    PrepareUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_INIT_FW_UPDATE.value,
)
bind_layers(
    VdPciHdrPacket,
    PrepareUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_INIT_CFM_UPDATE.value,
)
bind_layers(
    VdPciHdrPacket,
    PrepareUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_INIT_PCD_UPDATE.value,
)
bind_layers(
    VdPciHdrPacket,
    PrepareUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_INIT_PFM_UPDATE.value,
)
bind_layers(
    VdPciHdrPacket,
    PrepareUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.OVERLAKE_PROTOCOL_SOC_INIT_FW_UPDATE.value,
)


class GenericUpdatePacket(AllowRawSummary, Packet):
    name = "Update REQ"
    fields_desc = [
        ConditionalField(
            XByteField("port_id", 0),
            lambda pkt: pkt.underlayer.getfieldval("vdm_cmd_code")
            == ChallengeCmdCodes.CERBERUS_PROTOCOL_PFM_UPDATE.value,
        ),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        fw_type = _get_update_type_name(self.underlayer.getfieldval("vdm_cmd_code"))
        summary = f"{fw_type}-{self.name}"
        if "port_id" in self.fields:
            summary += f" (port_id: {self.port_id})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    GenericUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_FW_UPDATE.value,
)
bind_layers(
    VdPciHdrPacket,
    GenericUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_CFM_UPDATE.value,
)
bind_layers(
    VdPciHdrPacket,
    GenericUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_PCD_UPDATE.value,
)
bind_layers(
    VdPciHdrPacket,
    GenericUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_PFM_UPDATE.value,
)
bind_layers(
    VdPciHdrPacket,
    GenericUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.OVERLAKE_PROTOCOL_SOC_UPDATE_FW.value,
)


class ActivateUpdatePacket(AllowRawSummary, Packet):
    name = "Activate-Update REQ"
    fields_desc = [
        ConditionalField(
            XByteField("port_id", 0),
            lambda pkt: pkt.underlayer.getfieldval("vdm_cmd_code")
            == ChallengeCmdCodes.CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE.value,
        ),
        ConditionalField(
            XByteField("activation", 0),
            lambda pkt: pkt.underlayer.getfieldval("vdm_cmd_code")
            in [
                ChallengeCmdCodes.CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE.value,
                ChallengeCmdCodes.CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE.value,
            ],
        ),
    ]

    def mysummary(self) -> Union[str, Tuple[str, List[AnyPacketType]]]:
        fw_type = _get_update_type_name(self.underlayer.getfieldval("vdm_cmd_code"))
        summary = f"{self.name} {fw_type}"
        if "PFM" == fw_type:
            summary += f" (port_id: {self.port_id}, activation: {self.activation})"
        elif "CFM" == fw_type:
            summary += f" (activation: {self.activation})"
        return summary, [VdPciHdrPacket]

    def is_request(self, check_payload: bool = True) -> bool:
        return True


bind_layers(
    VdPciHdrPacket,
    ActivateUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_COMPLETE_FW_UPDATE.value,
)
bind_layers(
    VdPciHdrPacket,
    ActivateUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_COMPLETE_CFM_UPDATE.value,
)
bind_layers(
    VdPciHdrPacket,
    ActivateUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_COMPLETE_PCD_UPDATE.value,
)
bind_layers(
    VdPciHdrPacket,
    ActivateUpdatePacket,
    vendor_id=VdPCIVendorIds.Msft,
    vdm_cmd_code=ChallengeCmdCodes.CERBERUS_PROTOCOL_COMPLETE_PFM_UPDATE.value,
)
