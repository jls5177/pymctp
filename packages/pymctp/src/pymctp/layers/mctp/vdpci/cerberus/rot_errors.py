# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""ROT error definitions from the Project-Cerberus firmware.

This module provides structured decoding of ROT error codes returned in the
Cerberus Error Response "data" field. The error value is structured as:

    0x7f | module_id (16 bits) | error_code (8 bits)

Module IDs and error codes are split between public (Project-Cerberus) and
private packages. Additional error tables can be registered to support
private module definitions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


ROT_ERROR_MARKER = 0x7F000000


def rot_is_error(value: int) -> bool:
    """Check if a value is a ROT error code."""
    return (value & 0xFF000000) == ROT_ERROR_MARKER


def rot_error_module(value: int) -> int:
    """Extract the module ID from a ROT error code."""
    return (value & 0x00FFFF00) >> 8


def rot_error_code(value: int) -> int:
    """Extract the error code from a ROT error code."""
    return value & 0x000000FF


class RotModuleId(IntEnum):
    """Module identifiers from Project-Cerberus firmware."""

    INIT = 0x0000  # Top-level application that initializes the system.
    AES_GCM_ENGINE = 0x0001  # An AES-GCM crypto engine.  All engines use the same ID.
    ECC_ENGINE = 0x0002  # An ECC crypto engine.  All engines use the same ID.
    HASH_ENGINE = 0x0003  # A hash crypto engine.  All engines use the same ID.
    RSA_ENGINE = 0x0004  # An RSA crypto engine.  All engines use the same ID.
    X509_ENGINE = 0x0005  # An X.509 crypto engine.  All engines use the same ID.
    BASE64_ENGINE = 0x0006  # A base64 crypto engine.  All engines use the same ID.
    FLASH_MASTER = 0x0007  # A driver for SPI flash.  All drivers use the same ID.
    SPI_FLASH = 0x0008  # The interface to accessing SPI flash.
    FLASH_COMMON = 0x0009  # Common components for SPI flash commands.
    FLASH_UTIL = 0x000A  # Utilities for programming and verifying flash.
    APP_IMAGE = 0x000B  # Utilities for loading and verifying application images.
    FIRMWARE_IMAGE = 0x000C  # Interface to the firmware image format for the platform.
    KEY_MANIFEST = 0x000D  # Manifest containing authenticated keys.
    FIRMWARE_UPDATE = 0x000E  # Firmware updater.
    I2C_MASTER = 0x000F  # A driver for an I2C master.  All drivers use the same ID.
    I2C_SLAVE = 0x0010  # A driver for an I2C slave.  All drivers use the same ID.
    SPI_FILTER = 0x0011  # A driver for the SPI filter.  All drivers use the same ID.
    MFG_FILTER_HANDLER = 0x0012  # Configuration interface to set the flash device for the filter.
    SPI_FILTER_IRQ = 0x0013  # IRQ handler for the SPI filter.
    LOGGING = 0x0014  # Logger for system or security events.
    CMD_HANDLER = 0x0015  # Handler for received commands.
    MCTP_BASE_PROTOCOL = 0x0016  # MCTP base protocol handler.
    RIOT_CORE = 0x0017  # Implementation of RIoT Core.
    HOST_FW_UTIL = 0x0018  # Host firmware validation functions.
    BMC_RECOVERY = 0x0019  # BMC recovery manager.
    HOST_CONTROL = 0x001A  # Driver interface for controlling the host processor.
    HOST_IRQ_CTRL = 0x001B  # Driver interface for controlling host state IRQs.
    HOST_IRQ_HANDLER = 0x001C  # Handler for host state IRQs.
    HOST_PROCESSOR = 0x001D  # Manager for the host processor being protected.
    HOST_FLASH_MGR = 0x001E  # Manager for host flash state.
    MOCK = 0x001F  # Mock objects for unit testing.
    PLATFORM_TIMEOUT = 0x0020  # Platform abstraction for a timeout.
    PLATFORM_MUTEX = 0x0021  # Platform abstraction for mutexes.
    PLATFORM_TIMER = 0x0022  # Platform abstraction for a timer.
    STATE_MANAGER = 0x0023  # Storage for state information.
    MANIFEST = 0x0024  # Manifest files used for provisioning.
    PFM = 0x0025  # PFM files for host provisioning.
    CFM = 0x0026  # CFM files for component provisioning.
    MANIFEST_MANAGER = 0x0027  # Manager for manifest files.
    KEYSTORE = 0x0028  # Persistent storage for device keys.
    RIOT_KEY_MANAGER = 0x0029  # Management of RIoT keys and certificates.
    AUX_ATTESTATION = 0x002A  # Handler for auxiliary attestation flows.
    FIRMWARE_HEADER = 0x002B  # Header information on firmware images.
    ATTESTATION = 0x002C  # Attestation manager.
    RNG_ENGINE = 0x002D  # A RNG crypto engine.  All engines use the same ID.
    DEVICE_MANAGER = 0x002E  # Device manager.
    PCR = 0x002F  # PCR manager.
    CMD_BACKGROUND = 0x0030  # Command handler background context.
    OBSERVABLE = 0x0031  # Manager for observer notifications.
    PFM_OBSERVER = 0x0032  # Observers for PFM management.
    CFM_OBSERVER = 0x0033  # Observers for CFM management.
    SIG_VERIFICATION = 0x0034  # Verification for signatures.
    MANIFEST_VERIFICATION = 0x0035  # Verification and key management for manifests.
    SPI_FLASH_SFDP = 0x0036  # SFDP parsing for SPI flash devices.
    HOST_FLASH_INIT = 0x0037  # Delayed host flash initialization manager.
    FLASH = 0x0038  # Flash device.
    RECOVERY_IMAGE_HEADER = 0x0039  # Header information on a recovery image.
    IMAGE_HEADER = 0x003A  # Header information on an image.
    RECOVERY_IMAGE_SECTION_HEADER = 0x003B  # Header information on a recovery section image.
    CMD_CHANNEL = 0x003C  # Communication channel for commands.
    FIRMWARE_COMPONENT = 0x003D  # Firmware image component wrapper.
    SPI_SLAVE = 0x003E  # A driver for a SPI slave.  All drivers use the same ID.
    RESERVED_3F = 0x003F  # Reserved.
    FLASH_UPDATER = 0x0040  # Flash update management.
    CERT_DEVICE_HW = 0x0041  # Device hardware for certificate management.
    APP_CONTEXT = 0x0042  # Running context storage.
    RESERVED_43 = 0x0043  # Reserved.
    TPM = 0x0044  # TPM implementation.
    RESERVED_45 = 0x0045  # Reserved.
    AUTHORIZATION = 0x0046  # Authorization management for operations.
    CONFIG_RESET = 0x0047  # Manager for clearing device configuration.
    CMD_AUTHORIZATION = 0x0048  # Command authorization handler.
    RECOVERY_IMAGE = 0x0049  # Recovery image.
    RECOVERY_IMAGE_OBSERVER = 0x004A  # Observers for recovery image management.
    RECOVERY_IMAGE_MANAGER = 0x004B  # Recovery image manager.
    PCD = 0x004C  # PCD files for platform configuration.
    PCD_OBSERVER = 0x004D  # Observers for PCD management.
    CONFIG_CMD_TASK = 0x004E  # Command configuration task context.
    CMD_DEVICE = 0x004F  # Command handler for device-specific workflows.
    HOST_PROCESSOR_OBSERVER = 0x0050  # Observers for host processor management.
    COUNTER_MANAGER = 0x0051  # Counter operation management.
    SESSION_MANAGER = 0x0052  # Encrypted session management.
    FLASH_STORE = 0x0053  # Block data storage in flash.
    KDF = 0x0054  # Key derivation function.
    HOST_STATE_OBSERVER = 0x0055  # Observers for host state changes.
    SYSTEM = 0x0056  # Main system manager.
    SYSTEM_OBSERVER = 0x0057  # Observers for system events.
    PLATFORM_SEMAPHORE = 0x0058  # Platform abstraction for semaphores.
    INTRUSION_STATE = 0x0059  # Chassis intrusion state detection.
    INTRUSION_STATE_OBSERVER = 0x005A  # Observers for intrusion state changes.
    INTRUSION_MANAGER = 0x005B  # Manager for intrusion detection.
    CMD_HANDLER_MCTP_CTRL = 0x005C  # Handler for received MCTP control protocol messages.
    CERBERUS_PROTOCOL_OBSERVER = 0x005D  # Cerberus protocol observer.
    ECC_DER_UTIL = 0x005E  # Utilities for handling DER encoded ECC information.
    BUFFER_UTIL = 0x005F  # General buffer handling utilities.
    OCP_RECOVERY_DEVICE = 0x0060  # Device handler for the OCP Recovery protocol.
    OCP_RECOVERY_SMBUS = 0x0061  # SMBus layer for the OCP Recovery protocol.
    MCTP_CONTROL_PROTOCOL_OBSERVER = 0x0062  # MCTP control command interface observer.
    CMD_HANDLER_SPDM = 0x0063  # Handler for received SPDM protocol commands.
    SPDM_PROTOCOL_OBSERVER = 0x0064  # SPDM protocol observer.
    ASN1_UTIL = 0x0065  # ASN.1 operations.
    EVENT_TASK = 0x0066  # Task for event handling.
    PERIODIC_TASK = 0x0067  # Task for periodic execution.
    FIRMWARE_LOADER = 0x0068  # Handler to load firmware images into memory.
    DEVICE_MANAGER_OBSERVER = 0x0069  # Observers for device manager events.
    ECC_HW = 0x006A  # Driver interface for ECC accelerator hardware.
    COMMON_MATH = 0x006B  # Common math operations.
    HEAP_WITH_DEFRAG = 0x006C  # Heap allocator with defragmentation.
    PLATFORM_OS = 0x006D  # Platform abstraction for OS and task control.
    X509_EXTENSION = 0x006E  # Extension handler for X.509 certificates.
    DICE_TCBINFO_EXTENSION = 0x006F  # Extension handler for TCG DICE TcbInfo extensions.
    DICE_UEID_EXTENSION = 0x0070  # Extension handler for TCG DICE Ueid extensions.
    DME_EXTENSION = 0x0071  # Extension handler for DME extensions.
    DME_STRUCTURE = 0x0072  # Parsing and management of the DME structure.
    HOST_FIRMWARE_IMAGE = 0x0073  # Interface to Host firmware image operations.
    SECURE_DEVICE_UNLOCK = 0x0074  # Handler for device unlock requests.
    SECURITY_MANAGER = 0x0075  # Manager for the device security configuration.
    SECURITY_POLICY = 0x0076  # The device security policy.
    AUTH_TOKEN = 0x0077  # Authorization token handler.
    DEVICE_UNLOCK_TOKEN = 0x0078  # Handler for device unlock tokens.
    DOE_CMD_CHANNEL = 0x0079  # Communication channel for DOE commands.
    DOE_INTERFACE = 0x007A  # DOE interface.
    REAL_TIME_CLOCK = 0x007B  # The real time clock interface.
    RMA_UNLOCK_TOKEN = 0x007C  # Handler for device RMA unlock tokens.
    DEVICE_RMA_TRANSITION = 0x007D  # Device interface for RMA configuration.
    SPDM_TRANSCRIPT_MANAGER = 0x007E  # SPDM Transcript Manager.
    CMD_HANDLER_SPDM_RESPONDER = 0x007F  # Handler for SPDM protocol request commands.
    SPDM_MEASUREMENTS = 0x0080  # SPDM measurement block handler.
    CMD_INTERFACE_IDE_RESPONDER = 0x0081  # Handler for IDE protocol request commands.
    IDE_DRIVER = 0x0082  # Driver interface for programming IDE registers.
    MSG_TRANSPORT = 0x0083  # Handler for issuing remote requests.
    CMD_INTERFACE_TDISP_RESPONDER = 0x0084  # Handler for TDISP protocol request commands.
    TDISP_DRIVER = 0x0085  # Driver interface for programming TDISP registers.
    MCTP_NOTIFIER = 0x0086  # MCTP Notifier module.
    SPDM_SECURE_SESSION_MANAGER = 0x0087  # SPDM Secure Session Manager.
    ECDSA = 0x0088  # ECDSA signature handling.
    KEY_CACHE = 0x0089  # Key cache to handle rsa key management.
    EPHEMERAL_KEY_MANAGER = 0x008A  # Ephemeral key manager.
    EPHEMERAL_KEY_GENERATION = 0x008B  # Ephemeral key generation.
    AUTHORIZED_EXECUTION = 0x008C  # Execution context for authorized operations.
    SPDM_VDM_PROTOCOL = 0x008D  # SPDM vendor defined messages protocol.
    SPDM_PCISIG_PROTOCOL = 0x008E  # SPDM PCISIG messages protocol.
    IMPACTFUL_CHECK = 0x008F  # Device check for conditions requiring impactful updates.
    IMPACTFUL_UPDATE = 0x0090  # Interface for handling impactful updates.
    AES_XTS_ENGINE = 0x0091  # An AES-XTS crypto engine.  All engines use the same ID.
    MMIO_REGISTER = 0x0092  # MMIO register operations.
    MPU = 0x0093  # MPU interface
    TDISP_TDI_CONTEXT_MANAGER = 0x0094  # TDISP TDI context manager interface
    RSASSA = 0x0095  # RSASSA signature handling.
    ACVP_PROTO = 0x0096  # ACVP Proto handler.
    FIRMWARE_PFM_VERIFY = 0x0097  # Handler for verifying device FW with a PFM.
    BACKEND_SHA = 0x0098  # ACVP SHA backend.
    ACVP_PROTO_TESTER = 0x0099  # ACVP Proto tester.
    ECDH = 0x009A  # ECDH handling.
    AES_ECB_ENGINE = 0x009B  # An AES-ECB crypto engine.  All engines use the same ID.
    AES_CBC_ENGINE = 0x009C  # An AES-CBC crypto engine.  All engines use the same ID.
    AES_KEY_WRAP = 0x009D  # Handler for AES key wrap/unwrap.
    HKDF = 0x009E  # HKDF key derivation.
    BACKEND_AEAD = 0x009F  # ACVP AEAD backend.
    BACKEND_RSA = 0x00A0  # ACVP RSA backend.
    BACKEND_ECDSA = 0x00A1  # ACVP ECDSA backend.
    BACKEND_HKDF = 0x00A2  # ACVP HKDF backend.
    BACKEND_SYM = 0x00A3  # ACVP symmetric cipher backend.
    BACKEND_HMAC = 0x00A4  # ACVP HMAC backend.
    BACKEND_ECDH = 0x00A5  # ACVP ECDH backend.
    ERROR_STATE_ENTRY = 0x00A6  # FIPS error state entry handler.
    ERROR_STATE_EXIT = 0x00A7  # FIPS error state exit handler.
    AUTH_DATA = 0x00A8  # Authorized data handler for operation authentication.
    AUTH_SIGNATURE = 0x00A9  # Authorized data signature for operation authentication.
    EKU_EXTENSION = 0x00AA  # Extension handler for Extended Key Usage extensions.
    SPDM_PROTOCOL_SESSION_OBSERVER = 0x00AB  # SPDM protocol session observer.
    IDE_DRIVER_OBSERVER = 0x00AC  # IDE driver observer interface.
    TDISP_DRIVER_OBSERVER = 0x00AD  # TDISP driver observer interface.
    FATAL_ERROR_HANDLER = 0x00AE  # Handler for fatal firmware errors.
    SPDM_PERSISTENT_CONTEXT = 0x00AF  # SPDM persistent context interface.
    SPDM_CERT_CHAIN = 0x00B0  # SPDM certificate chain manager.


class RotAesGcmEngineErrors(IntEnum):
    """Error codes for An AES-GCM crypto engine.  All engines use the same ID."""

    AES_GCM_ENGINE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    AES_GCM_ENGINE_NO_MEMORY = 0x01  # Memory allocation failed.
    AES_GCM_ENGINE_SET_KEY_FAILED = 0x02  # The encryption key could not be set.
    AES_GCM_ENGINE_ENCRYPT_FAILED = 0x03  # The plaintext was not encrypted.
    AES_GCM_ENGINE_DECRYPT_FAILED = 0x04  # The ciphertext was not decrypted.
    AES_GCM_ENGINE_UNSUPPORTED_KEY_LENGTH = 0x05  # The encryption key length is not supported by the engine.
    AES_GCM_ENGINE_INVALID_KEY_LENGTH = 0x06  # The key length is not a valid AES key length.
    AES_GCM_ENGINE_OUT_BUFFER_TOO_SMALL = 0x07  # Not enough space in an output buffer provided for the operation.
    AES_GCM_ENGINE_NO_KEY = 0x08  # No key was set prior to encryption/decryption.
    AES_GCM_ENGINE_GCM_AUTH_FAILED = 0x09  # The decrypted plaintext failed authentication.
    AES_GCM_ENGINE_HW_NOT_INIT = 0x0A  # The AES hardware has not been initialized.
    AES_GCM_ENGINE_SELF_TEST_FAILED = 0x0B  # An internal self-test of the AES engine failed.
    AES_GCM_ENGINE_UNSUPPORTED_OPERATION = 0x0C  # The requested operation is not supported.
    AES_GCM_ENGINE_ENCRYPT_ADD_DATA_FAILED = 0x0D  # The plaintext with additional data was not encrypted.
    AES_GCM_ENGINE_DECRYPT_ADD_DATA_FAILED = 0x0E  # The ciphertext with additional data was not decrypted.
    AES_GCM_ENGINE_CLEAR_KEY_FAILED = 0x0F  # The encryption key could not be cleared.


class RotEccEngineErrors(IntEnum):
    """Error codes for An ECC crypto engine.  All engines use the same ID."""

    ECC_ENGINE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    ECC_ENGINE_NO_MEMORY = 0x01  # Memory allocation failed.
    ECC_ENGINE_KEY_PAIR_FAILED = 0x02  # Failed to initialize a key pair from DER data.
    ECC_ENGINE_PUBLIC_KEY_FAILED = 0x03  # Failed to initialize a public key from DER data.
    ECC_ENGINE_DERIVED_KEY_FAILED = 0x04  # Failed to generate a deterministic key pair.
    ECC_ENGINE_GENERATE_KEY_FAILED = 0x05  # Failed to generate a random key pair.
    ECC_ENGINE_PRIVATE_KEY_DER_FAILED = 0x06  # The private key was not encoded to DER.
    ECC_ENGINE_PUBLIC_KEY_DER_FAILED = 0x07  # The public key was not encoded to DER.
    ECC_ENGINE_SIGN_FAILED = 0x08  # The ECDSA signature was not generated.
    ECC_ENGINE_VERIFY_FAILED = 0x09  # A error unrelated to signature checking caused verification to fail.
    ECC_ENGINE_SHARED_SECRET_FAILED = 0x0A  # The ECDH secret was not generated.
    ECC_ENGINE_NOT_EC_KEY = 0x0B  # Key data does not contain an EC key.
    ECC_ENGINE_NOT_PRIVATE_KEY = 0x0C  # The key is not a private key.
    ECC_ENGINE_NOT_PUBLIC_KEY = 0x0D  # The key is not a public key.
    ECC_ENGINE_SIG_BUFFER_TOO_SMALL = 0x0E  # There is not enough buffer space to store the signature.
    ECC_ENGINE_SECRET_BUFFER_TOO_SMALL = 0x0F  # There is not enough buffer space to store the ECDH secret.
    ECC_ENGINE_BAD_SIGNATURE = 0x10  # ECDSA signature verification failed.
    ECC_ENGINE_HW_NOT_INIT = 0x11  # The ECC hardware has not been initialized.
    ECC_ENGINE_SIG_LENGTH_FAILED = 0x12  # Failed to get the maximum signature length.
    ECC_ENGINE_SECRET_LENGTH_FAILED = 0x13  # Failed to get the maximum shared secret length.
    ECC_ENGINE_UNSUPPORTED_KEY_LENGTH = 0x14  # The ECC key length is not supported by the implementation.
    ECC_ENGINE_UNSUPPORTED_HASH_TYPE = (
        0x15  # The hash algorithm for a signature digest is not supported by the implementation.
    )
    ECC_ENGINE_SELF_TEST_FAILED = 0x16  # An internal self-test of the ECC engine failed.
    ECC_ENGINE_UNSUPPORTED_OPERATION = 0x17  # The requested operation is not supported by the implementation.
    ECC_ENGINE_INCOMPATIBLE_DIGEST = 0x18  # The specified digest cannot be used for a signing operation.
    ECC_ENGINE_SIG_VERIFY_LENGTH_FAILED = 0x1A  # Failed to get the maximum signature length for verification.


class RotHashEngineErrors(IntEnum):
    """Error codes for A hash crypto engine.  All engines use the same ID."""

    HASH_ENGINE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    HASH_ENGINE_NO_MEMORY = 0x01  # Memory allocation failed.
    HASH_ENGINE_SHA1_FAILED = 0x02  # The SHA-1 hash was not calculated.
    HASH_ENGINE_SHA256_FAILED = 0x03  # The SHA-256 hash was not calculated.
    HASH_ENGINE_START_SHA1_FAILED = 0x04  # The engine has not been initialized for SHA-1.
    HASH_ENGINE_START_SHA256_FAILED = 0x05  # The engine has not been initialized for SHA-256.
    HASH_ENGINE_UPDATE_FAILED = 0x06  # The hash has not been updated with new data.
    HASH_ENGINE_FINISH_FAILED = 0x07  # The hash was not calculated.
    HASH_ENGINE_HASH_BUFFER_TOO_SMALL = 0x08  # The output buffer is not large enough for the specified hash.
    HASH_ENGINE_NO_ACTIVE_HASH = 0x09  # No hash has been started for calculation.
    HASH_ENGINE_UNSUPPORTED_HASH = 0x0A  # The hash is not supported by the engine.
    HASH_ENGINE_HW_NOT_INIT = 0x0B  # The hash hardware has not been initialized.
    HASH_ENGINE_SHA384_FAILED = 0x0C  # The SHA-384 hash was not calculated.
    HASH_ENGINE_SHA512_FAILED = 0x0D  # The SHA-512 hash was not calculated.
    HASH_ENGINE_START_SHA384_FAILED = 0x0E  # The engine has not been initialized for SHA-384.
    HASH_ENGINE_START_SHA512_FAILED = 0x0F  # The engine has not been initialized for SHA-512.
    HASH_ENGINE_UNKNOWN_HASH = 0x10  # An unknown hash type was requested.
    HASH_ENGINE_HASH_IN_PROGRESS = 0x11  # Attempt to start a new hash before finishing the previous one.
    HASH_ENGINE_SELF_TEST_FAILED = 0x12  # An internal self-test of the hash engine failed.
    HASH_ENGINE_GET_HASH_FAILED = 0x13  # Getting the hash failed.
    HASH_ENGINE_UNSUPPORTED_OPERATION = 0x14  # The requested operation is not supported by the engine.
    HASH_ENGINE_SHA1_SELF_TEST_FAILED = 0x15  # A SHA-1 self-test of the hash engine failed.
    HASH_ENGINE_SHA256_SELF_TEST_FAILED = 0x16  # A SHA-256 self-test of the hash engine failed.
    HASH_ENGINE_SHA384_SELF_TEST_FAILED = 0x17  # A SHA-384 self-test of the hash engine failed.
    HASH_ENGINE_SHA512_SELF_TEST_FAILED = 0x18  # A SHA-512 self-test of the hash engine failed.
    HASH_ENGINE_HMAC_SHA1_SELF_TEST_FAILED = 0x19  # A SHA-1 HMAC self-test of the hash engine failed.
    HASH_ENGINE_HMAC_SHA256_SELF_TEST_FAILED = 0x1A  # A SHA-256 HMAC self-test of the hash engine failed.
    HASH_ENGINE_HMAC_SHA384_SELF_TEST_FAILED = 0x1B  # A SHA-384 HMAC self-test of the hash engine failed.
    HASH_ENGINE_HMAC_SHA512_SELF_TEST_FAILED = 0x1C  # A SHA-512 HMAC self-test of the hash engine failed.


class RotRsaEngineErrors(IntEnum):
    """Error codes for An RSA crypto engine.  All engines use the same ID."""

    RSA_ENGINE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    RSA_ENGINE_NO_MEMORY = 0x01  # Memory allocation failed.
    RSA_ENGINE_GENERATE_KEY_FAILED = 0x02  # Failed to generate a random RSA key pair.
    RSA_ENGINE_KEY_PAIR_FAILED = 0x03  # Failed to initialize a private key from DER data.
    RSA_ENGINE_PRIVATE_KEY_DER_FAILED = 0x04  # The private key was not encoded to DER.
    RSA_ENGINE_PUBLIC_KEY_DER_FAILED = 0x05  # The public key was not encoded to DER.
    RSA_ENGINE_DECRYPT_FAILED = 0x06  # The data was not decrypted.
    RSA_ENGINE_VERIFY_FAILED = 0x07  # A error unrelated to signature checking caused verification to fail.
    RSA_ENGINE_NOT_RSA_KEY = 0x08  # Key data does not contain an RSA key.
    RSA_ENGINE_NOT_PRIVATE_KEY = 0x09  # The key is not a private key.
    RSA_ENGINE_OUT_BUFFER_TOO_SMALL = 0x0A  # Not enough space in the output buffer for decryption.
    RSA_ENGINE_BAD_SIGNATURE = 0x0B  # RSA signature verification failed.
    RSA_ENGINE_HW_NOT_INIT = 0x0C  # The RSA hardware has not been initialized.
    RSA_ENGINE_PUBLIC_KEY_FAILED = 0x0D  # Failed to initialize a public key from DER data.
    RSA_ENGINE_UNSUPPORTED_KEY_LENGTH = 0x0E  # The RSA key length is not supported.
    RSA_ENGINE_UNSUPPORTED_HASH_TYPE = 0x0F  # The encryption hash type is not supported.
    RSA_ENGINE_SELF_TEST_FAILED = 0x10  # An internal self-test of the RSA engine failed.
    RSA_ENGINE_UNSUPPORTED_SIG_TYPE = 0x11  # The signature hash type is not supported.


class RotX509EngineErrors(IntEnum):
    """Error codes for An X.509 crypto engine.  All engines use the same ID."""

    X509_ENGINE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    X509_ENGINE_NO_MEMORY = 0x01  # Memory allocation failed.
    X509_ENGINE_CSR_FAILED = 0x02  # The CSR was not created.
    X509_ENGINE_SELF_SIGNED_FAILED = 0x03  # The self-signed certificate was not created.
    X509_ENGINE_CA_SIGNED_FAILED = 0x04  # The CA-signed certificate was not created.
    X509_ENGINE_LOAD_FAILED = 0x05  # The certificate DER was not loaded.
    X509_ENGINE_CERT_DER_FAILED = 0x06  # The certificate was not encoded to DER.
    X509_ENGINE_KEY_TYPE_FAILED = 0x07  # Failed to get the key type from the certificate.
    X509_ENGINE_KEY_FAILED = 0x08  # Failed to get the key from the certificate.
    X509_ENGINE_ROOT_CA_FAILED = 0x09  # The root CA was not added for path validation.
    X509_ENGINE_INIT_STORE_FAILED = 0x0A  # The intermediate CA certificate store was not initialized.
    X509_ENGINE_INTER_CA_FAILED = 0x0B  # The intermediate CA was not added for path validation.
    X509_ENGINE_AUTH_FAILED = 0x0C  # An error unrelated to path validation caused authentication to fail.
    X509_ENGINE_RIOT_NO_FWID = 0x0D  # No FWID provided for the RIoT extension.
    X509_ENGINE_RIOT_UNSUPPORTED_HASH = 0x0E  # The RIoT FWID uses an unsupported hash algorithm.
    X509_ENGINE_UNSUPPORTED_KEY_TYPE = 0x0F  # A certificate contains a key for an unsupported algorithm.
    X509_ENGINE_UNKNOWN_KEY_TYPE = 0x10  # The type of key in a certificate could not be determined.
    X509_ENGINE_UNSUPPORTED_SIG_TYPE = 0x11  # The certificate signature uses an unsupported algorithm.
    X509_ENGINE_NOT_CA_CERT = 0x12  # The certificate is not a CA.
    X509_ENGINE_NOT_SELF_SIGNED = 0x13  # The certificate is not self-signed.
    X509_ENGINE_IS_SELF_SIGNED = 0x14  # The certificate is self-signed.
    X509_ENGINE_BAD_SIGNATURE = 0x15  # The certificate failed signature verification.
    X509_ENGINE_CERT_NOT_VALID = 0x16  # Path validation for the certificate failed.
    X509_ENGINE_RIOT_AUTH_FAILED = (
        0x17  # Path validation for the certificate succeeded, but the RIoT extension was not valid.
    )
    X509_ENGINE_HW_NOT_INIT = 0x18  # The X.509 hardware has not been initialized.
    X509_ENGINE_CERT_SIGN_FAILED = 0x19  # Failure related to signing the certificate.
    X509_ENGINE_LONG_SERIAL_NUM = 0x1A  # The certificate serial number exceeds the length supported by the engine.
    X509_ENGINE_BIG_CERT_SIZE = 0x1B  # The certificate length exceeds the size supported by the engine.
    X509_ENGINE_VERSION_FAILED = 0x1C  # Failed to get the version number from the certificate.
    X509_ENGINE_SERIAL_NUM_FAILED = 0x1D  # Failed to get the serial number from the certificate.
    X509_ENGINE_KEY_LENGTH_FAILED = 0x1E  # Failed to get the key length from the certificate.
    X509_ENGINE_SMALL_SERIAL_BUFFER = 0x1F  # Insufficient buffer space for the serial number.
    X509_ENGINE_LONG_OID = 0x20  # An OID is too long to be processed.
    X509_ENGINE_DICE_NO_VERSION = 0x21  # No version information for the DICE extension.
    X509_ENGINE_DICE_NO_UEID = 0x22  # No UEID information for the DICE extension.
    X509_ENGINE_INVALID_SERIAL_NUM = 0x23  # Provided serial number is an invalid value.
    X509_ENGINE_UNSUPPORTED_SIG_HASH = 0x24  # The certificate signature uses an unsupported digest.
    X509_ENGINE_TRUSTED_CA_FAILED = 0x25  # The trusted intermediate CA was not added for path validation.


class RotBase64EngineErrors(IntEnum):
    """Error codes for A base64 crypto engine.  All engines use the same ID."""

    BASE64_ENGINE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    BASE64_ENGINE_NO_MEMORY = 0x01  # Memory allocation failed.
    BASE64_ENGINE_ENCODE_FAILED = 0x02  # The data was not encoded.
    BASE64_ENGINE_ENC_BUFFER_TOO_SMALL = 0x03  # There is not enough space for the base64 encoded data.
    BASE64_ENGINE_HW_NOT_INIT = 0x04  # The base64 hardware has not been initialized.


class RotFlashMasterErrors(IntEnum):
    """Error codes for A driver for SPI flash.  All drivers use the same ID."""

    FLASH_MASTER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FLASH_MASTER_NO_MEMORY = 0x01  # Memory allocation failed.
    FLASH_MASTER_XFER_FAILED = 0x02  # The SPI transaction did not complete.
    FLASH_MASTER_UNSUPPORTED_XFER = 0x03  # The SPI transfer uses capabilities not supported by the driver.
    FLASH_MASTER_HW_NOT_INIT = 0x04  # The SPI hardware has not been initialized.
    FLASH_MASTER_XFER_TIMEOUT = 0x05  # The SPI transfer has timed out without completing.
    FLASH_MASTER_NO_XFER_DATA = 0x06  # No data buffer was provided for the transfer.
    FLASH_MASTER_XFER_DMA_ERROR = 0x07  # The was a DMA error while executing the transfer.
    FLASH_MASTER_GET_FREQ_FAILED = 0x08  # Failed to get the current SPI clock frequency.
    FLASH_MASTER_SET_FREQ_FAILED = 0x09  # Failed to set the SPI clock frequency.
    FLASH_MASTER_SPI_FREQ_UNSUPPORTED = 0x0A  # SPI clock operations are not supported by the driver.
    FLASH_MASTER_FREQ_OUT_OF_RANGE = 0x0B  # The target SPI clock frequency cannot be achieved by the hardware.
    FLASH_MASTER_XFER_IN_PROGRESS = 0x0C  # The operation is not possible because there is an active transfer.
    FLASH_MASTER_RX_FIFO_OVERFLOW = 0x0D  # The SPI HW receive FIFO overflowed and data was lost.
    FLASH_MASTER_TX_FIFO_UNDERFLOW = 0x0E  # The SPI HW transmit FIFO underflowed, corrupting the transfer.
    FLASH_MASTER_XFER_LEN_TOO_LARGE = 0x0F  # The SPI transfer exceeds allowed size.


class RotSpiFlashErrors(IntEnum):
    """Error codes for The interface to accessing SPI flash."""

    SPI_FLASH_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SPI_FLASH_NO_MEMORY = 0x01  # Memory allocation failed.
    SPI_FLASH_WIP_TIMEOUT = 0x02  # The write operation did not complete within the expected time.
    SPI_FLASH_WRITE_IN_PROGRESS = 0x03  # An operation couldn't be executed because the flash is processing a write.
    SPI_FLASH_UNSUPPORTED_DEVICE = 0x04  # The flash device is not supported.
    SPI_FLASH_ADDRESS_OUT_OF_RANGE = 0x05  # A supplied address is out of range for the device.
    SPI_FLASH_OPERATION_OUT_OF_RANGE = 0x06  # An operation would exceed the storage capacity of the device.
    SPI_FLASH_UNSUPPORTED_ADDR_MODE = 0x07  # The address mode is not supported by the device.
    SPI_FLASH_ADDR_MODE_FIXED = 0x08  # The address mode of the device is fixed.
    SPI_FLASH_INCOMPATIBLE_SPI_MASTER = 0x09  # The SPI master is not compatible with the flash device.
    SPI_FLASH_NO_DEVICE = 0x0A  # There is no flash device responding on the SPI bus.
    SPI_FLASH_CONFIG_FAILURE = 0x0B  # Configuration did not get set properly.
    SPI_FLASH_NO_4BYTE_CMDS = 0x0C  # The device does not support required 4-byte commands.
    SPI_FLASH_RESET_NOT_SUPPORTED = 0x0D  # Soft reset is not supported by the device.
    SPI_FLASH_PWRDOWN_NOT_SUPPORTED = 0x0E  # Deep power down is not supported by the device.
    SPI_FLASH_READ_ONLY_INTERFACE = 0x0F  # The interface is only configured to allow read access.
    SPI_FLASH_DEVICE_SIZE_OVER_16MB = 0x10  # Device size larger than 16MB.


class RotFlashCommonErrors(IntEnum):
    """Error codes for Common components for SPI flash commands."""

    FLASH_COMMON_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FLASH_COMMON_NO_MEMORY = 0x01  # Memory allocation failed.


class RotFlashUtilErrors(IntEnum):
    """Error codes for Utilities for programming and verifying flash."""

    FLASH_UTIL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FLASH_UTIL_NO_MEMORY = 0x01  # Memory allocation failed.
    FLASH_UTIL_UNSUPPORTED_SIG_HASH = 0x02  # Flash signature checking is using an unsupported hash algorithm.
    FLASH_UTIL_UNKNOWN_SIG_HASH = 0x03  # Flash signature checking is using an unknown hash algorithm.
    FLASH_UTIL_DATA_MISMATCH = 0x04  # The flash does not contain the expected data.
    FLASH_UTIL_NOT_BLANK = 0x05  # The flash is not blank.
    FLASH_UTIL_INCOMPLETE_WRITE = 0x06  # A multi-page write was only partially completed.
    FLASH_UTIL_SAME_ERASE_BLOCK = 0x07  # Attempt to copy data within the same flash erase block.
    FLASH_UTIL_COPY_OVERLAP = 0x08  # Attempt to copy data between overlapping address ranges.
    FLASH_UTIL_UNEXPECTED_VALUE = 0x09  # The flash does not contain the expected value.
    FLASH_UTIL_HASH_BUFFER_TOO_SMALL = 0x0A  # The hash out buffer is not large enough.
    FLASH_UTIL_UNSUPPORTED_PAGE_SIZE = 0x0B  # Flash page size is unsupported.


class RotAppImageErrors(IntEnum):
    """Error codes for Utilities for loading and verifying application images."""

    APP_IMAGE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    APP_IMAGE_NO_MEMORY = 0x01  # Memory allocation failed.
    APP_IMAGE_TOO_LARGE = 0x02  # There is not enough space available to load the image.
    APP_IMAGE_HASH_BUFFER_TOO_SMALL = 0x03  # The buffer for the image hash is not large enough.
    APP_IMAGE_SIG_BUFFER_TOO_SMALL = 0x04  # The buffer for the signature is not large enough.


class RotFirmwareImageErrors(IntEnum):
    """Error codes for Interface to the firmware image format for the platform."""

    FIRMWARE_IMAGE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FIRMWARE_IMAGE_NO_MEMORY = 0x01  # Memory allocation failed.
    FIRMWARE_IMAGE_LOAD_FAILED = 0x02  # The firmware image was not parsed.
    FIRMWARE_IMAGE_VERIFY_FAILED = 0x03  # An error not related to image validity caused verification to fail.
    FIRMWARE_IMAGE_GET_SIZE_FAILED = 0x04  # The image size could not be determined.
    FIRMWARE_IMAGE_GET_MANIFEST_FAILED = 0x05  # No key manifest could be retrieved.
    FIRMWARE_IMAGE_INVALID_FORMAT = 0x06  # The image structure is not valid.
    FIRMWARE_IMAGE_BAD_CHECKSUM = 0x07  # A checksum within in the image structure failed verification.
    FIRMWARE_IMAGE_NOT_LOADED = 0x08  # No firmware image has been loaded by the instance.
    FIRMWARE_IMAGE_NO_APP_KEY = 0x09  # Could not get the application signing key.
    FIRMWARE_IMAGE_MANIFEST_REVOKED = 0x0A  # The key manifest contained in the image has been revoked.
    FIRMWARE_IMAGE_NOT_AVAILABLE = 0x0B  # A firmware component is not available in the image.
    FIRMWARE_IMAGE_INVALID_SIGNATURE = 0x0C  # An image signature is malformed.
    FIRMWARE_IMAGE_FORCE_RECOVERY = 0x0D  # Force loading the recovery firmware image.
    FIRMWARE_IMAGE_BAD_SIGNATURE = 0x0E  # Signature verification of the image failed.
    FIRMWARE_IMAGE_REVOKED = 0x0F  # Firmware data contained in the image has been revoked.
    FIRMWARE_IMAGE_INCOMPATIBLE = 0x10  # Image is not compatible with the device or current state.


class RotKeyManifestErrors(IntEnum):
    """Error codes for Manifest containing authenticated keys."""

    KEY_MANIFEST_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    KEY_MANIFEST_NO_MEMORY = 0x01  # Memory allocation failed.
    KEY_MANIFEST_VERIFY_FAILED = 0x02  # Verification of the key manifest failed.
    KEY_MANIFEST_IS_ALLOWED_FAILED = 0x03  # Unable to determine if the manifest is revoked.
    KEY_MANIFEST_REVOKE_CHECK_FAILED = 0x04  # Unable to determine if the manifest revokes an old manifest.
    KEY_MANIFEST_REVOKE_UPDATE_FAILED = 0x05  # Revocation was not updated.
    KEY_MANIFEST_BAD_ROOT_KEY = 0x06  # The root key in the manifest is not valid.
    KEY_MANIFEST_INVALID_FORMAT = 0x07  # The manifest is not formatted correctly.
    KEY_MANIFEST_UNSUPPORTED_KEY = 0x08  # A key in the manifest is not supported.
    KEY_MANIFEST_UNSUPPORTED_CERT = 0x09  # A certificate in the manifest is not supported.
    KEY_MANIFEST_WEAK_KEY = 0x0A  # A key in the manifest does not meet security requirements.
    KEY_MANIFEST_UNTRUSTED_ROOT_KEY = 0x0B  # A valid root key is not trusted (e.g. revoked by hardware).
    KEY_MANIFEST_REVOKED = 0x0C  # The key manifest has been revoked.
    KEY_MANIFEST_ID_TOO_HIGH = 0x0D  # The key manifest is reporting an ID too much greater than the current state.
    KEY_MANIFEST_MISSING_KEY = 0x0E  # A required key is missing from the manifest.


class RotFirmwareUpdateErrors(IntEnum):
    """Error codes for Firmware updater."""

    FIRMWARE_UPDATE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FIRMWARE_UPDATE_NO_MEMORY = 0x01  # Memory allocation failed.
    FIRMWARE_UPDATE_CONTEXT_SAVE_FAILED = 0x02  # The running context has not been saved.
    FIRMWARE_UPDATE_FINALIZE_IMG_FAILED = 0x03  # A generic error while executing the finalize hook.
    FIRMWARE_UPDATE_VERIFY_BOOT_FAILED = 0x04  # An error not related to image validation caused verification to fail.
    FIRMWARE_UPDATE_INVALID_FLASH_MAP = 0x05  # The flash map provided to the updater is not valid.
    FIRMWARE_UPDATE_INCOMPLETE_IMAGE = 0x06  # The staging flash has not been programmed with all expected data.
    FIRMWARE_UPDATE_NO_KEY_MANIFEST = 0x07  # Could not retrieve the key manifest for the new image.
    FIRMWARE_UPDATE_IMG_TOO_LARGE = 0x08  # The new image is too big for the staging flash region.
    FIRMWARE_UPDATE_NO_SPACE = 0x09  # Not enough space remaining in staging flash for more data.
    FIRMWARE_UPDATE_INCOMPLETE_WRITE = 0x0A  # Update payload was only partially written to flash.
    FIRMWARE_UPDATE_NO_TASK = 0x0B  # No update task is running .
    FIRMWARE_UPDATE_TASK_BUSY = 0x0C  # The update task is busy performing an operation.
    FIRMWARE_UPDATE_NO_FIRMWARE_HEADER = 0x0D  # Could not retrieve the firmware header for the new image.
    FIRMWARE_UPDATE_REJECTED_ROLLBACK = 0x0E  # The new image revision ID is a disallowed version.
    FIRMWARE_UPDATE_NO_RECOVERY_IMAGE = 0x0F  # There is no recovery image available for the operation.
    FIRMWARE_UPDATE_RESTORE_NOT_NEEDED = 0x10  # An image restore operation was not necessary.
    FIRMWARE_UPDATE_INVALID_BOOT_IMAGE = 0x11  # The boot image is not valid based on additional verification.
    FIRMWARE_UPDATE_TOO_MUCH_DATA = 0x12  # Too much data was sent in a single request.
    FIRMWARE_UPDATE_UNSUPPORTED_HASH = 0x13  # A specified digest uses an unsupported hash algorithm.
    FIRMWARE_UPDATE_DIGEST_TOO_LARGE = 0x14  # A specified digest is too large.
    FIRMWARE_UPDATE_NO_EXPECTED_IMAGE = 0x15  # The updater is not expecting to receive any image data.
    FIRMWARE_UPDATE_EXTRA_IMAGE_DATA = 0x16  # More image data was received than was expected.
    FIRMWARE_UPDATE_IMAGE_DIGEST_MISMATCH = 0x17  # The staging image does not match the expected digest.
    FIRMWARE_UPDATE_NO_IMAGE_DIGEST = 0x18  # No expected digest has been provided for the image data.


class RotI2cMasterErrors(IntEnum):
    """Error codes for A driver for an I2C master.  All drivers use the same ID."""

    I2C_MASTER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    I2C_MASTER_NO_MEMORY = 0x01  # Memory allocation failed.
    I2C_MASTER_WRITE_REG_FAILED = 0x02  # Could not write to a register.
    I2C_MASTER_READ_REG_FAILED = 0x03  # Could not read from a register.
    I2C_MASTER_BUSY = 0x04  # The I2C master is busy executing a transaction.
    I2C_MASTER_TIMEOUT = 0x05  # The I2C transaction timed out.


class RotI2cSlaveErrors(IntEnum):
    """Error codes for A driver for an I2C slave.  All drivers use the same ID."""

    I2C_SLAVE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    I2C_SLAVE_NO_MEMORY = 0x01  # Memory allocation failed.
    I2C_SLAVE_HW_ERROR = 0x02  # A generic HW error occurred.
    I2C_SLAVE_RX_QUEUE_FULL = 0x03  # I2C slave RX queue is full.


class RotSpiFilterErrors(IntEnum):
    """Error codes for A driver for the SPI filter.  All drivers use the same ID."""

    SPI_FILTER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SPI_FILTER_NO_MEMORY = 0x01  # Memory allocation failed.
    SPI_FILTER_GET_MFG_FAILED = 0x02  # Failed to get the configured manufacturer ID.
    SPI_FILTER_SET_MFG_FAILED = 0x03  # Failed to configure manufacturer ID.
    SPI_FILTER_GET_ENABLED_FAILED = 0x04  # Could not determine if the filter is enabled.
    SPI_FILTER_ENABLE_FAILED = 0x05  # The filter was not enabled.
    SPI_FILTER_GET_RO_FAILED = 0x06  # Could not determine the configured RO chip select.
    SPI_FILTER_SET_RO_FAILED = 0x07  # The RO chip select was not set.
    SPI_FILTER_GET_RO_READ_FAILED = 0x08  # Could not determine the configured RO read region.
    SPI_FILTER_SET_RO_READ_FAILED = 0x09  # The RO read region was not set.
    SPI_FILTER_GET_READ_SWITCH_FAILED = 0x0A  # Could not determine if switching the RO read region is allowed.
    SPI_FILTER_ENABLE_SWITCH_FAILED = 0x0B  # RO read switch was not enabled/disabled.
    SPI_FILTER_GET_ADDR_MODE_FAILED = 0x0C  # Could not determine the filter address mode.
    SPI_FILTER_SET_ADDR_MODE_FAILED = 0x0D  # The filter address mode was not set.
    SPI_FILTER_GET_DIRTY_FAILED = 0x0E  # Could not determine the filter dirty state.
    SPI_FILTER_CLEAR_DIRTY_FAILED = 0x0F  # The dirty bit was not cleared.
    SPI_FILTER_GET_BYPASS_FAILED = 0x10  # Could not determine the filter bypass mode.
    SPI_FILTER_SET_BYPASS_FAILED = 0x11  # The bypass mode was not set.
    SPI_FILTER_GET_RW_FAILED = 0x12  # Could not get the configured RW filter.
    SPI_FILTER_SET_RW_FAILED = 0x13  # The RW filter was not set.
    SPI_FILTER_CLEAR_RW_FAILED = 0x14  # The RW filters were not cleared.
    SPI_FILTER_UNSUPPORTED_RW_REGION = 0x15  # The specified R/W region is not supported by the filter.
    SPI_FILTER_MISALIGNED_ADDRESS = 0x16  # A filter address was not aligned properly.
    SPI_FILTER_UNSUPPORTED_PORT = 0x17  # The port identifier is not supported by the filter.
    SPI_FILTER_UNKNOWN_VERSION = 0x18  # The filter version could not be determined.
    SPI_FILTER_GET_SIZE_FAILED = 0x19  # Failed to get the configured filter device size.
    SPI_FILTER_SET_SIZE_FAILED = 0x1A  # The filer device size was not configured.
    SPI_FILTER_UNSUPPORTED_OPERATION = 0x1B  # The requested operation is not supported by the filter.
    SPI_FILTER_GET_WREN_REQ_FAILED = 0x1C  # Failed to get the required write enable configuration.
    SPI_FILTER_SET_WREN_REQ_FAILED = 0x1D  # The write enable requirement was not configured.
    SPI_FILTER_GET_FIXED_ADDR_FAILED = 0x1E  # Failed to get the fixed address mode configuration.
    SPI_FILTER_SET_FIXED_ADDR_FAILED = 0x1F  # The fixed address mode setting was not configured.
    SPI_FILTER_GET_RESET_ADDR_FAILED = 0x20  # Failed to get the configured address mode on reset.
    SPI_FILTER_SET_RESET_ADDR_FAILED = 0x21  # The address mode on reset was not configured.
    SPI_FILTER_GET_WREN_DETECT_FAILED = 0x22  # Could not determine the detected write enable state.
    SPI_FILTER_GET_FILTER_MODE_FAILED = 0x23  # Could not determine the filter operational mode.
    SPI_FILTER_SET_FILTER_MODE_FAILED = 0x24  # Failed to set the filter operational mode.
    SPI_FILTER_GET_ALLOW_WRITE_FAILED = 0x25  # Could not got the write permissions for single chip.
    SPI_FILTER_SET_ALLOW_WRITE_FAILED = 0x26  # Failed to set single chip write permissions.
    SPI_FILTER_INVALID_ADDR_RANGE = 0x27  # The specified R/W region address range is not valid.
    SPI_FILTER_OPCODE_CFG_FAILED = 0x28  # Failed to configure flash opcode information in the filter.


class RotMfgFilterHandlerErrors(IntEnum):
    """Error codes for Configuration interface to set the flash device for the filter."""

    MFG_FILTER_HANDLER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    MFG_FILTER_HANDLER_NO_MEMORY = 0x01  # Memory allocation failed.
    MFG_FILTER_HANDLER_SET_MFG_FAILED = 0x02  # The filter was not configured for the flash device.
    MFG_FILTER_HANDLER_UNSUPPORTED_VENDOR = 0x03  # The flash vendor is not supported by the SPI filter.
    MFG_FILTER_HANDLER_UNSUPPORTED_DEVICE = 0x04  # The vendor's flash device is not supported by the SPI filter.


class RotSpiFilterIrqErrors(IntEnum):
    """Error codes for IRQ handler for the SPI filter."""

    SPI_FILTER_IRQ_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SPI_FILTER_IRQ_NO_MEMORY = 0x01  # Memory allocation failed.
    SPI_FILTER_IRQ_STATUS_FAIL = 0x02  # Error determining IRQ status.


class RotLoggingErrors(IntEnum):
    """Error codes for Logger for system or security events."""

    LOGGING_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    LOGGING_NO_MEMORY = 0x01  # Memory allocation failed.
    LOGGING_CREATE_ENTRY_FAILED = 0x02  # A new entry was not added to the log.
    LOGGING_FLUSH_FAILED = 0x03  # The log was not stored to persistent memory.
    LOGGING_CLEAR_FAILED = 0x04  # The log entries were not cleared.
    LOGGING_GET_SIZE_FAILED = 0x05  # The log size could not be determined.
    LOGGING_READ_CONTENTS_FAILED = 0x06  # Could not retrieve the log entries.
    LOGGING_INCOMPLETE_FLUSH = 0x07  # Not all log entries were made accessible.
    LOGGING_UNSUPPORTED_SEVERITY = 0x08  # An entry was specified at an unsupported severity level.
    LOGGING_STORAGE_NOT_ALIGNED = 0x09  # Memory for the log is not aligned correctly.
    LOGGING_BAD_ENTRY_LENGTH = 0x0A  # The entry data is not the right size for the log.
    LOGGING_NO_LOG_AVAILABLE = 0x0B  # There is no log available for the operation.
    LOGGING_INSUFFICIENT_STORAGE = 0x0C  # Memory for the log does not meet minimum requirements.


class RotCmdHandlerErrors(IntEnum):
    """Error codes for Handler for received commands."""

    CMD_HANDLER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    CMD_HANDLER_NO_MEMORY = 0x01  # Memory allocation failed.
    CMD_HANDLER_PROCESS_FAILED = 0x02  # A general error while processing the request.
    CMD_HANDLER_PAYLOAD_TOO_SHORT = 0x03  # The request does not contain the minimum amount of data.
    CMD_HANDLER_BAD_LENGTH = 0x04  # The payload length is wrong for the request.
    CMD_HANDLER_OUT_OF_RANGE = 0x05  # A request argument is not within the valid range.
    CMD_HANDLER_UNKNOWN_REQUEST = 0x06  # A command does not represent a known request.
    CMD_HANDLER_UNSUPPORTED_EID = 0x07  # The request was sent to an unsupported endpoint.
    CMD_HANDLER_UNSUPPORTED_INDEX = 0x08  # Request for information with an unsupported index was received.
    CMD_HANDLER_UNSUPPORTED_LEN = 0x09  # Request for information with an unsupported length was received.
    CMD_HANDLER_INVALID_DEVICE_MODE = 0x0A  # Invalid device mode.
    CMD_HANDLER_BUF_TOO_SMALL = 0x0B  # Provided buffer too small for output.
    CMD_HANDLER_UNSUPPORTED_COMMAND = 0x0C  # The command is valid but is not supported by the device.
    CMD_HANDLER_UNSUPPORTED_MSG = 0x0D  # Message type not supported.
    CMD_HANDLER_UNSUPPORTED_CHANNEL = 0x0E  # The command is received on a channel not supported by the device.
    CMD_HANDLER_UNSUPPORTED_OPERATION = 0x0F  # The requested operation is not supported.
    CMD_HANDLER_RESPONSE_TOO_SMALL = 0x10  # The maximum allowed response is too small for the output.
    CMD_HANDLER_ENCRYPTION_UNSUPPORTED = 0x11  # Channel encryption not supported on this interface.
    CMD_HANDLER_CMD_SHOULD_BE_ENCRYPTED = (
        0x12  # Secure command received unencrypted after establishing an encrypted channel.
    )
    CMD_HANDLER_RSVD_NOT_ZERO = 0x13  # Reserved field is non-zero.
    CMD_HANDLER_ERROR_MESSAGE = 0x14  # The handler received an error message for processing.
    CMD_HANDLER_ISSUE_FAILED = 0x15  # Failed to generate the request message.
    CMD_HANDLER_ERROR_MSG_FAILED = 0x16  # Failed to generate an error message.
    CMD_HANDLER_UNKNOWN_RESPONSE = 0x17  # A command does not represent a known response.
    CMD_HANDLER_INVALID_ERROR_MSG = 0x18  # The handler received an invalid error message.
    CMD_HANDLER_UNKNOWN_MESSAGE_TYPE = 0x19  # The received message type is unknown to the handler.
    CMD_HANDLER_PROTO_PARSE_FAILED = 0x1A  # Failed to parse a message.
    CMD_HANDLER_PROTO_HANDLE_FAILED = 0x1B  # Failed to handle the result of request processing.
    CMD_HANDLER_PROTO_ERROR_RESPONSE = 0x1C  # The protocol generated an error response.


class RotMctpBaseProtocolErrors(IntEnum):
    """Error codes for MCTP base protocol handler."""

    MCTP_BASE_PROTOCOL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    MCTP_BASE_PROTOCOL_NO_MEMORY = 0x01  # Memory allocation failed.
    MCTP_BASE_PROTOCOL_NO_SOM = 0x02  # A packet was received without a SOM.
    MCTP_BASE_PROTOCOL_UNEXPECTED_PKT = (
        0x03  # A packet was received that doesn't match the context for the current message.
    )
    MCTP_BASE_PROTOCOL_BAD_LENGTH = 0x04  # The received packet was not the expected length.
    MCTP_BASE_PROTOCOL_MSG_TOO_LARGE = 0x05  # The message is bigger than the maximum supported size.
    MCTP_BASE_PROTOCOL_INVALID_PKT = 0x06  # An invalid packet was received.
    MCTP_BASE_PROTOCOL_BAD_CHECKSUM = 0x07  # The packet checksum is bad.
    MCTP_BASE_PROTOCOL_PKT_TOO_SHORT = 0x08  # The received packet was shorter than the minimum length.
    MCTP_BASE_PROTOCOL_BAD_BUFFER_LENGTH = 0x09  # The packet buffer is an invalid size.
    MCTP_BASE_PROTOCOL_BUF_TOO_SMALL = 0x0A  # Provided buffer too small for output.
    MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG = 0x0B  # Received message type not supported.
    MCTP_BASE_PROTOCOL_INVALID_EID = 0x0C  # Received packet from device using incorrect EID.
    MCTP_BASE_PROTOCOL_BUILD_UNSUPPORTED = 0x0D  # Failed to construct a packet for an unsupported message type.
    MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT = 0x0E  # Timeout elapsed before receiving a response.
    MCTP_BASE_PROTOCOL_UNSUPPORTED_OPERATION = 0x0F  # Requested operation not supported by device.
    MCTP_BASE_PROTOCOL_ERROR_RESPONSE = 0x10  # Error response received.
    MCTP_BASE_PROTOCOL_FAIL_RESPONSE = 0x11  # Response processing failed.
    MCTP_BASE_PROTOCOL_MSG_TOO_SHORT = 0x12  # A received message is shorter tha the minimum length.
    MCTP_BASE_PROTOCOL_PKT_LENGTH_MISMATCH = 0x13  # A packet length was inconsistent with the data length.
    MCTP_BASE_PROTOCOL_INVALID_MSG = 0x14  # An invalid message was received.
    MCTP_BASE_PROTOCOL_OUT_OF_SEQUENCE = 0x15  # A packet was received out of sequence for a message.
    MCTP_BASE_PROTOCOL_MIDDLE_PKT_LENGTH = 0x16  # A middle packet was received with different length than SOM.
    MCTP_BASE_PROTOCOL_MAX_RESP_TOO_SMALL = 0x17  # The maximum response length is less than the required minimum.
    MCTP_BASE_PROTOCOL_NO_HEADER_SPACE = 0x18  # There is no room in a message buffer for the MCTP header.


class RotRiotCoreErrors(IntEnum):
    """Error codes for Implementation of RIoT Core."""

    RIOT_CORE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    RIOT_CORE_NO_MEMORY = 0x01  # Memory allocation failed.
    RIOT_CORE_NO_DEVICE_ID = 0x02  # No Device ID has been generated.
    RIOT_CORE_NO_ALIAS_KEY = 0x03  # No Alias Key has been generated.
    RIOT_CORE_BAD_FWID_LENGTH = 0x04  # The FWID is not the right length.
    RIOT_CORE_NO_CDI = 0x05  # The CDI is not available for use.
    RIOT_CORE_BAD_CDI = 0x06  # The CDI was determined to be invalid.
    RIOT_CORE_UNSUPPORTED_KEY_LENGTH = 0x07  # The DICE key length is not supported.
    RIOT_CORE_BAD_PATHLEN_CONSTRAINT = 0x08  # A DICE CA path length is not valid.


class RotHostFwUtilErrors(IntEnum):
    """Error codes for Host firmware validation functions."""

    HOST_FW_UTIL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    HOST_FW_UTIL_NO_MEMORY = 0x01  # Memory allocation failed.
    HOST_FW_UTIL_UNSUPPORTED_VERSION = 0x02  # The host firmware does not match a supported version.
    HOST_FW_UTIL_DIFF_REGION_COUNT = 0x03  # Data migration with a different number of regions.
    HOST_FW_UTIL_DIFF_REGION_ADDR = 0x04  # Data migration with different region addresses.
    HOST_FW_UTIL_DIFF_REGION_SIZE = 0x05  # Data migration with different region sizes.
    HOST_FW_UTIL_BAD_IMAGE_HASH = 0x06  # A host firmware image on flash has an invalid hash.
    HOST_FW_UTIL_DIFF_FW_COUNT = 0x07  # Data migration with a different number of FW components.


class RotBmcRecoveryErrors(IntEnum):
    """Error codes for BMC recovery manager."""

    BMC_RECOVERY_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    BMC_RECOVERY_NO_MEMORY = 0x01  # Memory allocation failed.
    BMC_RECOVERY_HOST_RESET_FAILED = 0x02  # Failure while processing host reset event.
    BMC_RECOVERY_HOST_EXIT_RESET_FAILED = 0x03  # Failure while processing host reset exit event.
    BMC_RECOVERY_CS0_FAILED = 0x04  # Failure while processing CS0 event.
    BMC_RECOVERY_CS1_FAILED = 0x05  # Host firmware could not be recovered to a previous state.
    BMC_RECOVERY_INVALID_MIN_WDT = 0x06  # Invalid minimum watchdog event value.


class RotHostControlErrors(IntEnum):
    """Error codes for Driver interface for controlling the host processor."""

    HOST_CONTROL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    HOST_CONTROL_NO_MEMORY = 0x01  # Memory allocation failed.
    HOST_CONTROL_HOLD_RESET_FAILED = 0x02  # The host reset has not been enabled/disabled.
    HOST_CONTROL_HOLD_CHECK_FAILED = 0x03  # Could not determine if the host is being held in reset.
    HOST_CONTROL_RESET_CHECK_FAILED = 0x04  # Could not determine if the host is in reset.
    HOST_CONTROL_FLASH_ACCESS_FAILED = 0x05  # Host flash access has not been enabled/disabled.
    HOST_CONTROL_FLASH_CHECK_FAILED = 0x06  # Could not determine if the host has flash access.


class RotHostIrqCtrlErrors(IntEnum):
    """Error codes for Driver interface for controlling host state IRQs."""

    HOST_IRQ_CTRL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    HOST_IRQ_CTRL_NO_MEMORY = 0x01  # Memory allocation failed.
    HOST_IRQ_CTRL_EXIT_RESET_FAILED = 0x02  # Exit reset IRQ has not been enabled/disabled.
    HOST_IRQ_CTRL_CHIP_SEL_FAILED = 0x03  # Chip select IRQs have not been enabled/disabled.
    HOST_IRQ_CTRL_IRQ_NOT_SUPPORTED = 0x04  # The type of IRQ is not supported by the driver.


class RotHostIrqHandlerErrors(IntEnum):
    """Error codes for Handler for host state IRQs."""

    HOST_IRQ_HANDLER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    HOST_IRQ_HANDLER_NO_MEMORY = 0x01  # Memory allocation failed.
    HOST_IRQ_HANDLER_ENTER_RESET_FAILED = 0x02  # Failure while processing an enter reset event.
    HOST_IRQ_HANDLER_EXIT_RESET_FAILED = 0x03  # Failure while processing an exit reset event.
    HOST_IRQ_HANDLER_CS0_FAILED = 0x04  # Failure while processing a CS0 reset event.
    HOST_IRQ_HANDLER_CS1_FAILED = 0x05  # Failure while processing a CS1 reset event.


class RotHostProcessorErrors(IntEnum):
    """Error codes for Manager for the host processor being protected."""

    HOST_PROCESSOR_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    HOST_PROCESSOR_NO_MEMORY = 0x01  # Memory allocation failed.
    HOST_PROCESSOR_POR_FAILED = 0x02  # POR validation and configuration was not completed
    HOST_PROCESSOR_SOFT_RESET_FAILED = 0x03  # Soft reset operations were not completed.
    HOST_PROCESSOR_ROLLBACK_FAILED = 0x04  # Flash rollback was not completed.
    HOST_PROCESSOR_NO_ROLLBACK = 0x05  # Flash rollback is not possible.
    HOST_PROCESSOR_ROLLBACK_DIRTY = 0x06  # The rollback flash has been changed.
    HOST_PROCESSOR_RW_SKIPPED = 0x07  # Validation of read/write flash was skipped.
    HOST_PROCESSOR_RUN_TIME_FAILED = 0x08  # Run-time validation was not completed.
    HOST_PROCESSOR_NOTHING_TO_VERIFY = 0x09  # No update requiring verification has occurred.
    HOST_PROCESSOR_NEXT_ACTIONS_FAILED = 0x0A  # Failed to determine the pending verification actions.
    HOST_PROCESSOR_NEEDS_RECOVERY_FAILED = 0x0B  # Failed to determine if the host needs recovery.
    HOST_PROCESSOR_RECOVERY_IMG_FAILED = 0x0C  # Applying recovery image was not completed.
    HOST_PROCESSOR_RECOVERY_UNSUPPORTED = 0x0D  # Host recovery is not supported.
    HOST_PROCESSOR_NO_RECOVERY_IMAGE = 0x0E  # There is no valid recovery image.
    HOST_PROCESSOR_BYPASS_FAILED = 0x0F  # Failed to configure bypass mode.
    HOST_PROCESSOR_FLASH_NOT_SUPPORTED = 0x10  # The flash configuration is not supported.
    HOST_PROCESSOR_RW_RECOVERY_FAILED = 0x11  # Failed to recover active read/write data.
    HOST_PROCESSOR_RW_RECOVERY_UNSUPPORTED = 0x12  # Recovery of active read/write data is not supported.
    HOST_PROCESSOR_NO_ACTIVE_RW_DATA = 0x13  # There is no active image for read/write recovery.
    HOST_PROCESSOR_GET_CONFIG_FAILED = 0x14  # Failed to retrieve the current host flash configuration.
    HOST_PROCESSOR_CONFIG_RO_FAILED = 0x15  # Failed to configure the host read-only flash.
    HOST_PROCESSOR_FLASH_CONFIG_UNSUPPORTED = 0x16  # Changing the flash configuration is not supported.
    HOST_PROCESSOR_NO_TASK = 0x17  # No host command task is running.
    HOST_PROCESSOR_TASK_BUSY = 0x18  # The command task is busy performing an operation.
    HOST_PROCESSOR_UNSUPPORTED_CMD = 0x19  # The requested command is not supported by the host.


class RotHostFlashMgrErrors(IntEnum):
    """Error codes for Manager for host flash state."""

    HOST_FLASH_MGR_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    HOST_FLASH_MGR_NO_MEMORY = 0x01  # Memory allocation failed.
    HOST_FLASH_MGR_GET_RO_FAILED = 0x02  # Could not determine read-only flash.
    HOST_FLASH_MGR_GET_RW_FAILED = 0x03  # Could not determine read-write flash.
    HOST_FLASH_MGR_VALIDATE_RO_FAILED = 0x04  # An error unrelated to validation caused verification to fail.
    HOST_FLASH_MGR_VALIDATE_RW_FAILED = 0x05  # An error unrelated to validation caused verification to fail.
    HOST_FLASH_MGR_CONFIG_TYPE_FAILED = 0x06  # The flash type could not be configured.
    HOST_FLASH_MGR_CONFIG_FILTER_FAILED = 0x07  # The device state could not be configured.
    HOST_FLASH_MGR_SWAP_FAILED = 0x08  # The flash device roles were not swapped.
    HOST_FLASH_MGR_INIT_PROTECT_FAILED = 0x09  # Flash protection was not initialized.
    HOST_FLASH_MGR_ROT_ACCESS_FAILED = 0x0A  # Flash is not accessible by the RoT.
    HOST_FLASH_MGR_HOST_ACCESS_FAILED = 0x0B  # Flash is not accessible by the host.
    HOST_FLASH_MGR_MISMATCH_VENDOR = 0x0C  # The host flash devices are not from the same vendor.
    HOST_FLASH_MGR_MISMATCH_DEVICE = 0x0D  # The host flash devices are not the same device type.
    HOST_FLASH_MGR_INVALID_VENDOR = 0x0E  # The flash device reports an invalid vendor ID.
    HOST_FLASH_MGR_RW_REGIONS_FAILED = 0x0F  # Could not determine read-write flash regions.
    HOST_FLASH_MGR_CHECK_ACCESS_FAILED = 0x10  # Could not determine if the host has flash access.
    HOST_FLASH_MGR_MISMATCH_SIZES = 0x11  # The host flash devices are not the same size.
    HOST_FLASH_MGR_MISMATCH_ADDR_MODE = 0x12  # The host flash devices support different address mode behavior.
    HOST_FLASH_MGR_RESTORE_RW_FAILED = 0x13  # Flash read/write regions were not restore successfully.
    HOST_FLASH_MGR_UNSUPPORTED_OPERATION = 0x14  # The operation is unsupported by the flash manager.


class RotStateManagerErrors(IntEnum):
    """Error codes for Storage for state information."""

    STATE_MANAGER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    STATE_MANAGER_NO_MEMORY = 0x01  # Memory allocation failed.
    STATE_MANAGER_NOT_SECTOR_ALIGNED = 0x02  # The base address is not properly aligned.
    STATE_MANAGER_NOT_BLANK = 0x03  # The next flash block was not blank for saving state.
    STATE_MANAGER_OUT_OF_RANGE = 0x04  # Argument is not within the valid range.
    STATE_MANAGER_INCOMPLETE_WRITE = 0x05  # The state was not completely written to flash.
    STATE_MANAGER_SAVE_ACTIVE_FAILED = 0x06  # Failed to save the active manifest region.
    STATE_MANAGER_DEFAULTS_FAILED = 0x07  # Failed to restore default state.
    STATE_MANAGER_MANIFEST_VALID_FAILED = 0x08  # Failed to determine validity of a manifest index.


class RotManifestErrors(IntEnum):
    """Error codes for Manifest files used for provisioning."""

    MANIFEST_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    MANIFEST_NO_MEMORY = 0x01  # Memory allocation failed.
    MANIFEST_VERIFY_FAILED = 0x02  # A verify failure unrelated to authentication.
    MANIFEST_GET_ID_FAILED = 0x03  # The ID was not retrieved.
    MANIFEST_BAD_MAGIC_NUMBER = 0x04  # The manifest magic number was not valid.
    MANIFEST_BAD_LENGTH = 0x05  # The manifest length is bad.
    MANIFEST_MALFORMED = 0x06  # The manifest is not formatted correctly.
    MANIFEST_BAD_RESERVED_BYTE = 0x07  # The manifest has data in reserved bytes.
    MANIFEST_GET_HASH_FAILED = 0x08  # The hash could not be calculated.
    MANIFEST_GET_SIGNATURE_FAILED = 0x09  # The signature could not be retrieved.
    MANIFEST_HASH_BUFFER_TOO_SMALL = 0x0A  # A buffer for hash output was too small.
    MANIFEST_SIG_BUFFER_TOO_SMALL = 0x0B  # A buffer for signature output was too small.
    MANIFEST_STORAGE_NOT_ALIGNED = 0x0C  # The manifest storage is not aligned correctly.
    MANIFEST_GET_PLATFORM_ID_FAILED = 0x0D  # The platform ID was not retrieved.
    MANIFEST_SIG_UNKNOWN_HASH_TYPE = 0x0E  # The manifest signature uses an unknown hash type.
    MANIFEST_TOC_UNKNOWN_HASH_TYPE = 0x0F  # The manifest table of contents uses an unknown hash type.
    MANIFEST_NO_PLATFORM_ID = 0x10  # The manifest does not contain a platform ID entry.
    MANIFEST_PLAT_ID_BUFFER_TOO_SMALL = 0x11  # A buffer for the platform ID was too small.
    MANIFEST_NO_MANIFEST = 0x12  # A manifest has not been successfully validated.
    MANIFEST_ELEMENT_NOT_FOUND = 0x13  # The specified element was not found in the manifest.
    MANIFEST_TOC_INVALID = 0x14  # The table of contents failed validation.
    MANIFEST_ELEMENT_INVALID = 0x15  # A manifest element failed validation.
    MANIFEST_WRONG_PARENT = 0x16  # Parent element is not of the correct type.
    MANIFEST_CHILD_NOT_FOUND = 0x17  # A child element was not found in the manifest.
    MANIFEST_CHECK_EMPTY_FAILED = 0x18  # Failed to determine if the manifest was empty.


class RotPfmErrors(IntEnum):
    """Error codes for PFM files for host provisioning."""

    PFM_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    PFM_NO_MEMORY = 0x01  # Memory allocation failed.
    PFM_GET_VERSIONS_FAILED = 0x02  # The supported firmware version list was not generated.
    PFM_GET_READ_WRITE_FAILED = 0x03  # The list of read/write regions was not generated.
    PFM_GET_FW_IMAGES_FAILED = 0x04  # The list of signed firmware was not generated.
    PFM_UNSUPPORTED_VERSION = 0x05  # The firmware version is not supported by the PFM.
    PFM_UNKNOWN_KEY_ID = 0x06  # A firmware image is signed with a key not in the PFM.
    PFM_GET_FW_FAILED = 0x07  # The list of firmware components was not generated.
    PFM_UNKNOWN_FIRMWARE = 0x08  # The requested firmware component is not in the PFM.
    PFM_READ_WRITE_UNSUPPORTED = 0x09  # A read/write region configuration is not supported.
    PFM_UNKNOWN_HASH_TYPE = 0x0A  # A firmware image uses an unknown hashing algorithm.
    PFM_FW_IMAGE_UNSUPPORTED = 0x0B  # An authenticated image configuration is not supported.
    PFM_MALFORMED_FLASH_DEV_ELEMENT = 0x0C  # The flash device element in the PFM is malformed.
    PFM_MALFORMED_FIRMWARE_ELEMENT = 0x0D  # A firmware element in the PFM is malformed.
    PFM_MALFORMED_FW_VER_ELEMENT = 0x0E  # A firmware version element in the PFM is malformed.
    PFM_KEY_UNSUPPORTED = 0x0F  # A firmware image signing key is not supported.


class RotCfmErrors(IntEnum):
    """Error codes for CFM files for component provisioning."""

    CFM_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    CFM_NO_MEMORY = 0x01  # Memory allocation failed.
    CFM_PMR_DIGEST_NOT_FOUND = 0x02  # CFM does not contain allowable PMR digests for PMR ID provided.
    CFM_ROOT_CA_NOT_FOUND = 0x03  # Could not find root CA digest for component type in CFM.
    CFM_ENTRY_NOT_FOUND = 0x04  # Could not find requested entry for component type in CFM.
    CFM_PMR_NOT_FOUND = 0x05  # CFM does not contain PMR for PMR ID provided.
    CFM_ENTRY_MISSING_DIGESTS = 0x06  # CFM entry missing expected digests list.
    CFM_GET_COMP_DEVICE_FAIL = 0x07  # Retrieving component device failed.
    CFM_BUFFER_SUPPORTED_COMP_FAIL = 0x08  # The list of supported components was not generated.
    CFM_GET_COMP_PMR_FAIL = 0x09  # Retrieving component PMR failed.
    CFM_GET_COMP_PMR_DIGEST_FAIL = 0x0A  # Retrieving component PMR digest failed.
    CFM_GET_NEXT_MEASUREMENT_FAIL = 0x0B  # Retrieving next allowable measurement failed.
    CFM_GET_ROOT_CA_DIGEST_FAIL = 0x0C  # Retrieving list of root CA digests failed.
    CFM_GET_NEXT_PFM_FAIL = 0x0D  # Retrieving next allowable PFM failed.
    CFM_GET_NEXT_CFM_FAIL = 0x0E  # Retrieving next allowable CFM failed.
    CFM_GET_PCD_FAIL = 0x0F  # Retrieving allowable PCD failed.
    CFM_MALFORMED_COMPONENT_DEVICE_ENTRY = 0x10  # CFM Component Device entry too short.
    CFM_MALFORMED_PMR_DIGEST_ENTRY = 0x11  # CFM PMR Digest entry too short.
    CFM_MALFORMED_ALLOWABLE_DATA_ENTRY = 0x12  # CFM Allowable Data entry too short.
    CFM_MALFORMED_ALLOWABLE_ID_ENTRY = 0x13  # CFM Allowable ID entry too short.
    CFM_MALFORMED_PMR_ENTRY = 0x14  # CFM PMR entry too short.
    CFM_MALFORMED_MEASUREMENT_ENTRY = 0x15  # CFM Measurement entry too short.
    CFM_MALFORMED_MEASUREMENT_DATA_ENTRY = 0x16  # CFM Measurement Data entry too short.
    CFM_MALFORMED_ROOT_CA_DIGESTS_ENTRY = 0x17  # CFM Root CA Digests entry too short.
    CFM_MALFORMED_ALLOWABLE_PFM_ENTRY = 0x18  # CFM Allowable PFM entry too short.
    CFM_INVALID_TRANSCRIPT_HASH_TYPE = 0x19  # CFM transcript hash type is invalid.
    CFM_INVALID_MEASUREMENT_HASH_TYPE = 0x1A  # CFM measurement hash type is invalid.


class RotManifestManagerErrors(IntEnum):
    """Error codes for Manager for manifest files."""

    MANIFEST_MANAGER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    MANIFEST_MANAGER_NO_MEMORY = 0x01  # Memory allocation failed.
    MANIFEST_MANAGER_ACTIVATE_FAILED = 0x02  # Pending manifest was not activated.
    MANIFEST_MANAGER_CLEAR_FAILED = 0x03  # The pending region was not cleared.
    MANIFEST_MANAGER_WRITE_FAILED = 0x04  # Data was not written to the pending region.
    MANIFEST_MANAGER_VERIFY_FAILED = 0x05  # An error unrelated to verification occurred.
    MANIFEST_MANAGER_INVALID_ID = 0x06  # The manifest ID is not valid.
    MANIFEST_MANAGER_NONE_PENDING = 0x07  # There is no manifest pending for the operation.
    MANIFEST_MANAGER_PENDING_IN_USE = 0x08  # The pending manifest is actively being used.
    MANIFEST_MANAGER_NOT_CLEARED = 0x09  # Pending region was not cleared before write.
    MANIFEST_MANAGER_OUT_OF_SPACE = 0x0A  # Not enough room in the pending region for data.
    MANIFEST_MANAGER_INCOMPLETE_WRITE = 0x0B  # Not all data was written.
    MANIFEST_MANAGER_HAS_PENDING = 0x0C  # A pending manifest is already present.
    MANIFEST_MANAGER_NO_TASK = 0x0D  # No manager command task is running.
    MANIFEST_MANAGER_TASK_BUSY = 0x0E  # The command task is busy performing an operation.
    MANIFEST_MANAGER_UNSUPPORTED_OP = 0x0F  # The requested operation is not supported by the manager.
    MANIFEST_MANAGER_INCOMPATIBLE = 0x10  # The pending manifest is incompatible with the system.
    MANIFEST_MANAGER_INCOMPLETE_UPDATE = 0x11  # The staging flash has not been programmed with all the expected data.
    MANIFEST_MANAGER_NO_ACTIVE_MANIFEST = 0x12  # No active manifest found.
    MANIFEST_MANAGER_ACTIVE_IN_USE = 0x13  # The active manifest is currently being used.
    MANIFEST_MANAGER_CLEAR_ALL_FAILED = 0x14  # Failed to clear the manifest data.
    MANIFEST_MANAGER_TOO_MUCH_DATA = 0x15  # Too much data was sent in a single request.
    MANIFEST_MANAGER_SAME_HASH_ENGINE = 0x16  # The same instance is used when hashing manifest measured data.


class RotKeystoreErrors(IntEnum):
    """Error codes for Persistent storage for device keys."""

    KEYSTORE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    KEYSTORE_NO_MEMORY = 0x01  # Memory allocation failed.
    KEYSTORE_SAVE_FAILED = 0x02  # The key was not saved.
    KEYSTORE_LOAD_FAILED = 0x03  # The key was not load.
    KEYSTORE_UNSUPPORTED_ID = 0x04  # The ID is not supported by the keystore.
    KEYSTORE_KEY_TOO_LONG = 0x05  # The key data is too long for the keystore.
    KEYSTORE_NO_KEY = 0x06  # There is no key stored for an ID.
    KEYSTORE_BAD_KEY = 0x07  # The key stored for an ID is not valid.
    KEYSTORE_STORAGE_NOT_ALIGNED = 0x08  # Memory for the keystore is not aligned correctly.
    KEYSTORE_NO_STORAGE = 0x09  # The keystore was created with no storage for keys.
    KEYSTORE_INSUFFICIENT_STORAGE = 0x0A  # There is not enough storage space for the keys.
    KEYSTORE_ERASE_FAILED = 0x0B  # The key was not erased.


class RotRiotKeyManagerErrors(IntEnum):
    """Error codes for Management of RIoT keys and certificates."""

    RIOT_KEY_MANAGER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    RIOT_KEY_MANAGER_NO_MEMORY = 0x01  # Memory allocation failed.
    RIOT_KEY_MANAGER_KEYSTORE_LOCKED = 0x02  # The keystore is locked from modification.
    RIOT_KEY_MANAGER_NO_SIGNED_DEVICE_ID = 0x03  # There is no signed device ID stored.
    RIOT_KEY_MANAGER_NO_ROOT_CA = 0x04  # There is no root CA stored.
    RIOT_KEY_MANAGER_UNKNOWN_CSR = 0x05  # There is no CSR for the requested index.


class RotAuxAttestationErrors(IntEnum):
    """Error codes for Handler for auxiliary attestation flows."""

    AUX_ATTESTATION_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    AUX_ATTESTATION_NO_MEMORY = 0x01  # Memory allocation failed.
    AUX_ATTESTATION_HAS_CERTIFICATE = 0x02  # A certificate has already been provisioned.
    AUX_ATTESTATION_PCR_MISMATCH = 0x03  # The sealing policy doesn't match the local PCRs.
    AUX_ATTESTATION_HMAC_MISMATCH = 0x04  # The payload failed verification against the HMAC.
    AUX_ATTESTATION_UNSUPPORTED_CRYPTO = 0x05  # The asymmetric crypto algorithm is not supported.
    AUX_ATTESTATION_UNSUPPORTED_KEY_LENGTH = 0x06  # The requested key length is not supported.
    AUX_ATTESTATION_UNSUPPORTED_HMAC = 0x07  # The HMAC algorithm is not supported.
    AUX_ATTESTATION_UNKNOWN_SEED = 0x08  # Unknown seed algorithm.
    AUX_ATTESTATION_BUFFER_TOO_SMALL = 0x09  # Output buffer too small.
    AUX_ATTESTATION_BAD_SEED_PARAM = 0x0A  # Seed parameter option is invalid or unsupported.
    AUX_ATTESTATION_PCR_LENGTH_MISMATCH = 0x0B  # The sealing policy doesn't match the local PCR length.


class RotFirmwareHeaderErrors(IntEnum):
    """Error codes for Header information on firmware images."""

    FIRMWARE_HEADER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FIRMWARE_HEADER_NO_MEMORY = 0x01  # Memory allocation failed.
    FIRMWARE_HEADER_NOT_MINIMUM_SIZE = 0x02  # The header length is not the minimum size.
    FIRMWARE_HEADER_TOO_LONG = 0x03  # The header length exceeds the maximum.
    FIRMWARE_HEADER_BAD_MARKER = 0x04  # The header marker is not valid.
    FIRMWARE_HEADER_BAD_FORMAT_LENGTH = 0x05  # The header length doesn't match the expected length for the format.
    FIRMWARE_HEADER_INFO_NOT_AVAILABLE = 0x06  # The requested information is not available in the header format.


class RotRngEngineErrors(IntEnum):
    """Error codes for A RNG crypto engine.  All engines use the same ID."""

    RNG_ENGINE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    RNG_ENGINE_NO_MEMORY = 0x01  # Memory allocation failed.
    RNG_ENGINE_RANDOM_FAILED = 0x02  # Failed to generate random data.
    RNG_ENGINE_SELF_TEST_FAILED = 0x03  # An internal self-test of the RNG failed.


class RotDeviceManagerErrors(IntEnum):
    """Error codes for Device manager."""

    DEVICE_MGR_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    DEVICE_MGR_NO_MEMORY = 0x01  # Memory allocation failed.
    DEVICE_MGR_UNKNOWN_DEVICE = 0x02  # Invalid device number.
    DEVICE_MGR_INVALID_CERT_NUM = 0x03  # Invalid certificate number.
    DEVICE_MGR_BUF_TOO_SMALL = 0x04  # Provided buffer too small for output.
    DEVICE_MGR_INPUT_TOO_LARGE = 0x05  # Provided data larger than storage buffer.
    DEVICE_MGR_DIGEST_LEN_MISMATCH = 0x06  # Provided digest not same length as cached digest.
    DEVICE_MGR_DIGEST_MISMATCH = 0x07  # Provided digest not same as cached digest.
    DEVICE_MGR_NO_DEVICES_AVAILABLE = 0x08  # No devices ready for attestation.
    DEVICE_MGR_DIGEST_NOT_UNIQUE = 0x09  # Certificate chain digest not unique.
    DEVICE_MGR_INVALID_RESPONDER_COUNT = 0x0A  # Invalid responder count.
    DEVICE_MGR_STATE_UPDATE_UNSUPPORTED = 0x0B  # State update not supported.
    DEVICE_MGR_NO_PENDING_ACTION = 0x0C  # No pending action available.


class RotPcrErrors(IntEnum):
    """Error codes for PCR manager."""

    PCR_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    PCR_NO_MEMORY = 0x01  # Memory allocation failed.
    PCR_UNSUPPORTED_ALGO = 0x02  # Unsupported hashing algorithm.
    PCR_INVALID_PCR = 0x03  # Invalid PCR bank.
    PCR_INVALID_TYPE = 0x04  # Invalid measurement type.
    PCR_INVALID_INDEX = 0x05  # Invalid measurement index.
    PCR_INVALID_DATA_TYPE = 0x06  # Invalid PCR measured data type.
    PCR_MEASURED_DATA_INVALID_MEMORY = 0x08  # PCR Measured data memory location is null or invalid
    PCR_MEASURED_DATA_INVALID_FLASH_DEVICE = 0x09  # Flash device storing PCR Measured data is null or invalid
    PCR_MEASURED_DATA_INVALID_CALLBACK = 0x0A  # Callback to retrieve PCR Measured data is null or invalid
    PCR_INCORRECT_DIGEST_LENGTH = 0x0B  # The digest length is not correct for the PCR.
    PCR_SMALL_OUTPUT_BUFFER = 0x0C  # The output buffer is not large enough for the PCR.
    PCR_INVALID_VALUE_TYPE = 0x0D  # Invalid DMTF value type identifier.
    PCR_INVALID_SEQUENTIAL_ID = 0x0E  # Invalid sequential measurement ID.
    PCR_MEASURED_DATA_NOT_AVIALABLE = 0x0F  # The raw measured data is not available for the measurement.
    PCR_MEASURED_DATA_NO_HASH_CALLBACK = 0x10  # The measured data does not provide a hash callback.
    PCR_CONSTANT_MEASUREMENT = 0x11  # Attempt to update a constant measurement.


class RotCmdBackgroundErrors(IntEnum):
    """Error codes for Command handler background context."""

    CMD_BACKGROUND_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    CMD_BACKGROUND_NO_MEMORY = 0x01  # Memory allocation failed.
    CMD_BACKGROUND_UNSEAL_FAILED = 0x02  # Failed to start unsealing.
    CMD_BACKGROUND_UNSEAL_RESULT_FAILED = 0x03  # Failed to get unsealing result.
    CMD_BACKGROUND_BYPASS_FAILED = 0x04  # Failed to reset to bypass mode.
    CMD_BACKGROUND_DEFAULT_FAILED = 0x05  # Failed to restore defaults.
    CMD_BACKGROUND_BUF_TOO_SMALL = 0x06  # Provided buffer too small for output.
    CMD_BACKGROUND_INPUT_TOO_BIG = 0x07  # Provided input too large.
    CMD_BACKGROUND_UNSUPPORTED_REQUEST = 0x08  # The command is not supported.
    CMD_BACKGROUND_NO_TASK = 0x09  # No manager command task is running.
    CMD_BACKGROUND_TASK_BUSY = 0x0A  # The command task is busy performing an operation.
    CMD_BACKGROUND_UNSUPPORTED_OP = 0x0B  # The scheduled operation is not understood by the task.
    CMD_BACKGROUND_PLATFORM_CFG_FAILED = 0x0C  # Failed to clear platform configuration.
    CMD_BACKGROUND_INTRUSION_FAILED = 0x0D  # Failed to reset the intrusion state.
    CMD_BACKGROUND_CFM_FAILED = 0x0E  # Failed to clear component manifests.
    CMD_BACKGROUND_REBOOT_FAILED = 0x0F  # Failed to warm reset the device.
    CMD_BACKGROUND_AUTH_OP_FAILED = 0x10  # Failed to execute an authorized operation.
    CMD_BACKGROUND_AUTH_OP_INVALID_DATA = 0x11  # Invalid data provided for an authorized operation.


class RotObservableErrors(IntEnum):
    """Error codes for Manager for observer notifications."""

    OBSERVABLE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    OBSERVABLE_NO_MEMORY = 0x01  # Memory allocation failed.


class RotPfmObserverErrors(IntEnum):
    """Error codes for Observers for PFM management."""

    PFM_OBSERVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    PFM_OBSERVER_NO_MEMORY = 0x01  # Memory allocation failed.
    PFM_OBSERVER_MEASUREMENTS_NOT_UNIQUE = 0x02  # Measurement IDs are not unique


class RotCfmObserverErrors(IntEnum):
    """Error codes for Observers for CFM management."""

    CFM_OBSERVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    CFM_OBSERVER_NO_MEMORY = 0x01  # Memory allocation failed.
    CFM_OBSERVER_MEASUREMENTS_NOT_UNIQUE = 0x02  # Measurement IDs are not unique


class RotSigVerificationErrors(IntEnum):
    """Error codes for Verification for signatures."""

    SIG_VERIFICATION_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SIG_VERIFICATION_NO_MEMORY = 0x01  # Memory allocation failed.
    SIG_VERIFICATION_VERIFY_SIG_FAILED = 0x02  # There was a failure during signature verification.
    SIG_VERIFICATION_SET_KEY_FAILED = 0x03  # Failed to set a key for verification.
    SIG_VERIFICATION_NO_KEY = 0x04  # There is no key available to use for verification.
    SIG_VERIFICATION_BAD_SIGNATURE = 0x05  # The signature failed verification.
    SIG_VERIFICATION_UNSUPPORTED = 0x06  # The operation is not supported by the implementation.
    SIG_VERIFICATION_CHECK_KEY_FAILED = 0x07  # Failed to determine if the key is valid for verification.
    SIG_VERIFICATION_INVALID_KEY = 0x08  # The key cannot be used for verification.
    SIG_VERIFICATION_UNKNOWN_HASH = 0x09  # The hash to verify is an unknown type.
    SIG_VERIFICATION_INCONSISTENT_KEY = 0x0A  # A null key of non-zero length or a non-null key of zero length.
    SIG_VERIFICATION_NO_ACTIVE_HASH = 0x0B  # There is no active hash context available to sign.
    SIG_VERIFICATION_SIG_LENGTH_FAILED = 0x0C  # Failed to get the maximum signature length.


class RotManifestVerificationErrors(IntEnum):
    """Error codes for Verification and key management for manifests."""

    MANIFEST_VERIFICATION_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    MANIFEST_VERIFICATION_NO_MEMORY = 0x01  # Memory allocation failed.
    MANIFEST_VERIFICATION_INVALID_STORED_KEY = 0x02  # The stored key is not valid.


class RotSpiFlashSfdpErrors(IntEnum):
    """Error codes for SFDP parsing for SPI flash devices."""

    SPI_FLASH_SFDP_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SPI_FLASH_SFDP_NO_MEMORY = 0x01  # Memory allocation failed.
    SPI_FLASH_SFDP_BAD_SIGNATURE = 0x02  # The SFDP header signature is not correct.
    SPI_FLASH_SFDP_BAD_HEADER = 0x03  # SFDP header information is invalid.
    SPI_FLASH_SFDP_LARGE_DEVICE = 0x04  # The device is too large to correctly report size.
    SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE = 0x05  # Device is not compatible with supported 4-byte addressing.
    SPI_FLASH_SFDP_QUAD_ENABLE_UNKNOWN = 0x06  # QSPI enabled method cannot be determined.
    SPI_FLASH_SFDP_RESET_NOT_SUPPORTED = 0x07  # Soft reset is not supported by the device.
    SPI_FLASH_SFDP_PWRDOWN_NOT_SUPPORTED = 0x08  # Deep power down is not supported by the device.


class RotHostFlashInitErrors(IntEnum):
    """Error codes for Delayed host flash initialization manager."""

    HOST_FLASH_INIT_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    HOST_FLASH_INIT_NO_MEMORY = 0x01  # Memory allocation failed.


class RotFlashErrors(IntEnum):
    """Error codes for Flash device."""

    FLASH_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FLASH_NO_MEMORY = 0x01  # Memory allocation failed.
    FLASH_DEVICE_SIZE_FAILED = 0x02  # Failed to determine flash device size.
    FLASH_READ_FAILED = 0x03  # Failed to read data from flash.
    FLASH_PAGE_SIZE_FAILED = 0x04  # Failed to determine page write size.
    FLASH_WRITE_FAILED = 0x05  # Failed to write data to flash.
    FLASH_SECTOR_SIZE_FAILED = 0x06  # Failed to determine sector erase size.
    FLASH_SECTOR_ERASE_FAILED = 0x07  # Failed to erase a flash sector.
    FLASH_BLOCK_SIZE_FAILED = 0x08  # Failed to determine block erase size.
    FLASH_BLOCK_ERASE_FAILED = 0x09  # Failed to erase a flash block.
    FLASH_CHIP_ERASE_FAILED = 0x0A  # Failed to erase the entire flash device.
    FLASH_ADDRESS_OUT_OF_RANGE = 0x0B  # Invalid address provided for the request.
    FLASH_NOT_BLANK = 0x0C  # The flash is expected to be blank but is not.
    FLASH_HW_NOT_INIT = 0x0D  # The flash hardware interface was not initialized.
    FLASH_MINIMUM_WRITE_FAILED = 0x0E  # Failed to determine the minimum write size.


class RotRecoveryImageHeaderErrors(IntEnum):
    """Error codes for Header information on a recovery image."""

    RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    RECOVERY_IMAGE_HEADER_NO_MEMORY = 0x01  # Memory allocation failed.
    RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH = (
        0x02  # The header length doesn't match the expected length for the format.
    )
    RECOVERY_IMAGE_HEADER_BAD_PLATFORM_ID = 0x03  # An error related to the platform identifier string.
    RECOVERY_IMAGE_HEADER_BAD_VERSION_ID = 0x04  # An error related to the version identifier string.
    RECOVERY_IMAGE_HEADER_BAD_IMAGE_LENGTH = 0x05  # The recovery image length is invalid.


class RotImageHeaderErrors(IntEnum):
    """Error codes for Header information on an image."""

    IMAGE_HEADER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    IMAGE_HEADER_NO_MEMORY = 0x01  # Memory allocation failed.
    IMAGE_HEADER_NOT_MINIMUM_SIZE = 0x02  # The header length is not the minimum size.
    IMAGE_HEADER_BAD_MARKER = 0x03  # The header marker is not valid.
    IMAGE_HEADER_TOO_LONG = 0x04  # The header length exceeds the maximum.


class RotCmdChannelErrors(IntEnum):
    """Error codes for Communication channel for commands."""

    CMD_CHANNEL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    CMD_CHANNEL_NO_MEMORY = 0x01  # Memory allocation failed.
    CMD_CHANNEL_RX_FAILED = 0x02  # Error receiving a packet.
    CMD_CHANNEL_TX_FAILED = 0x03  # Error sending a packet.
    CMD_CHANNEL_RX_TIMEOUT = 0x04  # No packet was received within the specified time.
    CMD_CHANNEL_TX_TIMEOUT = 0x05  # Packet transmission timed out.
    CMD_CHANNEL_PKT_OVERFLOW = 0x06  # Packet overflow encountered.
    CMD_CHANNEL_INVALID_PKT_STATE = 0x07  # Packet state is not valid.
    CMD_CHANNEL_PKT_EXPIRED = 0x08  # The timeout on a received packet has expired.
    CMD_CHANNEL_INVALID_PKT_SIZE = 0x09  # The packet size is larger than the buffer.
    CMD_CHANNEL_TX_ABORTED = 0x0A  # Packet transmission was aborted.
    CMD_CHANNEL_UNKNOWN_TARGET = 0x0B  # The target device is not available.


class RotFirmwareComponentErrors(IntEnum):
    """Error codes for Firmware image component wrapper."""

    FIRMWARE_COMPONENT_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FIRMWARE_COMPONENT_NO_MEMORY = 0x01  # Memory allocation failed.
    FIRMWARE_COMPONENT_BAD_HEADER = 0x02  # The component header is not valid.
    FIRMWARE_COMPONENT_SIG_BUFFER_TOO_SMALL = 0x03  # The buffer for the signature is not large enough.
    FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL = 0x04  # The buffer for the image hash is not large enough.
    FIRMWARE_COMPONENT_TOO_LARGE = 0x05  # There is not enough space available to load the image.
    FIRMWARE_COMPONENT_WRONG_VERSION = 0x06  # The component does not report the expected build version.
    FIRMWARE_COMPONENT_NO_LOAD_ADDRESS = 0x07  # The component does not specify a destination load address.
    FIRMWARE_COMPONENT_VERIFY_FAILED = 0x10  # The component failed verification.
    FIRMWARE_COMPONENT_BAD_SIGNATURE = 0x11  # The component signature failed verification.
    FIRMWARE_COMPONENT_INVALID_SIGNATURE = 0x12  # The component signature is either corrupted or missing.
    FIRMWARE_COMPONENT_SIG_TOO_LARGE = 0x13  # The component signature is larger than the maximum allowed size.


class RotSpiSlaveErrors(IntEnum):
    """Error codes for A driver for a SPI slave.  All drivers use the same ID."""

    SPI_SLAVE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SPI_SLAVE_NO_MEMORY = 0x01  # Memory allocation failed.
    SPI_SLAVE_BUSY = 0x02  # SPI slave busy.
    SPI_SLAVE_TX_FAILED = 0x03  # SPI slave failed to write to master.


class RotFlashUpdaterErrors(IntEnum):
    """Error codes for Flash update management."""

    FLASH_UPDATER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FLASH_UPDATER_NO_MEMORY = 0x01  # Memory allocation failed.
    FLASH_UPDATER_TOO_LARGE = 0x02  # The update is too large for the allocated region.
    FLASH_UPDATER_INCOMPLETE_WRITE = 0x03  # All update data was not written to flash.
    FLASH_UPDATER_OUT_OF_SPACE = 0x04  # Update data would extend beyond region boundaries.


class RotCertDeviceHwErrors(IntEnum):
    """Error codes for Device hardware for certificate management."""

    CERT_DEVICE_HW_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    CERT_DEVICE_HW_NO_MEMORY = 0x01  # Memory allocation failed.
    CERT_DEVICE_HW_VERIFY_ROOT_FAILED = 0x02  # The root key could not be verified.
    CERT_DEVICE_HW_CHECK_ROOT_FAILED = 0x03  # Failed to check root key trust.
    CERT_DEVICE_HW_GET_MIN_LENGTH_FAILED = 0x04  # Unable to determine the minimum required key length.
    CERT_DEVICE_HW_GET_REVOKE_FAILED = 0x05  # Unable to get the revocation status.
    CERT_DEVICE_HW_SET_REVOKE_FAILED = 0x06  # Unable to set the revocation status.
    CERT_DEVICE_HW_BAD_ROOT_KEY = 0x07  # The root key is not valid.
    CERT_DEVICE_HW_NOT_INIT = 0x08  # Hardware has not been initialized.
    CERT_DEVICE_HW_UNSUPPORTED = 0x09  # Hardware does not support certificate functions.


class RotAppContextErrors(IntEnum):
    """Error codes for Running context storage."""

    APP_CONTEXT_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    APP_CONTEXT_NO_MEMORY = 0x01  # Memory allocation failed.
    APP_CONTEXT_SAVE_FAILED = 0x02  # The running context has not been saved.
    APP_CONTEXT_NO_CONTEXT = 0x03  # No context is available.
    APP_CONTEXT_NO_DATA = 0x04  # No data is available.


class RotTpmErrors(IntEnum):
    """Error codes for TPM implementation."""

    TPM_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    TPM_NO_MEMORY = 0x01  # Memory allocation failed.
    TPM_STORAGE_WRITE_FAIL = 0x02  # Failure when writing to persistent storage.
    TPM_INVALID_STORAGE = 0x03  # TPM storage contents invalid.
    TPM_INVALID_LEN = 0x04  # Buffer provided too small for requested contents.
    TPM_OUT_OF_RANGE = 0x05  # Parameter out of range.
    TPM_INVALID_SEGMENT = 0x06  # TPM storage segment not written to.
    TPM_STORAGE_NOT_ALIGNED = 0x07  # Address for the TPM is not aligned correctly.
    TPM_INSUFFICIENT_STORAGE = 0x08  # There is not enough storage space for the TPM.
    TPM_INCOMPLETE_WRITE = 0x09  # Write to storage only partially completed.


class RotAuthorizationErrors(IntEnum):
    """Error codes for Authorization management for operations."""

    AUTHORIZATION_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    AUTHORIZATION_NO_MEMORY = 0x01  # Memory allocation failed.
    AUTHORIZATION_AUTHORIZE_FAILED = 0x02  # Could not determine authorization.
    AUTHORIZATION_NOT_AUTHORIZED = 0x03  # The operation is not authorized to execute.
    AUTHORIZATION_CHALLENGE = 0x04  # The requester must be challenged for authority.


class RotConfigResetErrors(IntEnum):
    """Error codes for Manager for clearing device configuration."""

    CONFIG_RESET_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    CONFIG_RESET_NO_MEMORY = 0x01  # Memory allocation failed.
    CONFIG_RESET_NO_MANIFESTS = 0x02  # No manifest are available.
    CONFIG_RESET_NO_CERTS = 0x03  # Certificate clearing is not supported.


class RotCmdAuthorizationErrors(IntEnum):
    """Error codes for Command authorization handler."""

    CMD_AUTHORIZATION_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    CMD_AUTHORIZATION_NO_MEMORY = 0x01  # Memory allocation failed.
    CMD_AUTHORIZATION_BYPASS_FAILED = 0x02  # Failed authorization to revert to bypass mode.
    CMD_AUTHORIZATION_DEFAULTS_FAILED = 0x03  # Failed authorization to restore defaults.
    CMD_AUTHORIZATION_CONFIG_FAILED = 0x04  # Failed authorization to clear platform config.
    CMD_AUTHORIZATION_COMPONENTS_FAILED = 0x05  # Failed authorization to clear component manifests.
    CMD_AUTHORIZATION_INTRUSION_FAILED = 0x06  # Failed authorization to reset intrusion state.
    CMD_AUTHORIZATION_AUTH_OP_FAILED = 0x07  # Failed authorization for an authenticated operation.
    CMD_AUTHORIZATION_UNSUPPORTED_OP = 0x08  # The specified operation is not supported.


class RotRecoveryImageErrors(IntEnum):
    """Error codes for Recovery image."""

    RECOVERY_IMAGE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    RECOVERY_IMAGE_NO_MEMORY = 0x01  # Memory allocation failed.
    RECOVERY_IMAGE_HASH_BUFFER_TOO_SMALL = 0x02  # A buffer for hash output was too small.
    RECOVERY_IMAGE_VERIFY_FAILED = 0x03  # A verify failure unrelated to authentication.
    RECOVERY_IMAGE_MALFORMED = 0x04  # The recovery image is not formated correctly.
    RECOVERY_IMAGE_GET_HASH_FAILED = 0x05  # The hash could not be calculated.
    RECOVERY_IMAGE_INCOMPATIBLE = 0x06  # The recovery image is incompatible with the system.
    RECOVERY_IMAGE_INVALID_SECTION_ADDRESS = 0x07  # The section address is an invalid value.
    RECOVERY_IMAGE_ID_BUFFER_TOO_SMALL = 0x08  # A buffer for version output was too small.


class RotRecoveryImageObserverErrors(IntEnum):
    """Error codes for Observers for recovery image management."""

    RECOVERY_IMAGE_OBSERVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    RECOVERY_IMAGE_OBSERVER_NO_MEMORY = 0x01  # Memory allocation failed.


class RotRecoveryImageManagerErrors(IntEnum):
    """Error codes for Recovery image manager."""

    RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    RECOVERY_IMAGE_MANAGER_NO_MEMORY = 0x01  # Memory allocation failed.
    RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE = 0x02  # The recovery image is actively being used.
    RECOVERY_IMAGE_MANAGER_NOT_CLEARED = 0x03  # The recovery image region was not cleared before write.
    RECOVERY_IMAGE_MANAGER_INCOMPLETE_UPDATE = 0x04  # The flash has not been programmed with all the expected data.
    RECOVERY_IMAGE_MANAGER_NONE_PENDING = 0x05  # There is no recovery image pending for the operation.
    RECOVERY_IMAGE_MANAGER_TASK_BUSY = 0x06  # The command task is busy performing an operation.
    RECOVERY_IMAGE_MANAGER_NO_TASK = 0x07  # No manager command task is running.
    RECOVERY_IMAGE_MANAGER_UNSUPPORTED_OP = 0x08  # The requested operation is not supported by the manager.
    RECOVERY_IMAGE_MANAGER_NO_IMAGE = 0x09  # No recovery image is available.
    RECOVERY_IMAGE_MANAGER_ACTIVATE_FAILED = 0x0A  # Failed to activate the recovery image.
    RECOVERY_IMAGE_MANAGER_CLEAR_FAILED = 0x0B  # Failed to clear the recovery image region.
    RECOVERY_IMAGE_MANAGER_WRITE_FAILED = 0x0C  # Failed to write recovery image data.
    RECOVERY_IMAGE_MANAGER_ERASE_ALL_FAILED = 0x0D  # Failed to erase all recovery image regions.
    RECOVERY_IMAGE_MANAGER_TOO_MUCH_DATA = 0x0E  # Too much data was sent in a single request.


class RotPcdErrors(IntEnum):
    """Error codes for PCD files for platform configuration."""

    PCD_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    PCD_NO_MEMORY = 0x01  # Memory allocation failed.
    PCD_INVALID_PORT = 0x02  # Port not found in PCD.
    PCD_UNKNOWN_COMPONENT = 0x03  # The component identifier is not present in the PCD.
    PCD_MALFORMED_ROT_ELEMENT = 0x04  # PCD RoT element too short.
    PCD_MALFORMED_DIRECT_I2C_COMPONENT_ELEMENT = 0x05  # PCD direct i2c component element too short.
    PCD_MALFORMED_BRIDGE_COMPONENT_ELEMENT = 0x06  # PCD bridge component element too short.
    PCD_MALFORMED_PORT_ELEMENT = 0x07  # PCD port element too short.


class RotPcdObserverErrors(IntEnum):
    """Error codes for Observers for PCD management."""

    PCD_OBSERVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    PCD_OBSERVER_NO_MEMORY = 0x01  # Memory allocation failed.
    PCD_OBSERVER_MEASUREMENTS_NOT_UNIQUE = 0x02  # Measurement IDs are not unique


class RotCmdDeviceErrors(IntEnum):
    """Error codes for Command handler for device-specific workflows."""

    CMD_DEVICE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    CMD_DEVICE_NO_MEMORY = 0x01  # Memory allocation failed.
    CMD_DEVICE_UUID_BUFFER_TOO_SMALL = 0x02  # A buffer for the UUID output data was too small.
    CMD_DEVICE_RESET_FAILED = 0x03  # Failed to trigger a device reset.
    CMD_DEVICE_INVALID_COUNTER = 0x04  # Invalid counter type.
    CMD_DEVICE_HEAP_FAILED = 0x05  # Failed to get heap statistics.
    CMD_DEVICE_UUID_FAILED = 0x06  # Failed to retrieve the device UUID.
    CMD_DEVICE_RESET_COUNTER_FAILED = 0x07  # Failed to retrieve the reset counter.
    CMD_DEVICE_STACK_FAILED = 0x08  # Failed to get stack statistics.


class RotHostProcessorObserverErrors(IntEnum):
    """Error codes for Observers for host processor management."""

    HOST_PROCESSOR_OBSERVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    HOST_PROCESSOR_OBSERVER_NO_MEMORY = 0x01  # Memory allocation failed.


class RotCounterManagerErrors(IntEnum):
    """Error codes for Counter operation management."""

    COUNTER_MANAGER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    COUNTER_MANAGER_NO_MEMORY = 0x01  # Memory allocation failed.
    COUNTER_MANAGER_UNKNOWN_COUNTER = 0x02  # Invalid counter.


class RotSessionManagerErrors(IntEnum):
    """Error codes for Encrypted session management."""

    SESSION_MANAGER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SESSION_MANAGER_NO_MEMORY = 0x01  # Memory allocation failed.
    SESSION_MANAGER_UNEXPECTED_EID = 0x02  # Device EID unexpected.
    SESSION_MANAGER_SESSION_NOT_ESTABLISHED = 0x03  # Operation can't be completed without establishing session.
    SESSION_MANAGER_INVALID_ORDER = 0x04  # Invalid order attempted for session establishment.
    SESSION_MANAGER_FULL = 0x05  # Session manager at capacity and cannot support more sessions.
    SESSION_MANAGER_MALFORMED_MSG = 0x06  # Provided message to decrypt invalid.
    SESSION_MANAGER_BUF_TOO_SMALL = 0x07  # Provided output buffer too small for operation.
    SESSION_MANAGER_INVALID_REQUEST = 0x08  # Provided session request invalid.
    SESSION_MANAGER_OPERATION_UNSUPPORTED = 0x09  # Requested operation not supported.
    SESSION_MANAGER_OPERATION_NOT_PERMITTED = 0x0A  # Requested operation not permitted.
    SESSION_MANAGER_PAIRING_NOT_SUPPORTED_WITH_DEVICE = 0x0B  # Pairing not supported with device.
    SESSION_MANAGER_ADD_SESSION_FAILED = 0x0C  # Failed to add a new session.
    SESSION_MANAGER_ESTABLISH_SESSION_FAILED = 0x0D  # Failed to establish the encrypted connection.
    SESSION_MANAGER_SESSION_CHECK_FAILED = 0x0E  # Failed to check the session state.
    SESSION_MANAGER_PAIRING_STATE_FAILED = 0x0F  # Failed to check the pairing state.
    SESSION_MANAGER_DECRYPT_MSG_FAILED = 0x10  # Failed to decrypt a message.
    SESSION_MANAGER_ENCRYPT_MSG_FAILED = 0x11  # Failed to encrypt a message.
    SESSION_MANAGER_RESET_SESSION_FAILED = 0x12  # Failed to terminate a session.
    SESSION_MANAGER_PAIR_SESSION_FAILED = 0x13  # Failed to pair with a device.
    SESSION_MANAGER_SESSION_SYNC_FAILED = 0x14  # Failed to sync the current session.


class RotFlashStoreErrors(IntEnum):
    """Error codes for Block data storage in flash."""

    FLASH_STORE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FLASH_STORE_NO_MEMORY = 0x01  # Memory allocation failed.
    FLASH_STORE_WRITE_FAILED = 0x02  # Failed to write data to flash.
    FLASH_STORE_READ_FAILED = 0x03  # Failed to read data from flash.
    FLASH_STORE_ERASE_FAILED = 0x04  # Failed to erase data from flash.
    FLASH_STORE_ERASE_ALL_FAILED = 0x05  # Failed to erase all data from flash.
    FLASH_STORE_GET_LENGTH_FAILED = 0x06  # Failed to determine length of stored data.
    FLASH_STORE_DATA_CHECK_FAILED = 0x07  # Failed to determine if data is stored.
    FLASH_STORE_GET_MAX_FAILED = 0x08  # Failed to determine the maximum data length.
    FLASH_STORE_FLASH_SIZE_FAILED = 0x09  # Failed to determine the size of reserved flash.
    FLASH_STORE_STORAGE_NOT_ALIGNED = 0x0A  # Memory for flash storage is not aligned correctly.
    FLASH_STORE_NO_STORAGE = 0x0B  # The flash storage was created with no data blocks.
    FLASH_STORE_INSUFFICIENT_STORAGE = 0x0C  # There is not enough storage space for the data.
    FLASH_STORE_BAD_BASE_ADDRESS = 0x0D  # The base address is not valid for the device.
    FLASH_STORE_BLOCK_TOO_LARGE = 0x0E  # The data block size is too large.
    FLASH_STORE_BAD_DATA_LENGTH = 0x0F  # Data being stored is not the correct length.
    FLASH_STORE_UNSUPPORTED_ID = 0x10  # Invalid block ID specified.
    FLASH_STORE_CORRUPT_DATA = 0x11  # Data stored in flash is corrupt.
    FLASH_STORE_BUFFER_TOO_SMALL = 0x12  # Output buffer is not large enough for stored data.
    FLASH_STORE_NO_DATA = 0x13  # No data is stored in the flash block.
    FLASH_STORE_NUM_BLOCKS_FAILED = 0x14  # Failed to determine the number of managed data blocks.


class RotKdfErrors(IntEnum):
    """Error codes for Key derivation function."""

    KDF_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    KDF_NO_MEMORY = 0x01  # Memory allocation failed.
    KDF_OPERATION_UNSUPPORTED = 0x02  # Requested operation not supported.
    KDF_BAD_INPUT_DATA = 0x03  # Input data is not valid.
    KDF_INPUT_KEY_TOO_SHORT = 0x04  # Input KDF key is not long enough.
    KDF_OUTPUT_KEY_TOO_LONG = 0x05  # Output key is longer than is supported by the KDF.
    KDF_NIST800_108_SHA1_KAT_FAILED = 0x06  # Failed a SHA-1 NIST800-108 self test.
    KDF_NIST800_108_SHA256_KAT_FAILED = 0x07  # Failed a SHA-256 NIST800-108 self test.
    KDF_NIST800_108_SHA384_KAT_FAILED = 0x08  # Failed a SHA-384 NIST800-108 self test.
    KDF_NIST800_108_SHA512_KAT_FAILED = 0x09  # Failed a SHA-512 NIST800-108 self test.
    KDF_HKDF_EXPAND_SHA1_KAT_FAILED = 0x0A  # Failed a SHA-1 HKDF-Expand self test.
    KDF_HKDF_EXPAND_SHA256_KAT_FAILED = 0x0B  # Failed a SHA-256 HKDF-Expand self test.
    KDF_HKDF_EXPAND_SHA384_KAT_FAILED = 0x0C  # Failed a SHA-384 HKDF-Expand self test.
    KDF_HKDF_EXPAND_SHA512_KAT_FAILED = 0x0D  # Failed a SHA-512 HKDF-Expand self test.


class RotHostStateObserverErrors(IntEnum):
    """Error codes for Observers for host state changes."""

    HOST_STATE_OBSERVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    HOST_STATE_OBSERVER_NO_MEMORY = 0x01  # Memory allocation failed.


class RotSystemErrors(IntEnum):
    """Error codes for Main system manager."""

    SYSTEM_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SYSTEM_NO_MEMORY = 0x01  # Memory allocation failed.


class RotSystemObserverErrors(IntEnum):
    """Error codes for Observers for system events."""

    SYSTEM_OBSERVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SYSTEM_OBSERVER_NO_MEMORY = 0x01  # Memory allocation failed.


class RotIntrusionStateErrors(IntEnum):
    """Error codes for Chassis intrusion state detection."""

    INTRUSION_STATE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    INTRUSION_STATE_NO_MEMORY = 0x01  # Memory allocation failed.
    INTRUSION_STATE_SET_FAILED = 0x02  # Failed to set intrusion.
    INTRUSION_STATE_CLEAR_FAILED = 0x03  # Failed to clear intrusion.
    INTRUSION_STATE_CHECK_FAILED = 0x04  # Failed to check intrusion state.
    INTRUSION_STATE_CHECK_DEFERRED = 0x05  # State checking will be done in the background.
    INTRUSION_STATE_REMOTE_REQUEST_FAILED = 0x06  # Request to remote component failed.
    INTRUSION_STATE_GET_COUNT_FAILED = 0x07  # Request to get intrusion count failed.
    INTRUSION_STATE_IS_ACTIVE_FAILED = 0x08  # Request to get intrusion active state failed.


class RotIntrusionManagerErrors(IntEnum):
    """Error codes for Manager for intrusion detection."""

    INTRUSION_MANAGER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    INTRUSION_MANAGER_NO_MEMORY = 0x01  # Memory allocation failed.
    INTRUSION_MANAGER_INTRUSION_FAILED = 0x02  # Intrusion event handling failed.
    INTRUSION_MANAGER_RESET_FAILED = 0x03  # Intrusion state was not reset.
    INTRUSION_MANAGER_CHECK_FAILED = 0x04  # Failed to check the intrusion state.
    INTRUSION_MANAGER_INTRUSION_STILL_ACTIVE = 0x05  # Intrusion state was still active once intrusion reset was issued.


class RotEccDerUtilErrors(IntEnum):
    """Error codes for Utilities for handling DER encoded ECC information."""

    ECC_DER_UTIL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    ECC_DER_UTIL_NO_MEMORY = 0x01  # Memory allocation failed.
    ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH = 0x02  # The key length is not supported.
    ECC_DER_UTIL_MALFORMED = 0x03  # The buffer contains malformed ASN.1 data.
    ECC_DER_UTIL_UNKNOWN_SEQUENCE = 0x04  # The buffer contains an unknown ASN.1 sequence.
    ECC_DER_UTIL_UNSUPPORTED_CURVE = 0x05  # The key uses a curve not supported for the key length.
    ECC_DER_UTIL_SMALL_KEY_BUFFER = 0x06  # A key output buffer is not large enough for the decoded data.
    ECC_DER_UTIL_SMALL_DER_BUFFER = 0x07  # A DER output buffer is not large enough for the encoded data.
    ECC_DER_UTIL_UNSUPPORTED_ALGORITHM = 0x08  # A public key uses an unsupported algorithm.
    ECC_DER_UTIL_SIG_TOO_LONG = 0x09  # The encoded signature is too long for the key length.
    ECC_DER_UTIL_UNEXPECTED_TAG = 0x0A  # The encoded data contained a tag not correct for ASN.1 sequence.
    ECC_DER_UTIL_INVALID_ECPOINT = 0x0B  # The public key is representation is not valid.
    ECC_DER_UTIL_COMPRESSED_ECPOINT = 0x0C  # The public key is represented in compressed form.
    ECC_DER_UTIL_INFINITY_ECPOINT = 0x0D  # The public key provided is the point at infinity.
    ECC_DER_UTIL_INVALID_SIGNATURE = 0x0E  # The encoded signature is not valid.


class RotBufferUtilErrors(IntEnum):
    """Error codes for General buffer handling utilities."""

    BUFFER_UTIL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    BUFFER_UTIL_NO_MEMORY = 0x01  # Memory allocation failed.
    BUFFER_UTIL_DATA_MISMATCH = 0x02  # A buffer does not contain the expected data.
    BUFFER_UTIL_UNEXPETCED_ALIGNMENT = 0x03  # Detected unexpected buffer address alignment.


class RotOcpRecoveryDeviceErrors(IntEnum):
    """Error codes for Device handler for the OCP Recovery protocol."""

    OCP_RECOVERY_DEVICE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    OCP_RECOVERY_DEVICE_NO_MEMORY = 0x01  # Memory allocation failed.
    OCP_RECOVERY_DEVICE_GET_DEV_ID_FAILED = 0x02  # Failed to get the current device's identifier.
    OCP_RECOVERY_DEVICE_ACTIVATE_REC_FAILED = 0x03  # Failure activating a recovery image.
    OCP_RECOVERY_DEVICE_NACK = 0x04  # A NACK must be generated on the physical bus.
    OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND = 0x05  # No recovery command has been started.
    OCP_RECOVERY_DEVICE_RO_COMMAND = 0x06  # A write was accepted for a RO command.
    OCP_RECOVERY_DEVICE_UNSUPPORTED = 0x07  # The requested operation is unsupported by the device.
    OCP_RECOVERY_DEVICE_CMD_INCOMPLETE = 0x08  # Not enough data was sent for the command.
    OCP_RECOVERY_DEVICE_CMS_NOT_CODE_REGION = 0x09  # A memory region used for recovery is not a code region.
    OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS = 0x0A  # An unsupported CMS was requested.
    OCP_RECOVERY_DEVICE_RO_CMS = 0x0B  # Received a write request for a RO CMS.
    OCP_RECOVERY_DEVICE_RW_CMS_NOT_ALIGNED = 0x0C  # A RW CMS is not 4-byte aligned.
    OCP_RECOVERY_DEVICE_RW_LOG = 0x0D  # A CMS with a logging interface was set as RW.
    OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM = 0x0E  # Received a valid operation with an unsupported parameter.
    OCP_RECOVERY_DEVICE_EXTRA_CMD_BYTES = 0x0F  # Too much data was sent for the command.
    OCP_RECOVERY_DEVICE_CMS_SIZE_FAILED = 0x10  # Could not determine the size of a variable CMS.
    OCP_RECOVERY_DEVICE_CMS_DATA_FAILED = 0x11  # Failed to read data from a variable CMS.
    OCP_RECOVERY_DEVICE_CMS_FLASH_ADDR_OVERFLOW = 0x12  # Base address plus offset is greater than the device size.


class RotOcpRecoverySmbusErrors(IntEnum):
    """Error codes for SMBus layer for the OCP Recovery protocol."""

    OCP_RECOVERY_SMBUS_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    OCP_RECOVERY_SMBUS_NO_MEMORY = 0x01  # Memory allocation failed.
    OCP_RECOVERY_SMBUS_OVERFLOW = 0x02  # A block write has received too many bytes.
    OCP_RECOVERY_SMBUS_NACK = 0x03  # The received data is for an invalid command.


class RotCmdHandlerSpdmErrors(IntEnum):
    """Error codes for Handler for received SPDM protocol commands."""

    CMD_HANDLER_SPDM_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    CMD_HANDLER_SPDM_NO_MEMORY = 0x01  # Memory allocation failed.
    CMD_HANDLER_SPDM_PAYLOAD_TOO_SHORT = 0x02  # The request does not contain the minimum amount of data.
    CMD_HANDLER_SPDM_BAD_LENGTH = 0x03  # The payload length is wrong for the request.
    CMD_HANDLER_SPDM_UNKNOWN_COMMAND = 0x04  # A command does not represent a known request.
    CMD_HANDLER_SPDM_BUF_TOO_SMALL = 0x05  # Provided buffer too small for output.
    CMD_HANDLER_SPDM_UNSUPPORTED_MSG = 0x06  # Message type not supported.
    CMD_HANDLER_SPDM_UNSUPPORTED_OPERATION = 0x07  # The requested operation is not supported.
    CMD_HANDLER_SPDM_NOT_INTEROPERABLE = 0x08  # Received message using different specification major version
    CMD_HANDLER_SPDM_UNSUPPORTED_MEAS_SPEC = 0x09  # Requested measurement specification unsupported
    CMD_HANDLER_SPDM_UNSUPPORTED_ASYM_ALGO = 0x0A  # Requested asymmetric cryptographic algorithm unsupported
    CMD_HANDLER_SPDM_UNSUPPORTED_HASH_ALGO = 0x0B  # Requested hashing algorithm unsupported
    CMD_HANDLER_SPDM_UNSUPPORTED_SLOT_ID = 0x0C  # Requested slot id unsupported
    CMD_HANDLER_SPDM_BAD_RESPONSE = 0x0D  # Received bad response to request
    CMD_HANDLER_SPDM_SIG_CONTEXT_TOO_LONG = 0x0E  # SPDM signature context too long


class RotAsn1UtilErrors(IntEnum):
    """Error codes for ASN.1 operations."""

    ASN1_UTIL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    ASN1_UTIL_NO_MEMORY = 0x01  # Memory allocation failed.
    ASN1_UTIL_NOT_VALID = 0x02  # ASN.1 decoding failed.
    ASN1_UTIL_SMALL_DER_BUFFER = 0x03  # A DER buffer is not large enough for the encoded data.
    ASN1_UTIL_OUT_OF_RANGE = 0x04  # A value is out of the allowed range for an operation.
    ASN1_UTIL_UNEXPECTED_TAG = 0x05  # The encoded data contained a tag that does not match the expected value.


class RotEventTaskErrors(IntEnum):
    """Error codes for Task for event handling."""

    EVENT_TASK_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    EVENT_TASK_NO_MEMORY = 0x01  # Memory allocation failed.
    EVENT_TASK_LOCK_FAILED = 0x02  # Failure to lock the task.
    EVENT_TASK_UNLOCK_FAILED = 0x03  # Failure to unlock the task.
    EVENT_TASK_GET_CONTEXT_FAILED = 0x04  # Failure to retrieve the event context.
    EVENT_TASK_NOTIFY_FAILED = 0x05  # Failure to notify the event handler.
    EVENT_TASK_NO_TASK = 0x06  # The task has not been started.
    EVENT_TASK_BUSY = 0x07  # The task is busy performing an operation.
    EVENT_TASK_UNKNOWN_HANDLER = 0x08  # The handler is not known to the task.
    EVENT_TASK_NOT_READY = 0x09  # The handler was not prepared to be notified.
    EVENT_TASK_TOO_MUCH_DATA = 0x0A  # An event was submitted with too much data.


class RotPeriodicTaskErrors(IntEnum):
    """Error codes for Task for periodic execution."""

    PERIODIC_TASK_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    PERIODIC_TASK_NO_MEMORY = 0x01  # Memory allocation failed.
    PERIODIC_TASK_NO_HANDLERS = 0x02  # A list of handlers only contains null pointers.


class RotFirmwareLoaderErrors(IntEnum):
    """Error codes for Handler to load firmware images into memory."""

    FIRMWARE_LOADER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FIRMWARE_LOADER_NO_MEMORY = 0x01  # Memory allocation failed.
    FIRMWARE_LOADER_ADDR_CHECK_FAILED = 0x02  # Failed to determine if a target address is valid.
    FIRMWARE_LOADER_LOAD_IMG_FAILED = 0x03  # Failed to load an image into memory.
    FIRMWARE_LOADER_INVALID_ADDR = 0x04  # The target address for loading an image is not valid.
    FIRMWARE_LOADER_IMAGE_TOO_LARGE = 0x05  # The image will not fit in the target memory.
    FIRMWARE_LOADER_BAD_IV_LENGTH = 0x06  # The IV length is not correct for the image.
    FIRMWARE_LOADER_ENCRYPTION_NOT_SUPPORTED = 0x07  # Encrypted images are not supported.
    FIRMWARE_LOADER_COPY_IMG_FAILED = 0x08  # Failed to copy on image from memory.
    FIRMWARE_LOADER_MAP_ADDR_FAILED = 0x09  # Failed to allocate a virtual address.


class RotDeviceManagerObserverErrors(IntEnum):
    """Error codes for Observers for device manager events."""

    DEVICE_MANAGER_OBSERVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    DEVICE_MANAGER_NO_MEMORY = 0x01  # Memory allocation failed.


class RotEccHwErrors(IntEnum):
    """Error codes for Driver interface for ECC accelerator hardware."""

    ECC_HW_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    ECC_HW_NO_MEMORY = 0x01  # Memory allocation failed.
    ECC_HW_ECC_PUBLIC_FAILED = 0x02  # Failed to calculate an ECC public key.
    ECC_HW_ECC_GENERATE_FAILED = 0x03  # Failed to generate a random ECC key pair.
    ECC_HW_ECDSA_SIGN_FAILED = 0x04  # Failed to generate an ECDSA signature.
    ECC_HW_ECDSA_VERIFY_FAILED = 0x05  # Failed to verify an ECDSA signature.
    ECC_HW_ECDH_COMPUTE_FAILED = 0x06  # Failed to compute an ECDH secret.
    ECC_HW_MONT_CONST_FAILED = 0x07  # Montgomery constant calculation failed.
    ECC_HW_INVALID_ADDRESS = 0x08  # A buffer is not in memory accessible to the hardware.
    ECC_HW_CMD_NOT_STARTED = 0x09  # The ECC HW did not accept a submitted command.
    ECC_HW_ADDRESS_NOT_ALIGNED = 0x0A  # A buffer address is not word aligned.
    ECC_HW_ECDSA_BAD_SIGNATURE = 0x0B  # An ECDSA signature is not valid for the digest.
    ECC_HW_UNSUPPORTED_KEY_LENGTH = 0x0C  # The private key length is not supported.
    ECC_HW_PUBLIC_KEY_TOO_SMALL = 0x0D  # The public key buffer is too small for the key length.
    ECC_HW_DIGEST_TOO_LONG = 0x0E  # The digest is too long for the key length.
    ECC_HW_SIGNATURE_TOO_SMALL = 0x0F  # The ECDSA signature buffer is too small for the key length.
    ECC_HW_ECDH_TOO_SMALL = 0x10  # The ECDH secret buffer is too small for the key length.
    ECC_HW_SIGNATURE_WRONG_LENGTH = 0x11  # An ECDSA signature does not match the public key length.
    ECC_HW_PUBLIC_WRONG_LENGTH = 0x12  # An ECC public key does not match the private key length.
    ECC_HW_SELF_TEST_FAILED = 0x13  # A self-test of the ECC HW failed.
    ECC_HW_FREE_CHECK_FAILED = 0x14  # An error occurred while checking if ECC HW is free.
    ECC_HW_MEM_WIPE_FAILED = 0x15  # An error occurred while attempting to wipe internal memory for the ECC hardware.
    ECC_HW_UNSUPPORTED_OP = 0x16  # The ECC HW does not support this command.
    ECC_HW_INT_TO_MONT_FAILED = 0x17  # Failed to convert to Montgomery representation.
    ECC_HW_MONT_TO_INT_FAILED = 0x18  # Failed to convert from Montgomery representation.
    ECC_HW_MOD_INVERSE_FAILED = 0x19  # Failed a modular inversion calculation.
    ECC_HW_MOD_MULTIPLY_FAILED = 0x1A  # Failed a modular multiplication.
    ECC_HW_MOD_ADD_FAILED = 0x1B  # Failed a modular addition.
    ECC_HW_MOD_REDUCE_FAILED = 0x1C  # Failed a modular reduction.
    ECC_HW_PRIV_KEY_GEN_FAILED = 0x1D  # Failed to generate a valid private key for the curve.
    ECC_HW_VERIFY_PUBLIC_FAILED = 0x1E  # Failed to verify an ECC public key.
    ECC_HW_INVALID_PUBLIC_KEY = 0x1F  # The ECC public key is not valid.
    ECC_HW_CMD_EXE_TIMEOUT = 0x20  # ECC command execution timeout.


class RotCommonMathErrors(IntEnum):
    """Error codes for Common math operations."""

    COMMON_MATH_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    COMMON_MATH_NO_MEMORY = 0x01  # Memory allocation failed.
    COMMON_MATH_BOUNDARY_REACHED = 0x02  # Upper boundary of an array or a counter is reached.
    COMMON_MATH_OUT_OF_RANGE = 0x03  # The request is out of the valid range.


class RotX509ExtensionErrors(IntEnum):
    """Error codes for Extension handler for X.509 certificates."""

    X509_EXTENSION_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    X509_EXTENSION_NO_MEMORY = 0x01  # Memory allocation failed.
    X509_EXTENSION_BUILD_FAILED = 0x02  # Failed to build the extension data.


class RotDiceTcbinfoExtensionErrors(IntEnum):
    """Error codes for Extension handler for TCG DICE TcbInfo extensions."""

    DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    DICE_TCBINFO_EXTENSION_NO_MEMORY = 0x01  # Memory allocation failed.
    DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER = 0x02  # The extension buffer is too small for the data.
    DICE_TCBINFO_EXTENSION_UNKNOWN_FWID = 0x03  # The FWID digest is an unknown type.
    DICE_TCBINFO_EXTENSION_NO_FWID = 0x04  # No FWID digest was provided in the TCB info.
    DICE_TCBINFO_EXTENSION_NO_VERSION = 0x05  # No version was provided in the TCB info.
    DICE_TCBINFO_EXTENSION_NO_SVN = 0x06  # No SVN was provided in the TCB info.
    DICE_TCBINFO_EXTENSION_NO_FWID_LIST = 0x07  # No FWID list was provided in the TCB info.
    DICE_TCBINFO_EXTENSION_NO_IR_ID = 0x08  # No ID was provided for a named digest.
    DICE_TCBINFO_EXTENSION_UNKNOWN_IR_DIGEST = 0x09  # A named digest uses an unknown digest type.
    DICE_TCBINFO_EXTENSION_NO_IR_DIGEST = 0x0A  # No digest value was provided for a named digest.
    DICE_TCBINFO_EXTENSION_NO_IR_DIGEST_LIST = 0x0B  # No digest list was provided for a named digest.


class RotDiceUeidExtensionErrors(IntEnum):
    """Error codes for Extension handler for TCG DICE Ueid extensions."""

    DICE_UEID_EXTENSION_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    DICE_UEID_EXTENSION_NO_MEMORY = 0x01  # Memory allocation failed.
    DICE_UEID_EXTENSION_SMALL_EXT_BUFFER = 0x02  # The extension buffer is too small for the data.


class RotDmeExtensionErrors(IntEnum):
    """Error codes for Extension handler for DME extensions."""

    DME_EXTENSION_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    DME_EXTENSION_NO_MEMORY = 0x01  # Memory allocation failed.
    DME_EXTENSION_SMALL_EXT_BUFFER = 0x02  # The extension buffer is too small for the data.
    DME_EXTENSION_NO_TYPE_OID = 0x03  # The DME structure does not specify a type identifier.
    DME_EXTENSION_NO_DATA = 0x04  # The DME structure does not provide any structure data.
    DME_EXTENSION_NO_SIG_TYPE_OID = 0x05  # The DME structure does not specify a signature type.
    DME_EXTENSION_NO_SIGNATURE = 0x06  # The DME structure does not provide a signature.
    DME_EXTENSION_NO_DME_KEY = 0x07  # The DME structure does not provide a public key.


class RotDmeStructureErrors(IntEnum):
    """Error codes for Parsing and management of the DME structure."""

    DME_STRUCTURE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    DME_STRUCTURE_NO_MEMORY = 0x01  # Memory allocation failed.
    DME_STRUCTURE_BAD_LENGTH = 0x02  # DME structure length is not correct.
    DME_STRUCTURE_UNSUPPORTED_SIGNATURE = 0x03  # The signature uses an unsupported digest.
    DME_STRUCTURE_UNSUPPORTED_KEY_LENGTH = 0x04  # The DME key length is not supported.


class RotSecureDeviceUnlockErrors(IntEnum):
    """Error codes for Handler for device unlock requests."""

    SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SECURE_DEVICE_UNLOCK_NO_MEMORY = 0x01  # Memory allocation failed.
    SECURE_DEVICE_UNLOCK_GET_TOKEN_FAILED = 0x02  # Failed to get an unlock token.
    SECURE_DEVICE_UNLOCK_APPLY_POLICY_FAILED = 0x03  # Failed to apply an unlock policy.
    SECURE_DEVICE_UNLOCK_CLEAR_POLICY_FAILED = 0x04  # Failed to clear an unlock policy.
    SECURE_DEVICE_UNLOCK_NOT_LOCKED = 0x05  # Attempt to unlock an unlocked device.
    SECURE_DEVICE_UNLOCK_COUNTER_EXHAUSTED = 0x06  # The device unlock counter has reached the max value.
    SECURE_DEVICE_UNLOCK_UNSUPPORTED = 0x07  # The requested operation is not supported.
    SECURE_DEVICE_UNLOCK_SMALL_BUFFER = 0x08  # An output buffer was too small for the data.


class RotSecurityManagerErrors(IntEnum):
    """Error codes for Manager for the device security configuration."""

    SECURITY_MANAGER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SECURITY_MANAGER_NO_MEMORY = 0x01  # Memory allocation failed.
    SECURITY_MANAGER_LOCK_FAILED = 0x02  # Failed to lock the device.
    SECURITY_MANAGER_UNLOCK_FAILED = 0x03  # Failed to unlock the device.
    SECURITY_MANAGER_GET_COUNTER_FAILED = 0x04  # Failed to get the unlock counter value.
    SECURITY_MANAGER_HAS_UNLOCK_FAILED = 0x05  # Failed to query for an active unlock policy.
    SECURITY_MANAGER_LOAD_FAILED = 0x06  # Failed to load the active security policy.
    SECURITY_MANAGER_CONFIG_FAILED = 0x07  # Failed to apply the security configuration.
    SECURITY_MANAGER_GET_POLICY_FAILED = 0x08  # Failed to get the active security policy.
    SECURITY_MANAGER_UNSUPPORTED = 0x09  # The operation is not supported by the manager.
    SECURITY_MANAGER_SMALL_COUNTER_BUFFER = 0x0A  # Unlock counter buffer is too small.
    SECURITY_MANAGER_UNALIGNED_ADDRESS = 0x0B  # An address does not meet alignment requirements.
    SECURITY_MANAGER_UNALIGNED_BUFFER = 0x0C  # A buffer length does not meet alignment requirements.
    SECURITY_MANAGER_SMALL_NONCE_BUFFER = 0x0D  # A buffer for nonce management is too small.
    SECURITY_MANAGER_BAD_UNLOCK_POLICY = 0x0E  # A stored unlock policy failed verification.
    SECURITY_MANAGER_BAD_DEVICE_STATE = 0x0F  # The device state is not compatible with the operation.
    SECURITY_MANAGER_COUNTER_MISMATCH = 0x10  # The unlock counter is not the expected value.
    SECURITY_MANAGER_NONCE_MISMATCH = 0x11  # The policy nonce is not the expected value.
    SECURITY_MANAGER_INVALID_COUNTER_VALUE = 0x12  # The unlock counter is not a valid value.
    SECURITY_MANAGER_SMALL_POLICY_BUFFER = 0x13  # A buffer for unlock policy management is too small.


class RotSecurityPolicyErrors(IntEnum):
    """Error codes for The device security policy."""

    SECURITY_POLICY_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SECURITY_POLICY_NO_MEMORY = 0x01  # Memory allocation failed.
    SECURITY_POLICY_PERSIST_CHECK_FAILED = 0x02  # Failed to determine policy persistence.
    SECURITY_POLICY_FW_SIGNING_CHECK_FAILED = 0x03  # Failed to determine signature enforcement.
    SECURITY_POLICY_ANTI_ROLLBACK_CHECK_FAILED = 0x04  # Failed to determine anti-rollback enforcement.
    SECURITY_POLICY_PARSE_UNLOCK_FAILED = 0x05  # Failed to parse an unlock policy.
    SECURITY_POLICY_SMALL_BUFFER = 0x06  # An output buffer is not large enough.
    SECURITY_POLICY_IMMUTABLE = 0x07  # The security policy cannot be changed.
    SECURITY_POLICY_BAD_DATA = 0x08  # The security policy data is not valid.


class RotAuthTokenErrors(IntEnum):
    """Error codes for Authorization token handler."""

    AUTH_TOKEN_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    AUTH_TOKEN_NO_MEMORY = 0x01  # Memory allocation failed.
    AUTH_TOKEN_BUILD_FAILED = 0x02  # Failed to build a new token.
    AUTH_TOKEN_CHECK_FAILED = 0x03  # Failed to verify against the active token.
    AUTH_TOKEN_INVALIDATE_FAILED = 0x04  # Failed to invalidate the active token.
    AUTH_TOKEN_NOT_VALID = 0x05  # A token is not valid for the device.
    AUTH_TOKEN_SMALL_BUFFER = 0x06  # The token buffer is not large enough.
    AUTH_TOKEN_WRONG_SIG_LENGTH = 0x07  # The configured signature length does not match the token key.
    AUTH_TOKEN_DATA_TOO_LONG = 0x08  # Too much context data was provided for the token.


class RotDeviceUnlockTokenErrors(IntEnum):
    """Error codes for Handler for device unlock tokens."""

    DEVICE_UNLOCK_TOKEN_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    DEVICE_UNLOCK_TOKEN_NO_MEMORY = 0x01  # Memory allocation failed.
    DEVICE_UNLOCK_TOKEN_BAD_AUTH_DATA = 0x02  # Authorized data cannot be parsed.
    DEVICE_UNLOCK_TOKEN_SMALL_BUFFER = 0x03  # Output token buffer is not large enough.
    DEVICE_UNLOCK_TOKEN_INVALID_COUNTER = 0x04  # The counter value is not valid for the token.


class RotDoeCmdChannelErrors(IntEnum):
    """Error codes for Communication channel for DOE commands."""

    DOE_CMD_CHANNEL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    DOE_CMD_CHANNEL_NO_MEMORY = 0x01  # Memory allocation failed.
    DOE_CMD_CHANNEL_RX_FAILED = 0x02  # Failed to receive a message.
    DOE_CMD_CHANNEL_TX_FAILED = 0x03  # Failed to send a message.


class RotDoeInterfaceErrors(IntEnum):
    """Error codes for DOE interface."""

    DOE_INTERFACE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    DOE_INTERFACE_NO_MEMORY = 0x01  # Memory allocation failed.
    DOE_INTERFACE_UNSUPPORTED_DATA_OBJECT_TYPE = 0x02  # Data object type is unsupported.
    DOE_INTERFACE_INVALID_MSG_SIZE = 0x03  # The message size is incorrect.
    DOE_INTERFACE_INVALID_VENDOR_ID = 0x04  # The vendor id is invalid.
    DOE_INTERFACE_INVALID_MSG = 0x05  # The message is invalid.
    DOE_INTERFACE_INVALID_DISCOVERY_INDEX = 0x06  # The index for DOE discovery is invalid.


class RotRealTimeClockErrors(IntEnum):
    """Error codes for The real time clock interface."""

    REAL_TIME_CLOCK_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    REAL_TIME_CLOCK_NO_MEMORY = 0x01  # Memory allocation failed.
    REAL_TIME_CLOCK_GET_TIME_FAILED = 0x02  # Get time operation failed.
    REAL_TIME_CLOCK_SET_TIME_FAILED = 0x03  # Set time operation failed.
    REAL_TIME_CLOCK_UNSUPPORTED = 0x04  # Operation is unsupported.
    REAL_TIME_CLOCK_SET_BLOCKED = 0x05  # Set time was called too quickly from the last call.
    REAL_TIME_CLOCK_OUT_OF_RANGE = 0x06  # Time value is out of range.
    REAL_TIME_CLOCK_READ_TIMEOUT = 0x07  # Timeout while trying to read RTC values.
    REAL_TIME_CLOCK_WRITE_TIMEOUT = 0x08  # Timeout while trying to write RTC values.


class RotRmaUnlockTokenErrors(IntEnum):
    """Error codes for Handler for device RMA unlock tokens."""

    RMA_UNLOCK_TOKEN_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    RMA_UNLOCK_TOKEN_NO_MEMORY = 0x01  # Memory allocation failed.
    RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA = 0x02  # The token data is not structured correctly.
    RMA_UNLOCK_TOKEN_DEVICE_MISMATCH = 0x03  # The token is not for this device.


class RotSpdmTranscriptManagerErrors(IntEnum):
    """Error codes for SPDM Transcript Manager."""

    SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SPDM_TRANSCRIPT_MANAGER_NO_MEMORY = 0x01  # Memory allocation failed.
    SPDM_TRANSCRIPT_MANAGER_BUFFER_FULL = 0x02  # VCA buffer is full.
    SPDM_TRANSCRIPT_MANAGER_HASH_NOT_STARTED = 0x03  # Hash not started.
    SPDM_TRANSCRIPT_MANAGER_INVALID_STATE = 0x04  # Invalid state.
    SPDM_TRANSCRIPT_MANAGER_HASH_ALGO_ALREADY_SET = 0x05  # Hash algorithm is already set.
    SPDM_TRANSCRIPT_MANAGER_INVALID_SESSION_IDX = 0x06  # Invalid session index.
    SPDM_TRANSCRIPT_MANAGER_BUFFER_TOO_SMALL = 0x07  # Buffer is too small.
    SPDM_TRANSCRIPT_MANAGER_UNSUPPORTED_CONTEXT_TYPE = 0x08  # Unsupported context type.
    SPDM_TRANSCRIPT_MANAGER_SET_HASH_ALGO_FAILED = 0x09  # Setting the hash algorithm failed.
    SPDM_TRANSCRIPT_MANAGER_UPDATE_FAILED = 0x0A  # Updating the transcript failed.
    SPDM_TRANSCRIPT_MANAGER_GET_HASH_FAILED = 0x0B  # Getting the hash failed.
    SPDM_TRANSCRIPT_MANAGER_RESET_FAILED = 0x0C  # Resetting the transcript manager failed.
    SPDM_TRANSCRIPT_MANAGER_RESET_SESSION_FAILED = 0x0D  # Resetting the session transcript failed.


class RotSpdmMeasurementsErrors(IntEnum):
    """Error codes for SPDM measurement block handler."""

    SPDM_MEASUREMENTS_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SPDM_MEASUREMENTS_NO_MEMORY = 0x01  # Memory allocation failed.
    SPDM_MEASUREMENTS_GET_COUNT_FAILED = 0x02  # Failed to determine the number of measurements.
    SPDM_MEASUREMENTS_GET_BLOCK_FAILED = 0x03  # Failed to get a measurement block.
    SPDM_MEASUREMENTS_BLOCK_LENGTH_FAILED = 0x04  # Failed to determine a measurement block length.
    SPDM_MEASUREMENTS_GET_ALL_BLOCKS_FAILED = 0x05  # Failed to get all measurement blocks.
    SPDM_MEASUREMENTS_ALL_BLOCKS_LENGTH_FAILED = 0x06  # Failed to determine the length of all blocks.
    SPDM_MEASUREMENTS_GET_SUMMARY_FAILED = 0x07  # Failed to get the measurement summary hash.
    SPDM_MEASUREMENTS_RAW_BIT_STREAM_NOT_AVAILABLE = 0x08  # The raw bit stream for the measurement is not available.
    SPDM_MEASUREMENTS_HASH_NOT_APPLICABLE = 0x09  # Returning the hash of the measurement is not allowed.
    SPDM_MEASUREMENTS_HASH_NOT_POSSIBLE = (
        0x0A  # It's not possible to hash the measurement with the requested algorithm.
    )
    SPDM_MEASUREMENTS_BUFFER_TOO_SMALL = 0x0B  # The output buffer is not large enough for the measurement record.
    SPDM_MEASUREMENTS_RESERVED_BLOCK_ID = 0x0C  # The request uses a reserved block ID.
    SPDM_MEASUREMENTS_SAME_HASH_ENGINE = 0x0D  # Non-unique hash engines have been provided.


class RotIdeDriverErrors(IntEnum):
    """Error codes for Driver interface for programming IDE registers."""

    IDE_DRIVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    IDE_DRIVER_NO_MEMORY = 0x01  # Memory allocation failed.
    IDE_DRIVER_GET_CAPABILITY_REGISTER_FAILED = 0x02  # The driver failed to get the capability register.
    IDE_DRIVER_GET_CONTROL_REGISTER_FAILED = 0x03  # The driver failed to get the control register.
    IDE_DRIVER_GET_LINK_IDE_REGISTER_BLOCK_FAILED = 0x04  # The driver failed to get the link IDE register block.
    IDE_DRIVER_GET_SELECTIVE_IDE_STREAM_REGISTER_BLOCK_FAILED = (
        0x05  # The driver failed to get the selective IDE stream register block.
    )
    IDE_DRIVER_KEY_PROG_FAILED = 0x06  # The driver failed to stash the IDE host key information.
    IDE_DRIVER_KEY_SET_GO_FAILED = 0x07  # The driver failed to set the IDE host key.
    IDE_DRIVER_KEY_SET_STOP_FAILED = 0x08  # The driver failed to stop using the IDE host key.
    IDE_DRIVER_GET_BUS_DEVICE_SEGMENT_INFO_FAILED = (
        0x09  # The driver failed to get the bus, device/function, and segment information.
    )
    IDE_DRIVER_KEY_SET_GO_RX_KEY_FAILED = (
        0x0A  # The driver failed to set the IDE Rx key for a given key_set, stream and sub-stream.
    )
    IDE_DRIVER_KEY_SET_GO_TX_KEY_FAILED = (
        0x0B  # The driver failed to set the IDE Tx key for a given key_set, stream and sub-stream.
    )
    IDE_DRIVER_INVALID_STREAM_ID = 0x0C  # The driver failed due to invalid stream ID.
    IDE_DRIVER_UNSUPPORTED_PORT_INDEX = 0x0D  # Unsupported port index


class RotMsgTransportErrors(IntEnum):
    """Error codes for Handler for issuing remote requests."""

    MSG_TRANSPORT_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    MSG_TRANSPORT_NO_MEMORY = 0x01  # Memory allocation failed.
    MSG_TRANSPORT_MAX_OVERHEAD_FAILED = 0x02  # Failed to determine the maximum transport overhead.
    MSG_TRANSPORT_MAX_PAYLOAD_FAILED = 0x03  # Failed to determine the maximum transport payload.
    MSG_TRANSPORT_MAX_BUFFER_FAILED = 0x04  # Failed to determine tha maximum encapsulated length.
    MSG_TRANSPORT_OVERHEAD_FAILED = 0x05  # Failed to determine the message overhead size.
    MSG_TRANSPORT_SEND_REQUEST_FAILED = 0x06  # Failed to send a request message.
    MSG_TRANSPORT_REQUEST_TIMEOUT = 0x07  # Timeout while waiting for a response.
    MSG_TRANSPORT_NO_WAIT_RESPONSE = 0x08  # Did not wait for a response after sending a request.
    MSG_TRANSPORT_OVERHEAD_MORE_THAN_BUFFER = 0x09  # The request buffer is smaller than the transport overhead.
    MSG_TRANSPORT_REQUEST_TOO_LARGE = 0x0A  # The request payload exceeds the transport maximum.
    MSG_TRANSPORT_RESPONSE_TOO_LARGE = 0x0B  # The response payload exceeds the provided buffer space.
    MSG_TRANSPORT_UNEXPECTED_RESPONSE = 0x0C  # The response does not match the request.
    MSG_TRANSPORT_RESPONSE_TOO_SHORT = 0x0D  # A response message does not contain enough data.


class RotTdispDriverErrors(IntEnum):
    """Error codes for Driver interface for programming TDISP registers."""

    TDISP_DRIVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    TDISP_DRIVER_NO_MEMORY = 0x01  # Memory allocation failed.
    TDISP_DRIVER_GET_TDISP_CAPABILITIES_FAILED = 0x02  # The driver failed to get the TDISP capabilities.
    TDISP_DRIVER_GET_DEVICE_INTERFACE_STATE_FAILED = 0x03  # The driver failed to get the device interface state.
    TDISP_DRIVER_LOCK_INTERFACE_REQUEST_FAILED = 0x04  # The driver failed to lock the device interface.
    TDISP_DRIVER_START_INTERFACE_REQUEST_FAILED = 0x05  # The driver failed to start the device interface.
    TDISP_DRIVER_STOP_INTERFACE_REQUEST_FAILED = 0x06  # The driver failed to stop the device interface.
    TDISP_DRIVER_GET_DEVICE_INTERFACE_REPORT_FAILED = 0x07  # The driver failed to get the device interface report.
    TDISP_DRIVER_GET_MMIO_RANGES_FAILED = 0x08  # The driver failed to get the mmio ranges.
    TDISP_DRIVER_GET_FUNCTION_INDEX_FAILED = 0x09  # The driver failed to get the function index.
    TDISP_DRIVER_NOT_IMPLEMENTED = 0x0A  # The driver function is not implemented.
    TDISP_DRIVER_INTERFACE_INVALID_STATE = 0x0B  # Interface invalid state
    TDISP_DRIVER_INVALID_INTERFACE = 0x0C  # Invalid interface ID
    TDISP_DRIVER_IDE_NOT_SECURE = 0x0D  # IDE stream is not in secure state
    TDISP_DRIVER_UPDATE_NOT_ALLOWED = 0x0E  # Firmware update is not allowed for the current driver configuration
    TDISP_DRIVER_CONTROLLER_NOT_ENABLED = 0x0F  # TDISP controller is not enabled


class RotMctpNotifierErrors(IntEnum):
    """Error codes for MCTP Notifier module."""

    MCTP_NOTIFIER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    MCTP_NOTIFIER_NO_MEMORY = 0x01  # Memory allocation failed.
    MCTP_NOTIFIER_REGISTER_FAILED = 0x02  # Registration failed.
    MCTP_NOTIFIER_FORCE_REGISTER_FAILED = 0x03  # Force registration failed.
    MCTP_NOTIFIER_DEREGISTER_FAILED = 0x04  # Deregistration failed.
    MCTP_NOTIFIER_SEND_NOTIFICATION_FAILED = 0x05  # Sending notification failed.
    MCTP_NOTIFIER_NOTIFICATION_RESP_MISMATCH = 0x06  # Notification response mismatch.
    MCTP_NOTIFIER_MAX_REGISTERED = 0x07  # Max number of EID already registered.
    MCTP_NOTIFIER_NOT_REGISTERED = 0x08  # EID is not registered.
    MCTP_NOTIFIER_PAYLOAD_TOO_LARGE = 0x09  # Notification payload length too long.
    MCTP_NOTIFIER_PAYLOAD_TOO_SHORT = 0x0A  # Notification payload length too short.
    MCTP_NOTIFIER_RESP_PAYLOAD_TOO_SHORT = 0x0B  # Notification response payload length too short.
    MCTP_NOTIFIER_UNSUPPORTED_OPERATION = 0x0C  # Requested notifier operation not supported.


class RotEcdsaErrors(IntEnum):
    """Error codes for ECDSA signature handling."""

    ECDSA_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    ECDSA_NO_MEMORY = 0x01  # Memory allocation failed.
    ECDSA_P256_SIGN_SELF_TEST_FAILED = 0x02  # Failed a self-test for ECDSA sign for the P-256 curve.
    ECDSA_P384_SIGN_SELF_TEST_FAILED = 0x03  # Failed a self-test for ECDSA sign for the P-384 curve.
    ECDSA_P521_SIGN_SELF_TEST_FAILED = 0x04  # Failed a self-test for ECDSA sign for the P-521 curve.
    ECDSA_P256_VERIFY_SELF_TEST_FAILED = 0x05  # Failed a self-test for ECDSA verify for the P-256 curve.
    ECDSA_P384_VERIFY_SELF_TEST_FAILED = 0x06  # Failed a self-test for ECDSA verify for the P-384 curve.
    ECDSA_P521_VERIFY_SELF_TEST_FAILED = 0x07  # Failed a self-test for ECDSA verify for the P-521 curve.
    ECDSA_UNSUPPORTED_SELF_TEST = 0x08  # The curve or hash algorithm is not supported.
    ECDSA_NO_ACTVE_HASH = 0x09  # There is no active hash context available to sign.
    ECDSA_PCT_FAILURE = 0x0A  # Failed the pairwise consistency test.


class RotKeyCacheErrors(IntEnum):
    """Error codes for Key cache to handle rsa key management."""

    KEY_CACHE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    KEY_CACHE_NO_MEMORY = 0x01  # Memory allocation failed.
    KEY_CACHE_INIT_CACHE_FAILED = 0x02  # Failed to check if the key cache is initialized
    KEY_CACHE_ADD_KEY_FAILED = 0x03  # Failed to add/write the key on the persistent store
    KEY_CACHE_REMOVE_KEY_FAILED = 0x04  # Failed to remove/read the key from the persistent store
    KEY_CACHE_QUEUE_IS_EMPTY = 0x05  # No key available on the flash all the flash sectors are empty
    KEY_CACHE_QUEUE_IS_FULL = 0x06  # No new flash sector available to store new key
    KEY_CACHE_CREDIT_NOT_AVAILABLE = 0x07  # All credit is used for the Requestor
    KEY_CACHE_INVALID_REQUESTOR_ID = 0x08  # Invalid requestor ID
    KEY_CACHE_INVALID_ADD_INDEX = 0x09  # Invalid add/write index
    KEY_CACHE_INVALID_REMOVE_INDEX = 0x0A  # Invalid remove/read index
    KEY_CACHE_INSUFFICIENT_STORAGE = 0x0B  # Not enough flash storage for the required number of keys.
    KEY_CACHE_STORAGE_MISMATCH = 0x0C  # The flash store does not contain the expected number of blocks.
    KEY_CACHE_UNAVAILABLE_STORAGE = 0x0D  # Too much storage is not available for use.
    KEY_CACHE_NOT_INITIALIZED = 0x0E  # The key cache is not initialized.
    KEY_CACHE_MEMORY_CORRUPTED = 0x0F  # The memory is corrupted.
    KEY_CACHE_KEY_NOT_FOUND_AT_INDEX = 0x10  # No key available on the given index


class RotEphemeralKeyManagerErrors(IntEnum):
    """Error codes for Ephemeral key manager."""

    EPHEMERAL_KEY_MANAGER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    EPHEMERAL_KEY_MANAGER_NO_MEMORY = 0x01  # Memory allocation failure.
    EPHEMERAL_KEY_MANAGER_INVALID_KEY_TYPE = 0x02  # Invalid supported bits for key generation/read
    EPHEMERAL_KEY_MANAGER_GET_KEY_FAILED = 0x03  # Get key request failed


class RotEphemeralKeyGenerationErrors(IntEnum):
    """Error codes for Ephemeral key generation."""

    EPHEMERAL_KEY_GEN_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    EPHEMERAL_KEY_GEN_NO_MEMORY = 0x01  # Memory allocation failed.
    EPHEMERAL_KEY_GEN_PRIVATE_KEY_GEN_UNSUPPORTED = 0x02  # Requested operation not supported.
    EPHEMERAL_KEY_GEN_GENERATE_KEY_FAILED = 0x03  # Key Generate API Failed.
    EPHEMERAL_KEY_GEN_EXTRACT_KEY_FAILED = 0x04  # Key extract API Failed.
    EPHEMERAL_KEY_GEN_PRIVATE_KEY_GEN_FAILED = 0x05  # Private key generation failed.
    EPHEMERAL_KEY_GEN_SMALL_KEY_BUFFER = 0x06  # Insufficient space to copy data to the buffer.


class RotAuthorizedExecutionErrors(IntEnum):
    """Error codes for Execution context for authorized operations."""

    AUTHORIZED_EXECUTION_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    AUTHORIZED_EXECUTION_NO_MEMORY = 0x01  # Memory allocation failed.
    AUTHORIZED_EXECUTION_EXECUTE_FAILED = 0x02  # Failed to execute the operation.
    AUTHORIZED_EXECUTION_CHECK_DATA_FAILED = 0x03  # Failed to check the operation data.
    AUTHORIZED_EXECUTION_DATA_NOT_VALID = 0x04  # The provided data is not valid for the operation.


class RotSpdmVdmProtocolErrors(IntEnum):
    """Error codes for SPDM vendor defined messages protocol."""

    SPDM_VDM_PROTOCOL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SPDM_VDM_PROTOCOL_NO_MEMORY = 0x01  # Memory allocation failed.
    SPDM_VDM_PROTOCOL_MSG_TOO_SHORT = 0x02  # Protocol message is too short.
    SPDM_VDM_PROTOCOL_INVALID_RESPONSE = 0x03  # Message response layout is invalid.


class RotSpdmPcisigProtocolErrors(IntEnum):
    """Error codes for SPDM PCISIG messages protocol."""

    SPDM_PCISIG_PROTOCOL_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SPDM_PCISIG_PROTOCOL_NO_MEMORY = 0x01  # Memory allocation failed.
    SPDM_PCISIG_PROTOCOL_MSG_TOO_SHORT = 0x02  # Protocol message is too short.
    SPDM_PCISIG_PROTOCOL_INVALID_HEADER = 0x03  # Invalid message header.
    SPDM_PCISIG_PROTOCOL_INVALID_RESPONSE = 0x04  # Response message layout is invalid.


class RotImpactfulCheckErrors(IntEnum):
    """Error codes for Device check for conditions requiring impactful updates."""

    IMPACTFUL_CHECK_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    IMPACTFUL_CHECK_NO_MEMORY = 0x01  # Memory allocation failed.
    IMPACTFUL_CHECK_NOT_IMPACTFUL_FAILED = 0x02  # Failed to determine if an update is impactful.
    IMPACTFUL_CHECK_AUTH_ALLOWED_FAILED = 0x03  # Failed to determine if an impactful update can be authorized.
    IMPACTFUL_CHECK_IMPACTFUL_UPDATE = 0x04  # An update in the current context would be impactful.
    IMPACTFUL_CHECK_AUTH_NOT_ALLOWED = 0x05  # Authorization is not allowed for an impactful update.


class RotImpactfulUpdateErrors(IntEnum):
    """Error codes for Interface for handling impactful updates."""

    IMPACTFUL_UPDATE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    IMPACTFUL_UPDATE_NO_MEMORY = 0x01  # Memory allocation failed.
    IMPACTFUL_UPDATE_IS_NOT_IMPACTFUL_FAILED = 0x02  # Failed to determine if an update is impactful.
    IMPACTFUL_UPDATE_IS_ALLOWED_FAILED = 0x03  # Failed to determine if an update is blocked.
    IMPACTFUL_UPDATE_AUTHORIZE_FAILED = 0x04  # Failed to authorize impactful updates.
    IMPACTFUL_UPDATE_RESET_AUTH_FAILED = 0x05  # Failed to reset impactful update authorization.
    IMPACTFUL_UPDATE_NOT_ALLOWED = 0x06  # The update is not allowed for use.
    IMPACTFUL_UPDATE_BLOCKED = 0x07  # The update is not allowed and cannot be authorized.


class RotAesXtsEngineErrors(IntEnum):
    """Error codes for An AES-XTS crypto engine.  All engines use the same ID."""

    AES_XTS_ENGINE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    AES_XTS_ENGINE_NO_MEMORY = 0x01  # Memory allocation failed.
    AES_XTS_ENGINE_SET_KEY_FAILED = 0x02  # The encryption key could not be set.
    AES_XTS_ENGINE_ENCRYPT_FAILED = 0x03  # The ciphertext was not decrypted.
    AES_XTS_ENGINE_DECRYPT_FAILED = 0x04  # The plaintext was not encrypted.
    AES_XTS_ENGINE_UNSUPPORTED_KEY_LENGTH = 0x05  # The encryption key length is not supported by the engine.
    AES_XTS_ENGINE_INVALID_KEY_LENGTH = 0x06  # The key length is not a valid AES-XTS key length.
    AES_XTS_ENGINE_MATCHING_KEYS = 0x07  # XTS key 1 and key 2 are the same.
    AES_XTS_ENGINE_UNSUPPORTED_DATA_LENGTH = 0x08  # The data unit length is not supported by the engine.
    AES_XTS_ENGINE_INVALID_DATA_LENGTH = 0x09  # The data unit length is not valid for AES-XTS.
    AES_XTS_ENGINE_OUT_BUFFER_TOO_SMALL = 0x0A  # Not enough space in an output buffer provided for the operation.
    AES_XTS_ENGINE_NO_KEY = 0x0B  # No key was set prior to encryption/decryption.
    AES_XTS_ENGINE_HW_NOT_INIT = 0x0C  # The AES hardware has not been initialized.
    AES_XTS_ENGINE_SELF_TEST_FAILED = 0x0D  # An internal self-test of the AES engine failed.
    AES_XTS_ENGINE_UNSUPPORTED_OPERATION = 0x0E  # The requested operation is not supported.
    AES_XTS_ENGINE_CLEAR_KEY_FAILED = 0x0F  # The encryption key could not be cleared.


class RotMmioRegisterErrors(IntEnum):
    """Error codes for MMIO register operations."""

    MMIO_REGISTER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    MMIO_REGISTER_NO_MEMORY = 0x01  # Memory allocation failed.
    MMIO_REGISTER_MAP_FAILED = 0x02  # Failed to peform internal map operation
    MMIO_REGISTER_READ32_FAILED = 0x03  # Failed to read 32bits register
    MMIO_REGISTER_WRITE32_FAILED = 0x04  # Failed to write 32bits register
    MMIO_REGISTER_BLOCK_READ32_FAILED = 0x05  # Failed to read registers block
    MMIO_REGISTER_BLOCK_WRITE32_FAILED = 0x06  # Failed to write registers block
    MMIO_REGISTER_UNALIGNED_ADDRESS = 0x07  # Unaligned memory address.
    MMIO_REGISTER_UNALIGNED_OFFSET = 0x08  # Unaligned register offset detected.
    MMIO_REGISTER_UNALIGNED_SIZE = 0x09  # Unaligned block size detected.
    MMIO_REGISTER_OFFSET_OUT_OF_RANGE = 0x0A  # Register offset is out of range.
    MMIO_REGISTER_NOT_MAPPED = 0x0B  # Memory is not mapped before accessing registers
    MMIO_REGISTER_BIT_OUT_OF_RANGE = 0x0C  # Bit number larger than the register size.
    MMIO_REGISTER_BIT_MASK_OUT_OF_RANGE = 0x0D  # Set of bits larger than the register size.
    MMIO_REGISTER_ADDRESS_OUT_OF_RANGE = 0x0E  # Register physical address is out of range
    MMIO_REGISTER_READ32_BY_ADDR_FAILED = 0x0F  # Failed to read 32bits register by physical address
    MMIO_REGISTER_WRITE32_BY_ADDR_FAILED = 0x10  # Failed to write 32bits register by physical address
    MMIO_REGISTER_BLOCK_READ32_BY_ADDR_FAILED = 0x11  # Failed to read register block by physical address
    MMIO_REGISTER_BLOCK_WRITE32_BY_ADDR_FAILED = 0x12  # Failed to write register block by physical address
    MMIO_REGISTER_GET_PHYSICAL_ADDRESS_FAILED = 0x13  # Failed to convert offset to physical address
    MMIO_REGISTER_GET_ADDRESS_OFFSET_FAILED = 0x14  # Failed to convert physical address to offset


class RotMpuErrors(IntEnum):
    """Error codes for MPU interface"""

    MPU_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    MPU_NO_MEMORY = 0x01  # Memory allocation failed.
    MPU_GET_PAGE_SIZE_FAILED = 0x02  # Get page size failure
    MPU_SET_REGION_ATTRIBUTES_FAILED = 0x03  # Set region attributes failure
    MPU_GET_PAGE_ATTRIBUTES_FAILED = 0x04  # Get page attributes failure
    MPU_UNALIGNED_ADDRESS = 0x05  # MPU page address is unaligned
    MPU_UNALIGNED_SIZE = 0x06  # Region size is unaligned
    MPU_UNSUPPORTED_ADDRESS = 0x07  # Memory address is unsupported by current hardware
    MPU_UNSUPPORTED_PROTECTION_LEVEL = 0x08  # Unsupported protection level


class RotRsassaErrors(IntEnum):
    """Error codes for RSASSA signature handling."""

    RSASSA_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    RSASSA_NO_MEMORY = 0x01  # Memory allocation failed.
    RSASSA_2K_SIGN_SELF_TEST_FAILED = 0x02  # Failed a self-test for RSASSA sign with a 2048-bit key.
    RSASSA_3K_SIGN_SELF_TEST_FAILED = 0x03  # Failed a self-test for RSASSA sign with a 3072-bit key.
    RSASSA_4K_SIGN_SELF_TEST_FAILED = 0x04  # Failed a self-test for RSASSA sign with a 4096-bit key.
    RSASSA_2K_VERIFY_SELF_TEST_FAILED = 0x05  # Failed a self-test for RSASSA verify with a 2048-bit key.
    RSASSA_3K_VERIFY_SELF_TEST_FAILED = 0x06  # Failed a self-test for RSASSA verify with a 3072-bit key.
    RSASSA_4K_VERIFY_SELF_TEST_FAILED = 0x07  # Failed a self-test for RSASSA verify with a 4096-bit key.
    RSASSA_UNSUPPORTED_SELF_TEST = 0x08  # The key length or hash algorithm is not supported.


class RotAcvpProtoErrors(IntEnum):
    """Error codes for ACVP Proto handler."""

    ACVP_PROTO_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    ACVP_PROTO_NO_MEMORY = 0x01  # Memory allocation failed.
    ACVP_PROTO_INIT_NOT_READY = 0x02  # Device is not ready for an ACVP test.
    ACVP_PROTO_INIT_TOO_LARGE = 0x03  # Test data size is too large.
    ACVP_PROTO_INIT_FAILED = 0x04  # Failure during test initialization.
    ACVP_PROTO_ADD_TEST_DATA_TOO_MUCH_DATA = 0x05  # Attempt to add more data than expected.
    ACVP_PROTO_ADD_TEST_DATA_OFFSET_OUT_OF_RANGE = 0x06  # The offset for the test data is out of range.
    ACVP_PROTO_ADD_TEST_DATA_FAILED = 0x07  # Failure while adding test data.
    ACVP_PROTO_EXECUTE_TEST_FAILED = 0x08  # Failure while executing test.
    ACVP_PROTO_GET_TEST_RESULTS_FAILED = 0x09  # Failure while getting test results.
    ACVP_PROTO_INVALID_STATE = 0x0A  # The ACVP Proto interface is in an invalid state.


class RotFirmwarePfmVerifyErrors(IntEnum):
    """Error codes for Handler for verifying device FW with a PFM."""

    FIRMWARE_PFM_VERIFY_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FIRMWARE_PFM_VERIFY_NO_MEMORY = 0x01  # Memory allocation failed.
    FIRMWARE_PFM_VERIFY_NOT_VERIFIED = 0x02  # Firmware verification has not been run.
    FIRMWARE_PFM_VERIFY_PFM_MULTI_FW = 0x03  # The PFM contains multiple FW components.
    FIRMWARE_PFM_VERIFY_EMPTY_PFM = 0x04  # The PFM contains no firmware information.
    FIRMWARE_PFM_VERIFY_PFM_MULTI_VERSION = 0x05  # The PFM contains multiple firmware versions.
    FIRMWARE_PFM_VERIFY_PFM_NO_VERSION = 0x06  # The PFM contains no firmware version.
    FIRMWARE_PFM_VERIFY_PFM_NO_IMAGE = 0x07  # The PFM contains no firmware image information.
    FIRMWARE_PFM_VERIFY_UNSUPPORTED_ID = 0x08  # The PFM contains an unsupported ID.


class RotBackendShaErrors(IntEnum):
    """Error codes for ACVP SHA backend."""

    BACKEND_SHA_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    BACKEND_SHA_NO_MEMORY = 0x01  # Memory allocation failed.
    BACKEND_SHA_NO_ENGINE = 0x02  # No SHA engine is available.
    BACKEND_SHA_ENGINE_NOT_FOUND = 0x03  # No SHA engine found for the specified implementation.
    BACKEND_SHA_ENGINE_HASH_GENERATE_FAILED = 0x04  # SHA hash generation failed.
    BACKEND_SHA_ENGINE_MCT_INNER_LOOP_FAILED = 0x05  # SHA MCT inner loop failed.
    BACKEND_SHA_UNEXPECTED_HASH_LENGTH = 0x06  # SHA hash length does not match the expected length.


class RotAcvpProtoTesterErrors(IntEnum):
    """Error codes for ACVP Proto tester."""

    ACVP_PROTO_TESTER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    ACVP_PROTO_TESTER_NO_MEMORY = 0x01  # Memory allocation failed.
    ACVP_PROTO_TESTER_LENGTH_TOO_SMALL = 0x02  # Input length is too small.
    ACVP_PROTO_TESTER_LENGTH_TOO_LARGE = 0x03  # Input length is too large.
    ACVP_PROTO_TESTER_TEST_FAILED = 0x04  # ACVP test execution failed.
    ACVP_PROTO_TESTER_CHECK_INPUT_LENGTH_FAILED = 0x05  # ACVP test input length check failed.
    ACVP_PROTO_TESTER_PROTO_TEST_ALGO_FAILED = 0x06  # ACVP proto test algorithm execution failed.


class RotEcdhErrors(IntEnum):
    """Error codes for ECDH handling."""

    ECDH_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    ECDH_NO_MEMORY = 0x01  # Memory allocation failed.
    ECDH_PCT_FAILURE = 0x02  # Failed the pairwise consistency test.
    ECDH_P256_SELF_TEST_FAILED = 0x03  # Failed a self-test for ECDH for the P-256 curve.
    ECDH_P384_SELF_TEST_FAILED = 0x04  # Failed a self-test for ECDH for the P-384 curve.
    ECDH_P521_SELF_TEST_FAILED = 0x05  # Failed a self-test for ECDH for the P-521 curve.
    ECDH_UNSUPPORTED_SELF_TEST = 0x06  # The curve algorithm is not supported.
    ECDH_UNSUPPORTED_KEY_LENGTH = 0x07  # An unsupported key length was provided.


class RotAesEcbEngineErrors(IntEnum):
    """Error codes for An AES-ECB crypto engine.  All engines use the same ID."""

    AES_ECB_ENGINE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    AES_ECB_ENGINE_NO_MEMORY = 0x01  # Memory allocation failed.
    AES_ECB_ENGINE_SET_KEY_FAILED = 0x02  # The encryption key could not be set.
    AES_ECB_ENGINE_CLEAR_KEY_FAILED = 0x03  # The encryption key could not be cleared.
    AES_ECB_ENGINE_ENCRYPT_FAILED = 0x04  # The ciphertext was not decrypted.
    AES_ECB_ENGINE_DECRYPT_FAILED = 0x05  # The plaintext was not encrypted.
    AES_ECB_ENGINE_UNSUPPORTED_KEY_LENGTH = 0x06  # The encryption key length is not supported by the engine.
    AES_ECB_ENGINE_INVALID_KEY_LENGTH = 0x07  # The key length is not a valid AES-ECB key length.
    AES_ECB_ENGINE_INVALID_DATA_LENGTH = 0x08  # The data length is aligned to the AES block size.
    AES_ECB_ENGINE_OUT_BUFFER_TOO_SMALL = 0x09  # Not enough space in an output buffer provided for the operation.
    AES_ECB_ENGINE_NO_KEY = 0x0A  # No key was set prior to encryption/decryption.
    AES_ECB_ENGINE_HW_NOT_INIT = 0x0B  # The AES hardware has not been initialized.
    AES_ECB_ENGINE_SELF_TEST_FAILED = 0x0C  # An internal self-test of the AES engine failed.
    AES_ECB_ENGINE_UNSUPPORTED_OPERATION = 0x0D  # The requested operation is not supported.


class RotAesCbcEngineErrors(IntEnum):
    """Error codes for An AES-CBC crypto engine.  All engines use the same ID."""

    AES_CBC_ENGINE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    AES_CBC_ENGINE_NO_MEMORY = 0x01  # Memory allocation failed.
    AES_CBC_ENGINE_SET_KEY_FAILED = 0x02  # The encryption key could not be set.
    AES_CBC_ENGINE_CLEAR_KEY_FAILED = 0x03  # The encryption key could not be cleared.
    AES_CBC_ENGINE_ENCRYPT_FAILED = 0x04  # The ciphertext was not decrypted.
    AES_CBC_ENGINE_DECRYPT_FAILED = 0x05  # The plaintext was not encrypted.
    AES_CBC_ENGINE_UNSUPPORTED_KEY_LENGTH = 0x06  # The encryption key length is not supported by the engine.
    AES_CBC_ENGINE_INVALID_KEY_LENGTH = 0x07  # The key length is not a valid AES-CBC key length.
    AES_CBC_ENGINE_INVALID_DATA_LENGTH = 0x08  # The data length is aligned to the AES block size.
    AES_CBC_ENGINE_OUT_BUFFER_TOO_SMALL = 0x09  # Not enough space in an output buffer provided for the operation.
    AES_CBC_ENGINE_NO_KEY = 0x0A  # No key was set prior to encryption/decryption.
    AES_CBC_ENGINE_HW_NOT_INIT = 0x0B  # The AES hardware has not been initialized.
    AES_CBC_ENGINE_SELF_TEST_FAILED = 0x0C  # An internal self-test of the AES engine failed.
    AES_CBC_ENGINE_UNSUPPORTED_OPERATION = 0x0D  # The requested operation is not supported.


class RotAesKeyWrapErrors(IntEnum):
    """Error codes for Handler for AES key wrap/unwrap."""

    AES_KEY_WRAP_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    AES_KEY_WRAP_NO_MEMORY = 0x01  # Memory allocation failed.
    AES_KEY_WRAP_SET_KEK_FAILED = 0x02  # Failed to set a new KEK.
    AES_KEY_WRAP_CLEAR_KEK_FAILED = 0x03  # Failed to clear the existing KEK.
    AES_KEY_WRAP_WRAP_FAILED = 0x04  # Failed to wrap the secret data.
    AES_KEY_WRAP_UNWRAP_FAILED = 0x05  # Failed to unwrap the secret data.
    AES_KEY_WRAP_NOT_BLOCK_ALIGNED = 0x06  # The data length is not 64-bit aligned.
    AES_KEY_WRAP_NOT_ENOUGH_DATA = 0x07  # The data length is too short.
    AES_KEY_WRAP_TOO_MUCH_DATA = 0x08  # The requested data is longer than can be supported.
    AES_KEY_WRAP_SMALL_OUTPUT_BUFFER = 0x09  # The output buffer is too small for the provided data.
    AES_KEY_WRAP_INTEGRITY_CHECK_FAIL = 0x0A  # The integrity check detected corruption in the unwrapped data.
    AES_KEY_WRAP_LENGTH_CHECK_FAIL = 0x0B  # The output data length does not fall within expected bounds.
    AES_KEY_WRAP_PADDING_CHECK_FAIL = 0x0C  # Padding bytes in the unwrapped data are non-zero.
    AES_KEY_WRAP_SELF_TEST_FAILED = 0x0D  # An self-test of key wrap or unwrap failed.


class RotHkdfErrors(IntEnum):
    """Error codes for HKDF key derivation."""

    HKDF_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    HKDF_NO_MEMORY = 0x01  # Memory allocation failed.
    HKDF_EXTRACT_FAILED = 0x02  # Failed to extract the PRK.
    HKDF_EXPAND_FAILED = 0x03  # Failed to derive a new key.
    HKDF_CLEAR_PRK_FAILED = 0x04  # Failed to clear the PRK.
    HKDF_NO_PRK_AVAILABLE = 0x05  # The PRK has not been extracted for use in key derivations.
    HKDF_SHA1_KAT_FAILED = 0x06  # Failed a SHA-1 HKDF-Expand self test.
    HKDF_SHA256_KAT_FAILED = 0x07  # Failed a SHA-256 HKDF-Expand self test.
    HKDF_SHA384_KAT_FAILED = 0x08  # Failed a SHA-384 HKDF-Expand self test.
    HKDF_SHA512_KAT_FAILED = 0x09  # Failed a SHA-512 HKDF-Expand self test.
    HKDF_UPDATE_PRK_FAILED = 0x0A  # Failed to update PRK.


class RotBackendAeadErrors(IntEnum):
    """Error codes for ACVP AEAD backend."""

    BACKEND_AEAD_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    BACKEND_AEAD_NO_MEMORY = 0x01  # Memory allocation failed.
    BACKEND_AEAD_NO_ENGINE = 0x02  # No AEAD engine is available.
    BACKEND_AEAD_ENGINE_NOT_FOUND = 0x03  # No AEAD engine found for the specified implementation.
    BACKEND_AEAD_NO_RNG = 0x04  # No RNG engine found for the specified implementation.
    BACKEND_AEAD_GCM_ENCRYPT_FAILED = 0x05  # AES-GCM encryption failed.
    BACKEND_AEAD_GCM_DECRYPT_FAILED = 0x06  # AES-GCM decryption failed.
    BACKEND_AEAD_CCM_ENCRYPT_FAILED = 0x07  # AES-CCM encryption failed.
    BACKEND_AEAD_CCM_DECRYPT_FAILED = 0x08  # AES-CCM decryption failed.


class RotBackendRsaErrors(IntEnum):
    """Error codes for ACVP RSA backend."""

    BACKEND_RSA_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    BACKEND_RSA_NO_MEMORY = 0x01  # Memory allocation failed.
    BACKEND_RSA_NO_ENGINE = 0x02  # No RSA engine is available.
    BACKEND_RSA_ENGINE_NOT_FOUND = 0x03  # No RSA engine found for the specified implementation.
    BACKEND_RSA_KEYGEN_FAILED = 0x04  # RSA key generation failed.
    BACKEND_RSA_SIGGEN_FAILED = 0x05  # RSA signature generation failed.
    BACKEND_RSA_SIGVER_FAILED = 0x06  # RSA signature verification failed.
    BACKEND_RSA_KEYGEN_PRIME_FAILED = 0x07  # RSA key generation prime number generation (B.3.3) failed.
    BACKEND_RSA_KEYGEN_PROV_PRIME_FAILED = 0x08  # RSA key generation prime number generation (B.3.2) failed.
    BACKEND_RSA_RANDOM_E_UNSUPPORTED = 0x09  # Random E generation is not supported.
    BACKEND_RSA_INVALID_KEY = 0x0A  # The generated RSA key is invalid.
    BACKEND_RSA_KEY_LEN_TOO_LARGE = 0x0B  # The given RSA key length is too large.


class RotBackendEcdsaErrors(IntEnum):
    """Error codes for ACVP ECDSA backend."""

    BACKEND_ECDSA_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    BACKEND_ECDSA_NO_MEMORY = 0x01  # Memory allocation failed.
    BACKEND_ECDSA_NO_ENGINE = 0x02  # No ECDSA engine is available.
    BACKEND_ECDSA_ENGINE_NOT_FOUND = 0x03  # No ECDSA engine found for the specified implementation.
    BACKEND_ECDSA_KEYGEN_TYPE_UNSUPPORTED = 0x04  # Key generation type is not supported.
    BACKEND_ECDSA_HASH_TYPE_UNSUPPORTED = 0x05  # Hash type is not supported.
    BACKEND_ECDSA_CURVE_TYPE_UNSUPPORTED = 0x06  # ECC curve type is not supported.
    BACKEND_ECDSA_KEYGEN_FAILED = 0x07  # Key generation failed.
    BACKEND_ECDSA_SIGGEN_FAILED = 0x08  # Signature generation failed.
    BACKEND_ECDSA_SIGVER_FAILED = 0x09  # Signature verification failed.
    BACKEND_ECDSA_PKVVER_FAILED = 0x0A  # Public key verification failed.
    BACKEND_ECDSA_INVALID_ECC_IMPLEMENTATION = 0x0B  # Invalid ECC implementation.
    BACKEND_ECDSA_API_TYPE_UNSUPPORTED = 0x0C  # ECDSA API type is not supported.


class RotBackendHkdfErrors(IntEnum):
    """Error codes for ACVP HKDF backend."""

    BACKEND_HKDF_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    BACKEND_HKDF_NO_MEMORY = 0x01  # Memory allocation failed.
    BACKEND_HKDF_NO_ENGINE = 0x02  # No HKDF engine is available.
    BACKEND_HKDF_ENGINE_NOT_FOUND = 0x03  # No HKDF engine found for the specified implementation.
    BACKEND_HKDF_HKDF_FAILED = 0x04  # HKDF operation failed.


class RotBackendSymErrors(IntEnum):
    """Error codes for ACVP symmetric cipher backend."""

    BACKEND_SYM_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    BACKEND_SYM_NO_MEMORY = 0x01  # Memory allocation failed.
    BACKEND_SYM_NO_ENGINE = 0x02  # No symmetric cipher engine is available.
    BACKEND_SYM_ENGINE_NOT_FOUND = 0x03  # No symmetric cipher engine found for the specified implementation.
    BACKEND_SYM_ENCRYPT_FAILED = 0x04  # Symmetric cipher encryption failed.
    BACKEND_SYM_DECRYPT_FAILED = 0x05  # Symmetric cipher decryption failed.
    BACKEND_SYM_MCT_INIT_FAILED = 0x06  # MCT initialization failed.
    BACKEND_SYM_MCT_UPDATE_FAILED = 0x07  # MCT update failed.
    BACKEND_SYM_MCT_FINI_FAILED = 0x08  # MCT finalization failed.
    BACKEND_SYM_UNSUPPORTED_CIPHER_TYPE = 0x09  # Unsupported symmetric cipher type.


class RotBackendHmacErrors(IntEnum):
    """Error codes for ACVP HMAC backend."""

    BACKEND_HMAC_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    BACKEND_HMAC_NO_MEMORY = 0x01  # Memory allocation failed.
    BACKEND_HMAC_NO_ENGINE = 0x02  # No HMAC engine is available.
    BACKEND_HMAC_ENGINE_NOT_FOUND = 0x03  # No HMAC engine found for the specified implementation.
    BACKEND_HMAC_GENERATE_FAILED = 0x04  # HMAC generation failed.
    BACKEND_HMAC_CMAC_VERIFY_FAILED = 0x05  # CMAC verification failed.
    BACKEND_HMAC_HASH_TYPE_UNSUPPORTED = 0x06  # Hash type is not supported.


class RotBackendEcdhErrors(IntEnum):
    """Error codes for ACVP ECDH backend."""

    BACKEND_ECDH_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    BACKEND_ECDH_NO_MEMORY = 0x01  # Memory allocation failed.
    BACKEND_ECDH_NO_ENGINE = 0x02  # No ECDH engine is available.
    BACKEND_ECDH_ENGINE_NOT_FOUND = 0x03  # No ECDH engine found for the specified implementation.
    BACKEND_ECDH_SS_FAILED = 0x04  # ECDH shared secret generation failed.
    BACKEND_ECDH_SS_VER_FAILED = 0x05  # ECDH shared secret verification failed.
    BACKEND_ECDH_CURVE_TYPE_UNSUPPORTED = 0x06  # ECC curve type is not supported.


class RotErrorStateEntryErrors(IntEnum):
    """Error codes for FIPS error state entry handler."""

    ERROR_STATE_ENTRY_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    ERROR_STATE_ENTRY_NO_MEMORY = 0x01  # Memory allocation failed.


class RotErrorStateExitErrors(IntEnum):
    """Error codes for FIPS error state exit handler."""

    ERROR_STATE_EXIT_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    ERROR_STATE_EXIT_NO_MEMORY = 0x01  # Memory allocation failed.
    ERROR_STATE_EXIT_EXIT_FAILED = 0x02  # Failed to exit the error state.


class RotAuthDataErrors(IntEnum):
    """Error codes for Authorized data handler for operation authentication."""

    AUTH_DATA_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    AUTH_DATA_NO_MEMORY = 0x01  # Memory allocation failed.
    AUTH_DATA_TOKEN_OFFSET_FAILED = 0x02  # Failed to determine the token offset in the payload.
    AUTH_DATA_GET_AAD_FAILED = 0x03  # Failed to retrieve the AAD from the payload.
    AUTH_DATA_AAD_LENGTH_FAILED = 0x04  # Failed to determine the AAD length in the payload.
    AUTH_DATA_NO_AUTH_TOKEN = 0x05  # The authorized data does not contain a token.
    AUTH_DATA_BAD = 0x06  # Authorized data cannot be parsed.


class RotAuthSignatureErrors(IntEnum):
    """Error codes for Authorized data signature for operation authentication."""

    AUTH_SIGNATURE_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    AUTH_SIGNATURE_NO_MEMORY = 0x01  # Memory allocation failed.
    AUTH_SIGNATURE_GET_SIG_FAILED = 0x02  # Failed to retrieve the authorizing signature from the payload.
    AUTH_SIGNATURE_SIG_LENGTH_FAILED = 0x03  # Failed to determine the signature length in the payload.
    AUTH_SIGNATURE_NO_SIGNATURE = 0x04  # No signature was found in the payload.


class RotEkuExtensionErrors(IntEnum):
    """Error codes for Extension handler for Extended Key Usage extensions."""

    EKU_EXTENSION_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    EKU_EXTENSION_NO_MEMORY = 0x01  # Memory allocation failed.
    EKU_EXTENSION_SMALL_EXT_BUFFER = 0x02  # The extension buffer is too small for the data.


class RotIdeDriverObserverErrors(IntEnum):
    """Error codes for IDE driver observer interface."""

    IDE_DRIVER_OBSERVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    IDE_DRIVER_OBSERVER_NO_MEMORY = 0x01  # Memory allocation failed.


class RotTdispDriverObserverErrors(IntEnum):
    """Error codes for TDISP driver observer interface."""

    TDISP_DRIVER_OBSERVER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    TDISP_DRIVER_OBSERVER_NO_MEMORY = 0x01  # Memory allocation failed.


class RotFatalErrorHandlerErrors(IntEnum):
    """Error codes for Handler for fatal firmware errors."""

    FATAL_ERROR_HANDLER_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    FATAL_ERROR_HANDLER_NO_MEMORY = 0x01  # Memory allocation failed.


class RotSpdmPersistentContextErrors(IntEnum):
    """Error codes for SPDM persistent context interface."""

    SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SPDM_PERSISTENT_CONTEXT_NO_MEMORY = 0x01  # Memory allocation failed.
    SPDM_PERSISTENT_CONTEXT_GET_RESPONDER_STATE_FAILED = 0x02  # Failed to get the responder state.
    SPDM_PERSISTENT_CONTEXT_GET_SESSION_MANAGER_STATE_FAILED = 0x03  # Failed to get the secure session manager state.


class RotSpdmCertChainErrors(IntEnum):
    """Error codes for SPDM certificate chain manager."""

    SPDM_CERT_CHAIN_INVALID_ARGUMENT = 0x00  # Input parameter is null or not valid.
    SPDM_CERT_CHAIN_NO_MEMORY = 0x01  # Memory allocation failed.
    SPDM_CERT_CHAIN_GET_DIGEST_FAILED = 0x02  # Failed to calculate the certificate chain digest.
    SPDM_CERT_CHAIN_GET_CHAIN_FAILED = 0x03  # Failed to retrieve the certificate chain.
    SPDM_CERT_CHAIN_SIGN_MSG_FAILED = 0x04  # Failed to sign using the certificate chain.
    SPDM_CERT_CHAIN_MISSING_CERT = 0x05  # A required cert is not available.


@dataclass
class RotErrorInfo:
    """Decoded ROT error information."""

    module_id: int
    module_name: str
    module_desc: str
    error_code: int
    error_name: str | None = None
    error_desc: str | None = None


@dataclass
class RotModuleErrors:
    """Error definitions for a single ROT module."""

    module_id: RotModuleId
    errors: type[IntEnum] | None = None


class RotErrorTable:
    """Registry of ROT module error definitions.

    Multiple tables can be combined to support both public (Project-Cerberus)
    and private module error definitions.
    """

    def __init__(self) -> None:
        self._modules: dict[int, RotModuleErrors] = {}

    def register(self, module: RotModuleErrors) -> None:
        """Register error definitions for a module."""
        self._modules[module.module_id] = module

    def register_table(self, table: RotErrorTable) -> None:
        """Merge another error table into this one."""
        self._modules.update(table._modules)

    def decode(self, error_value: int) -> RotErrorInfo | None:
        """Decode a ROT error value into structured information.

        Returns None if the value is not a ROT error."""
        if not rot_is_error(error_value):
            return None

        mod_id = rot_error_module(error_value)
        err_code = rot_error_code(error_value)

        try:
            mod_enum = RotModuleId(mod_id)
            mod_name = mod_enum.name
            mod_desc = mod_enum.name
        except ValueError:
            mod_name = f"UNKNOWN_0x{mod_id:04X}"
            mod_desc = f"Unknown module 0x{mod_id:04X}"

        info = RotErrorInfo(
            module_id=mod_id,
            module_name=mod_name,
            module_desc=mod_desc,
            error_code=err_code,
        )

        mod_entry = self._modules.get(mod_id)
        if mod_entry is not None and mod_entry.errors is not None:
            try:
                err_enum = mod_entry.errors(err_code)
                info.error_name = err_enum.name
                # Extract description from docstring-style comment if available
            except ValueError:
                info.error_name = f"UNKNOWN_0x{err_code:02X}"

        return info


def _build_public_table() -> RotErrorTable:
    """Build the error table for public Project-Cerberus modules."""
    table = RotErrorTable()
    table.register(RotModuleErrors(RotModuleId.INIT))
    table.register(RotModuleErrors(RotModuleId.AES_GCM_ENGINE, RotAesGcmEngineErrors))
    table.register(RotModuleErrors(RotModuleId.ECC_ENGINE, RotEccEngineErrors))
    table.register(RotModuleErrors(RotModuleId.HASH_ENGINE, RotHashEngineErrors))
    table.register(RotModuleErrors(RotModuleId.RSA_ENGINE, RotRsaEngineErrors))
    table.register(RotModuleErrors(RotModuleId.X509_ENGINE, RotX509EngineErrors))
    table.register(RotModuleErrors(RotModuleId.BASE64_ENGINE, RotBase64EngineErrors))
    table.register(RotModuleErrors(RotModuleId.FLASH_MASTER, RotFlashMasterErrors))
    table.register(RotModuleErrors(RotModuleId.SPI_FLASH, RotSpiFlashErrors))
    table.register(RotModuleErrors(RotModuleId.FLASH_COMMON, RotFlashCommonErrors))
    table.register(RotModuleErrors(RotModuleId.FLASH_UTIL, RotFlashUtilErrors))
    table.register(RotModuleErrors(RotModuleId.APP_IMAGE, RotAppImageErrors))
    table.register(RotModuleErrors(RotModuleId.FIRMWARE_IMAGE, RotFirmwareImageErrors))
    table.register(RotModuleErrors(RotModuleId.KEY_MANIFEST, RotKeyManifestErrors))
    table.register(RotModuleErrors(RotModuleId.FIRMWARE_UPDATE, RotFirmwareUpdateErrors))
    table.register(RotModuleErrors(RotModuleId.I2C_MASTER, RotI2cMasterErrors))
    table.register(RotModuleErrors(RotModuleId.I2C_SLAVE, RotI2cSlaveErrors))
    table.register(RotModuleErrors(RotModuleId.SPI_FILTER, RotSpiFilterErrors))
    table.register(RotModuleErrors(RotModuleId.MFG_FILTER_HANDLER, RotMfgFilterHandlerErrors))
    table.register(RotModuleErrors(RotModuleId.SPI_FILTER_IRQ, RotSpiFilterIrqErrors))
    table.register(RotModuleErrors(RotModuleId.LOGGING, RotLoggingErrors))
    table.register(RotModuleErrors(RotModuleId.CMD_HANDLER, RotCmdHandlerErrors))
    table.register(RotModuleErrors(RotModuleId.MCTP_BASE_PROTOCOL, RotMctpBaseProtocolErrors))
    table.register(RotModuleErrors(RotModuleId.RIOT_CORE, RotRiotCoreErrors))
    table.register(RotModuleErrors(RotModuleId.HOST_FW_UTIL, RotHostFwUtilErrors))
    table.register(RotModuleErrors(RotModuleId.BMC_RECOVERY, RotBmcRecoveryErrors))
    table.register(RotModuleErrors(RotModuleId.HOST_CONTROL, RotHostControlErrors))
    table.register(RotModuleErrors(RotModuleId.HOST_IRQ_CTRL, RotHostIrqCtrlErrors))
    table.register(RotModuleErrors(RotModuleId.HOST_IRQ_HANDLER, RotHostIrqHandlerErrors))
    table.register(RotModuleErrors(RotModuleId.HOST_PROCESSOR, RotHostProcessorErrors))
    table.register(RotModuleErrors(RotModuleId.HOST_FLASH_MGR, RotHostFlashMgrErrors))
    table.register(RotModuleErrors(RotModuleId.MOCK))
    table.register(RotModuleErrors(RotModuleId.PLATFORM_TIMEOUT))
    table.register(RotModuleErrors(RotModuleId.PLATFORM_MUTEX))
    table.register(RotModuleErrors(RotModuleId.PLATFORM_TIMER))
    table.register(RotModuleErrors(RotModuleId.STATE_MANAGER, RotStateManagerErrors))
    table.register(RotModuleErrors(RotModuleId.MANIFEST, RotManifestErrors))
    table.register(RotModuleErrors(RotModuleId.PFM, RotPfmErrors))
    table.register(RotModuleErrors(RotModuleId.CFM, RotCfmErrors))
    table.register(RotModuleErrors(RotModuleId.MANIFEST_MANAGER, RotManifestManagerErrors))
    table.register(RotModuleErrors(RotModuleId.KEYSTORE, RotKeystoreErrors))
    table.register(RotModuleErrors(RotModuleId.RIOT_KEY_MANAGER, RotRiotKeyManagerErrors))
    table.register(RotModuleErrors(RotModuleId.AUX_ATTESTATION, RotAuxAttestationErrors))
    table.register(RotModuleErrors(RotModuleId.FIRMWARE_HEADER, RotFirmwareHeaderErrors))
    table.register(RotModuleErrors(RotModuleId.ATTESTATION))
    table.register(RotModuleErrors(RotModuleId.RNG_ENGINE, RotRngEngineErrors))
    table.register(RotModuleErrors(RotModuleId.DEVICE_MANAGER, RotDeviceManagerErrors))
    table.register(RotModuleErrors(RotModuleId.PCR, RotPcrErrors))
    table.register(RotModuleErrors(RotModuleId.CMD_BACKGROUND, RotCmdBackgroundErrors))
    table.register(RotModuleErrors(RotModuleId.OBSERVABLE, RotObservableErrors))
    table.register(RotModuleErrors(RotModuleId.PFM_OBSERVER, RotPfmObserverErrors))
    table.register(RotModuleErrors(RotModuleId.CFM_OBSERVER, RotCfmObserverErrors))
    table.register(RotModuleErrors(RotModuleId.SIG_VERIFICATION, RotSigVerificationErrors))
    table.register(RotModuleErrors(RotModuleId.MANIFEST_VERIFICATION, RotManifestVerificationErrors))
    table.register(RotModuleErrors(RotModuleId.SPI_FLASH_SFDP, RotSpiFlashSfdpErrors))
    table.register(RotModuleErrors(RotModuleId.HOST_FLASH_INIT, RotHostFlashInitErrors))
    table.register(RotModuleErrors(RotModuleId.FLASH, RotFlashErrors))
    table.register(RotModuleErrors(RotModuleId.RECOVERY_IMAGE_HEADER, RotRecoveryImageHeaderErrors))
    table.register(RotModuleErrors(RotModuleId.IMAGE_HEADER, RotImageHeaderErrors))
    table.register(RotModuleErrors(RotModuleId.RECOVERY_IMAGE_SECTION_HEADER))
    table.register(RotModuleErrors(RotModuleId.CMD_CHANNEL, RotCmdChannelErrors))
    table.register(RotModuleErrors(RotModuleId.FIRMWARE_COMPONENT, RotFirmwareComponentErrors))
    table.register(RotModuleErrors(RotModuleId.SPI_SLAVE, RotSpiSlaveErrors))
    table.register(RotModuleErrors(RotModuleId.RESERVED_3F))
    table.register(RotModuleErrors(RotModuleId.FLASH_UPDATER, RotFlashUpdaterErrors))
    table.register(RotModuleErrors(RotModuleId.CERT_DEVICE_HW, RotCertDeviceHwErrors))
    table.register(RotModuleErrors(RotModuleId.APP_CONTEXT, RotAppContextErrors))
    table.register(RotModuleErrors(RotModuleId.RESERVED_43))
    table.register(RotModuleErrors(RotModuleId.TPM, RotTpmErrors))
    table.register(RotModuleErrors(RotModuleId.RESERVED_45))
    table.register(RotModuleErrors(RotModuleId.AUTHORIZATION, RotAuthorizationErrors))
    table.register(RotModuleErrors(RotModuleId.CONFIG_RESET, RotConfigResetErrors))
    table.register(RotModuleErrors(RotModuleId.CMD_AUTHORIZATION, RotCmdAuthorizationErrors))
    table.register(RotModuleErrors(RotModuleId.RECOVERY_IMAGE, RotRecoveryImageErrors))
    table.register(RotModuleErrors(RotModuleId.RECOVERY_IMAGE_OBSERVER, RotRecoveryImageObserverErrors))
    table.register(RotModuleErrors(RotModuleId.RECOVERY_IMAGE_MANAGER, RotRecoveryImageManagerErrors))
    table.register(RotModuleErrors(RotModuleId.PCD, RotPcdErrors))
    table.register(RotModuleErrors(RotModuleId.PCD_OBSERVER, RotPcdObserverErrors))
    table.register(RotModuleErrors(RotModuleId.CONFIG_CMD_TASK))
    table.register(RotModuleErrors(RotModuleId.CMD_DEVICE, RotCmdDeviceErrors))
    table.register(RotModuleErrors(RotModuleId.HOST_PROCESSOR_OBSERVER, RotHostProcessorObserverErrors))
    table.register(RotModuleErrors(RotModuleId.COUNTER_MANAGER, RotCounterManagerErrors))
    table.register(RotModuleErrors(RotModuleId.SESSION_MANAGER, RotSessionManagerErrors))
    table.register(RotModuleErrors(RotModuleId.FLASH_STORE, RotFlashStoreErrors))
    table.register(RotModuleErrors(RotModuleId.KDF, RotKdfErrors))
    table.register(RotModuleErrors(RotModuleId.HOST_STATE_OBSERVER, RotHostStateObserverErrors))
    table.register(RotModuleErrors(RotModuleId.SYSTEM, RotSystemErrors))
    table.register(RotModuleErrors(RotModuleId.SYSTEM_OBSERVER, RotSystemObserverErrors))
    table.register(RotModuleErrors(RotModuleId.PLATFORM_SEMAPHORE))
    table.register(RotModuleErrors(RotModuleId.INTRUSION_STATE, RotIntrusionStateErrors))
    table.register(RotModuleErrors(RotModuleId.INTRUSION_STATE_OBSERVER))
    table.register(RotModuleErrors(RotModuleId.INTRUSION_MANAGER, RotIntrusionManagerErrors))
    table.register(RotModuleErrors(RotModuleId.CMD_HANDLER_MCTP_CTRL))
    table.register(RotModuleErrors(RotModuleId.CERBERUS_PROTOCOL_OBSERVER))
    table.register(RotModuleErrors(RotModuleId.ECC_DER_UTIL, RotEccDerUtilErrors))
    table.register(RotModuleErrors(RotModuleId.BUFFER_UTIL, RotBufferUtilErrors))
    table.register(RotModuleErrors(RotModuleId.OCP_RECOVERY_DEVICE, RotOcpRecoveryDeviceErrors))
    table.register(RotModuleErrors(RotModuleId.OCP_RECOVERY_SMBUS, RotOcpRecoverySmbusErrors))
    table.register(RotModuleErrors(RotModuleId.MCTP_CONTROL_PROTOCOL_OBSERVER))
    table.register(RotModuleErrors(RotModuleId.CMD_HANDLER_SPDM, RotCmdHandlerSpdmErrors))
    table.register(RotModuleErrors(RotModuleId.SPDM_PROTOCOL_OBSERVER))
    table.register(RotModuleErrors(RotModuleId.ASN1_UTIL, RotAsn1UtilErrors))
    table.register(RotModuleErrors(RotModuleId.EVENT_TASK, RotEventTaskErrors))
    table.register(RotModuleErrors(RotModuleId.PERIODIC_TASK, RotPeriodicTaskErrors))
    table.register(RotModuleErrors(RotModuleId.FIRMWARE_LOADER, RotFirmwareLoaderErrors))
    table.register(RotModuleErrors(RotModuleId.DEVICE_MANAGER_OBSERVER, RotDeviceManagerObserverErrors))
    table.register(RotModuleErrors(RotModuleId.ECC_HW, RotEccHwErrors))
    table.register(RotModuleErrors(RotModuleId.COMMON_MATH, RotCommonMathErrors))
    table.register(RotModuleErrors(RotModuleId.HEAP_WITH_DEFRAG))
    table.register(RotModuleErrors(RotModuleId.PLATFORM_OS))
    table.register(RotModuleErrors(RotModuleId.X509_EXTENSION, RotX509ExtensionErrors))
    table.register(RotModuleErrors(RotModuleId.DICE_TCBINFO_EXTENSION, RotDiceTcbinfoExtensionErrors))
    table.register(RotModuleErrors(RotModuleId.DICE_UEID_EXTENSION, RotDiceUeidExtensionErrors))
    table.register(RotModuleErrors(RotModuleId.DME_EXTENSION, RotDmeExtensionErrors))
    table.register(RotModuleErrors(RotModuleId.DME_STRUCTURE, RotDmeStructureErrors))
    table.register(RotModuleErrors(RotModuleId.HOST_FIRMWARE_IMAGE))
    table.register(RotModuleErrors(RotModuleId.SECURE_DEVICE_UNLOCK, RotSecureDeviceUnlockErrors))
    table.register(RotModuleErrors(RotModuleId.SECURITY_MANAGER, RotSecurityManagerErrors))
    table.register(RotModuleErrors(RotModuleId.SECURITY_POLICY, RotSecurityPolicyErrors))
    table.register(RotModuleErrors(RotModuleId.AUTH_TOKEN, RotAuthTokenErrors))
    table.register(RotModuleErrors(RotModuleId.DEVICE_UNLOCK_TOKEN, RotDeviceUnlockTokenErrors))
    table.register(RotModuleErrors(RotModuleId.DOE_CMD_CHANNEL, RotDoeCmdChannelErrors))
    table.register(RotModuleErrors(RotModuleId.DOE_INTERFACE, RotDoeInterfaceErrors))
    table.register(RotModuleErrors(RotModuleId.REAL_TIME_CLOCK, RotRealTimeClockErrors))
    table.register(RotModuleErrors(RotModuleId.RMA_UNLOCK_TOKEN, RotRmaUnlockTokenErrors))
    table.register(RotModuleErrors(RotModuleId.DEVICE_RMA_TRANSITION))
    table.register(RotModuleErrors(RotModuleId.SPDM_TRANSCRIPT_MANAGER, RotSpdmTranscriptManagerErrors))
    table.register(RotModuleErrors(RotModuleId.CMD_HANDLER_SPDM_RESPONDER))
    table.register(RotModuleErrors(RotModuleId.SPDM_MEASUREMENTS, RotSpdmMeasurementsErrors))
    table.register(RotModuleErrors(RotModuleId.CMD_INTERFACE_IDE_RESPONDER))
    table.register(RotModuleErrors(RotModuleId.IDE_DRIVER, RotIdeDriverErrors))
    table.register(RotModuleErrors(RotModuleId.MSG_TRANSPORT, RotMsgTransportErrors))
    table.register(RotModuleErrors(RotModuleId.CMD_INTERFACE_TDISP_RESPONDER))
    table.register(RotModuleErrors(RotModuleId.TDISP_DRIVER, RotTdispDriverErrors))
    table.register(RotModuleErrors(RotModuleId.MCTP_NOTIFIER, RotMctpNotifierErrors))
    table.register(RotModuleErrors(RotModuleId.SPDM_SECURE_SESSION_MANAGER))
    table.register(RotModuleErrors(RotModuleId.ECDSA, RotEcdsaErrors))
    table.register(RotModuleErrors(RotModuleId.KEY_CACHE, RotKeyCacheErrors))
    table.register(RotModuleErrors(RotModuleId.EPHEMERAL_KEY_MANAGER, RotEphemeralKeyManagerErrors))
    table.register(RotModuleErrors(RotModuleId.EPHEMERAL_KEY_GENERATION, RotEphemeralKeyGenerationErrors))
    table.register(RotModuleErrors(RotModuleId.AUTHORIZED_EXECUTION, RotAuthorizedExecutionErrors))
    table.register(RotModuleErrors(RotModuleId.SPDM_VDM_PROTOCOL, RotSpdmVdmProtocolErrors))
    table.register(RotModuleErrors(RotModuleId.SPDM_PCISIG_PROTOCOL, RotSpdmPcisigProtocolErrors))
    table.register(RotModuleErrors(RotModuleId.IMPACTFUL_CHECK, RotImpactfulCheckErrors))
    table.register(RotModuleErrors(RotModuleId.IMPACTFUL_UPDATE, RotImpactfulUpdateErrors))
    table.register(RotModuleErrors(RotModuleId.AES_XTS_ENGINE, RotAesXtsEngineErrors))
    table.register(RotModuleErrors(RotModuleId.MMIO_REGISTER, RotMmioRegisterErrors))
    table.register(RotModuleErrors(RotModuleId.MPU, RotMpuErrors))
    table.register(RotModuleErrors(RotModuleId.TDISP_TDI_CONTEXT_MANAGER))
    table.register(RotModuleErrors(RotModuleId.RSASSA, RotRsassaErrors))
    table.register(RotModuleErrors(RotModuleId.ACVP_PROTO, RotAcvpProtoErrors))
    table.register(RotModuleErrors(RotModuleId.FIRMWARE_PFM_VERIFY, RotFirmwarePfmVerifyErrors))
    table.register(RotModuleErrors(RotModuleId.BACKEND_SHA, RotBackendShaErrors))
    table.register(RotModuleErrors(RotModuleId.ACVP_PROTO_TESTER, RotAcvpProtoTesterErrors))
    table.register(RotModuleErrors(RotModuleId.ECDH, RotEcdhErrors))
    table.register(RotModuleErrors(RotModuleId.AES_ECB_ENGINE, RotAesEcbEngineErrors))
    table.register(RotModuleErrors(RotModuleId.AES_CBC_ENGINE, RotAesCbcEngineErrors))
    table.register(RotModuleErrors(RotModuleId.AES_KEY_WRAP, RotAesKeyWrapErrors))
    table.register(RotModuleErrors(RotModuleId.HKDF, RotHkdfErrors))
    table.register(RotModuleErrors(RotModuleId.BACKEND_AEAD, RotBackendAeadErrors))
    table.register(RotModuleErrors(RotModuleId.BACKEND_RSA, RotBackendRsaErrors))
    table.register(RotModuleErrors(RotModuleId.BACKEND_ECDSA, RotBackendEcdsaErrors))
    table.register(RotModuleErrors(RotModuleId.BACKEND_HKDF, RotBackendHkdfErrors))
    table.register(RotModuleErrors(RotModuleId.BACKEND_SYM, RotBackendSymErrors))
    table.register(RotModuleErrors(RotModuleId.BACKEND_HMAC, RotBackendHmacErrors))
    table.register(RotModuleErrors(RotModuleId.BACKEND_ECDH, RotBackendEcdhErrors))
    table.register(RotModuleErrors(RotModuleId.ERROR_STATE_ENTRY, RotErrorStateEntryErrors))
    table.register(RotModuleErrors(RotModuleId.ERROR_STATE_EXIT, RotErrorStateExitErrors))
    table.register(RotModuleErrors(RotModuleId.AUTH_DATA, RotAuthDataErrors))
    table.register(RotModuleErrors(RotModuleId.AUTH_SIGNATURE, RotAuthSignatureErrors))
    table.register(RotModuleErrors(RotModuleId.EKU_EXTENSION, RotEkuExtensionErrors))
    table.register(RotModuleErrors(RotModuleId.SPDM_PROTOCOL_SESSION_OBSERVER))
    table.register(RotModuleErrors(RotModuleId.IDE_DRIVER_OBSERVER, RotIdeDriverObserverErrors))
    table.register(RotModuleErrors(RotModuleId.TDISP_DRIVER_OBSERVER, RotTdispDriverObserverErrors))
    table.register(RotModuleErrors(RotModuleId.FATAL_ERROR_HANDLER, RotFatalErrorHandlerErrors))
    table.register(RotModuleErrors(RotModuleId.SPDM_PERSISTENT_CONTEXT, RotSpdmPersistentContextErrors))
    table.register(RotModuleErrors(RotModuleId.SPDM_CERT_CHAIN, RotSpdmCertChainErrors))
    return table


ROT_ERROR_TABLE_PUBLIC = _build_public_table()
