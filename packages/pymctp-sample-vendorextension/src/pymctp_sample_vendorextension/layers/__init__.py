# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Sample vendor layer definitions.

This module is automatically loaded by pymctp's plugin system.
Importing this module registers all sample vendor-specific layer bindings.

This serves as a template for creating your own vendor extensions.

After installation, this extension is accessible via:
    from pymctp.oem.sample_vendor import SampleVendorPacket
"""

# Import all layer modules to trigger their auto-binding decorators
from .mctp import *

__all__ = [
    "SAMPLE_VENDOR_ID",
    "SampleVendorPacket",
    "SampleVendorGetVersionRequest",
    "SampleVendorGetVersionResponse",
]
