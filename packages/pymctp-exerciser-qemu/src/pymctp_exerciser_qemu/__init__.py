# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""QEMU I2C and I3C exercisers for pymctp.

This module provides support for using QEMU's I2C and I3C virtual devices
as MCTP exercisers.
"""

from .qemu_i2c_netdev import QemuI2CNetDevSocket
from .qemu_i3c_chardev import QemuI3CCharDevSocket

# Auto-register with pymctp when imported
try:
    from pymctp.exerciser import register_exerciser

    register_exerciser("qemu-i2c", QemuI2CNetDevSocket)
    register_exerciser("qemu-i3c", QemuI3CCharDevSocket)
except ImportError:
    # pymctp not installed or exerciser module not available
    pass

__version__ = "0.2.4"
__all__ = ["QemuI2CNetDevSocket", "QemuI3CCharDevSocket"]
