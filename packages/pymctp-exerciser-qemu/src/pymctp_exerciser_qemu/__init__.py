# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""QEMU I2C and I3C exercisers for pymctp.

This module provides support for using QEMU's I2C and I3C virtual devices
as MCTP exercisers.
"""

from .qemu_i2c_netdev import QemuI2CNetDevSocket
from .qemu_i2c_stream import QemuI2CStreamSocket
from .qemu_i3c_chardev import QemuI3CCharDevSocket
from .qemu_i3c_netdev import QemuI3CNetDevSocket
from .qemu_i3c_netdev2 import QemuI3CNetDev2Socket
from .qemu_i3c_stream import QemuI3CStreamSocket

# Auto-register with pymctp when imported
try:
    from pymctp.exerciser import register_exerciser

    register_exerciser("qemu-i2c", QemuI2CNetDevSocket)
    register_exerciser("qemu-i3c", QemuI3CCharDevSocket)
    register_exerciser("qemu-i3c-netdev", QemuI3CNetDevSocket)
    register_exerciser("qemu-i3c-netdev2", QemuI3CNetDev2Socket)
    register_exerciser("qemu-i3c-stream", QemuI3CStreamSocket)
    register_exerciser("qemu-i2c-stream", QemuI2CStreamSocket)
except ImportError:
    # pymctp not installed or exerciser module not available
    pass

# Import the endpoint configs so they self-register with core pymctp. Guarded
# for older pymctp releases without the pluggable SupersocketConfig base.
try:
    from . import configs  # noqa: F401
except ImportError:
    pass

__version__ = "0.2.7"
__all__ = [
    "QemuI2CNetDevSocket",
    "QemuI2CStreamSocket",
    "QemuI3CCharDevSocket",
    "QemuI3CNetDevSocket",
    "QemuI3CNetDev2Socket",
    "QemuI3CStreamSocket",
]
