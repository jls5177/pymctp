# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""TTY/Serial port exerciser for pymctp.

This module provides support for using serial/UART devices as MCTP exercisers.
"""

from .tty_serial import TTYSerialSocket

# Auto-register with pymctp when imported
try:
    from pymctp.exerciser import register_exerciser

    register_exerciser("serial", TTYSerialSocket)
except ImportError:
    # pymctp not installed or exerciser module not available
    pass

__version__ = "0.2.4"
__all__ = ["TTYSerialSocket"]
