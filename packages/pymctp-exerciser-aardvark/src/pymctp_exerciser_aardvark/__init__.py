# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Total Phase Aardvark I2C exerciser for pymctp.

This module provides support for using Total Phase Aardvark I2C/SPI adapters
as MCTP exercisers.
"""

from .aardvark_i2c import AardvarkI2CSocket

# Auto-register with pymctp when imported
try:
    from pymctp.exerciser import register_exerciser

    register_exerciser("aardvark", AardvarkI2CSocket)
except ImportError:
    # pymctp not installed or exerciser module not available
    pass

__version__ = "0.2.4"
__all__ = ["AardvarkI2CSocket"]
