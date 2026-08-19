# SPDX-FileCopyrightText: 2026 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Microsoft OEM QEMU exercisers for pymctp.

Provides the NPCM8xx TIP shared-memory mailbox transport (Nuvoton/Microsoft
specific), registered with pymctp's exerciser registry so the core
``EndpointManager`` can resolve it by name (``qemu-tip-mbox-stream``) exactly
like the generic QEMU I2C/I3C stream transports.
"""

from .qemu_tip_mbox_stream import QemuTipMboxStreamSocket

# Auto-register with pymctp when imported (via the ``pymctp.exercisers`` entry
# point declared in this package's pyproject).
try:
    from pymctp.exerciser import register_exerciser

    register_exerciser("qemu-tip-mbox-stream", QemuTipMboxStreamSocket)
except ImportError:
    # pymctp not installed or exerciser registry not available.
    pass

__all__ = ["QemuTipMboxStreamSocket"]
