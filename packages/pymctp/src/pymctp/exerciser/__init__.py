# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Pymctp exerciser package.

Exercisers are hardware/virtual device interfaces for sending and receiving
MCTP packets. Different exercisers can be installed as separate packages.

Core exercisers are deprecated and will be moved to separate packages in a future release.
For now, they are still available for backward compatibility.
"""

# Import plugin system
from .plugin_loader import (
    discover_and_load_exercisers,
    get_exerciser,
    list_exercisers,
    load_exercisers_silent,
    register_exerciser,
)

# Auto-discover and load exerciser plugins
__all_exerciser_packages__ = load_exercisers_silent()


# Backward compatibility: provide convenience imports that reference the registry
def __getattr__(name):
    """Provide backward compatibility for direct imports.

    This allows imports like `from pymctp.exerciser import AardvarkI2CSocket`
    to work by looking up the exerciser in the registry.
    """
    exerciser_map = {
        "AardvarkI2CSocket": "aardvark",
        "QemuI2CNetDevSocket": "qemu-i2c",
        "QemuI3CCharDevSocket": "qemu-i3c",
        "TTYSerialSocket": "serial",
    }

    if name in exerciser_map:
        exerciser = get_exerciser(exerciser_map[name])
        if exerciser is None:
            raise ImportError(
                f"{name} is not available. "
                f"Install it with: pip install pymctp-exerciser-{exerciser_map[name].replace('-', '_')}"
            )
        return exerciser

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = [
    "register_exerciser",
    "get_exerciser",
    "list_exercisers",
    "discover_and_load_exercisers",
    "load_exercisers_silent",
    "__all_exerciser_packages__",
]
