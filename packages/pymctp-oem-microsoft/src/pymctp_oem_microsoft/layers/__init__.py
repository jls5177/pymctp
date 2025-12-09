# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Microsoft OEM layer definitions.

This module is automatically loaded by pymctp's plugin system.
Importing this module registers all Microsoft-specific layer bindings.
"""

# Import all layer modules to trigger their auto-binding decorators
from .ipmi import *
from .mctp import *

__all__ = []
