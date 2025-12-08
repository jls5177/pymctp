# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Sample vendor layer definitions.

This module is automatically loaded by pymctp's plugin system.
Importing this module registers all sample vendor-specific layer bindings.

This serves as a template for creating your own vendor extensions.
"""

# Import all layer modules to trigger their auto-binding decorators
from .mctp import *

__all__ = []
