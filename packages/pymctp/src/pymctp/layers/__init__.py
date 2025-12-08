# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from .ipmi import *
from .mctp import *

# Auto-discover and load pymctp extensions
# This must come after core layer imports to ensure base classes are available
from .plugin_loader import load_extensions_silent

__all_extensions__ = load_extensions_silent()
