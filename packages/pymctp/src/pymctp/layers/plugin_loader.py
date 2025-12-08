# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Plugin loader for pymctp extensions.

This module provides automatic discovery and loading of pymctp extensions
through Python entry points. Extensions can register themselves via the
'pymctp.extensions' entry point group in their package metadata.
"""

import logging
from importlib.metadata import entry_points
from typing import List

logger = logging.getLogger(__name__)


def discover_and_load_extensions() -> list[str]:
    """Discover and load all registered pymctp extensions.

    Extensions are discovered via the 'pymctp.extensions' entry point group.
    Each entry point should reference a module that will be imported to
    register its layer bindings.

    Returns:
        List of successfully loaded extension names.

    Example:
        In an extension's pyproject.toml:

        [project.entry-points."pymctp.extensions"]
        microsoft = "pymctp_oem_microsoft.layers"
    """
    loaded_extensions = []

    try:
        # Python 3.10+ syntax
        eps = entry_points(group="pymctp.extensions")
    except TypeError:
        # Python 3.8-3.9 syntax
        eps = entry_points().get("pymctp.extensions", [])

    for ep in eps:
        try:
            logger.info(f"Loading pymctp extension: {ep.name}")
            # Load the entry point - this imports the module
            ep.load()
            loaded_extensions.append(ep.name)
            logger.info(f"Successfully loaded extension: {ep.name}")
        except Exception as e:
            logger.error(f"Failed to load extension '{ep.name}': {e}", exc_info=True)

    if loaded_extensions:
        logger.info(f"Loaded {len(loaded_extensions)} pymctp extension(s): {', '.join(loaded_extensions)}")
    else:
        logger.debug("No pymctp extensions found")

    return loaded_extensions


def load_extensions_silent() -> list[str]:
    """Load extensions without logging errors to console.

    This is useful for optional extensions that may not be installed.

    Returns:
        List of successfully loaded extension names.
    """
    loaded_extensions = []

    try:
        # Python 3.10+ syntax
        eps = entry_points(group="pymctp.extensions")
    except TypeError:
        # Python 3.8-3.9 syntax
        eps = entry_points().get("pymctp.extensions", [])

    for ep in eps:
        try:
            ep.load()
            loaded_extensions.append(ep.name)
        except Exception:
            # Silently ignore failures
            pass

    return loaded_extensions
