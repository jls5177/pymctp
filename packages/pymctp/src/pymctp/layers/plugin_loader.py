# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Plugin loader for pymctp extensions.

This module provides automatic discovery and loading of pymctp extensions
through Python entry points. Extensions can register themselves via the
'pymctp.extensions' entry point group in their package metadata.

Extensions are automatically registered into the pymctp namespace based on
their package name:
- pymctp-oem-<vendor> -> pymctp.oem.<vendor>
- pymctp-<category>-<name> -> pymctp.<category>.<name>
"""

import logging
import sys
from importlib.metadata import entry_points
from typing import List

logger = logging.getLogger(__name__)


def _register_extension_in_namespace(ep_name: str, module) -> None:
    """Register an extension module in the pymctp namespace.

    Maps extension entry point names to pymctp namespace locations:
    - 'microsoft' (from pymctp-oem-microsoft) -> pymctp.oem.microsoft
    - 'sample-vendor' -> pymctp.oem.sample_vendor
    - Any name with '-' gets converted to '_' for Python import compatibility

    Args:
        ep_name: The entry point name (e.g., 'microsoft', 'sample-vendor')
        module: The loaded module to register
    """
    import pymctp

    # Normalize the entry point name for Python module naming (replace - with _)
    normalized_name = ep_name.replace("-", "_")

    # Determine the namespace path based on naming convention
    # Default to oem namespace for extensions
    namespace_parts = ["oem", normalized_name]

    # Build the namespace path
    current_ns = pymctp
    for i, part in enumerate(namespace_parts):
        if not hasattr(current_ns, part):
            # Create intermediate namespace if needed
            if i < len(namespace_parts) - 1:
                # This is an intermediate namespace (e.g., 'oem')
                import types

                intermediate_ns = types.ModuleType(f"pymctp.{'.'.join(namespace_parts[: i + 1])}")
                setattr(current_ns, part, intermediate_ns)
                sys.modules[f"pymctp.{'.'.join(namespace_parts[: i + 1])}"] = intermediate_ns
                current_ns = intermediate_ns
            else:
                # This is the final module
                setattr(current_ns, part, module)
                sys.modules[f"pymctp.{'.'.join(namespace_parts)}"] = module
        else:
            current_ns = getattr(current_ns, part)

    logger.debug(f"Registered extension '{ep_name}' at pymctp.{'.'.join(namespace_parts)}")


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
            module = ep.load()
            # Register the module in the pymctp namespace
            _register_extension_in_namespace(ep.name, module)
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
            module = ep.load()
            # Register the module in the pymctp namespace
            _register_extension_in_namespace(ep.name, module)
            loaded_extensions.append(ep.name)
        except Exception:
            # Silently ignore failures
            pass

    return loaded_extensions
