# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Plugin loader for pymctp exercisers.

This module provides automatic discovery and loading of pymctp exerciser
implementations through Python entry points. Exercisers can register themselves
via the 'pymctp.exercisers' entry point group in their package metadata.
"""

import logging
from importlib.metadata import entry_points
from typing import Dict, List, Type

logger = logging.getLogger(__name__)

# Registry of discovered exercisers
_exerciser_registry: dict[str, type] = {}


def register_exerciser(name: str, exerciser_class: type) -> None:
    """Register an exerciser class.

    Args:
        name: Unique name for the exerciser (e.g., 'aardvark', 'qemu-i2c')
        exerciser_class: The exerciser class (should be a SuperSocket subclass)
    """
    if name in _exerciser_registry:
        logger.warning(f"Exerciser '{name}' is already registered, overwriting")
    _exerciser_registry[name] = exerciser_class
    logger.debug(f"Registered exerciser: {name} -> {exerciser_class.__name__}")


def get_exerciser(name: str) -> type | None:
    """Get an exerciser class by name.

    Args:
        name: The exerciser name

    Returns:
        The exerciser class, or None if not found
    """
    return _exerciser_registry.get(name)


def list_exercisers() -> list[str]:
    """List all registered exerciser names.

    Returns:
        List of exerciser names
    """
    return list(_exerciser_registry.keys())


def discover_and_load_exercisers() -> list[str]:
    """Discover and load all registered pymctp exercisers.

    Exercisers are discovered via the 'pymctp.exercisers' entry point group.
    Each entry point should reference a module that registers exerciser classes
    using the register_exerciser() function.

    Returns:
        List of successfully loaded exerciser package names.

    Example:
        In an exerciser's pyproject.toml:

        [project.entry-points."pymctp.exercisers"]
        aardvark = "pymctp_exerciser_aardvark"
    """
    loaded_packages = []

    try:
        # Python 3.10+ syntax
        eps = entry_points(group="pymctp.exercisers")
    except TypeError:
        # Python 3.8-3.9 syntax
        eps = entry_points().get("pymctp.exercisers", [])

    for ep in eps:
        try:
            logger.info(f"Loading pymctp exerciser: {ep.name}")
            # Load the entry point - this imports the module
            ep.load()
            loaded_packages.append(ep.name)
            logger.info(f"Successfully loaded exerciser package: {ep.name}")
        except Exception as e:
            logger.error(f"Failed to load exerciser '{ep.name}': {e}", exc_info=True)

    if loaded_packages:
        logger.info(f"Loaded {len(loaded_packages)} exerciser package(s): {', '.join(loaded_packages)}")
    else:
        logger.debug("No pymctp exerciser packages found")

    return loaded_packages


def load_exercisers_silent() -> list[str]:
    """Load exercisers without logging errors to console.

    This is useful for optional exercisers that may not be installed.

    Returns:
        List of successfully loaded exerciser package names.
    """
    loaded_packages = []

    try:
        # Python 3.10+ syntax
        eps = entry_points(group="pymctp.exercisers")
    except TypeError:
        # Python 3.8-3.9 syntax
        eps = entry_points().get("pymctp.exercisers", [])

    for ep in eps:
        try:
            ep.load()
            loaded_packages.append(ep.name)
        except Exception:
            # Silently ignore failures
            pass

    return loaded_packages
