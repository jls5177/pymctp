# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Plugin discovery for third-party behaviors.

Extension packages can register custom behaviors via the
``pymctp.behaviors`` entry point group in their ``pyproject.toml``::

    [project.entry-points."pymctp.behaviors"]
    my_behaviors = "my_package.behaviors:get_behaviors"

The entry point must reference a callable that returns a
``list[Behavior]`` (instances) or a single ``Behavior`` instance.
"""

from __future__ import annotations

import logging
import sys

if sys.version_info >= (3, 10):
    from importlib.metadata import entry_points
else:
    from importlib_metadata import entry_points  # type: ignore[no-redef]

from .base import Behavior

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "pymctp.behaviors"


def discover_behaviors() -> list[Behavior]:
    """Discover and instantiate behaviors from installed packages.

    Returns:
        List of behavior instances from all discovered entry points.
    """
    behaviors: list[Behavior] = []

    try:
        eps = entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:
        eps = entry_points().get(ENTRY_POINT_GROUP, [])  # type: ignore[assignment]

    for ep in eps:
        try:
            factory = ep.load()
            if callable(factory):
                result = factory()
                if isinstance(result, list):
                    behaviors.extend(result)
                elif isinstance(result, Behavior):
                    behaviors.append(result)
                else:
                    logger.warning(
                        "Behavior entry point '%s' returned %s, expected list[Behavior] or Behavior",
                        ep.name,
                        type(result).__name__,
                    )
            else:
                logger.warning(
                    "Behavior entry point '%s' is not callable (got %s)",
                    ep.name,
                    type(factory).__name__,
                )
        except Exception:
            logger.warning("Failed to load behavior entry point '%s'", ep.name, exc_info=True)

    return behaviors
