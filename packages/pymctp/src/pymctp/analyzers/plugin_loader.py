# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Plugin discovery for third-party analyzer rules.

Extension packages can register custom analysis rules via the
``pymctp.analyzer_rules`` entry point group in their ``pyproject.toml``::

    [project.entry-points."pymctp.analyzer_rules"]
    my_rules = "my_package.analyzers:get_rules"

The entry point must reference a callable that returns a
``list[AnalysisRule]``.
"""

from __future__ import annotations

import logging
import sys
from typing import List

if sys.version_info >= (3, 10):
    from importlib.metadata import entry_points
else:
    from importlib_metadata import entry_points  # type: ignore[no-redef]

from .base import AnalysisRule

logger = logging.getLogger(__name__)

ENTRY_POINT_GROUP = "pymctp.analyzer_rules"


def discover_analyzer_rules() -> list[AnalysisRule]:
    """Discover and instantiate analysis rules from installed packages.

    Returns:
        List of rule instances from all discovered entry points.
    """
    rules: list[AnalysisRule] = []

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
                    rules.extend(result)
                elif isinstance(result, AnalysisRule):
                    rules.append(result)
                else:
                    logger.warning(
                        "Analyzer rule entry point '%s' returned %s, expected list[AnalysisRule]",
                        ep.name,
                        type(result).__name__,
                    )
            else:
                logger.warning(
                    "Analyzer rule entry point '%s' is not callable (got %s)",
                    ep.name,
                    type(factory).__name__,
                )
        except Exception:
            logger.warning("Failed to load analyzer rule entry point '%s'", ep.name, exc_info=True)

    return rules
