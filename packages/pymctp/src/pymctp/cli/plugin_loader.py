# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""CLI plugin discovery and loading.

This module enables other packages to extend the pymctp CLI with additional
commands via entry points.
"""

import sys
from typing import List

import click

if sys.version_info >= (3, 10):
    from importlib.metadata import entry_points
else:
    from importlib_metadata import entry_points


def discover_cli_commands(cli_group: click.Group) -> list[str]:
    """Discover and register CLI command extensions via entry points.

    Extension packages can register CLI commands by adding an entry point
    in their pyproject.toml:

    [project.entry-points."pymctp.cli_commands"]
    my_command = "my_package.cli:my_command"

    The entry point should reference a Click command or command group.

    Args:
        cli_group: The main CLI group to register commands with

    Returns:
        List of registered command names
    """
    loaded_commands = []

    try:
        # Python 3.10+ API
        eps = entry_points(group="pymctp.cli_commands")
    except TypeError:
        # Python 3.9 fallback
        eps = entry_points().get("pymctp.cli_commands", [])

    for ep in eps:
        try:
            # Load the command from the entry point
            command = ep.load()

            # Register it with the CLI group
            if isinstance(command, (click.Command, click.Group)):
                cli_group.add_command(command, name=ep.name)
                loaded_commands.append(ep.name)
            else:
                click.echo(
                    f"Warning: CLI extension '{ep.name}' from '{ep.value}' "
                    f"is not a Click command or group (got {type(command).__name__})",
                    err=True,
                )
        except Exception as e:
            # Don't fail if an extension has issues, just warn
            click.echo(f"Warning: Failed to load CLI extension '{ep.name}': {e}", err=True)

    return loaded_commands


def discover_cli_commands_silent(cli_group: click.Group) -> list[str]:
    """Discover and register CLI commands silently (no warnings).

    Same as discover_cli_commands but suppresses all output.

    Args:
        cli_group: The main CLI group to register commands with

    Returns:
        List of registered command names
    """
    loaded_commands = []

    try:
        eps = entry_points(group="pymctp.cli_commands")
    except TypeError:
        eps = entry_points().get("pymctp.cli_commands", [])

    for ep in eps:
        try:
            command = ep.load()
            if isinstance(command, (click.Command, click.Group)):
                cli_group.add_command(command, name=ep.name)
                loaded_commands.append(ep.name)
        except Exception:
            pass  # Silently ignore failures

    return loaded_commands
