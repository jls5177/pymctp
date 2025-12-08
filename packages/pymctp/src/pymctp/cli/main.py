# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Main CLI entry point for pymctp tools."""

import click

from pymctp.__about__ import __version__
from pymctp.cli.analyze_tcpdump import analyze_tcpdump
from pymctp.cli.extensions import extensions
from pymctp.cli.plugin_loader import discover_cli_commands_silent


@click.group()
@click.version_option(version=__version__, prog_name="pymctp")
def cli():
    """PyMCTP - MCTP/PLDM/IPMI protocol analysis tools."""


# Register built-in commands
cli.add_command(analyze_tcpdump)
cli.add_command(extensions)

# Discover and register extension commands from other packages
discover_cli_commands_silent(cli)


def main():
    """Entry point for the pymctp CLI."""
    cli()


if __name__ == "__main__":
    main()
