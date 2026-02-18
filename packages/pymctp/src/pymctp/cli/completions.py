# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""CLI command to output shell completion scripts.

Ships pre-generated static completions for the built-in commands.
Can also regenerate completions dynamically to include plugin commands
(requires the ``pycomplete`` package).
"""

from importlib import resources
from pathlib import Path

import click

_SHELLS = ("bash", "zsh")
_BUNDLED = {
    "bash": "pymctp.bash",
    "zsh": "pymctp.zsh",
}


def _read_bundled(shell: str) -> str | None:
    """Read a pre-generated completion script from package data."""
    filename = _BUNDLED.get(shell)
    if filename is None:
        return None
    try:
        return resources.files("pymctp.completions").joinpath(filename).read_text()
    except (FileNotFoundError, TypeError):
        return None


@click.command()
@click.argument("shell", type=click.Choice(_SHELLS, case_sensitive=False))
@click.option(
    "--dynamic",
    is_flag=True,
    default=False,
    help="Regenerate completions dynamically (includes plugin commands, requires pycomplete).",
)
def completions(shell: str, dynamic: bool) -> None:
    """Output shell completion script for pymctp.

    Prints a static completion script to stdout. Pipe it to a file and
    source it from your shell configuration.

    Examples:

    \b
    # Zsh — install completions
    pymctp completions zsh > ~/.zsh/completions/_pymctp
    # then add to .zshrc: fpath=(~/.zsh/completions $fpath); autoload -Uz compinit && compinit

    \b
    # Bash — install completions
    pymctp completions bash > ~/.local/share/bash-completion/completions/pymctp

    \b
    # Regenerate with plugin commands included
    pymctp completions zsh --dynamic > ~/.zsh/completions/_pymctp
    """
    if dynamic:
        _generate_dynamic(shell)
    else:
        script = _read_bundled(shell)
        if script is None:
            click.echo(f"Error: no bundled completion script for {shell}.", err=True)
            raise click.Abort()
        click.echo(script, nl=False)


def _generate_dynamic(shell: str) -> None:
    """Generate completions dynamically using pycomplete, including plugins."""
    try:
        from pycomplete import Completer
    except ImportError:
        click.echo(
            "Error: pycomplete is required for --dynamic. Install with: pip install pycomplete",
            err=True,
        )
        raise click.Abort()

    # Import the full CLI (triggers lazy loading of all commands + plugins)
    from pymctp.cli.main import _LazyCommand, cli as cli_group

    # Force-load all lazy commands so pycomplete can introspect them
    ctx = click.Context(cli_group)
    for name in cli_group.list_commands(ctx):
        cmd = cli_group.get_command(ctx, name)
        if isinstance(cmd, _LazyCommand):
            cli_group.add_command(cmd._load(), name=name)

    completer = Completer(cli_group, prog=["pymctp"])
    script = completer.render(shell)
    click.echo(script, nl=False)
