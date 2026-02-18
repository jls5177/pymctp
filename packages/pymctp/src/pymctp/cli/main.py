# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Main CLI entry point for pymctp tools.

Commands are loaded lazily so that tab completions and ``--help`` remain fast.
Heavy imports (scapy, packet layers, etc.) only happen when a command is
actually invoked.
"""

import sys
from importlib import import_module

import click

from pymctp.__about__ import __version__

if sys.version_info >= (3, 10):
    from importlib.metadata import entry_points
else:
    from importlib_metadata import entry_points


class _LazyCommand(click.BaseCommand):
    """Proxy that defers importing the real Click command until invocation.

    For tab-completion Click only calls :meth:`get_params` (which we
    delegate to the real command on first access).  For ``--help`` and
    actual execution we also load the real command.  The import cost is
    thus paid only once and only when needed.
    """

    def __init__(self, name: str, import_path: str, short_help: str | None = None) -> None:
        super().__init__(name)
        self._import_path = import_path
        self._short_help = short_help
        self._real: click.BaseCommand | None = None

    def _load(self) -> click.BaseCommand:
        if self._real is None:
            module_path, attr = self._import_path.rsplit(":", 1)
            mod = import_module(module_path)
            self._real = getattr(mod, attr)
        return self._real

    def get_params(self, ctx: click.Context) -> list[click.Parameter]:
        return self._load().get_params(ctx)

    def invoke(self, ctx: click.Context):
        return self._load().invoke(ctx)

    def get_short_help_str(self, limit: int = 150) -> str:
        if self._short_help is not None:
            return self._short_help
        # Avoid importing the module just for completion help text
        if self._real is None:
            return ""
        return self._real.get_short_help_str(limit)

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        self._load().format_help(ctx, formatter)

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        return self._load().parse_args(ctx, args)

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent: click.Context | None = None,
        **extra,
    ) -> click.Context:
        return self._load().make_context(info_name, args, parent=parent, **extra)


class _LazyGroup(click.Group):
    """Click Group that discovers plugin commands lazily.

    Plugin entry points are resolved (``ep.load()``) only when the
    command is first looked up, not at group construction time.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._plugin_eps: dict[str, object] | None = None

    def _discover_plugins(self) -> dict[str, object]:
        """Scan entry points once and cache them (but don't load yet)."""
        if self._plugin_eps is not None:
            return self._plugin_eps

        self._plugin_eps = {}
        try:
            eps = entry_points(group="pymctp.cli_commands")
        except TypeError:
            eps = entry_points().get("pymctp.cli_commands", [])

        for ep in eps:
            self._plugin_eps[ep.name] = ep
        return self._plugin_eps

    def list_commands(self, ctx: click.Context) -> list[str]:
        builtin = super().list_commands(ctx)
        plugin_names = list(self._discover_plugins().keys())
        return sorted(set(builtin + plugin_names))

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.BaseCommand | None:
        # Check built-in commands first
        cmd = super().get_command(ctx, cmd_name)
        if cmd is not None:
            return cmd

        # Try plugin entry points — wrap in _LazyCommand to defer ep.load()
        plugins = self._discover_plugins()
        ep = plugins.get(cmd_name)
        if ep is None:
            return None

        return _LazyCommand(cmd_name, ep.value)


@click.group(cls=_LazyGroup)
@click.version_option(version=__version__, prog_name="pymctp")
def cli():
    """PyMCTP - MCTP/PLDM/IPMI protocol analysis tools."""


# Register built-in commands lazily — no heavy imports at module level
cli.add_command(
    _LazyCommand(
        "analyze-tcpdump",
        "pymctp.cli.analyze_tcpdump:analyze_tcpdump",
        short_help="Analyze MCTP packet captures from tcpdump or pcap files.",
    )
)
cli.add_command(
    _LazyCommand(
        "extensions",
        "pymctp.cli.extensions:extensions",
        short_help="List all detected pymctp extension packages and their versions.",
    )
)


def main():
    """Entry point for the pymctp CLI."""
    cli()


if __name__ == "__main__":
    main()
