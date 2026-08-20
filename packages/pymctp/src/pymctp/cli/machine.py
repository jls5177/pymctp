# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""CLI commands for inspecting, validating, and running machine topologies."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click


_SPEC_SUFFIXES = {".json", ".yaml", ".yml"}


@click.group()
def machine() -> None:
    """Inspect, validate, and run registered or file-backed machine topologies."""


@machine.command("list")
@click.option("--json", "json_output", is_flag=True, help="Emit machine-readable JSON.")
def list_registered_machines(json_output: bool) -> None:
    """List registered machines."""

    from pymctp.topology import list_machines, machine_info

    machines = []
    for name in list_machines():
        info = dict(machine_info(name))
        info["name"] = name
        machines.append(info)

    if json_output:
        click.echo(json.dumps(machines, indent=2, sort_keys=True))
        return

    if not machines:
        click.echo("No registered machines found.")
        click.echo("Machines are discovered from the pymctp.machines entry point group.")
        return

    _print_rows(
        ("Name", "Description", "Devices"),
        [
            (
                str(info["name"]),
                str(info.get("description") or "-"),
                str(info.get("device_count", 0)),
            )
            for info in machines
        ],
    )


@machine.command("show")
@click.argument("name_or_file")
@click.option("--eid-map", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="JSON/YAML EID map.")
@click.option("--set", "overrides", multiple=True, metavar="KEY=VALUE", help="Apply a dotted-key override.")
@click.option("--json", "json_output", is_flag=True, help="Emit the resolved spec as JSON.")
def show_machine(name_or_file: str, eid_map: Path | None, overrides: tuple[str, ...], json_output: bool) -> None:
    """Show a registered machine or spec file."""

    from pymctp.topology import dump_machine_spec

    spec = _resolve_spec(name_or_file, eid_map_path=eid_map, overrides=overrides)

    if json_output:
        click.echo(dump_machine_spec(spec))
        return

    click.echo(f"Machine: {spec.name}")
    if spec.description:
        click.echo(f"Description: {spec.description}")
    click.echo()
    _print_topology(spec)


@machine.command("run")
@click.argument("name_or_file")
@click.option("--eid-map", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="JSON/YAML EID map.")
@click.option("--set", "overrides", multiple=True, metavar="KEY=VALUE", help="Apply a dotted-key override.")
@click.option("--shell", "interactive_shell", is_flag=True, help="Open an interactive shell after startup.")
@click.option("--no-start", is_flag=True, help="Build endpoints without starting sniffer threads.")
@click.option("--rediscover", is_flag=True, help="Run bus-owner rediscovery immediately after startup.")
@click.option("--timeout", type=float, default=None, metavar="SECONDS", help="Maximum time to run before stopping.")
def run_machine(
    name_or_file: str,
    eid_map: Path | None,
    overrides: tuple[str, ...],
    interactive_shell: bool,
    no_start: bool,
    rediscover: bool,
    timeout: float | None,
) -> None:
    """Build and run a registered machine or spec file."""

    from pymctp.topology import Machine, MachineBuildError

    spec = _resolve_spec(name_or_file, eid_map_path=eid_map, overrides=overrides)
    runtime = Machine(spec)

    try:
        try:
            runtime.build()
        except MachineBuildError as exc:
            # Endpoint transports connect eagerly, so this usually just means the
            # peer (QEMU) is not listening yet. Report it as a clean CLI error.
            raise click.ClickException(str(exc)) from exc
        if no_start:
            if rediscover:
                msg = "--rediscover requires started endpoints; omit --no-start."
                raise click.ClickException(msg)
            click.echo(f"Built machine {spec.name!r} without starting endpoints.")
            _print_startup_banner(runtime)
            return

        runtime.start()
        _print_startup_banner(runtime)

        if rediscover:
            bus_owner = runtime.bus_owner
            if bus_owner is None:
                msg = "Cannot rediscover: this machine has no bus-owner endpoint."
                raise click.ClickException(msg)
            click.echo()
            click.echo(str(bus_owner.rediscover()))

        if interactive_shell:
            _open_shell(runtime, spec)
        else:
            runtime.install_signal_handler()
            _join_until_timeout(runtime, timeout)
    finally:
        runtime.stop()
        _print_summary(runtime)


@machine.command("validate")
@click.argument("name_or_file")
@click.option("--eid-map", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="JSON/YAML EID map.")
@click.option("--set", "overrides", multiple=True, metavar="KEY=VALUE", help="Apply a dotted-key override.")
def validate_machine(name_or_file: str, eid_map: Path | None, overrides: tuple[str, ...]) -> None:
    """Validate a registered machine or spec file."""

    spec = _resolve_spec(name_or_file, eid_map_path=eid_map, overrides=overrides)
    for warning in _transport_warnings(spec):
        click.echo(f"Warning: {warning}", err=True)

    try:
        spec.validate()
    except Exception as exc:
        raise click.ClickException(f"Machine spec {spec.name!r} is invalid: {exc}") from exc

    click.echo(f"Machine spec {spec.name!r} is valid.")


def _resolve_spec(name_or_file: str, *, eid_map_path: Path | None, overrides: tuple[str, ...]) -> Any:
    from pymctp.topology import apply_overrides, get_machine_spec, load_eid_map, load_machine_spec
    from pymctp.topology import parse_override_strings

    try:
        spec = get_machine_spec(name_or_file)
    except KeyError as exc:
        path = Path(name_or_file)
        if not path.exists():
            detail = exc.args[0] if exc.args else str(exc)
            msg = f"{name_or_file!r} is not a registered machine and is not an existing spec file. {detail}"
            raise click.ClickException(msg) from exc
        if path.suffix.lower() not in _SPEC_SUFFIXES:
            msg = f"{path} is not a supported machine spec file (.json, .yaml, .yml)."
            raise click.ClickException(msg) from exc
        try:
            spec = load_machine_spec(path)
        except Exception as load_exc:
            raise click.ClickException(f"Failed to load machine spec from {path}: {load_exc}") from load_exc

    if eid_map_path is not None:
        try:
            spec = spec.with_eids(load_eid_map(eid_map_path))
        except Exception as exc:
            raise click.ClickException(f"Failed to apply EID map {eid_map_path}: {exc}") from exc

    if overrides:
        try:
            spec = apply_overrides(spec, parse_override_strings(overrides))
        except Exception as exc:
            raise click.ClickException(f"Invalid --set override: {exc}") from exc

    return spec


def _print_topology(spec: Any) -> None:
    rows = []
    for device in spec.devices:
        try:
            eid = spec.resolve_eid(device)
        except Exception as exc:
            raise click.ClickException(f"Failed to resolve EID for device {device.name!r}: {exc}") from exc
        rows.append(
            (
                device.name,
                _format_int(eid),
                _format_int(device.physical_address),
                _format_transport(device.transport),
                ", ".join(device.roles) if device.roles else "-",
                "yes" if device.enabled else "no",
            )
        )
    _print_rows(("Device", "EID", "Physical", "Transport", "Roles", "Enabled"), rows)


def _print_startup_banner(runtime: Any) -> None:
    click.echo(f"Machine {runtime.spec.name!r} endpoints:")
    if not runtime.endpoints:
        click.echo("  (none)")
        return
    for name, endpoint in runtime.endpoints.items():
        click.echo(f"  {name}: EID {_format_int(getattr(endpoint.context, 'assigned_eid', None))}")


def _open_shell(runtime: Any, spec: Any) -> None:
    namespace = {"machine": runtime, "spec": spec}
    bus_owner = runtime.bus_owner
    if bus_owner is not None:
        namespace["bus_owner"] = bus_owner

    hint = (
        "Available: machine, spec"
        f"{', bus_owner' if bus_owner is not None else ''}. "
        "Try machine.hsp1, machine.summary(), or bus_owner.rediscover()."
    )
    click.echo(hint)
    try:
        from IPython import embed
    except ImportError:
        import code

        code.interact(banner=hint, local=namespace)
    else:
        embed(header=hint, user_ns=namespace)


def _join_until_timeout(runtime: Any, timeout: float | None) -> None:
    if timeout is None:
        runtime.join()
        return

    import time

    deadline = time.monotonic() + timeout
    for endpoint in runtime.endpoints.values():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        endpoint.thread.join(remaining)


def _print_summary(runtime: Any) -> None:
    summary = runtime.summary()
    click.echo()
    click.echo("Machine summary:")
    click.echo(summary or "(no endpoints)")


def _transport_warnings(spec: Any) -> list[str]:
    registry = _registered_config_types()
    warnings = []
    for device in spec.devices:
        transport_type = device.transport.get("type")
        if transport_type is not None and str(transport_type) not in registry:
            warnings.append(
                f"device {device.name!r} uses unregistered transport type {transport_type!r}; "
                "install the optional exerciser package that provides it if this is expected."
            )
    return warnings


def _registered_config_types() -> dict[str, type]:
    try:
        import pymctp.exerciser  # noqa: F401
    except Exception:
        pass

    from pymctp.automaton.manager import registered_config_types

    return registered_config_types()


def _format_transport(transport: dict[str, Any]) -> str:
    transport_type = str(transport.get("type", "<missing>"))
    details = [f"{key}={_format_value(value)}" for key, value in sorted(transport.items()) if key != "type"]
    if not details:
        return transport_type
    return f"{transport_type} ({', '.join(details)})"


def _format_value(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    return str(value)


def _format_int(value: int | None) -> str:
    if value is None:
        return "-"
    return f"0x{value:02X} ({value})"


def _print_rows(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    all_rows = [headers, *rows]
    widths = [max(len(row[index]) for row in all_rows) for index in range(len(headers))]
    click.echo("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    click.echo("  ".join("-" * width for width in widths))
    for row in rows:
        click.echo("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))
