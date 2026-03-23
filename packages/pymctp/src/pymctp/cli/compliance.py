# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""CLI subcommand for running MCTP compliance tests."""

from __future__ import annotations

import click


@click.group()
def compliance():
    """Run MCTP compliance tests against a live endpoint."""


@compliance.command("list")
def list_suites():
    """List all available compliance test suites."""
    from ..compliance.base import get_registered_suites, get_tests_for_suite

    # Force discovery of built-in modules
    from ..compliance import mctp_base as _  # noqa: F401
    from ..compliance import mctp_bridge as _b  # noqa: F401

    suites = get_registered_suites()
    if not suites:
        click.echo("No compliance test suites found.")
        return

    for name in suites:
        tests = get_tests_for_suite(name)
        click.echo(f"  {name} ({len(tests)} tests)")


@compliance.command("run")
@click.option("--target-eid", required=True, type=click.IntRange(0, 254), help="Destination endpoint EID.")
@click.option(
    "--suite",
    "suites",
    required=True,
    multiple=True,
    help="Compliance test suite(s) to run. Use 'all' for all suites. Use 'list' command to see available suites.",
)
@click.option("--timeout", default=5.0, type=float, help="Per-test timeout in seconds.")
@click.option(
    "--socket-type",
    type=click.Choice(["qemu-i2c", "qemu-i3c", "aardvark", "serial"]),
    default="qemu-i2c",
    help="Transport socket type.",
)
@click.option("--socket-addr", default="127.0.0.1", help="Socket address (host or device path).")
@click.option("--in-port", type=int, default=5559, help="Inbound port (QEMU sockets).")
@click.option("--out-port", type=int, default=5558, help="Outbound port (QEMU sockets).")
@click.option("--src-eid", type=int, default=0x08, help="Source endpoint EID for this session.")
@click.option("--src-addr", type=int, default=0x10, help="Source physical address (7-bit SMBus).")
def run_compliance(target_eid, suites, timeout, socket_type, socket_addr, in_port, out_port, src_eid, src_addr):
    """Execute compliance test suites against a target endpoint."""
    from ..automaton.sessions import EndpointSession
    from ..compliance.base import ComplianceTestSuite, get_all_tests, get_registered_suites, get_tests_for_suite
    from ..layers.mctp.types import EndpointContext, MsgTypes, Smbus7bitAddress

    # Force discovery of built-in modules
    from ..compliance import mctp_base as _  # noqa: F401
    from ..compliance import mctp_bridge as _b  # noqa: F401

    # Create socket
    sock = _create_socket(socket_type, socket_addr, in_port, out_port)

    # Create endpoint context and session
    ctx = EndpointContext(
        physical_address=Smbus7bitAddress(src_addr),
        assigned_eid=src_eid,
        supported_msg_types=[MsgTypes.CTRL],
    )
    session = EndpointSession(context=ctx, socket=sock)

    # Build test suite
    suite = ComplianceTestSuite(session, target_eid, timeout_s=timeout)

    selected = set(suites)
    if "all" in selected:
        suite.add_tests(get_all_tests())
    else:
        available = get_registered_suites()
        for name in selected:
            if name not in available:
                raise click.BadParameter(f"Unknown suite: {name!r}. Available: {available}")
            suite.add_tests(get_tests_for_suite(name))

    # Run and report
    click.echo(f"Running {len(suite._tests)} compliance tests against EID 0x{target_eid:02X}...")
    click.echo()
    suite.run_all()
    click.echo(suite.report())


def _create_socket(socket_type: str, addr: str, in_port: int, out_port: int):
    """Create the appropriate transport socket."""
    if socket_type == "qemu-i2c":
        from ..exerciser import QemuI2CNetDevSocket

        return QemuI2CNetDevSocket(iface=addr, in_port=in_port, out_port=out_port)
    if socket_type == "qemu-i3c":
        from ..exerciser import QemuI3CCharDevSocket

        return QemuI3CCharDevSocket(iface=addr)
    if socket_type == "aardvark":
        from ..exerciser import AardvarkI2CSocket

        return AardvarkI2CSocket()
    if socket_type == "serial":
        from ..exerciser import TTYSerialSocket

        return TTYSerialSocket(iface=addr)
    msg = f"Unknown socket type: {socket_type}"
    raise click.BadParameter(msg)
