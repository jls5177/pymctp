# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Sample CLI commands demonstrating pymctp CLI extension."""

import click

from pymctp_sample_vendorextension.layers.mctp.sample_vendor import (
    SAMPLE_VENDOR_ID,
    SampleVendorGetVersionRequest,
    SampleVendorPacket,
)


@click.command()
@click.option(
    "--command",
    "-c",
    type=click.IntRange(0, 255),
    default=0,
    help="Command code (0-255)",
)
@click.option(
    "--data",
    "-d",
    default="",
    help="Hex data payload (e.g., 'deadbeef' or 'de ad be ef')",
)
def craft_sample_vendor(command: int, data: str):
    """Craft a sample vendor-specific MCTP packet.

    This demonstrates how vendor extension packages can add their own
    CLI commands to the pymctp tool.

    Examples:

    \b
    # Craft a basic vendor packet
    pymctp craft-sample-vendor --command 0x10 --data "deadbeef"

    \b
    # Craft a get version request
    pymctp craft-sample-vendor --command 1
    """
    # Parse hex data
    data_str = data.replace(" ", "")
    try:
        data_bytes = bytes.fromhex(data_str) if data_str else b""
    except ValueError:
        click.echo(f"Error: Invalid hex data: {data}", err=True)
        return

    # Craft the packet
    pkt = SampleVendorPacket(
        command=command,
        status=0,
        sequence=0,
        data_len=len(data_bytes),
        data=data_bytes,
    )

    # Display the packet
    click.echo(f"Vendor ID: 0x{SAMPLE_VENDOR_ID:04X}")
    click.echo(f"Packet: {pkt.summary()}")
    click.echo(f"\nRaw bytes: {bytes(pkt).hex(' ')}")


@click.group()
def sample_vendor():
    """Sample vendor-specific commands.

    This command group demonstrates how vendor extension packages
    can add their own command groups to pymctp.
    """
    pass


@sample_vendor.command()
@click.option(
    "--component-id",
    "-c",
    type=click.IntRange(0, 255),
    default=0,
    help="Component ID to query (0-255)",
)
def get_version_request(component_id: int):
    """Craft a Get Version request packet."""
    pkt = SampleVendorGetVersionRequest(component_id=component_id)

    click.echo(f"Vendor ID: 0x{SAMPLE_VENDOR_ID:04X}")
    click.echo(f"Packet: {pkt.summary()}")
    click.echo(f"\nRaw bytes: {bytes(pkt).hex(' ')}")


@sample_vendor.command()
def info():
    """Display sample vendor protocol information."""
    click.echo("Sample Vendor Protocol Information")
    click.echo("=" * 50)
    click.echo(f"Vendor ID: 0x{SAMPLE_VENDOR_ID:04X} (example only)")
    click.echo(f"\nSupported Commands:")
    click.echo(f"  0x00 - General message")
    click.echo(f"  0x01 - Get Version")
    click.echo(f"\nNote: This is a sample/template vendor extension.")
    click.echo(f"Replace with your actual vendor ID and commands.")


# You can export either individual commands or command groups
# Both will work with the CLI extension system
__all__ = ["craft_sample_vendor", "sample_vendor"]
