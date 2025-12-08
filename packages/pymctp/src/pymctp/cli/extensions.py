# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""CLI command to list detected extension packages."""

import sys

import click

if sys.version_info >= (3, 10):
    from importlib.metadata import entry_points, version, PackageNotFoundError
else:
    from importlib_metadata import entry_points, version, PackageNotFoundError


@click.command()
def extensions():
    """List all detected pymctp extension packages and their versions."""
    # Track all extension packages found
    extension_packages = {}

    # Discover extensions from all entry point groups
    entry_point_groups = [
        "pymctp.cli_commands",
        "pymctp.extensions",
        "pymctp.layers",
        "pymctp.exercisers",
    ]

    for group in entry_point_groups:
        try:
            # Python 3.10+ API
            eps = entry_points(group=group)
        except TypeError:
            # Python 3.9 fallback
            eps = entry_points().get(group, [])

        for ep in eps:
            # Get the distribution (package) name from the entry point
            # This is more reliable than parsing ep.value
            if hasattr(ep, "dist") and hasattr(ep.dist, "name"):
                package_name = ep.dist.name
            else:
                # Fallback: extract from entry point value
                # Entry point value format: "package.module:attr"
                package_name = ep.value.split(".")[0]

            # Try to get the version
            try:
                pkg_version = version(package_name)
            except PackageNotFoundError:
                pkg_version = "unknown"

            # Track which extension types this package provides
            if package_name not in extension_packages:
                extension_packages[package_name] = {
                    "version": pkg_version,
                    "entry_points": {},
                }

            if group not in extension_packages[package_name]["entry_points"]:
                extension_packages[package_name]["entry_points"][group] = []

            extension_packages[package_name]["entry_points"][group].append(ep.name)

    # Display results
    if not extension_packages:
        click.echo("No extension packages detected.")
        return

    click.echo("Detected pymctp extension packages:\n")

    for package_name in sorted(extension_packages.keys()):
        pkg_info = extension_packages[package_name]
        click.echo(f"  {package_name} (v{pkg_info['version']})")

        for group, entry_point_names in sorted(pkg_info["entry_points"].items()):
            group_type = group.split(".")[-1]  # Extract "cli_commands", "layers", etc.
            click.echo(f"    {group_type}: {', '.join(sorted(entry_point_names))}")

        click.echo()
