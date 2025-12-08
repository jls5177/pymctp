<!--
SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>

SPDX-License-Identifier: MIT
-->

# PyMCTP CLI Extensions Guide

This guide explains how to extend the `pymctp` command-line interface with custom commands from your own packages.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Creating CLI Extensions](#creating-cli-extensions)
  - [Single Commands](#single-commands)
  - [Command Groups](#command-groups)
- [Registration](#registration)
- [Best Practices](#best-practices)
- [Example](#example)

## Overview

PyMCTP uses Python entry points to automatically discover and load CLI command extensions from installed packages. This allows vendor-specific or custom packages to seamlessly add their own commands to the `pymctp` CLI without modifying the core package.

When you run `pymctp --help`, all registered commands from all installed packages are displayed together.

## Quick Start

To add a custom command to the `pymctp` CLI:

1. Create a Click command in your package
2. Register it via entry points in `pyproject.toml`
3. Install your package
4. The command automatically appears in `pymctp --help`

## Creating CLI Extensions

### Single Commands

Create a Click command in your package:

```python
# my_package/cli/my_commands.py
import click

@click.command()
@click.option('--vendor-id', type=int, help='Vendor ID')
def decode_vendor_packet(vendor_id):
    """Decode a vendor-specific packet."""
    click.echo(f"Decoding packet for vendor {vendor_id:#06x}")
    # Your implementation here
```

### Command Groups

For multiple related commands, use a Click group:

```python
# my_package/cli/my_commands.py
import click

@click.group()
def my_vendor():
    """My vendor-specific commands."""
    pass

@my_vendor.command()
def list_devices():
    """List available devices."""
    click.echo("Listing devices...")

@my_vendor.command()
@click.argument('device_id')
def query_device(device_id):
    """Query a specific device."""
    click.echo(f"Querying device: {device_id}")
```

## Registration

Register your commands in `pyproject.toml` using entry points:

```toml
[project.entry-points."pymctp.cli_commands"]
# Register a single command
decode-vendor-packet = "my_package.cli.my_commands:decode_vendor_packet"

# Register a command group
my-vendor = "my_package.cli.my_commands:my_vendor"
```

**Important Notes:**

- The entry point name (left side) becomes the command name in the CLI
- Use kebab-case for command names (e.g., `decode-vendor-packet`)
- The value (right side) must point to a Click `Command` or `Group` object
- Multiple commands can be registered from the same package

## Best Practices

### 1. Naming Conventions

- Use descriptive, vendor-specific command names to avoid conflicts
- Prefix commands with your vendor/package name: `acme-decode`, `acme-analyze`
- Use kebab-case for multi-word commands: `get-version-info`

### 2. Help Text

Provide clear help text for all commands and options:

```python
@click.command()
@click.option('--format', type=click.Choice(['json', 'text']),
              help='Output format (json or text)')
def my_command(format):
    """Short one-line description.

    Longer description can go here explaining what the command does,
    what arguments it expects, and examples of usage.

    Examples:

    \b
    # Example 1
    pymctp my-command --format json

    \b
    # Example 2
    pymctp my-command --format text
    """
    pass
```

### 3. Error Handling

Use Click's utilities for user-friendly error messages:

```python
import click

@click.command()
@click.argument('file', type=click.Path(exists=True))
def analyze_file(file):
    """Analyze a capture file."""
    try:
        # Your logic here
        pass
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        raise click.Abort()
```

### 4. Dependencies

If your CLI commands need additional dependencies (like `click`), ensure they're in your package dependencies:

```toml
[project]
dependencies = [
    "pymctp>=0.2.0",
    "click>=8.0",
]
```

### 5. Command Organization

For packages with many commands, organize them into logical groups:

```
my_package/
├── cli/
│   ├── __init__.py
│   ├── decode.py      # Decoding commands
│   ├── craft.py       # Packet crafting commands
│   └── analyze.py     # Analysis commands
```

Then register each group:

```toml
[project.entry-points."pymctp.cli_commands"]
my-vendor-decode = "my_package.cli.decode:decode_group"
my-vendor-craft = "my_package.cli.craft:craft_group"
my-vendor-analyze = "my_package.cli.analyze:analyze_group"
```

## Example

Here's a complete example from `pymctp-sample-vendorextension`:

### 1. Create the CLI module

```python
# pymctp_sample_vendorextension/cli/sample_commands.py
import click
from pymctp_sample_vendorextension.layers.mctp.sample_vendor import SAMPLE_VENDOR_ID

@click.group()
def sample_vendor():
    """Sample vendor-specific commands."""
    pass

@sample_vendor.command()
def info():
    """Display sample vendor protocol information."""
    click.echo("Sample Vendor Protocol Information")
    click.echo(f"Vendor ID: 0x{SAMPLE_VENDOR_ID:04X}")
```

### 2. Register in pyproject.toml

```toml
[project.entry-points."pymctp.cli_commands"]
sample-vendor = "pymctp_sample_vendorextension.cli.sample_commands:sample_vendor"
```

### 3. Install and use

```bash
pip install pymctp-sample-vendorextension

# The command is now available
pymctp sample-vendor info
```

### Result

```
$ pymctp --help
Usage: pymctp [OPTIONS] COMMAND [ARGS]...

  PyMCTP - MCTP/PLDM/IPMI protocol analysis tools.

Commands:
  analyze-tcpdump  Analyze MCTP packet captures...
  sample-vendor    Sample vendor-specific commands.

$ pymctp sample-vendor info
Sample Vendor Protocol Information
Vendor ID: 0x9999
```

## Reference

For more examples, see:
- [pymctp-sample-vendorextension](packages/pymctp-sample-vendorextension) - Complete sample implementation
- [Click Documentation](https://click.palletsprojects.com/) - Click framework reference

## Troubleshooting

### Command not appearing

1. Verify entry point registration in `pyproject.toml`
2. Ensure package is installed: `pip list | grep your-package`
3. Reinstall in development mode: `pip install -e .`
4. Check for import errors in your CLI module

### Import errors

Make sure your CLI module can import successfully:

```bash
python -c "from my_package.cli.my_commands import my_command"
```

### Name conflicts

If two packages register the same command name, the last one loaded wins. Always prefix your commands with your vendor/package name to avoid conflicts.
