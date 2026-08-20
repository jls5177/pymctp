<!--
SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>

SPDX-License-Identifier: MIT
-->

# PyMCTP Extension Development Guide

This guide explains how to create and distribute pymctp extensions for OEM-specific or custom MCTP/IPMI layer implementations.

## Table of Contents

- [Overview](#overview)
- [Extension Architecture](#extension-architecture)
- [Creating an Extension](#creating-an-extension)
- [Package Structure](#package-structure)
- [Registering Your Extension](#registering-your-extension)
- [Testing Your Extension](#testing-your-extension)
- [Publishing Your Extension](#publishing-your-extension)
- [Endpoint Roles and Behaviors](#endpoint-roles-and-behaviors)
- [Machine Topologies](#machine-topologies)
- [Entry Point Groups](#entry-point-groups)
- [CLI Extensions](#cli-extensions)

## Overview

PyMCTP uses Python's entry points mechanism to automatically discover and load extensions. Extensions are separate Python packages that register themselves via the `pymctp.extensions` entry point group.

When pymctp is imported, it automatically:
1. Discovers all registered extensions via entry points
2. Imports the registered modules
3. Registers extensions into the pymctp namespace (e.g., pymctp.oem.acme)
4. Allows the extension's layer bindings to register automatically via decorators

This design keeps OEM-specific code separate from the core library while maintaining seamless integration.

Extensions are automatically accessible under the `pymctp.oem` namespace based on their entry point name:
- Entry point `acme` → `pymctp.oem.acme`
- Entry point `sample-vendor` → `pymctp.oem.sample_vendor` (hyphens converted to underscores)

## Extension Architecture

PyMCTP's layer binding system uses decorators that automatically register Scapy layer bindings:

- `@AutobindMessageType(msg_type)` - Binds a message header to MCTP transport layer
- `@AutobindControlMsg(cmd_code)` - Binds a control message to ControlHdrPacket
- `@AutobindPLDMMsg(pldm_type, cmd_code)` - Binds a PLDM message to PldmHdrPacket
- `@AutobindVDMMsg(vendor_id, cmd_code)` - Binds a VDM message to VdPciHdrPacket

You can also use Scapy's `bind_layers()` directly for more complex bindings.

## Creating an Extension

### Step 1: Set Up Package Structure

Create a new Python package with the following structure:

```
your-extension/
├── pyproject.toml
├── README.md
└── src/
    └── your_package_name/
        ├── __init__.py
        ├── __about__.py
        └── layers/
            ├── __init__.py
            ├── ipmi/
            │   ├── __init__.py
            │   └── your_ipmi_layers.py
            └── mctp/
                ├── __init__.py
                └── your_mctp_layers.py
```

### Step 2: Implement Your Layers

Create your layer definitions using pymctp's base classes:

```python
# src/your_package_name/layers/mctp/your_mctp_layers.py

from scapy.packet import Packet, bind_layers
from scapy.fields import XByteField, XLEShortField

from pymctp.layers.mctp import VdPciHdrPacket
from pymctp.layers.mctp.vdpci import VdPCIVendorIds, AutobindVDMMsg

# Define your vendor ID (if not already in VdPCIVendorIds)
YOUR_VENDOR_ID = 0x1234

# Define your packet class
class YourVendorPacket(Packet):
    name = "YOUR-VENDOR"
    fields_desc = [
        XByteField("command", 0),
        XLEShortField("param", 0),
    ]

# Bind it to the VDM header using the decorator
from pymctp.layers.mctp.vdpci.vdpci import AutobindVDMMsg

# Or use decorator approach if AutobindVDMMsg is available as a class decorator:
# @AutobindVDMMsg(YOUR_VENDOR_ID, 0x00)
# class YourVendorPacket(Packet):
#     ...

# Or bind directly:
bind_layers(VdPciHdrPacket, YourVendorPacket,
            vendor_id=YOUR_VENDOR_ID,
            vdm_cmd_code=0x00)
```

### Step 3: Create Layer Exports

In your `layers/__init__.py`, import all your layer modules:

```python
# src/your_package_name/layers/__init__.py

"""Your extension layer definitions.

This module is automatically loaded by pymctp's plugin system.
"""

from .ipmi import *
from .mctp import *

__all__ = []
```

### Step 4: Configure pyproject.toml

Register your extension using the `pymctp.extensions` entry point:

```toml
[project]
name = "pymctp-your-extension"
version = "0.1.0"
description = "Your description"
requires-python = ">=3.8"
dependencies = [
    "pymctp>=0.1.0",
]

# Register as a pymctp extension
[project.entry-points."pymctp.extensions"]
your_extension = "your_package_name.layers"
```

The entry point name (`your_extension`) can be any unique identifier. The value must point to the module that imports all your layer definitions.

## Package Structure

### Recommended Structure

```
pymctp-oem-yourcompany/
├── README.md                    # Package documentation
├── LICENSE                      # License file
├── pyproject.toml              # Package configuration
└── src/
    └── pymctp_oem_yourcompany/
        ├── __init__.py         # Package root
        ├── __about__.py        # Version info
        └── layers/
            ├── __init__.py     # Import all layers (entry point target)
            ├── ipmi/
            │   ├── __init__.py
            │   └── *.py        # IPMI layer implementations
            └── mctp/
                ├── __init__.py
                └── vdpci/      # Or other protocol dirs
                    ├── __init__.py
                    └── *.py    # MCTP layer implementations
```

### Naming Conventions

- Package name: `pymctp-<category>-<name>` (e.g., `pymctp-oem-acme`)
- Python module: Use underscores instead of hyphens (e.g., `pymctp_oem_acme`)
- Entry point name: Short, descriptive (e.g., `acme`, `intel`, `custom`)

## Registering Your Extension

The critical part is the entry point registration in `pyproject.toml`:

```toml
[project.entry-points."pymctp.extensions"]
your_name = "your_module.layers"
```

This tells pymctp:
- Entry point group: `pymctp.extensions` (required, must be exact)
- Extension name: `your_name` (can be any unique identifier)
- Module to load: `your_module.layers` (must be importable)

When this module is imported, all its layer definitions and bindings are registered automatically.

## Testing Your Extension

### Local Development

Install both packages in editable mode:

```bash
# Install core pymctp in editable mode
cd /path/to/pymctp
pip install -e .

# Install your extension in editable mode
cd /path/to/your-extension
pip install -e .
```

### Verify Auto-Discovery

Test that your extension is discovered:

```python
import pymctp

# Check if your extension was loaded
from pymctp.layers import __all_extensions__
print(__all_extensions__)  # Should include your extension name

# Access your extension via the pymctp namespace
# If your entry point is 'acme', it will be at:
from pymctp.oem.acme import YourCustomLayer

# Or for 'sample-vendor' entry point:
from pymctp.oem.sample_vendor import YourCustomLayer

# Test your layers
from pymctp.layers.mctp.vdpci import VdPciHdrPacket

# Your bindings should work automatically
data = b'...'  # Your test data
pkt = VdPciHdrPacket(data)
print(pkt.summary())
```

### Unit Tests

Create tests for your layers:

```python
# tests/test_your_layers.py

import pytest
from scapy.compat import raw
from pymctp.layers.mctp.vdpci import VdPciHdrPacket
from your_package_name.layers.mctp import YourVendorPacket

def test_your_vendor_packet_decode():
    # Test data
    data = b'...'

    # Decode
    pkt = VdPciHdrPacket(data)

    # Verify layer binding worked
    assert isinstance(pkt.payload, YourVendorPacket)
    assert pkt.payload.command == 0x01

def test_your_vendor_packet_encode():
    # Create packet
    pkt = VdPciHdrPacket(...) / YourVendorPacket(command=0x01)

    # Encode
    raw_bytes = raw(pkt)

    # Verify
    assert raw_bytes == b'...'
```

## Publishing Your Extension

### Option 1: Private Distribution

For internal use, you can:
- Host on a private PyPI server
- Install from a git repository: `pip install git+https://github.com/yourorg/your-extension.git`
- Distribute as wheel files: `python -m build` then share the `.whl` file

### Option 2: Public PyPI

1. Build your package:
   ```bash
   python -m build
   ```

2. Publish to PyPI:
   ```bash
   python -m twine upload dist/*
   ```

3. Users can then install:
   ```bash
   pip install pymctp-your-extension
   ```

## Example: Sample Vendor Extension

See the [pymctp-sample-vendorextension](packages/pymctp-sample-vendorextension) package for a complete working example that demonstrates:

- Proper package structure
- Custom VDM (Vendor Defined Message) packet definitions
- Layer bindings with `bind_layers()`
- Entry point registration
- Documentation and comments
- Complete example implementation

Key files to review:
- [pyproject.toml](packages/pymctp-sample-vendorextension/pyproject.toml) - Entry point configuration
- [layers/__init__.py](packages/pymctp-sample-vendorextension/src/pymctp_sample_vendorextension/layers/__init__.py) - Entry point target
- [layers/mctp/sample_vendor.py](packages/pymctp-sample-vendorextension/src/pymctp_sample_vendorextension/layers/mctp/sample_vendor.py) - Complete packet definitions and bindings
- [README.md](packages/pymctp-sample-vendorextension/README.md) - Usage guide

## Troubleshooting

### Extension Not Loading

1. Verify entry point is registered correctly in `pyproject.toml`
2. Check the module path is correct and importable
3. Ensure the extension package is installed: `pip list | grep pymctp`
4. Enable logging to see load errors:
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   from pymctp.layers.plugin_loader import discover_and_load_extensions
   discover_and_load_extensions()
   ```

### Import Errors

- Ensure `pymctp` is listed in your extension's `dependencies`
- Verify all pymctp imports use absolute paths: `from pymctp.layers import ...`
- Don't use relative imports to reference pymctp code

### Layer Bindings Not Working

- Verify your decorators or `bind_layers()` calls are executed when the module is imported
- Check that you're using the correct field names and values for binding
- Test layer bindings explicitly:
  ```python
  from scapy.layers.all import bind_layers
  from pymctp.layers.mctp.vdpci import VdPciHdrPacket

  # Check if binding exists
  print(VdPciHdrPacket._overload_fields)
  ```


## Endpoint Roles and Behaviors

Endpoint roles are named bundles of `Behavior` instances that are attached to a `RoleBasedEndpointAM`. A behavior can be a responder, an initiator, or both. Responder behaviors claim inbound packets with `can_handle()` and return a `HandlerResponse` from `handle()`. Initiator behaviors use the lifecycle hooks to send traffic once the answering machine's sniffer is live.

Built-in roles are:

- `simple` - no extra behaviors; use the default reply path.
- `bridge` - attaches `BridgeBehavior` and answers bridge/routing control commands.
- `bus-owner` - attaches `BusOwnerBehavior` and can run DSP0236 discovery.
- `spdm-responder` - attaches `SpdmResponderBehavior`; answers the SPDM attestation flow (GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS, GET_DIGESTS, GET_CERTIFICATE, CHALLENGE, GET_MEASUREMENTS).
- `cerberus-rot` - attaches `CerberusChallengeBehavior`; answers the Cerberus Challenge Protocol over MCTP VDM/PCI.
- `pldm-base` - attaches `PldmBaseBehavior`; answers PLDM Type 0 (GetTID, SetTID, GetPLDMTypes, GetPLDMVersion, GetPLDMCommands).
- `pldm-sensor` - attaches `PldmBaseBehavior` **and** `PldmSensorBehavior`, so a sensor endpoint is discoverable as well as pollable. Configure sensors with `role_options={"pldm-sensor": {"sensors": {...}}}`.

Roles are additive, so a Root-of-Trust endpoint typically combines several, e.g. `roles=["cerberus-rot", "spdm-responder"]`.

The `spdm-responder` and `cerberus-rot` roles sign with a **deterministic mock signer** by default: these behaviors exist to exercise a requester's state machine, not to provide real attestation. Both expose a pluggable `signer` so a caller can substitute real crypto. See their module docstrings.

Every responder behavior gates on the message type being present in `ctx.supported_msg_types` — declare `SPDM`, `VDPCI`, or `PLDM` on the endpoint context or the role will be silently inert.

`BridgeBehavior.on_attach()` now sets `ctx.is_bridge`, not `ctx.is_bus_owner`. Bridge and routing control commands gate on `ctx.supports_bridging`, which is true when `ctx.is_bridge` or `ctx.is_bus_owner` is true. This preserves older contexts that only set `is_bus_owner`, while allowing a bridge that is not the bus owner.

### Behavior Lifecycle

| Hook | When it runs | Typical use |
| --- | --- | --- |
| `on_bind(am, ctx)` | The behavior is bound to a `RoleBasedEndpointAM`; the socket is not live yet. | Save `am` or `am.session` for programmatic calls such as `rediscover()`. |
| `on_attach(ctx)` | The behavior is added to the endpoint. | Initialize `ctx.msg_type_context[self.name]` or set context flags such as `is_bridge`. |
| `on_start(am, ctx)` | The sniffer has started and packets can flow. | Start initiator work on a daemon thread. Do not block this hook. |
| `on_stop(am, ctx)` | The sniffer has stopped. | Signal and join background workers. |
| `on_detach(ctx)` | The behavior is removed from the endpoint. | Clean up per-behavior state. |

`RoleBasedEndpointAM.add_behavior()` calls `on_bind()` and `on_attach()`. If the endpoint is already running, it also calls `on_start()`. `remove_behavior()` calls `on_stop()` before `on_detach()` when needed. `RoleBasedEndpointAM.get_behavior(name)` returns the attached behavior with that `name`, or `None`.

### Responder Behaviors

Responder behaviors should return a complete reply packet or packet list. Use `build_layered_reply(pkt, ctx, payload)` to rebuild the MCTP transport header and, when the link has one, the physical framing layer. Point-to-point links such as I3C and the TIP mailbox have no SMBus/UART wrapper, so the helper skips the physical step.

```python
from scapy.packet import Packet

from pymctp.automaton.behaviors.base import Behavior
from pymctp.automaton.behaviors.replies import build_layered_reply
from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers.mctp.transport import TransportHdrPacket
from pymctp.layers.mctp.types import EndpointContext, MsgTypes


class RawVendorEchoBehavior(Behavior):
    @property
    def name(self) -> str:
        return "raw-vendor-echo"

    def can_handle(self, pkt: Packet, ctx: EndpointContext) -> bool:
        transport = pkt.getlayer(TransportHdrPacket)
        return bool(transport and transport.msg_type == MsgTypes.VDPCI)

    def handle(self, pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        transport = pkt.getlayer(TransportHdrPacket)
        payload = bytes(transport.payload)
        reply = build_layered_reply(pkt, ctx, payload)
        return HandlerResponse(stop_processing=True, reply=reply)
```

Use `layered_reply_response(pkt, ctx, payload)` when you want the same helper wrapped directly in a `HandlerResponse`.

### Initiator Behaviors

`on_start(am, ctx)` is the first safe place to originate traffic because it runs from the sniffer's `started_callback`. Start long-running discovery, polling, or heartbeat logic on a daemon thread and stop it from `on_stop()`.

When an answering machine owns the socket, use `am.session.sndrcv_control_msg(..., threaded=True)` or `am.session.sndrcv_mctp_msg(..., threaded=True)`. The sniffer is already receiving from the socket; `threaded=True` queues a pending request and lets `EndpointSession.on_packet_received()` match the response instead of trying to run a second blocking receive loop on the same socket.

```python
from __future__ import annotations

import threading

from scapy.packet import Packet

from pymctp.automaton.behaviors.base import Behavior
from pymctp.layers.mctp.control import GetEndpointID
from pymctp.layers.mctp.types import EndpointContext, Smbus7bitAddress


class PollEndpointIdBehavior(Behavior):
    def __init__(self, dst_eid: int, dst_phy_addr: Smbus7bitAddress, interval_s: float = 5.0) -> None:
        self.dst_eid = dst_eid
        self.dst_phy_addr = dst_phy_addr
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def name(self) -> str:
        return "poll-endpoint-id"

    def can_handle(self, pkt: Packet, ctx: EndpointContext) -> bool:
        return False

    def handle(self, pkt: Packet, ctx: EndpointContext) -> None:
        return None

    def on_start(self, am, ctx: EndpointContext) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, args=(am,), daemon=True)
        self._thread.start()

    def on_stop(self, am, ctx: EndpointContext) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _run(self, am) -> None:
        while not self._stop.wait(self.interval_s):
            rsp = am.session.sndrcv_control_msg(
                GetEndpointID(),
                dst_eid=self.dst_eid,
                dst_phy_addr=self.dst_phy_addr,
                timeout_s=1.0,
                threaded=True,
            )
            if rsp is not None:
                print(rsp.summary())
```

### Bus Owner Discovery Behavior

`BusOwnerBehavior` is an initiator behavior that runs the DSP0236 discovery flow. It accepts these keyword-only options:

- `targets: list[DiscoveryTarget] | list[dict] | None = None`
- `auto_discover: bool = True`
- `start_delay_s: float = 0.5`
- `timeout_s: float = 2.0`
- `retries: int = 1`
- `prepare_for_discovery: bool = True`
- `rediscover_on_notify: bool = True`
- `verify_routing_table: bool = True`

A `DiscoveryTarget` has `name`, `eid`, optional `physical_address`, optional `pool_start`, `pool_size`, and `is_bridge`. The sweep records `DiscoveryStep` entries in a `DiscoveryReport`. The step names are:

1. `prepare-for-endpoint-discovery`
2. `endpoint-discovery`
3. `get-endpoint-id`
4. `set-endpoint-id`
5. `allocate-endpoint-ids`
6. `get-mctp-version-support`
7. `get-message-type-support`
8. `get-routing-table-entries`

Call `rediscover(timeout_s=None, block=True)` to request a sweep, read the last report from `.report`, or append targets with `.add_target()`.

### Registering Roles

Role factories are registered under the `pymctp.roles` entry point group. The entry point callable returns a `dict[str, Callable[..., list[Behavior]]]`: role name to factory. A factory may accept keyword arguments. Bare role strings still call zero-argument factories.

```toml
[project.entry-points."pymctp.roles"]
my_roles = "my_package.roles:get_roles"
```

```python
from __future__ import annotations

from collections.abc import Callable

from pymctp.automaton.behaviors.base import Behavior
from pymctp.automaton.behaviors.bus_owner import BusOwnerBehavior
from pymctp.automaton.roles import RoleSpec, create_endpoint


def owner_role(*, targets: list[dict], timeout_s: float = 2.0) -> list[Behavior]:
    return [BusOwnerBehavior(targets=targets, timeout_s=timeout_s)]


def get_roles() -> dict[str, Callable[..., list[Behavior]]]:
    return {"lab-owner": owner_role}


am = create_endpoint(
    RoleSpec("lab-owner", {"targets": [{"name": "ep", "eid": 0x0F}], "timeout_s": 1.0}),
    context=ctx,
    session=session,
)
```

Serialized endpoint configs express parameterized roles with `role` plus `role_options`:

```json
{
  "role": ["bus-owner"],
  "role_options": {
    "bus-owner": {
      "targets": [{"name": "ep", "eid": 15, "physical_address": 32}],
      "timeout_s": 1.0
    }
  }
}
```

The lower-level helpers are `RoleSpec(name, options)`, `as_role_spec(role)`, `normalize_roles(roles, role_options)`, `register_role(name, factory)`, `list_roles()`, `get_behaviors_for_roles(*roles)`, and `create_endpoint(*roles, ...)`.

## Machine Topologies

Machine topologies describe a group of MCTP endpoints, their transport configs, EIDs, roles, and runtime defaults. They are serializable, so the same topology can be built in Python, loaded from JSON/YAML, or exposed by a plugin.

### Topology Model

| Type | Purpose |
| --- | --- |
| `DeviceSpec` | One endpoint. Key fields include `name`, `transport`, `eid` or `eid_key`, `physical_address`, `supported_msg_types`, `supported_vdm_msg_types`, `roles`, `role_options`, `pool_size`, `downstream`, `thread_kwargs`, `enabled`, and `context_overrides`. |
| `MachineSpec` | A complete topology with `name`, `description`, `devices`, `eids`, and `defaults`. Use `.device(name)`, `.device_names()`, `.with_eids(eids)`, `.resolve_eid(device)`, and `.validate()`. |
| `MachineDefaults` | Defaults applied when a `DeviceSpec` becomes an `EndpointConfig`: `thread_kwargs`, `dump_packet`, `dump_hex`, `host`, and `transport_defaults`. |
| `EidMap` | Logical names to EIDs plus bus-owner assignments. It contains `eids: dict[str, int]` and `assignments: list[EidAssignment]`. |
| `EidAssignment` | A bus-owner assignment with `target`, `eid`, optional `pool_start`, and `pool_size`. |

A `DeviceSpec` uses `roles` because a device can combine roles. When it is converted to an endpoint config, those become the endpoint `role` list plus `role_options` mapping consumed by `EndpointConfig.roles`.

### MachineBuilder

`MachineBuilder` is a fluent helper for creating validated `MachineSpec` objects:

```python
from pymctp.topology import MachineBuilder

spec = (
    MachineBuilder("lab-board", description="Two endpoints on a virtual bus")
    .defaults(host="127.0.0.1", timeout=60, dump_packet=False)
    .eids({"owner": 0x08, "ep1": 0x0F, "ep2": 0x10})
    .device(
        "owner",
        transport={"type": "i2c-stream", "port": 5570, "master": True, "target_address": 0x20},
        physical_address=0x20,
        roles=["bus-owner"],
        role_options={"bus-owner": {"targets": [{"name": "ep1", "eid": 0x0F, "physical_address": 0x21}]}},
    )
    .devices(
        ["ep1", "ep2"],
        lambda index, name: {"type": "i2c-stream", "port": 5571 + index, "name": name},
        physical_address=0x21,
        roles=["simple"],
    )
    .build()
)
```

Use `.defaults(...)` for shared thread, host, dump, and transport defaults; `.eids(...)` to merge logical EID names; `.device(...)` for one endpoint; `.devices(names, transport_factory, **common)` when only the transport differs by index/name; and `.build()` to validate and return a `MachineSpec`.

### JSON/YAML Specs and Overrides

Use `load_machine_spec(path_or_str)` for JSON/YAML files or serialized strings, `dump_machine_spec(spec, path=None)` to emit JSON or write JSON/YAML by suffix, and `load_eid_map(path)` to load an `EidMap`.

```json
{
  "name": "lab-board",
  "description": "Two endpoints on a virtual bus",
  "eids": {"eids": {"owner": 8, "ep1": 15}, "assignments": []},
  "devices": [
    {
      "name": "owner",
      "transport": {"type": "i2c-stream", "host": "127.0.0.1", "port": 5570},
      "physical_address": 32,
      "roles": ["bus-owner"],
      "role_options": {
        "bus-owner": {"targets": [{"name": "ep1", "eid": 15, "physical_address": 33}]}
      }
    },
    {"name": "ep1", "transport": {"type": "i2c-stream", "host": "127.0.0.1", "port": 5571}, "roles": ["simple"]}
  ]
}
```

Overrides use dotted keys. `parse_override_strings(["devices.ep1.transport.port=0x15c4"])` returns a nested mapping, and `apply_overrides(spec, overrides)` returns a new `MachineSpec`. The CLI exposes the same mechanism with repeatable `--set KEY=VALUE` and can merge a separate map with `--eid-map PATH`.

```bash
pymctp machine validate lab-board.yaml --eid-map lab-eids.yaml --set devices.ep1.transport.port=5572
pymctp machine show lab-board.yaml --json
```

### Machine Runtime

`Machine(spec, *, eids=None, start=False, verbose=False)` builds and runs endpoint managers from a topology. Use `build()` to create endpoints without starting sniffer threads, `start(timeout=5.0)` to build and start them, `stop(join=True, timeout=5.0)` to stop sniffers and close sockets, and `join(timeout=None)` to wait. `Machine` is also a context manager.

`start()` returns only once every endpoint's sniffer is live and its behaviors' `on_start()` hooks have run — `wait_until_started(timeout)` exposes the same wait and reports whether all endpoints came up. This matters because scapy's sniffer has a startup window in which a request sent (or a stop issued) by the caller would be lost: an endpoint torn down immediately after being started would otherwise keep sniffing until its own timeout expired. `stop()` likewise stops each sniffer, joins its thread, and only then closes the socket, so the file descriptor is never pulled out from under a live `select()`.

```python
from pymctp.topology import Machine

with Machine(spec) as machine:
    owner = machine["owner"]
    ep1 = machine.ep1
    print(machine.summary())
```

`machine.bus_owner` returns the first attached `bus-owner` behavior as a handle when one exists. The handle exposes `.rediscover(timeout_s=None)`, `.report`, and `.routing_table`.

The `pymctp machine` CLI has these subcommands:

```bash
pymctp machine list --json
pymctp machine show lab-board.yaml --eid-map lab-eids.yaml --set devices.ep1.enabled=false
pymctp machine run lab-board.yaml --rediscover --timeout 30
pymctp machine validate lab-board.yaml
```

`show`, `run`, and `validate` accept a registered machine name or a `.json`, `.yaml`, or `.yml` spec file. `run` also supports `--shell`, `--no-start`, `--rediscover`, and `--timeout SECONDS`.

### Registering Machines

Machine plugins use the `pymctp.machines` entry point group. The entry point callable returns a `dict[str, Callable[..., MachineSpec]]`.

```toml
[project.entry-points."pymctp.machines"]
my_machines = "my_package.machines:get_machines"
```

```python
from __future__ import annotations

from collections.abc import Callable

from pymctp.topology import MachineBuilder, MachineSpec


def lab_board(**options) -> MachineSpec:
    return (
        MachineBuilder("lab-board", description=options.get("description", "Lab board"))
        .eids({"owner": 0x08, "ep": 0x0F})
        .device("owner", transport={"type": "i2c-stream", "port": 5570}, roles=["bus-owner"])
        .device("ep", transport={"type": "i2c-stream", "port": 5571}, roles=["simple"])
        .build()
    )


def get_machines() -> dict[str, Callable[..., MachineSpec]]:
    return {"lab-board": lab_board}
```

Installed machines appear in `pymctp machine list`, can be inspected with `pymctp machine show lab-board`, and can be run with `pymctp machine run lab-board`.

## Entry Point Groups

| Group | Entry point target |
| --- | --- |
| `pymctp.extensions` | Module imported to register layer bindings and exposed under `pymctp.oem.<entry_name>`. |
| `pymctp.exercisers` | Module imported to call `register_exerciser(name, exerciser_class)`. |
| `pymctp.cli_commands` | Click command or command group loaded by the `pymctp` CLI. |
| `pymctp.analyzer_rules` | Callable returning `list[AnalysisRule]`; the loader also accepts a single `AnalysisRule`. |
| `pymctp.compliance_tests` | Module imported to register compliance tests. |
| `pymctp.roles` | Callable returning `dict[str, Callable[..., list[Behavior]]]`. |
| `pymctp.behaviors` | Callable returning `list[Behavior]` or a single `Behavior`. |
| `pymctp.machines` | Callable returning `dict[str, Callable[..., MachineSpec]]`. |

## CLI Extensions

In addition to layer extensions, you can also extend the `pymctp` command-line interface with custom commands!

Extension packages can add their own CLI commands that automatically appear in the `pymctp` command-line tool. This is useful for vendor-specific analysis tools, packet crafting utilities, or custom workflows.

### Quick Example

Add CLI commands to your extension by:

1. Creating Click commands in your package:
```python
# your_package/cli/commands.py
import click

@click.command()
def my_command():
    """My custom command."""
    click.echo("Hello from my extension!")
```

2. Registering them in `pyproject.toml`:
```toml
[project.entry-points."pymctp.cli_commands"]
my-command = "your_package.cli.commands:my_command"
```

3. Installing your package:
```bash
pip install your-package
pymctp my-command  # Your command is now available!
```

### Full Documentation

For complete details on creating CLI extensions, including:
- Single commands vs. command groups
- Best practices for naming and organization
- Error handling and help text
- Complete examples

See the dedicated [CLI-EXTENSIONS.md](CLI-EXTENSIONS.md) guide.

### Example Implementation

The [pymctp-sample-vendorextension](packages/pymctp-sample-vendorextension) package includes example CLI extensions:
- Single command: `craft-sample-vendor`
- Command group: `sample-vendor` with subcommands

Check these files:
- [cli/sample_commands.py](packages/pymctp-sample-vendorextension/src/pymctp_sample_vendorextension/cli/sample_commands.py) - CLI implementations
- [pyproject.toml](packages/pymctp-sample-vendorextension/pyproject.toml) - Entry point registration

## Additional Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Click Documentation](https://click.palletsprojects.com/) - CLI framework
- [Python Packaging Guide](https://packaging.python.org/)
- [Entry Points Specification](https://packaging.python.org/specifications/entry-points/)
- [PyMCTP Repository](https://github.com/jls5177/pymctp)
- [CLI Extensions Guide](CLI-EXTENSIONS.md) - Detailed CLI extension documentation
