# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Example endpoint setup using the QEMU I3C/I2C TCP "stream" transports.

Unlike the UDP-based examples (``l4a40_qemu.py`` / ``l4a40_qemu_netdev2.py``)
which use a pair of UDP ports (``in_port``/``out_port``) per endpoint, the
stream transports use a *single* bidirectional TCP connection per endpoint:
QEMU listens as the TCP server (``server=on``) and PyMCTP connects as the
client. See ``packages/pymctp-exerciser-qemu/README.md`` for the full wire
protocol and QEMU invocation reference.

This example is kept under ``docs/examples/`` (rather than the repo-root
``examples/``, which is gitignored as local/environment-specific scratch
space — see the "keep local examples out of the repository" commit) so it
stays tracked and reviewable, while remaining directly runnable.

The L4A40 board's I2C endpoints (HSP1-4 @ 0x58, HN @ 0x10) use the
``i2c-target-remote`` device's *master* mode (peer-as-master / multi-master,
like the old UDP ``i2c-netdev`` transport) rather than the slave/target
model: each endpoint masters its own (virtual) I2C bus to deliver packets to
the BMC, instead of waiting to be read from. ``target_address`` below is the
BMC-side SMBus address each endpoint masters writes to on its own bus,
following the same per-endpoint addressing used by the older UDP examples
(``examples/l4a40_qemu_netdev2.py`` / ``examples/l4a40_aardvark.py``): HN
(the renamed LION/MAN1 management-network endpoint) targets BMC address
0x10, while the HSP endpoints target BMC address 0x12.

Illustrative QEMU invocation for this example's ports::

    qemu-system-arm ... \\
        -device i3c-target-remote,bus=i3c0,port=5556,server=on \\
        -device i2c-target-remote,bus=i2c0,address=0x58,port=5570,server=on,master=on \\
        -device i2c-target-remote,bus=i2c1,address=0x58,port=5571,server=on,master=on \\
        -device i2c-target-remote,bus=i2c2,address=0x58,port=5572,server=on,master=on \\
        -device i2c-target-remote,bus=i2c3,address=0x58,port=5573,server=on,master=on \\
        -device i2c-target-remote,bus=i2c4,address=0x10,port=5574,server=on,master=on \\
        -device i3c-target-remote,bus=i3c1,port=5558,server=on \\
        -device i3c-target-remote,bus=i3c2,port=5559,server=on \\
        -device i3c-target-remote,bus=i3c3,port=5560,server=on
"""

import pathlib
import sys

from pymctp.automaton.manager import ConfigTypes, EndpointManager
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import DiscoveryNotify
from pymctp.utils import set_printable_raw_layer

thread_kwargs = {
    "count": 0,  # let the answering machine process an unlimited number of requests
    "timeout": 30 * 60,
    "bg": False,
}

# HSP1-4: SMBus/I2C target-remote endpoints in *master* mode (QEMU I2C buses
# 0-3, each endpoint's own target address 0x58). Each masters its own bus to
# deliver packets to the BMC at target_address 0x12 (matching the BMC target
# address used for HSP endpoints in the older UDP examples). A single TCP
# port per endpoint; QEMU listens, PyMCTP connects as the client.
hsp1_config = {
    "context": {
        "physical_address": {
            "address": 0xB0 >> 1,
        },
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.PLDM,
        ],
        "assigned_eid": 34,
    },
    "config": {
        "type": ConfigTypes.I2CStream,
        "host": "localhost",
        "port": 5570,
        "name": "HSP1",
        "dump_packet": True,
        "dump_hex": False,
        "master": True,
        "target_address": 0x12,
    },
    "thread_kwargs": thread_kwargs,
}

hsp2_config = {
    "context": {
        "physical_address": {
            "address": 0xB0 >> 1,
        },
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.PLDM,
        ],
        "assigned_eid": 35,
    },
    "config": {
        "type": ConfigTypes.I2CStream,
        "host": "localhost",
        "port": 5571,
        "name": "HSP2",
        "dump_packet": True,
        "dump_hex": False,
        "master": True,
        "target_address": 0x12,
    },
    "thread_kwargs": thread_kwargs,
}

hsp3_config = {
    "context": {
        "physical_address": {
            "address": 0xB0 >> 1,
        },
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.PLDM,
        ],
        "assigned_eid": 36,
    },
    "config": {
        "type": ConfigTypes.I2CStream,
        "host": "localhost",
        "port": 5572,
        "name": "HSP3",
        "dump_packet": True,
        "dump_hex": False,
        "master": True,
        "target_address": 0x12,
    },
    "thread_kwargs": thread_kwargs,
}

hsp4_config = {
    "context": {
        "physical_address": {
            "address": 0xB0 >> 1,
        },
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.PLDM,
        ],
        "assigned_eid": 37,
    },
    "config": {
        "type": ConfigTypes.I2CStream,
        "host": "localhost",
        "port": 5573,
        "name": "HSP4",
        "dump_packet": True,
        "dump_hex": False,
        "master": True,
        "target_address": 0x12,
    },
    "thread_kwargs": thread_kwargs,
}

# HN: SMBus/I2C target-remote endpoint in *master* mode (own target address
# 0x10), the renamed LION/MAN1 management-network endpoint. Masters its own
# bus to deliver packets to the BMC at target_address 0x10 (matching the BMC
# target address used for LION in the older UDP examples).
hn_config = {
    "context": {
        "physical_address": {
            "address": 0x10,
        },
        "supported_msg_types": [
            MsgTypes.CTRL,
        ],
        "assigned_eid": 66,
    },
    "config": {
        "type": ConfigTypes.I2CStream,
        "host": "localhost",
        "port": 5574,
        "name": "HN",
        "dump_packet": True,
        "dump_hex": False,
        "master": True,
        "target_address": 0x10,
    },
    "thread_kwargs": thread_kwargs,
}


# HCP0-HCP3: I3C target-remote endpoints on I3C buses 0-3. I3C addresses are
# dynamically assigned via ENTDAA, so physical_address is not set. Each
# endpoint uses a single TCP port (one per bus); QEMU listens, PyMCTP
# connects as the client.
hcp0_config = {
    "context": {
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.PLDM,
        ],
        "assigned_eid": 38,
    },
    "config": {
        "type": ConfigTypes.I3CStream,
        "host": "localhost",
        "port": 5556,
        "name": "HCP0",
        "dump_packet": True,
        "dump_hex": True,
    },
    "thread_kwargs": thread_kwargs,
}

hcp1_config = {
    "context": {
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.PLDM,
        ],
        "assigned_eid": 39,
    },
    "config": {
        "type": ConfigTypes.I3CStream,
        "host": "localhost",
        "port": 5558,
        "name": "HCP1",
        "dump_packet": True,
        "dump_hex": False,
    },
    "thread_kwargs": thread_kwargs,
}

hcp2_config = {
    "context": {
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.PLDM,
        ],
        "assigned_eid": 40,
    },
    "config": {
        "type": ConfigTypes.I3CStream,
        "host": "localhost",
        "port": 5559,
        "name": "HCP2",
        "dump_packet": True,
        "dump_hex": False,
    },
    "thread_kwargs": thread_kwargs,
}

hcp3_config = {
    "context": {
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.PLDM,
        ],
        "assigned_eid": 41,
    },
    "config": {
        "type": ConfigTypes.I3CStream,
        "host": "localhost",
        "port": 5560,
        "name": "HCP3",
        "dump_packet": True,
        "dump_hex": False,
    },
    "thread_kwargs": thread_kwargs,
}


if __name__ == "__main__":
    send_discovery_notify = (sys.argv[1] in (1, "1", True, "true", "True")) if len(sys.argv) > 1 else False
    start_threads = True

    set_printable_raw_layer()

    hsp1 = EndpointManager.from_config(hsp1_config, start_thread=start_threads)
    hsp2 = EndpointManager.from_config(hsp2_config, start_thread=start_threads)
    hsp3 = EndpointManager.from_config(hsp3_config, start_thread=start_threads)
    hsp4 = EndpointManager.from_config(hsp4_config, start_thread=start_threads)
    hn = EndpointManager.from_config(hn_config, start_thread=start_threads)
    hcp0 = EndpointManager.from_config(hcp0_config, start_thread=start_threads)
    hcp1 = EndpointManager.from_config(hcp1_config, start_thread=start_threads)
    hcp2 = EndpointManager.from_config(hcp2_config, start_thread=start_threads)
    hcp3 = EndpointManager.from_config(hcp3_config, start_thread=start_threads)
    if len(sys.argv) > 2:
        pcap_file = pathlib.Path(sys.argv[2])
        import_pcap_dump(pcap_file, False, hsp1.config.context)

    if send_discovery_notify:
        # The DiscoveryNotify goes to the BMC's SMBus address on this HSP bus
        # (hsp1's configured target_address, 0x12). In master mode the QEMU
        # i2c-target-remote masters the bus to this address and the packet's PEC
        # is computed over it, so it must match the real BMC target address.
        bmc_addr = hsp1_config["config"]["target_address"]
        resp = hsp1.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0A, timeout_s=5,
                                               dst_phy_addr=Smbus7bitAddress(bmc_addr))
        if resp:
            print("DiscoveryNotify response: ")
            resp.show2()

    print("Setup complete....")
