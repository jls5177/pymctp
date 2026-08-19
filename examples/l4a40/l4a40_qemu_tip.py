# SPDX-FileCopyrightText: 2026 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Runnable TIP endpoint mock using the QEMU NPCM8xx mailbox stream transport.

QEMU listens as the TCP server and PyMCTP connects as the TCP client. If QEMU
is running in a container, publish the TIP mailbox port to the host, e.g.
``-p 5580:5580``. Illustrative QEMU device option::

    qemu-system-aarch64 ... \\
        -device npcm8xx-tip-mbox,port=5580,server=on

The mailbox DATA frame body starts at SMBus command code 0x0F. The omitted
SMBus destination address byte is still included in PEC generation by the
transport.

The TIP mailbox transport lives in the Microsoft OEM package; importing
``pymctp_oem_microsoft.exerciser`` registers it under the exerciser name
``qemu-tip-mbox-stream`` so the core ``EndpointManager`` can resolve it.

Run with optional host/port arguments::

    python examples/l4a40/l4a40_qemu_tip.py [host] [port]
"""

from __future__ import annotations

import argparse

import pymctp_oem_microsoft.exerciser  # noqa: F401  (registers qemu-tip-mbox-stream + config)
from pymctp.automaton.manager import EndpointManager
from pymctp.layers.mctp import *  # noqa: F403
from pymctp.layers.mctp.control import DiscoveryNotify
from pymctp.utils import set_printable_raw_layer

# Config-type discriminator registered by pymctp_oem_microsoft.exerciser.config.
TIP_MBOX_STREAM_TYPE = "tip-mbox-stream"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5580
DEFAULT_TIMEOUT_S = 30 * 60
BMC_ADDR = 0x10
BMC_EID = 0x0F
TIP_ADDR = 0x41
TIP_EID = 0x20

# The BMC-side MCTP EID on this platform is 0x0F. This single PyMCTP endpoint
# mocks the TIP firmware endpoint at physical SMBus address 0x41 and assigned
# EID 0x20.


def build_tip_config(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    dump_packet: bool = True,
    dump_hex: bool = False,
) -> dict:
    return {
        "context": {
            "physical_address": {
                "address": TIP_ADDR,
            },
            "supported_msg_types": [
                MsgTypes.CTRL,
            ],
            "assigned_eid": TIP_EID,
        },
        "config": {
            "type": TIP_MBOX_STREAM_TYPE,
            "host": host,
            "port": port,
            "name": "TIP",
            "dump_packet": dump_packet,
            "dump_hex": dump_hex,
            "bmc_addr": BMC_ADDR,
            "tip_addr": TIP_ADDR,
        },
        "thread_kwargs": {
            "count": 0,
            "timeout": timeout_s,
            "bg": False,
        },
    }


tip_config = build_tip_config()


def run_tip_mock(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    send_discovery_notify: bool = False,
) -> EndpointManager:
    """Connect to QEMU and run the TIP MCTP control responder."""
    set_printable_raw_layer()
    cfg = build_tip_config(host=host, port=port, timeout_s=timeout_s)
    tip = EndpointManager.from_config(cfg, start_thread=True)

    print(
        f"TIP mailbox mock connected to {host}:{port}; "
        f"TIP addr=0x{TIP_ADDR:02x}, BMC addr=0x{BMC_ADDR:02x}, EID=0x{TIP_EID:02x}."
    )
    print("Responder is running for MCTP control requests. Press Ctrl-C to stop.")

    if send_discovery_notify:
        resp = tip.session.sndrcv_control_msg(
            DiscoveryNotify(),
            dst_eid=BMC_EID,
            timeout_s=5,
            dst_phy_addr=Smbus7bitAddress(BMC_ADDR),  # noqa: F405
        )
        if resp:
            print("DiscoveryNotify response: ")
            resp.show2()

    try:
        tip.thread.join()
    except KeyboardInterrupt:
        print("\nStopping TIP mailbox mock.")
    finally:
        if tip.am.sniffer is not None and tip.am.sniffer.running:
            tip.stop_sniffer()
        tip.socket.close()

    return tip


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a PyMCTP TIP mailbox mock for QEMU npcm8xx-tip-mbox.")
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST, help=f"QEMU host (default: {DEFAULT_HOST})")
    parser.add_argument("port", nargs="?", default=DEFAULT_PORT, type=int, help=f"QEMU port (default: {DEFAULT_PORT})")
    parser.add_argument(
        "--timeout",
        default=DEFAULT_TIMEOUT_S,
        type=float,
        help=f"responder timeout in seconds (default: {DEFAULT_TIMEOUT_S:g})",
    )
    parser.add_argument(
        "--discovery-notify",
        action="store_true",
        help="send an initial DiscoveryNotify to the BMC after connecting",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()
    run_tip_mock(
        host=args.host,
        port=args.port,
        timeout_s=args.timeout,
        send_discovery_notify=args.discovery_notify,
    )
