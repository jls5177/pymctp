# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import argparse
import functools
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from scapy.config import conf
from scapy.packet import Packet

from pymctp.automaton.manager import EndpointManager
from pymctp.automaton.sessions import EndpointSession, HandlerResponse
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import DiscoveryNotify, SetEndpointIDPacket
from pymctp.layers.mctp.vdpci import VdPCIVendorIds, VdPciHdr

from pymctp_oem_microsoft.layers import MsftVdmBaseCmdCodes, MsftVdmCommandSets, MsftVdmProtocolPacket
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm import MsftVdmRotCmdCodes
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.base import (
    CapNegotiationRequestPacket,
    CapNegotiationResponsePacket,
    CmdSetEntryPacket,
    CmdSetSupportRequestPacket,
    CmdSetSupportResponsePacket,
    HeartbeatControlRequestPacket,
    HeartbeatRequestPacket,
    ProtocolVersionPacket,
)
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.rot import (
    GetRotCapabilitiesRequestPacket,
    GetRotCapabilitiesResponsePacket,
)

thread_kwargs = {
    "count": 0,  # let the answering machine process an unlimited number of requests
    "timeout": 30 * 60,
    "bg": False,
}

# Two aardvark adapters emulating the CMC (host) and OMC (BMC-facing) endpoints of a C41A8 platform.
cmc1_config = {
    "context": {
        "physical_address": {
            "address": 0xAA >> 1,
        },
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.VDPCI,
        ],
        "assigned_eid": 16,
        "is_bus_owner": False,
        "supported_vdm_msg_types": [
            {
                "vendor_id": 0x1414,
            },
        ],
        "endpoint_uuid": "3573337f-6722-4bcb-ae4e-89bb63b184b0",
    },
    "config": {
        "type": "aardvark",
        "slave_address": 0xAA >> 1,
        "serial_number": "2239-233725",
        "name": "CMC1",
        "dump_packet": False,
        "dump_hex": False,
        "enable_pullups": True,
        "slave_only": False,
    },
    "thread_kwargs": thread_kwargs,
}

omc1_config = {
    "context": {
        "physical_address": {
            "address": 0x73,
        },
        # "static_eid": 66,
        "mtu_size": 64 + 4 + 4,
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.VDPCI,
        ],
        "endpoint_uuid": "9272dada-70bd-4e11-bb89-5e5714033d42",
    },
    "config": {
        "type": "aardvark",
        "slave_address": 0x73,
        "serial_number": "2237-704808",
        "name": "OMC1",
        "dump_packet": True,
        "dump_hex": True,
        "enable_pullups": True,
        "slave_only": False,
    },
    "thread_kwargs": thread_kwargs,
}


def make_mvdp_reply(pkt: Packet, ctx: EndpointContext, resp: Packet) -> HandlerResponse:
    """Wraps an MVDP response payload with the VdPCI/transport/smbus layers of the originating request."""
    vdm_req = pkt.getlayer(VdPciHdrPacket)
    transport_pkt = pkt.getlayer(TransportHdrPacket)
    smbus_layer = pkt.getlayer(SmbusTransportPacket)
    rsp_pkt = (
        VdPciHdr(
            rq=True,
            vendor_id=vdm_req.vendor_id,
            vdm_cmd_code=vdm_req.vdm_cmd_code,
        )
        / resp
    )
    transport_rsp = transport_pkt.build_reply(ctx, rsp_pkt)
    smbus_rsp = smbus_layer.build_reply(ctx, transport_rsp)
    return HandlerResponse(stop_processing=True, reply=smbus_rsp)


@dataclass(frozen=True)
class MvdpCommand:
    """Declarative binding between an MVDP request layer and the logic that builds its response."""

    request_cls: type[Packet]
    label: str
    build_response: Callable[[Packet, EndpointContext], Packet]


def register_mvdp_commands(session: EndpointSession, commands: Sequence[MvdpCommand]) -> None:
    """Registers every MvdpCommand on the session, sharing the same logging/reply-building envelope."""
    for command in commands:

        def handler(pkt: Packet, ctx: EndpointContext, _cmd: MvdpCommand = command) -> HandlerResponse:
            print(f"{_cmd.label}: {pkt.summary()}")
            resp = _cmd.build_response(pkt, ctx)
            return make_mvdp_reply(pkt, ctx, resp)

        session.register_handler(command.request_cls, handler)


def main(args) -> int:
    conf.debug_dissector = 4

    omc1_config["thread_kwargs"] = {
        "count": args.count,
        "timeout": args.timeout or None,
        "bg": args.bg,
    }

    # cmc1 = EndpointManager.from_config(cmc1_config, start_thread=True)
    omc1 = EndpointManager.from_config(omc1_config, start_thread=True)
    devices = [
        # cmc1,
        omc1
    ]

    # start a daemon thread to gracefully kill the AM on "ctrl+C"
    def monitor_thread():
        main_thread = threading.main_thread()
        main_thread.join()

        for device in devices:
            device.am.stop_sniffer(join=True)
            print(f"{device.socket.id_str} processed {device.am.sniffer.count} packets")
        print("Exiting program...")

    monitor = threading.Thread(target=monitor_thread)
    monitor.daemon = True
    monitor.start()

    start_heartbeat = threading.Event()

    def build_cap_negotiation_response(pkt: Packet, ctx: EndpointContext) -> Packet:
        return MsftVdmProtocolPacket(
            cmd_set=MsftVdmCommandSets.BASE,
            protocol_version=0,
            cmd=MsftVdmBaseCmdCodes.CAP_NEGOTIATION,
            completion_code=0,
        ) / CapNegotiationResponsePacket(
            max_message_size=4096, max_packet_size=247, message_timeout=100, feature_flags=0x02 if args.enable_hb else 0
        )

    def build_heartbeat_ctrl_response(pkt: Packet, ctx: EndpointContext) -> Packet:
        if args.enable_hb:
            start_heartbeat.set()
        return MsftVdmProtocolPacket(
            cmd_set=MsftVdmCommandSets.BASE,
            protocol_version=0,
            cmd=MsftVdmBaseCmdCodes.HEARTBEAT_CTRL,
            completion_code=0,
        )

    def build_rot_caps_response(pkt: Packet, ctx: EndpointContext) -> Packet:
        return MsftVdmProtocolPacket(
            cmd_set=MsftVdmCommandSets.ROT,
            protocol_version=0,
            cmd=MsftVdmRotCmdCodes.GET_ROT_CAPABILITIES,
            completion_code=0,
        ) / GetRotCapabilitiesResponsePacket(feature_flags=0x0)

    def build_cmd_set_support_response(pkt: Packet, ctx: EndpointContext) -> Packet:
        return MsftVdmProtocolPacket(
            cmd_set=MsftVdmCommandSets.BASE,
            protocol_version=0,
            cmd=MsftVdmBaseCmdCodes.CMD_SET_SUPPORT,
            completion_code=0,
        ) / CmdSetSupportResponsePacket(
            next_list_entry=0xFF,
            entries=[
                CmdSetEntryPacket(
                    cmd_set_id=MsftVdmCommandSets.BASE,
                    version_count=1,
                    versions=[ProtocolVersionPacket(major=0, minor=0)],
                ),
                CmdSetEntryPacket(
                    cmd_set_id=MsftVdmCommandSets.ROT,
                    version_count=1,
                    versions=[ProtocolVersionPacket(major=0, minor=0)],
                ),
            ],
        )

    # add new MVDP commands here: one builder function above + one entry below.
    mvdp_commands = [
        MvdpCommand(CapNegotiationRequestPacket, "GetMvdpCaps", build_cap_negotiation_response),
        MvdpCommand(HeartbeatControlRequestPacket, "StartHeartbeat", build_heartbeat_ctrl_response),
        MvdpCommand(GetRotCapabilitiesRequestPacket, "RoTCapsReq", build_rot_caps_response),
        MvdpCommand(CmdSetSupportRequestPacket, "CmdSetSupportRequest", build_cmd_set_support_response),
    ]
    register_mvdp_commands(omc1.session, mvdp_commands)

    def handle_set_endpoint_id(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        print(f"SetEndpointID: {pkt.summary()}")
        return HandlerResponse(stop_processing=False, reply=None)

    omc1.session.register_handler(SetEndpointIDPacket, handle_set_endpoint_id)

    bmc_addr = Smbus7bitAddress(0x10)

    if args.send_discovery_notify:
        print("Sending DiscoveryNotify ...")
        resp = omc1.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0A, dst_phy_addr=bmc_addr, timeout_s=0.3)
        if resp:
            print("DiscoveryNotify response: ")
            resp.show2()

    print("Setup complete.... waiting for request")

    while monitor.is_alive():
        if start_heartbeat.is_set():
            print("Sending heartbeat")
            req = (
                VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=1, vdm_cmd_code=0xFF)
                / MsftVdmProtocolPacket(
                    cmd_set=MsftVdmCommandSets.BASE, protocol_version=0, cmd=MsftVdmBaseCmdCodes.HEARTBEAT
                )
                / HeartbeatRequestPacket(timeout=15, cpu_count=0, health_entries=[0x00])
            )
            resp = omc1.session.sndrcv_mctp_msg(
                req,
                msg_type=MsgTypes.VDPCI,
                msg_tag=0x3,
                dst_eid=0x0A,
                dst_phy_addr=bmc_addr,
                timeout_s=0.5,
                threaded=True,
            )
            if resp:
                print(f"Heartbeat response: \n\t{resp.summary()}")
        time.sleep(3)

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-c", "--count", help="Max number of packets to answer", default=0, required=False, action="store", dest="count"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Max runtime (in seconds), default unlimited",
        default=0,
        type=int,
        required=False,
        action="store",
        dest="timeout",
    )
    parser.add_argument("-b", "--bg", dest="bg", default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument(
        "-d", "--dn", dest="send_discovery_notify", default=False, action=argparse.BooleanOptionalAction
    )
    parser.add_argument(
        "-e",
        "--hb",
        dest="enable_hb",
        default=False,
        action=argparse.BooleanOptionalAction,
        help="Advertise and start sending MVDP heartbeats",
    )

    args = parser.parse_args()
    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        raise e
