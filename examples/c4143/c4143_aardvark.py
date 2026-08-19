# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import argparse
import functools
import sys
import threading
import time

# import crc8
from pymctp.layers.mctp.vdpci import VdPCIVendorIds, VdPciHdr

from scapy.config import conf
from scapy.packet import Packet, Raw
from scapy.utils import hexdump

from pymctp.automaton.manager import EndpointManager
from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import (
    SetEndpointIDPacket,
    GetRoutingTableEntries,
    GetMctpVersionSupport,
    DiscoveryNotify,
)
from pymctp.utils import str_to_bytes

from pymctp_oem_microsoft.layers import (
    MsftVdmCommandSets,
    MsftVdmBmcCmdCodes,
    MsftVdmProtocolPacket,
    MsftVdmBaseCmdCodes,
)
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm import MsftVdmRotCmdCodes
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.base import (
    HeartbeatRequestPacket,
    CapNegotiationRequestPacket,
    CapNegotiationResponsePacket,
    HeartbeatControlRequestPacket,
    CmdSetSupportRequestPacket,
    CmdSetSupportResponsePacket,
    CmdSetEntryPacket,
    ProtocolVersionPacket,
)
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.bmc import GetSystemDevicesRequestPacket
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.rot import (
    GetRotCapabilitiesResponsePacket,
    GetRotCapabilitiesRequestPacket,
)

thread_kwargs = {
    "count": 0,  # let the answering machine process an unlimited number of requests
    "timeout": 30 * 60,
    "bg": False,
}


hsp1_config = {
    "context": {
        "physical_address": {
            "address": 0xAA >> 1,
        },
        "supported_msg_types": [MsgTypes.CTRL, MsgTypes.VDPCI],
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
        "serial_number": "2237-704808",
        "name": "HSP1",
        "dump_packet": True,
        "dump_hex": True,
        "enable_pullups": True,
        "slave_only": False,
    },
    "thread_kwargs": thread_kwargs,
}

first_run = True


def main(args) -> int:
    start_threads = True
    conf.debug_dissector = 4

    # Add endpoint using Python Dictionary, reuses data types
    hsp1_config["thread_kwargs"] = {
        "count": args.count,
        "timeout": args.timeout or None,
        "bg": args.bg,
    }

    hsp1 = EndpointManager.from_config(hsp1_config, start_thread=start_threads)

    devices = [
        hsp1,
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

    def make_reply(pkt: Packet, ctx: EndpointContext, resp: Packet) -> HandlerResponse:
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

    def get_mvdp_caps(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        print(f"GetMvdpcCaps: {pkt.summary()}")
        resp = MsftVdmProtocolPacket(
            cmd_set=MsftVdmCommandSets.BASE,
            protocol_version=0,
            cmd=MsftVdmBaseCmdCodes.CAP_NEGOTIATION,
            completion_code=0,
        ) / CapNegotiationResponsePacket(
            max_message_size=4096, max_packet_size=247, message_timeout=100, feature_flags=0x02
        )
        return make_reply(pkt, ctx, resp)

    hsp1.session.register_handler(CapNegotiationRequestPacket, get_mvdp_caps)

    start_heartbeat = threading.Event()

    def start_hearbeat(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        print(f"StartHeartbeat: {pkt.summary()}")
        resp = MsftVdmProtocolPacket(
            cmd_set=MsftVdmCommandSets.BASE,
            protocol_version=0,
            cmd=MsftVdmBaseCmdCodes.HEARTBEAT_CTRL,
            completion_code=0,
        )
        start_heartbeat.set()
        return make_reply(pkt, ctx, resp)

    hsp1.session.register_handler(HeartbeatControlRequestPacket, start_hearbeat)

    def handle_rot_caps(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        print(f"RoTCapsReq: {pkt.summary()}")
        resp = MsftVdmProtocolPacket(
            cmd_set=MsftVdmCommandSets.ROT,
            protocol_version=0,
            cmd=MsftVdmRotCmdCodes.GET_ROT_CAPABILITIES,
            completion_code=0,
        ) / GetRotCapabilitiesResponsePacket(feature_flags=0x0)
        return make_reply(pkt, ctx, resp)

    hsp1.session.register_handler(GetRotCapabilitiesRequestPacket, handle_rot_caps)

    def handle_cmd_set_support(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        print(f"CmdSetSupportRequest: {pkt.summary()}")
        resp = MsftVdmProtocolPacket(
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
        return make_reply(pkt, ctx, resp)

    hsp1.session.register_handler(CmdSetSupportRequestPacket, handle_cmd_set_support)

    if args.send_discovery_notify:
        resp = hsp1.session.sndrcv_control_msg(
            DiscoveryNotify(), dst_eid=0x0A, dst_phy_addr=Smbus7bitAddress(0x20 >> 1), timeout_s=5
        )
        if resp:
            print(f"DiscoveryNotify response: ")
            resp.show2()

    bmc_addr = Smbus7bitAddress(0x10)
    sndrcv_dst = functools.partial(hsp1.session.sndrcv_mctp_msg, timeout_s=5, dst_phy_addr=bmc_addr)

    discovered = threading.Event()

    def set_eid_callback(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        global first_run
        print("Setting eid callback")
        if first_run:
            discovered.set()
            first_run = False
        return HandlerResponse(stop_processing=False, reply=None)

    hsp1.session.register_handler(SetEndpointIDPacket, set_eid_callback)

    if args.send_discovery_notify:
        resp = hsp1.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0A, dst_phy_addr=bmc_addr, timeout_s=0.3)
        if resp:
            print(f"DiscoveryNotify response: ")
            resp.show2()

    print(f"Setup complete.... waiting for request")

    while monitor.is_alive():
        if start_heartbeat.is_set():
            print("Sending heartbeat")
            req = (
                VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=1, vdm_cmd_code=0xFF)
                / MsftVdmProtocolPacket(
                    cmd_set=MsftVdmCommandSets.BASE, protocol_version=0, cmd=MsftVdmBaseCmdCodes.HEARTBEAT
                )
                / HeartbeatRequestPacket(timeout=5, cpu_count=0, health_entries=[0x00])
            )
            resp = hsp1.session.sndrcv_mctp_msg(
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

    args = parser.parse_args()
    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        raise e
