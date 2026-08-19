import functools
import pathlib
import sys
import threading
import time

from pymctp.automaton.manager import ConfigTypes, EndpointManager
from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import DiscoveryNotify
from pymctp.layers.mctp.vdpci import VdPCIVendorIds, VdPciHdr
from scapy.packet import Packet

from pymctp_oem_microsoft.layers import MsftVdmCommandSets, MsftVdmBmcCmdCodes, MsftVdmProtocolPacket, \
    MsftVdmBaseCmdCodes
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm import MsftVdmRotCmdCodes
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.base import HeartbeatRequestPacket, CapNegotiationRequestPacket, \
    CapNegotiationResponsePacket, HeartbeatControlRequestPacket, CmdSetSupportRequestPacket, \
    CmdSetSupportResponsePacket, CmdSetEntryPacket, ProtocolVersionPacket
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.bmc import GetSystemDevicesRequestPacket
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.rot import GetRotCapabilitiesResponsePacket, \
    GetRotCapabilitiesRequestPacket

thread_kwargs = {
    "count": 0,
    "timeout": 30 * 60,
    "bg": False,
}

lion_config = {
    "context": {
        "physical_address": {
            "address": 0x82 >> 1,
        },
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.VDPCI,
        ],
        "assigned_eid": 66,
        "supported_vdm_msg_types": [
            {
                "vendor_id": 0x1414,
                "command_set_type": 0x04,
            },
        ],
    },
    "config": {
        "type": "socket",
        "out_port": 5564,
        "in_port": 5554,
        "name": "MAN1",
        "iface": "127.0.0.1",
        "iface_out": "localhost",
        "dump_packet": True,
        "dump_hex": True,
    },
    "thread_kwargs": thread_kwargs,
}

corsica_config = {
    "context": {
        "physical_address": {
            "address": 0x64 >> 1,
        },
        "supported_msg_types": [
            MsgTypes.CTRL,
        ],
        "assigned_eid": 16,
    },
    "config": {
        "type": "socket",
        "out_port": 5565,
        "in_port": 5555,
        "name": "COR1",
        "iface": "127.0.0.1",
        "iface_out": "localhost",
    },
    "thread_kwargs": thread_kwargs,
}

ovl_cerberus_config = {
    "context": {
        "physical_address": {
            "address": 0x82 >> 1,
        },
        "supported_msg_types": [
            MsgTypes.CTRL,
        ],
        "assigned_eid": 11,
    },
    "config": {
        "type": "socket",
        "out_port": 5558,
        "in_port": 5568,
        "name": "OMC1",
        "iface": "0.0.0.0",
    },
    "thread_kwargs": thread_kwargs,
}


if __name__ == '__main__':
    send_discovery_notify = (sys.argv[1] in (1, "1", True, "true", "True")) if len(sys.argv) > 1 else False
    start_threads = True
    enable_hb = (sys.argv[2] in (1, "1", True, "true", "True")) if len(sys.argv) > 2 else False


    lion1 = EndpointManager.from_config(lion_config, start_thread=start_threads)
    # ovl_cerberus1 = EndpointManager.from_config(ovl_cerberus_config, start_thread=start_threads)
    # corsica1 = EndpointManager.from_config(corsica_config, start_thread=start_threads)

    def make_reply(pkt: Packet, ctx: EndpointContext, resp: Packet) -> HandlerResponse:
        vdm_req = pkt.getlayer(VdPciHdrPacket)
        transport_pkt = pkt.getlayer(TransportHdrPacket)
        smbus_layer = pkt.getlayer(SmbusTransportPacket)
        rsp_pkt = VdPciHdr(
            rq=True,
            vendor_id=vdm_req.vendor_id,
            vdm_cmd_code=vdm_req.vdm_cmd_code,
        ) / resp
        transport_rsp = transport_pkt.build_reply(ctx, rsp_pkt)
        smbus_rsp = smbus_layer.build_reply(ctx, transport_rsp)
        return HandlerResponse(stop_processing=True, reply=smbus_rsp)


    def get_mvdp_caps(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        print(f"GetMvdpcCaps: {pkt.summary()}")
        resp = (
            MsftVdmProtocolPacket(cmd_set=MsftVdmCommandSets.BASE, protocol_version=0, cmd=MsftVdmBaseCmdCodes.CAP_NEGOTIATION, completion_code=0) /
            CapNegotiationResponsePacket(max_message_size=4096, max_packet_size=247, message_timeout=100, feature_flags=0x02 if enable_hb else 0))
        return make_reply(pkt, ctx, resp)
    lion1.session.register_handler(CapNegotiationRequestPacket, get_mvdp_caps)

    start_heartbeat = threading.Event()
    def start_hearbeat(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        print(f"StartHeartbeat: {pkt.summary()}")
        resp = (
            MsftVdmProtocolPacket(cmd_set=MsftVdmCommandSets.BASE, protocol_version=0, cmd=MsftVdmBaseCmdCodes.HEARTBEAT_CTRL, completion_code=0)
        )
        if enable_hb:
            start_heartbeat.set()
        return make_reply(pkt, ctx, resp)
    lion1.session.register_handler(HeartbeatControlRequestPacket, start_hearbeat)

    def handle_rot_caps(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        print(f"RoTCapsReq: {pkt.summary()}")
        resp = (
            MsftVdmProtocolPacket(cmd_set=MsftVdmCommandSets.ROT, protocol_version=0, cmd=MsftVdmRotCmdCodes.GET_ROT_CAPABILITIES, completion_code=0) /
            GetRotCapabilitiesResponsePacket(feature_flags=0x0))
        return make_reply(pkt, ctx, resp)
    lion1.session.register_handler(GetRotCapabilitiesRequestPacket, handle_rot_caps)

    def handle_cmd_set_support(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        print(f"CmdSetSupportRequest: {pkt.summary()}")
        resp = (
            MsftVdmProtocolPacket(cmd_set=MsftVdmCommandSets.BASE, protocol_version=0, cmd=MsftVdmBaseCmdCodes.CMD_SET_SUPPORT, completion_code=0) /
            CmdSetSupportResponsePacket(next_list_entry=0xFF, entries=[
                CmdSetEntryPacket(cmd_set_id=MsftVdmCommandSets.BASE, version_count=1, versions=[ProtocolVersionPacket(major=0, minor=0)]),
                CmdSetEntryPacket(cmd_set_id=MsftVdmCommandSets.ROT, version_count=1, versions=[ProtocolVersionPacket(major=0, minor=0)])])
        )
        return make_reply(pkt, ctx, resp)
    lion1.session.register_handler(CmdSetSupportRequestPacket, handle_cmd_set_support)

    if send_discovery_notify:
        resp = lion1.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0F,
                                               dst_phy_addr=Smbus7bitAddress(0x20 >> 1), timeout_s=5)
        if resp:
            print(f"DiscoveryNotify response: ")
            resp.show2()


    bmc_addr = Smbus7bitAddress(0x10)
    sndrcv_dst = functools.partial(lion1.session.sndrcv_mctp_msg,
                                   timeout_s=5,
                                   dst_phy_addr=bmc_addr)

    devices = [
        lion1,
        # ovl_cerberus1,
        # corsica1,
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

    print(f"Setup complete....")

    while monitor.is_alive():
        if start_heartbeat.is_set():
            print("Sending heartbeat")
            req = (VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=1, vdm_cmd_code=0xFF) /
                   MsftVdmProtocolPacket(cmd_set=MsftVdmCommandSets.BASE, protocol_version=0,
                                         cmd=MsftVdmBaseCmdCodes.HEARTBEAT) /
                   HeartbeatRequestPacket(timeout=15, cpu_count=0, health_entries=[0x00]))
            resp = lion1.session.sndrcv_mctp_msg(req, msg_type=MsgTypes.VDPCI, msg_tag=0x3,
                                                 dst_eid=0, dst_phy_addr=bmc_addr, timeout_s=0.5, threaded=True)
            if resp:
                print(f"Heartbeat response: \n\t{resp.summary()}")

        time.sleep(3)
