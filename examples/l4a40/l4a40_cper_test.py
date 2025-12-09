import pathlib
import sys
import threading
import time

from scapy.packet import Packet, Raw
from scapy.config import conf

from pymctp.automaton.manager import ConfigTypes, EndpointManager
from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import DiscoveryNotify
from pymctp.layers.mctp.vdpci import VdPciHdr
from pymctp.utils import set_printable_raw_layer, str_to_bytes, str_to_pkt

thread_kwargs = {
    "count": 0,  # let the answering machine process an unlimited number of requests
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
        ],
        "assigned_eid": 65,
    },
    "config": {
        "type": "socket",
        "out_port": 5564,
        "in_port": 5554,
        "name": "MAN1",
        "iface": "127.0.0.1",
        "iface_out": "localhost",
    },
    "thread_kwargs": thread_kwargs,
}

hsp1_config = {
    "context": {
        "physical_address": {
            "address": 0xB0 >> 1,
        },
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.PLDM,
        ],
        "assigned_eid": 38,
    },
    "config": {
        "type": "socket",
        "out_port": 5565,
        "in_port": 5555,
        "name": "HSP1",
        "iface": "127.0.0.1",
        "iface_out": "localhost",
        "dump_packet": True,
        "dump_hex": False,
    },
    "thread_kwargs": thread_kwargs,
}


if __name__ == '__main__':
    send_discovery_notify = False
    start_threads = False

    set_printable_raw_layer()

    hsp1 = EndpointManager.from_config(hsp1_config, start_thread=start_threads)

    def pldm_handler(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        pldm_pkt = pkt.getlayer(PldmHdrPacket)
        transport_pkt = pkt.getlayer(TransportHdrPacket)
        print(f"PldmHandler: {pldm_pkt.pldm_type} {pldm_pkt.cmd_code} {pldm_pkt.instance_id}")
        if pkt.rq == 1 and pkt.pldm_type == 2 and pkt.cmd_code == 81:
            print(f"DEBUG: is PLDM M&C command {pkt.cmd_code}")
            response = str_to_pkt("14 02 21 00 01 00 0a 00 0a", PldmHdrPacket)
            rsp_pkt = pldm_pkt.build_reply(ctx, response)
            transport_rsp = transport_pkt.build_reply(ctx, rsp_pkt)
            return HandlerResponse(stop_processing=True, reply=transport_rsp)
        return HandlerResponse(stop_processing=True, reply=None)

    hsp1.session.register_handler(PldmHdrPacket, pldm_handler)

    def vdpci_handler(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        vdm_req = pkt.getlayer(VdPciHdrPacket)
        payload = bytes(vdm_req.payload)
        transport_pkt = pkt.getlayer(TransportHdrPacket)
        print(f"VdpciHandler: {"REQ" if pkt.rq else "RESP"} 0x{pkt.vendor_id:04X} CMD={pkt.vdm_cmd_code}")
        if pkt.vendor_id == 0x1414 and pkt.vdm_cmd_code == 0xFF and pkt.rq == 1:
            if payload[0] == 0 and payload[1] == 0:
                resp = conf.raw_layer([0x44] * 700)
                rsp_pkt = VdPciHdr(
                    rq=False,
                    vendor_id=pkt.vendor_id,
                    vdm_cmd_code=pkt.vdm_cmd_code,
                ) / resp
                transport_rsp = transport_pkt.build_reply(ctx, rsp_pkt)
                return HandlerResponse(stop_processing=True, reply=transport_rsp)
        return HandlerResponse(stop_processing=False, reply=None)
    hsp1.session.register_handler(VdPciHdrPacket, vdpci_handler)

    # req = str_to_pkt("01 26 0f c9 01 94 02 51 f2 00 00 00 00 00 00 00 01 f0 00 00 00", TransportHdrPacket)
    # print(f"DEBUG: {req.summary()}")
    req = str_to_pkt("01 26 0f c2 7e 14 14 80 ff 00 00 00 05 00", TransportHdrPacket)
    print(f"DEBUG: {req.summary()}")

    # this tests the answering machine invokes the "pldm_handler" callback
    hsp1.session.on_packet_received(req)
