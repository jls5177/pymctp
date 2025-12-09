import pathlib
import sys
import threading
import time

from scapy.packet import Packet, Raw

from pymctp.automaton.manager import ConfigTypes, EndpointManager
from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import DiscoveryNotify


if __name__ == '__main__':
    send_discovery_notify = (sys.argv[1] in (1, "1", True, "true", "True")) if len(sys.argv) > 1 else False

    start_threads = True
    thread_kwargs = {
        "count": 10,
        "timeout": 30 * 60,
        "bg": False,
    }

    # Add endpoint using Python Dictionary, reuses data types
    cpu_config = {
        "context": {
            "physical_address": {
                "address": 0xA0 >> 1,
            },
            "supported_msg_types": [
                MsgTypes.CTRL,
                MsgTypes.PLDM,
            ],
            "assigned_eid": 29,
            "endpoint_uuid": "3573337f-6722-4bcb-ae4e-89bb63b184a6",
        },
        "config": {
            "type": "aardvark",
            "slave_address": 0xA0 >> 1,
            "serial_number": '2239-233725',
            "name": "CPU_0",
            "dump_packet": True,
            "dump_hex": True,
            "enable_pullups": True,
            "slave_only": False,
        },
        "thread_kwargs": thread_kwargs,
    }

    cpu_ep = EndpointManager.from_config(cpu_config, start_thread=start_threads)

    def pldm_handler(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        pldm_pkt = pkt.getlayer(PldmHdrPacket)
        print(f"PldmHandler: {pldm_pkt.pldm_type} {pldm_pkt.cmd_code} {pldm_pkt.instance_id}")
        # time.sleep(3)
        return HandlerResponse(True, None)

    cpu_ep.session.register_handler(PldmHdrPacket, pldm_handler)

    devices = [
        cpu_ep,
    ]

    # if not MCP_PCAP.exists():
    #     raise SystemExit(f"JSON file not found: {MCP_PCAP}")
    # import_pcap_dump(MCP_PCAP, False, mcp.config.context)

    # if not HSP_PCAP.exists():
    #     raise SystemExit(f"JSON file not found: {HSP_PCAP}")
    # hsp.config.context.import_json_responses(HSP_PCAP)

    if send_discovery_notify:
        resp = cpu_ep.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0a,
                                                 dst_phy_addr=Smbus7bitAddress(0x20 >> 1), timeout_s=5)
        if resp:
            print(f"DiscoveryNotify response: ")
            resp.show2()

    print(f"Setup complete....")

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

    while monitor.is_alive():
        time.sleep(1)
