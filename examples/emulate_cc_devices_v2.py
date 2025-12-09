import pathlib
import sys

from pymctp.automaton.manager import ConfigTypes, EndpointManager
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import DiscoveryNotify

MCP_PCAP = pathlib.Path(__file__).absolute().parent / pathlib.Path("mctpi3c2.dump")
HSP_PCAP = pathlib.Path(__file__).absolute().parent / pathlib.Path("mctpi2c6.dump")

if __name__ == '__main__':
    send_discovery_notify = (sys.argv[1] in (1, "1", True, "true", "True")) if len(sys.argv) > 1 else False

    start_threads = True
    thread_kwargs = {
        "count": 10,
        "timeout": 30 * 60,
        "bg": False,
    }

    # Add endpoint using Python Dictionary, reuses data types
    hsp_config = {
        "context": {
            "physical_address": {
                "address": 0x24 >> 1,
            },
            "supported_msg_types": [
                MsgTypes.CTRL,
            ],
            "endpoint_uuid": "3573337f-6722-4bcb-ae4e-89bb63b184a6",
        },
        "config": {
            "type": "socket",
            "out_port": 5556,
            "in_port": 5566,
            "name": "HSP",
        },
        "thread_kwargs": thread_kwargs,
    }

    hsp = EndpointManager.from_config(hsp_config, start_thread=start_threads)

    # if not MCP_PCAP.exists():
    #     raise SystemExit(f"JSON file not found: {MCP_PCAP}")
    # import_pcap_dump(MCP_PCAP, False, mcp.config.context)

    # if not HSP_PCAP.exists():
    #     raise SystemExit(f"JSON file not found: {HSP_PCAP}")
    # hsp.config.context.import_json_responses(HSP_PCAP)

    if send_discovery_notify:
        resp = hsp.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0a,
                                               dst_phy_addr=Smbus7bitAddress(0x20 >> 1), timeout_s=5)
        if resp:
            print(f"DiscoveryNotify response: ")
            resp.show2()

    print(f"Setup complete....")
