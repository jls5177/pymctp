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
        "assigned_eid": 18,
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
    send_discovery_notify = (sys.argv[1] in (1, "1", True, "true", "True")) if len(sys.argv) > 1 else False
    start_threads = True

    set_printable_raw_layer()

    # lion1 = EndpointManager.from_config(lion_config, start_thread=start_threads)
    hsp1 = EndpointManager.from_config(hsp1_config, start_thread=start_threads)
    if len(sys.argv) > 2:
        pcap_file = pathlib.Path(sys.argv[2])
        import_pcap_dump(pcap_file, False, hsp1.config.context)

    if send_discovery_notify:
        resp = hsp1.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0E,
                                               dst_phy_addr=Smbus7bitAddress(0x24 >> 1), timeout_s=5)
        if resp:
            print(f"DiscoveryNotify response: ")
            resp.show2()

    print(f"Setup complete....")
