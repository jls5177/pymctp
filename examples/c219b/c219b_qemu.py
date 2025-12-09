import pathlib
import sys

from pymctp.automaton.manager import ConfigTypes, EndpointManager
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import DiscoveryNotify

thread_kwargs = {
    "count": 10,
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
        "assigned_eid": 64,
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

    lion1 = EndpointManager.from_config(lion_config, start_thread=start_threads)
    # ovl_cerberus1 = EndpointManager.from_config(ovl_cerberus_config, start_thread=start_threads)
    corsica1 = EndpointManager.from_config(corsica_config, start_thread=start_threads)

    if send_discovery_notify:
        resp = lion1.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0a,
                                               dst_phy_addr=Smbus7bitAddress(0x20 >> 1), timeout_s=5)
        if resp:
            print(f"DiscoveryNotify response: ")
            resp.show2()

    print(f"Setup complete....")
