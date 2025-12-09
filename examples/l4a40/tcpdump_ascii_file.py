import pathlib
import sys

from pymctp.automaton.manager import ConfigTypes, EndpointManager
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import DiscoveryNotify
from pymctp.utils import set_printable_raw_layer, str_to_pkt

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
            MsgTypes.VDPCI,
        ],
        "assigned_eid": 34,
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
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {sys.argv[0]} <pcap file>")

    start_threads = False

    set_printable_raw_layer()

    req = str_to_pkt("B0 0F 15 25 01 22 0f C8 7E 14 14 80 FF 02 00 00 13 03 03 00 00 00 00 00 00", SmbusTransportPacket)
    print(f"DEBUG: {req.summary()}")
    print(f"DEBUG: {req.load.summary()}")

    # lion1 = EndpointManager.from_config(lion_config, start_thread=start_threads)
    hsp1 = EndpointManager.from_config(hsp1_config, start_thread=start_threads)
    pcap_file = pathlib.Path(sys.argv[1])
    import_pcap_dump(pcap_file, False, hsp1.config.context, debug=False)

    reply = req.make_reply(hsp1.context)
    for index, pkt in enumerate(reply):
        print(f"{index:02}: {pkt.summary()}")
