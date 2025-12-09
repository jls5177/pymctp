import argparse
import functools
import sys
import threading
import time
import crc8

from scapy.config import conf
from scapy.packet import Packet, Raw
from scapy.utils import hexdump

from pymctp.automaton.manager import EndpointManager
from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import SetEndpointIDPacket, GetRoutingTableEntries, GetMctpVersionSupport, \
    DiscoveryNotify
from pymctp.utils import str_to_bytes


manticore_config = {
    "context": {
        "physical_address": {
            "address": 0x82 >> 1,
        },
        "static_eid": 0x41,
        "mtu_size": 64 + 4 + 4,
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.VDPCI
        ],
        "endpoint_uuid": "9272dada-70bd-4e11-bb89-5e5714033d42",
    },
    "config": {
        "type": "aardvark",
        "slave_address": 0x82 >> 1,
        "serial_number": '2239-233725',
        "name": "LION",
        "dump_packet": True,
        "dump_hex": True,
        "enable_pullups": True,
        "slave_only": False,
    },
    "downstream_endpoints": {},
}

# ovl1 = EndpointManager.from_config(manticore_config, start_thread=start_threads)

first_run = True


def main(args) -> int:
    start_threads = True
    conf.debug_dissector = 4

    # Add endpoint using Python Dictionary, reuses data types
    manticore_config["thread_kwargs"] = {
        "count": args.count,
        "timeout": args.timeout or None,
        "bg": args.bg,
    }

    manticore = EndpointManager.from_config(manticore_config, start_thread=start_threads)
    devices = [
        manticore
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

    bmc_addr = Smbus7bitAddress(0x10)
    sndrcv_dst = functools.partial(manticore.session.sndrcv_control_msg,
                                   timeout_s=0.0001,
                                   dst_phy_addr=bmc_addr)

    while monitor.is_alive():
        print(f"Sending DiscoveryNotify to I2C address {bmc_addr}")
        resp = sndrcv_dst(DiscoveryNotify(), dst_eid=14)
        if resp:
            print(f"DiscoveryNotify response: \n\t{resp.summary()}")
            time.sleep(3)
        # else:
        #     time.sleep(0.01)

    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--count", help="Max number of packets to answer", default=0, required=False,
                        action="store", dest="count")
    parser.add_argument("-t", "--timeout", help="Max runtime (in seconds), default unlimited",
                        default=0, type=int, required=False, action="store", dest="timeout")
    parser.add_argument('-b', '--bg', dest='bg', default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument('-d', '--downstream-endpoints', default=False, action=argparse.BooleanOptionalAction,
                        dest="add_endpoints", help="Enable downstream endpoints")

    args = parser.parse_args()
    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        raise e
