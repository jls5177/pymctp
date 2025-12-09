import argparse
import functools
import pathlib
import sys
import threading
import time
import crc8

from scapy.packet import Packet, Raw
from scapy.utils import hexdump

from pymctp.automaton.manager import EndpointManager
from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import SetEndpointIDPacket, GetRoutingTableEntries, GetMctpVersionSupport, \
    DiscoveryNotify
from pymctp.utils import str_to_bytes, set_printable_raw_layer


pcap_file = pathlib.Path("/work/triage/l4a40/cper.pcap")


def main(args) -> int:
    set_printable_raw_layer()

    start_threads = True
    thread_kwargs = {
        "count": args.count,
        "timeout": args.timeout or None,
        "bg": args.bg,
    }

    mcp_config = {
        "context": {
            "physical_address": {
                "address": 0x28 >> 1,
            },
            "static_eid": 0,
            "is_bus_owner": False,
            "supported_msg_types": [
                MsgTypes.CTRL,
                # MsgTypes.PLDM,
            ],
            "endpoint_uuid": "3573337f-6722-4bcb-ae4e-89bb63b184a6",
            "mtu_size": 68 - 4,
        },
        "config": {
            "type": "tty",
            "baudrate": 115200,
            "tty": '/dev/cu.usbserial-11420',
            "name": "MCP",
            "dump_packet": True,
            "dump_hex": True,
        },
        "thread_kwargs": thread_kwargs,
    }
    mcp = EndpointManager.from_config(mcp_config, start_thread=start_threads)
    import_pcap_dump(pcap_file, False, mcp.config.context)
    devices = [
        mcp,
    ]

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

    for i in range(1, 2):
        resp = mcp.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0A, timeout_s=1)
        if resp:
            print("Received response:")
            hexdump(resp)
            resp.show()

    print(f"Setup complete....")

    while monitor.is_alive():
        time.sleep(5)

    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--count", help="Max number of packets to answer", default=0, required=False,
                        action="store", dest="count")
    parser.add_argument("-t", "--timeout", help="Max runtime (in seconds), default unlimited",
                        default=0, type=int, required=False, action="store", dest="timeout")
    parser.add_argument('-b', '--bg', dest='bg', default=False, action=argparse.BooleanOptionalAction)

    args = parser.parse_args()
    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        raise e
