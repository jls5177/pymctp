import argparse
import functools
import sys
import threading
import time

from scapy.packet import Packet, Raw
from scapy.utils import hexdump

from pymctp.automaton.manager import EndpointManager
from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import SetEndpointIDPacket, GetRoutingTableEntries
from pymctp.utils import str_to_bytes


def main(args) -> int:
    start_threads = True
    thread_kwargs = {
        "count": args.count,
        "timeout": args.timeout or None,
        "bg": args.bg,
    }

    # Add endpoint using Python Dictionary, reuses data types
    fpga0_config = {
        "context": {
            "physical_address": {
                "address": 0x28 >> 1,
            },
            "static_eid": 12,
            "is_bus_owner": True,
            "supported_msg_types": [
                MsgTypes.CTRL
            ],
            "endpoint_uuid": "3573337f-6722-4bcb-ae4e-89bb63b184a6",
        },
        "config": {
            "type": "aardvark",
            "slave_address": 0x28 >> 1,
            "serial_number": '2239-233725',
            "name": "FPGA_0",
            "dump_packet": True,
            "dump_hex": True,
            "enable_pullups": True,
            "slave_only": False,
        },
        "downstream_endpoints": {
            12: {
                "physical_address": {
                    "address": 0x28 >> 1,
                },
                "assigned_eid": 12,
                "is_bus_owner": False,
                "supported_msg_types": [
                    MsgTypes.CTRL
                ],
                "endpoint_uuid": "9f538fe7-1438-4ca2-8e5a-df3a0c0c6c56",
            },
            15: {
                "physical_address": {
                    "address": 0x28 >> 1,
                },
                "assigned_eid": 15,
                "is_bus_owner": False,
                "supported_msg_types": [
                    MsgTypes.CTRL
                ],
                "endpoint_uuid": "d9c5a65c-3bfc-4e75-a3a7-0bdbffe50ef3",
            },
            16: {
                "physical_address": {
                    "address": 0x28 >> 1,
                },
                "assigned_eid": 16,
                "is_bus_owner": False,
                "supported_msg_types": [
                    MsgTypes.CTRL
                ],
                "endpoint_uuid": "c036533b-c85b-4bd6-b2a7-28b857890c14",
            }
        },
        "thread_kwargs": thread_kwargs,
    }

    fpga0 = EndpointManager.from_config(fpga0_config, start_thread=start_threads)

    # fpga1_config = {
    #     "context": {
    #         "physical_address": {
    #             "address": 0x64 >> 1,
    #         },
    #         "static_eid": 68,
    #         "supported_msg_types": [
    #             MsgTypes.CTRL,
    #             MsgTypes.PLDM,
    #             MsgTypes.NCSI,
    #         ],
    #         "endpoint_uuid": "fec2fb70-b366-480c-80a5-e289b7e5e3b3",
    #     },
    #     "config": {
    #         "type": "aardvark",
    #         "slave_address": 0x64 >> 1,
    #         "serial_number": '2237-704808',
    #         "name": "CX7_1",
    #         "dump_packet": True,
    #         "dump_hex": True,
    #         "enable_pullups": True,
    #         "slave_only": False,
    #     },
    #     "thread_kwargs": thread_kwargs,
    # }
    #
    # fpga1 = EndpointManager.from_config(fpga1_config, start_thread=start_threads)

    # ovl1_config = {
    #     "context": {
    #         "physical_address": {
    #             "address": 0x53,
    #         },
    #         "static_eid": 0x0B,
    #         "mtu_size": 64 + 4 + 4,
    #         "supported_msg_types": [
    #             MsgTypes.CTRL,
    #             MsgTypes.VDPCI
    #         ],
    #         "endpoint_uuid": "9272dada-70bd-4e11-bb89-5e5714033d42",
    #     },
    #     "config": {
    #         "type": "aardvark",
    #         "slave_address": 0x53,
    #         "serial_number": '2239-233725',
    #         "name": "OMC",
    #         "dump_packet": True,
    #         "dump_hex": True,
    #         "enable_pullups": True,
    #         "slave_only": True,
    #     },
    #     "thread_kwargs": thread_kwargs,
    # }
    #
    # ovl1 = EndpointManager.from_config(ovl1_config, start_thread=start_threads)

    devices = [
        fpga0,
        # fpga1,
        # ovl1,
    ]

    # discovered = threading.Event()
    #
    # def set_eid_callback(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
    #     discovered.set()
    #     pkt.show2()
    #     return HandlerResponse(False, None)
    #
    # fpga1.session.register_handler(SetEndpointIDPacket, set_eid_callback)

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

    # bmc_addr = Smbus7bitAddress(0x20 >> 1)
    # sndrcv_dst = functools.partial(fpga0.session.sndrcv_mctp_msg,
    #                                timeout_s=5,
    #                                dst_phy_addr=bmc_addr)
    #
    # print("Dumping routing table...")
    # pkt = Raw(str_to_bytes("12 02 00 00 07 00 A8 0D 30 82 01 CB 30 82 01"))
    #
    # # pkt = GetRoutingTableEntries(entry_handle=0)
    # rsp_pkt = sndrcv_dst(pkt=pkt, dst_eid=0x0A, msg_type=MsgTypes.SPDM, msg_tag=0x5)
    # if rsp_pkt:
    #     print("Received response:")
    #     hexdump(rsp_pkt)
    #     rsp_pkt.show()
    # #
    # # keep the main thread alive until killed
    # discovered.wait()
    # discovered.clear()

    while monitor.is_alive():
        # print("Dumping routing table...")
        #
        # pkt = GetRoutingTableEntries(entry_handle=0)
        # rsp_pkt = sndrcv_dst(pkt=pkt, dst_eid=0x0A)
        # if rsp_pkt:
        #     print("Received response:")
        #     hexdump(rsp_pkt)
        #     rsp_pkt.show()

        time.sleep(1)

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
