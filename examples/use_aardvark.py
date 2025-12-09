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

downstream_endpoints = {
    15: {
        "physical_address": {
            "address": 0x28 >> 1,
        },
        "assigned_eid": 15,
        "is_bus_owner": False,
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.PLDM,
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
            MsgTypes.CTRL,
            MsgTypes.PLDM,
        ],
        "endpoint_uuid": "c036533b-c85b-4bd6-b2a7-28b857890c14",
    },
    17: {
        "physical_address": {
            "address": 0x28 >> 1,
        },
        "assigned_eid": 17,
        "is_bus_owner": False,
        "supported_msg_types": [
            MsgTypes.CTRL
        ],
        "endpoint_uuid": "9f538fe7-1438-4ca2-8e5a-df3a0c0c6c56",
    }
}

fpga0_config = {
    "context": {
        "physical_address": {
            "address": 0x28 >> 1,
        },
        "static_eid": 12,
        "is_bus_owner": False,
        "supported_msg_types": [
            MsgTypes.CTRL,
            MsgTypes.PLDM,
        ],
        "endpoint_uuid": "3573337f-6722-4bcb-ae4e-89bb63b184a6",
    },
    "config": {
        "type": "aardvark",
        "slave_address": 0x28 >> 1,
        "serial_number": '2237-704808',
        "name": "FPGA_0",
        "dump_packet": True,
        "dump_hex": True,
        "enable_pullups": True,
        "slave_only": False,
    },
    "downstream_endpoints": {},
}


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


first_run = True


def main(args) -> int:
    start_threads = True
    conf.debug_dissector = 4

    # Add endpoint using Python Dictionary, reuses data types
    fpga0_config["thread_kwargs"] = {
        "count": args.count,
        "timeout": args.timeout or None,
        "bg": args.bg,
    }

    fpga0 = EndpointManager.from_config(fpga0_config, start_thread=start_threads)
    downstream_endpoint_ctxs = {key:EndpointContext.from_dict(value) for key, value in downstream_endpoints.items()}
    if args.add_endpoints:
        fpga0.am.downstream_endpoints = downstream_endpoint_ctxs

    def vdpci_handler(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        print(f"VDPCI packet received: {pkt.summary()}")
        time.sleep(0.650)
        return HandlerResponse(stop_processing=False, reply=None)
    fpga0.session.register_handler(VdPciHdrPacket, vdpci_handler)

    devices = [
        fpga0,
        # fpga1,
        # ovl1,
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

    bmc_addr = Smbus7bitAddress(0x18)
    sndrcv_dst = functools.partial(fpga0.session.sndrcv_mctp_msg,
                                   timeout_s=5,
                                   dst_phy_addr=bmc_addr)

    testData = bytes(
        [0x30, 0xf, 0x45, 0x0c, 0x1, 0xa, 0x0c, 0xa0, 0x84, 0x90, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
         0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0, 0x42, 0xe2, 0x32, 0x0, 0x0, 0x0,
         0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x50, 0x7a, 0xdf, 0xfa, 0x54, 0x0, 0x0, 0x0, 0x0, 0x0,
         0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x64, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff])
    testData3 = bytes(
        [0x30, 0xf, 0x45, 0x3b, 0x1, 0xa, 0x49, 0xa0, 0x84, 0x90, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
         0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc0, 0x42, 0xe2, 0x32, 0x0, 0x0, 0x0,
         0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x50, 0x7a, 0xdf, 0xfa, 0x54, 0x0, 0x0, 0x0, 0x0, 0x0,
         0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x64, 0x0, 0x0, 0x0, 0x0, 0x0])
    # crc = crc8.crc8()
    # crc.update(testData)
    # val = crc.digest()
    # testData2 = testData + val
    # testPkt = Raw(testData2)
    # testPkt = Raw(testData)

    discovered = threading.Event()

    def set_eid_callback(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        global first_run
        print("Setting eid callback")
        if first_run:
            discovered.set()
            # fpga0.am.downstream_endpoints = dict()
            first_run = False
        return HandlerResponse(stop_processing=False, reply=None)

    fpga0.session.register_handler(SetEndpointIDPacket, set_eid_callback)
    # fpga0.session.register_handler(GetMctpVersionSupport, set_eid_callback)

    def pldm_handler(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        vdm_req = pkt.getlayer(PldmHdrPacket)
        transport_pkt = pkt.getlayer(TransportHdrPacket)
        smbus_layer = pkt.getlayer(SmbusTransportPacket)
        print()
        # Ensure required layers exist
        if vdm_req is None or transport_pkt is None or smbus_layer is None:
        # if vdm_req is None or transport_pkt is None:
            return HandlerResponse(stop_processing=False, reply=None)

        # Handle PLDM type 4 (FRU) and command 2
        if vdm_req.pldm_type == 0x4 and vdm_req.cmd_code == 0x2:
            print(f"Handling PLDM FRU command 2 request from EID {ctx.assigned_eid}:")
            # Example FRU response payload (raw bytes, excluding the PLDM header)
            resp_payload = bytes([
                4, 2, 0, 0, 0, 0, 0, 5, 1, 0, 254, 87, 1, 1, 4, 55, 1, 0, 0, 2, 2, 1, 0, 3, 9, 77, 83, 32, 65, 73, 32,
                83, 79, 67, 4, 7, 72, 83, 80, 46, 83, 80, 49, 5, 8, 49, 46, 56, 46, 49, 46, 54, 54, 4, 8, 72, 83, 80,
                46, 83, 80, 82, 84, 5, 8, 49, 46, 56, 46, 49, 46, 54, 54, 4, 4, 77, 83, 70, 84, 5, 8, 49, 46, 51, 46,
                48, 46, 52, 50, 6, 4, 50, 0, 0, 0, 7, 36, 50, 66, 57, 69, 56, 54, 49, 57, 45, 68, 56, 68, 68, 45, 65,
                66, 53, 57, 45, 69, 57,
                52, 67, 45, 51, 69, 67, 49, 54, 55, 67, 54, 52, 67, 51, 66, 8, 36, 54, 67, 54, 53, 51, 50, 49, 68, 45,
                48, 48, 55, 53, 45, 66, 49, 57, 56, 45, 49, 50, 70, 48, 45, 66, 50, 57, 51, 57, 66, 70, 69, 50, 52, 69,
                53, 6, 4, 51, 0, 0, 0, 7, 36, 52, 49, 48, 69, 54, 49, 67, 66, 45, 68, 50, 56, 51, 45, 50, 52, 48, 51,
                45, 56, 52, 55, 67, 45, 68, 57, 56, 68, 50, 48, 70, 65, 65, 69, 67, 55, 8, 36, 51, 57, 70, 68, 69, 70,
                69, 50, 45, 70, 65, 68, 56, 45, 49, 54, 70, 57, 45, 48, 69,
                66, 69, 45, 57, 66, 70, 55, 57, 52, 54, 54, 56, 56, 50, 68, 6, 4, 52, 0, 0, 0, 7, 36, 53, 69, 68, 57,
                68, 57, 69, 57, 45, 51, 66, 70, 65, 45, 52, 69, 68, 57, 45, 52, 68, 66, 51, 45, 65, 68, 49, 57, 57, 56,
                66, 53, 55, 57, 54, 70, 8, 36, 53, 55, 50, 49, 68, 68, 52, 49, 45, 56, 66, 50, 57, 45, 49, 57, 54, 68,
                45, 65, 56, 54, 66, 45, 49, 48, 65, 56, 65, 68, 57, 51, 67, 55, 55, 57, 6, 4, 53, 0, 0, 0, 7, 36, 57,
                69, 70, 49, 53, 50, 55, 57, 45, 69, 49, 65, 67, 45, 68,
                54, 69, 52, 45, 68, 50, 50, 55, 45, 65, 65, 70, 67, 49, 57, 70, 70, 55, 69, 57, 52, 8, 36, 70, 51, 65,
                65, 48, 55, 66, 67, 45, 54, 50, 50, 53, 45, 50, 69, 65, 52, 45, 69, 66, 69, 54, 45, 56, 48, 67, 57, 66,
                52, 65, 69, 69, 55, 65, 55, 6, 4, 54, 0, 0, 0, 7, 36, 52, 53, 70, 53, 52, 52, 52, 65, 45, 52, 57, 54,
                48, 45, 69, 69, 65, 57, 45, 48, 49, 57, 67, 45, 51, 56, 54, 66, 65, 49, 54, 70, 70, 56, 70, 50, 8, 36,
                66, 66, 69, 57, 65, 51, 52, 56, 45, 48, 52, 48, 69, 45, 55,
                50, 69, 56, 45, 65, 51, 65, 54, 45, 69, 51, 65, 57, 69, 52, 69, 52, 65, 56, 55, 65, 6, 4, 55, 0, 0, 0,
                7, 36, 70, 69, 66, 68, 56, 69, 48, 69, 45, 67, 53, 53, 49, 45, 55, 54, 55, 55, 45, 53, 53, 68, 48, 45,
                69, 68, 65, 57, 54, 55, 57, 68, 54, 65, 49, 52, 8, 36, 56, 55, 56, 69, 66, 48, 69, 66, 45, 68, 65, 57,
                56, 45, 55, 66, 69, 49, 45, 68, 50, 56, 70, 45, 48, 49, 65, 48, 67, 55, 57, 55, 69, 69, 52, 56, 6, 4,
                57, 0, 0, 0, 7, 36, 54, 56, 66, 67, 65, 55, 48, 69, 45,
                53, 53, 65, 69, 45, 69, 66, 56, 56, 45, 48, 57, 57, 56, 45, 66, 50, 49, 53, 56, 65, 50, 69, 56, 48, 70,
                53, 8, 36, 57, 55, 57, 55, 67, 67, 66, 67, 45, 51, 65, 48, 54, 45, 67, 70, 67, 53, 45, 50, 65, 66, 67,
                45, 66, 54, 68, 55, 55, 57, 53, 57, 54, 65, 65, 57, 9, 24, 57, 48, 53, 48, 53, 48, 51, 52, 51, 51, 51,
                50, 51, 49, 52, 52, 52, 57, 53, 52, 52, 70, 52, 67, 10, 1, 0, 11, 1, 0, 12, 1, 0, 13, 3, 48, 46, 48, 14,
                1, 0, 15, 12, 86, 69, 78, 71, 95, 67, 76, 85, 83, 84,
                69, 82, 16, 1, 5, 17, 2, 0, 0, 18, 2, 0, 0, 17, 2, 0, 0, 18, 2, 0, 0, 17, 2, 0, 0, 18, 2, 0, 0, 17, 2,
                0, 0, 18, 2, 0, 0, 17, 2, 0, 0, 18, 2, 0, 0, 15, 9, 86, 69, 78, 71, 95, 71, 78, 79, 67, 16, 1, 5, 17, 2,
                0, 0, 18, 2, 0, 0, 17, 2, 0, 0, 18, 2, 0, 0, 17, 2, 0, 0, 18, 2, 0, 0, 17, 2, 0, 0, 18, 2, 0, 0, 17, 2,
                0, 0, 18, 2, 0, 0, 15, 4, 86, 82, 65, 77, 16, 1, 5, 17, 2, 0, 0, 18, 2, 0, 0, 17, 2, 0, 0,
                18, 2, 0, 0, 17, 2, 0, 0, 18, 2, 0, 0, 17, 2, 0, 0, 18, 2, 0, 0, 17, 2, 0, 0, 18, 2, 0, 0, 15, 5, 86,
                72, 66, 77, 68, 16, 1, 4, 17, 2, 0, 0, 18, 2, 0, 0, 17, 2, 0, 0, 18, 2, 0, 0, 17, 2, 0, 0, 18, 2, 0, 0,
                17, 2, 0, 0, 18, 2, 0, 0, 19, 2, 0, 0, 20, 2, 82, 3, 21, 2, 182, 0, 22, 1, 56, 23, 3, 50, 53, 53

            ])

            transport_rsp = transport_pkt.build_reply(ctx, resp_payload)
            smbus_hdr: SmbusTransportPacket = pkt.getlayer(SmbusTransportPacket).copy()
            for tpacket in transport_rsp:
                print(f"DBG: pkt: {tpacket.summary()}")
            response_pkts = smbus_hdr.build_reply(ctx, transport_rsp)
            print("Response packets:", response_pkts)
            return HandlerResponse(stop_processing=True, reply=response_pkts)

        # Default: do not handle
        return HandlerResponse(stop_processing=False, reply=None)


    fpga0.session.register_handler(PldmHdrPacket, pldm_handler)

    print(f"Sending DiscoveryNotify to I2C address {bmc_addr}")
    resp = fpga0.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0A, timeout_s=5,
                                            dst_phy_addr=bmc_addr)
    if resp:
        print(f"DiscoveryNotify response: \n\t{resp.summary()}")

    # rsp_pkt = sndrcv_dst(pkt=pkt, dst_eid=0x0A, msg_type=MsgTypes.NVMeMgmtMsg, msg_tag=0x0)
    # if rsp_pkt:
    #     print("Received response:")
    #     hexdump(rsp_pkt)
    #     rsp_pkt.show()
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

    print(f"Setup complete.... waiting for request")

    while monitor.is_alive():
        # if discovered.is_set():
        #     print(f"Discovery complete, waiting 25 seconds before adding downstream endpoints")
        #     time.sleep(25)
        #     fpga0.am.downstream_endpoints = downstream_endpoint_ctxs
        #     print(f"Sending DiscoveryNotify to I2C address {bmc_addr}")
        #     resp = fpga0.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0A, timeout_s=5,
        #                                             dst_phy_addr=bmc_addr)
        #     if resp:
        #         print(f"DiscoveryNotify response: \n\t{resp.summary()}")
        #
        #     time.sleep(60)
        #     discovered.clear()

        #     fpga0.session.am.send_reply([testPkt])
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
    parser.add_argument('-d', '--downstream-endpoints', default=False, action=argparse.BooleanOptionalAction,
                        dest="add_endpoints", help="Enable downstream endpoints")

    args = parser.parse_args()
    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        raise e
