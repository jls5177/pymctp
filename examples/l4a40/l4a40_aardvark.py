# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import argparse
import functools
import sys
import threading
import time

# import crc8
from pymctp.layers.mctp.vdpci import VdPCIVendorIds

from scapy.config import conf
from scapy.packet import Packet, Raw
from scapy.utils import hexdump

from pymctp.automaton.manager import EndpointManager
from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import (
    SetEndpointIDPacket,
    GetRoutingTableEntries,
    GetMctpVersionSupport,
    DiscoveryNotify,
)
from pymctp.utils import str_to_bytes

from pymctp_oem_microsoft.layers import MsftVdmProtocolPacket, MsftVdmBmcCmdCodes, MsftVdmCommandSets
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.bmc import GetSystemDevicesRequestPacket, GetDeviceEidRequestPacket

thread_kwargs = {
    "count": 0,  # let the answering machine process an unlimited number of requests
    "timeout": 30 * 60,
    "bg": False,
}


hsp1_config = {
    "context": {
        "physical_address": {
            "address": 0xB0 >> 1,
        },
        "supported_msg_types": [MsgTypes.CTRL, MsgTypes.VDPCI],
        "assigned_eid": 34,
        "is_bus_owner": True,
        "supported_vdm_msg_types": [
            {
                "vendor_id": 0x1414,
            },
        ],
        "endpoint_uuid": "3573337f-6722-4bcb-ae4e-89bb63b184b0",
    },
    "config": {
        "type": "aardvark",
        "slave_address": 0xB0 >> 1,
        "serial_number": "2237-704808",
        "name": "HSP1",
        "dump_packet": True,
        "dump_hex": True,
        "enable_pullups": True,
        "slave_only": False,
    },
    "thread_kwargs": thread_kwargs,
}

first_run = True


def main(args) -> int:
    start_threads = True
    conf.debug_dissector = 4

    # Add endpoint using Python Dictionary, reuses data types
    hsp1_config["thread_kwargs"] = {
        "count": args.count,
        "timeout": args.timeout or None,
        "bg": args.bg,
    }

    hsp1 = EndpointManager.from_config(hsp1_config, start_thread=start_threads)
    # downstream_endpoint_ctxs = {key:EndpointContext.from_dict(value) for key, value in downstream_endpoints.items()}
    # if args.add_endpoints:
    #     fpga0.am.downstream_endpoints = downstream_endpoint_ctxs

    # def vdpci_handler(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
    #     print(f"VDPCI packet received: {pkt.summary()}")
    #     time.sleep(0.650)
    #     return HandlerResponse(stop_processing=False, reply=None)
    # fpga0.session.register_handler(VdPciHdrPacket, vdpci_handler)

    devices = [
        hsp1,
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

    bmc_addr = Smbus7bitAddress(0x12)
    sndrcv_dst = functools.partial(hsp1.session.sndrcv_mctp_msg, timeout_s=5, dst_phy_addr=bmc_addr)

    testData = bytes(
        [
            0x30,
            0xF,
            0x45,
            0x0C,
            0x1,
            0xA,
            0x0C,
            0xA0,
            0x84,
            0x90,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0xC0,
            0x42,
            0xE2,
            0x32,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x50,
            0x7A,
            0xDF,
            0xFA,
            0x54,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x64,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0xFF,
        ]
    )
    testData3 = bytes(
        [
            0x30,
            0xF,
            0x45,
            0x3B,
            0x1,
            0xA,
            0x49,
            0xA0,
            0x84,
            0x90,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0xC0,
            0x42,
            0xE2,
            0x32,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x50,
            0x7A,
            0xDF,
            0xFA,
            0x54,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
            0x64,
            0x0,
            0x0,
            0x0,
            0x0,
            0x0,
        ]
    )
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
            # hsp1.am.downstream_endpoints = dict()
            first_run = False
        return HandlerResponse(stop_processing=False, reply=None)

    hsp1.session.register_handler(SetEndpointIDPacket, set_eid_callback)
    # hsp1.session.register_handler(GetMctpVersionSupport, set_eid_callback)

    print(f"Sending DiscoveryNotify to I2C address {bmc_addr}")
    resp = hsp1.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0F, timeout_s=5, dst_phy_addr=bmc_addr)
    if resp:
        print(f"DiscoveryNotify response: \n\t{resp.summary()}")

    # time.sleep(2.5)
    # req = (VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=1, vdm_cmd_code=0xFF) /
    #        MsftVdmProtocolPacket(cmd_set=MsftVdmCommandSets.BMC, protocol_version=0, cmd=MsftVdmBmcCmdCodes.BMC_GET_SYSTEM_DEVICES) /
    #        GetSystemDevicesRequestPacket(start_index=0, max_entry_count=0, filter_properties=0))
    # resp = hsp1.session.sndrcv_mctp_msg(req, msg_type=MsgTypes.VDPCI, msg_tag=0x3,
    #                                     dst_eid=0x0f, dst_phy_addr=bmc_addr, timeout_s=5, threaded=True)
    # if resp:
    #     print(f"GetSystemDevices response: \n\t{resp.summary()}")
    #
    # print("Sending GetDeviceID Request for MANTICORE")
    # req = (VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=1, vdm_cmd_code=0xFF) /
    #        MsftVdmProtocolPacket(cmd_set=MsftVdmCommandSets.BMC, protocol_version=0, cmd=MsftVdmBmcCmdCodes.BMC_GET_DEVICE_EID) /
    #        GetDeviceEidRequestPacket(vendor_id=0x1414, device_id=0x2, subsystem_vendor_id=0x1414, subsystem_device_id=0x3, instance=0))
    # resp = hsp1.session.sndrcv_mctp_msg(req, msg_type=MsgTypes.VDPCI, msg_tag=0x3,
    #                                     dst_eid=0x0f, dst_phy_addr=bmc_addr, timeout_s=5, threaded=True)
    # if resp:
    #     print(f"GetDeviceEID response: \n\t{resp.summary()}")
    #
    # print("Sending GetDeviceID Request for HSP")
    # req = (VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=1, vdm_cmd_code=0xFF) /
    #        MsftVdmProtocolPacket(cmd_set=MsftVdmCommandSets.BMC, protocol_version=0,
    #                              cmd=MsftVdmBmcCmdCodes.BMC_GET_DEVICE_EID) /
    #        GetDeviceEidRequestPacket(vendor_id=0x1414, device_id=0x8, subsystem_vendor_id=0x1414,
    #                                  subsystem_device_id=0x8, instance=0))
    # resp = hsp1.session.sndrcv_mctp_msg(req, msg_type=MsgTypes.VDPCI, msg_tag=0x3,
    #                                     dst_eid=0x0f, dst_phy_addr=bmc_addr, timeout_s=5, threaded=True)
    # if resp:
    #     print(f"GetDeviceEID response: \n\t{resp.summary()}")
    #
    # print("Sending GetDeviceID Request for TIP")
    # req = (VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=1, vdm_cmd_code=0xFF) /
    #        MsftVdmProtocolPacket(cmd_set=MsftVdmCommandSets.BMC, protocol_version=0,
    #                              cmd=MsftVdmBmcCmdCodes.BMC_GET_DEVICE_EID) /
    #        GetDeviceEidRequestPacket(vendor_id=0x1414, device_id=0x6, subsystem_vendor_id=0x1414,
    #                                  subsystem_device_id=0x5, instance=0))
    # resp = hsp1.session.sndrcv_mctp_msg(req, msg_type=MsgTypes.VDPCI, msg_tag=0x3,
    #                                     dst_eid=0x0f, dst_phy_addr=bmc_addr, timeout_s=5, threaded=True)
    # if resp:
    #     print(f"GetDeviceEID response: \n\t{resp.summary()}")

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
        time.sleep(1)

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-c", "--count", help="Max number of packets to answer", default=0, required=False, action="store", dest="count"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="Max runtime (in seconds), default unlimited",
        default=0,
        type=int,
        required=False,
        action="store",
        dest="timeout",
    )
    parser.add_argument("-b", "--bg", dest="bg", default=False, action=argparse.BooleanOptionalAction)

    args = parser.parse_args()
    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        raise e
