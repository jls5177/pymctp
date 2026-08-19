# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from pymctp.automaton.manager import EndpointManager
from pymctp.layers.mctp import *
from pymctp.utils import set_printable_raw_layer, str_to_bytes
from scapy.config import conf
from scapy.packet import Raw
from scapy.utils import hexdump

bmc_config = {
    "context": {
        "physical_address": {
            "address": 0x14 >> 1,
        },
        "supported_msg_types": [MsgTypes.CTRL, MsgTypes.VDPCI],
    },
    "config": {
        "type": "socket",
        "name": "BMC",
        "iface": "localhost",
        "iface_out": "localhost",
        "dump_packet": True,
        "dump_hex": False,
    },
    "thread_kwargs": {
        "bg": False,
    },
}


if __name__ == "__main__":
    start_threads = True
    set_printable_raw_layer()

    # *********** TODO: Update the values to match HSP
    # 1. Set receiver thread configuration
    bmc_config["thread_kwargs"]["count"] = 1  # Stop after 1 response
    bmc_config["thread_kwargs"]["timeout"] = 30  # in seconds

    # 2. Set HSP EID and I2C address
    hsp_eid = 19
    hsp_i2c_addr = Smbus7bitAddress(0xB0 >> 1)

    # 3. Set BMC EID and I2C address
    bmc_eic = 14
    bmc_i2c_addr = Smbus7bitAddress(0x12 >> 1)

    # 4. Setup Socket details
    bmc_config["config"]["out_port"] = 5565
    bmc_config["config"]["in_port"] = 5555
    bmc_config["config"]["iface"] = "localhost"
    bmc_config["config"]["iface_out"] = "localhost"

    # 4. Create the MCTP packet to send
    pkt = TransportHdr(
        dst=hsp_eid, src=bmc_eic, som=True, eom=True, pkt_seq=0, to=True, tag=5, msg_type=MsgTypes.VDPCI
    ) / conf.raw_layer(str_to_bytes("14 14 0 e5 0"))

    # **************************************************

    bmc_config["context"]["physical_address"]["address"] = bmc_i2c_addr.address
    bmc_config["context"]["assigned_eid"] = bmc_eic

    bmc_ep = EndpointManager.from_config(bmc_config, start_thread=start_threads)

    resp = bmc_ep.session.sndrcv_mctp_msg(pkt, dst_eid=hsp_eid, dst_phy_addr=hsp_i2c_addr, timeout_s=3)
    if resp:
        print(f"Response: ")
        hexdump(resp)
        resp.show()
        raise SystemExit(0)

    print(f"Failed to receive response....")
    bmc_ep.am.stop_sniffer(join=True)
    raise SystemExit(1)
