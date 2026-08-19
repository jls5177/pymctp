import argparse
import binascii
import functools
import sys
import threading
import time
import crc8
from pymctp.layers.mctp.vdpci import VdPCIVendorIds

from scapy.config import conf
from scapy.packet import Packet, Raw
from scapy.utils import hexdump
from scapy.compat import raw

# from pymctp.automaton.manager import EndpointManager
# from pymctp.automaton.sessions import HandlerResponse
from pymctp.layers import MasterWriteReadRequestPacket
from pymctp.layers.ipmi.transport import MasterWriteReadBusType
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import SetEndpointIDPacket, GetRoutingTableEntries, GetMctpVersionSupport, \
    DiscoveryNotify, GetEndpointIDPacket, ControlHdr, SetEndpointID, SetEndpointIDOperation, ContrlCmdCodes
from pymctp_oem_microsoft.layers.mctp.vdpci.cerberus import ErrorResponsePacket
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.bmc import GetSystemDevicesRequestPacket
from pymctp_oem_microsoft.layers.mctp.vdpci import MsftVdmProtocolPacket
from pymctp.utils import str_to_bytes


def build_i2ctransfer_cmd():
    load = (TransportHdr(dst=0, src=10, som=True, eom=True, pkt_seq=0, to=True, tag=3) /
            ControlHdr(rq=True, instance_id=16, cmd_code=ContrlCmdCodes.SetEndpointID) /
            SetEndpointID(op=SetEndpointIDOperation.ForceEID, eid=66))
    dst_i2c_addr = Smbus7bitAddress(0xB0 >> 1)
    req = SmbusTransport(load=load, src_addr=Smbus7bitAddress(0x20 >> 1), dst_addr=dst_i2c_addr)
    print(req.summary())
    req_bytes = raw(req)
    output_str = binascii.hexlify(req_bytes[1:], b' ', 1).decode()
    print(output_str)
    length = len(req_bytes) - 1
    hex_str = " ".join(f"0x{x}" for x in output_str.split())
    print(hex_str)
    print(f"i2ctransfer -y -f 20 w{length}@0x{dst_i2c_addr.address:02x} {hex_str}")


def build_master_write_read_cmd():

    load = (TransportHdr(dst=0, src=9, som=True, eom=True, pkt_seq=0, to=True, tag=5) /
            ControlHdr(rq=True, instance_id=7) /
            GetEndpointIDPacket())
    req = TrimmedSmbusTransport(load=load, src_addr=0x10)
    print(req.summary())
    req_bytes = raw(req)
    print(binascii.hexlify(req_bytes))

    ipmi_req = MasterWriteReadRequestPacket(channel=1,
                                            bus_type=MasterWriteReadBusType.PUBLIC.value,
                                            bus=0,
                                            read_count=32,
                                            load=req)
    print(ipmi_req.summary())

    output_str = binascii.hexlify(bytes([0x06, 0x52]) + raw(ipmi_req), b' ', 1).decode()
    print(" ".join(f"0x{x}" for x in output_str.split()))


def build_master_write_read_cmd_getsocbootmode():
    load = (TransportHdr(dst=66, src=9, som=True, eom=True, pkt_seq=0, to=True, tag=5, msg_type=MsgTypes.VDPCI) /
            Raw(str_to_bytes("14 14 0 e5 0")))
    req = TrimmedSmbusTransport(load=load, src_addr=0x10)
    print(req.summary())
    req_bytes = raw(req)
    print(binascii.hexlify(req_bytes))

    ipmi_req = MasterWriteReadRequestPacket(channel=1,
                                            bus_type=MasterWriteReadBusType.PUBLIC.value,
                                            bus=0,
                                            read_count=32,
                                            load=req)
    print(ipmi_req.summary())

    output_str = binascii.hexlify(bytes([0x06, 0x52]) + raw(ipmi_req), b' ', 1).decode()
    print(" ".join(f"0x{x}" for x in output_str.split()))


def build_master_write_read_cmd_factoryreset():
    load = (TransportHdr(dst=11, src=10, som=True, eom=True, pkt_seq=0, to=True, tag=5, msg_type=MsgTypes.VDPCI) /
            Raw(str_to_bytes("14 14 0 6a 1")))
    dst_i2c_addr = Smbus7bitAddress(0xA6 >> 1)
    req = SmbusTransport(load=load, src_addr=Smbus7bitAddress(0x20 >> 1), dst_addr=dst_i2c_addr)

    print(req.summary())
    req_bytes = raw(req)
    output_str = binascii.hexlify(req_bytes[1:], b' ', 1).decode()
    print(output_str)
    length = len(req_bytes) - 1
    hex_str = " ".join(f"0x{x}" for x in output_str.split())
    print(hex_str)
    print(f"i2ctransfer -y -f 8 w{length}@0x{dst_i2c_addr.address:02x} {hex_str}")


def build_mvdp_req():
    req = (VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=1, vdm_cmd_code=0xFF) /
           MsftVdmProtocolPacket(cmd_set=1, protocol_version=0, cmd=0x13) /
           GetSystemDevicesRequestPacket(start_index=0, entry_count=0, filter_props=0))
    print(req.summary())
    req_bytes = raw(req)
    print(binascii.hexlify(req_bytes))

    output_str = binascii.hexlify(bytes([0x7e]) + req_bytes, b' ', 1).decode()
    print(" ".join(f"0x{x}" for x in output_str.split()))


def build_master_write_read_cmd_getsystemdevices():
    load = (TransportHdr(dst=0, src=9, som=True, eom=True, pkt_seq=0, to=True, tag=5, msg_type=MsgTypes.VDPCI) /
            VdPciHdrPacket(vendor_id=VdPCIVendorIds.Msft, rq=1, vdm_cmd_code=0xFF) /
            MsftVdmProtocolPacket(cmd_set=1, protocol_version=0, cmd=0x13) /
            GetSystemDevicesRequestPacket(start_index=0, max_entry_count=0, filter_properties=0))
    req = TrimmedSmbusTransport(load=load, src_addr=0x10)
    print(req.summary())
    req_bytes = raw(req)
    print(binascii.hexlify(req_bytes))

    ipmi_req = MasterWriteReadRequestPacket(channel=1,
                                            bus_type=MasterWriteReadBusType.PUBLIC.value,
                                            bus=0,
                                            read_count=32,
                                            load=req)
    print(ipmi_req.summary())

    output_str = binascii.hexlify(bytes([0x06, 0x52]) + raw(ipmi_req), b' ', 1).decode()
    print(" ".join(f"0x{x}" for x in output_str.split()))


def str_to_bytes2(byte_string: str, *, token: str = " ", base=16) -> bytes:
    if not byte_string:
        return b""
    return bytes([int(x, 10) for x in byte_string.split(token)])

if __name__ == '__main__':
    # err = ErrorResponsePacket(str_to_bytes("04 0f 15 00 7f"))
    # print(err.summary())
    # build_master_write_read_cmd_getsocbootmode()
    # build_i2ctransfer_cmd()
    # build_mvdp_req()
    # build_master_write_read_cmd_factoryreset()
    # build_master_write_read_cmd_getsystemdevices()
    build_master_write_read_cmd()
    # data = str_to_bytes("0x10 0xf 0xa 0x83 0x1 0xa 0xb 0xc0 0x0 0x7 0x6 0x2 0x0 0x9a")
    # pkt = SmbusTransportPacket(data)
    # pkt.summary()

    # data = str_to_bytes2("4 0 0 1 36 182 62 211 156 1 0 0", base=10)
    # hexdump(data)
    # pkt = MsftVdmProtocolPacket(data)
    # pkt.summary()
