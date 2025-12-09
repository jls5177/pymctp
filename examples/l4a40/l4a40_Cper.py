import pathlib
import sys
import time
import hashlib
import os
from typing import Optional
import functools

from pymctp.automaton.manager import ConfigTypes, EndpointManager
from pymctp.layers.mctp import *
from pymctp.layers.mctp.control import DiscoveryNotify
from pymctp.layers.mctp.vdpci.vdpci import VdPciHdr
from pymctp.utils import set_printable_raw_layer, str_to_pkt

from scapy.packet import Packet, Raw
from pymctp.automaton.sessions import HandlerResponse
from scapy.utils import hexdump

DEFAULT_EID_RAS_FILE = pathlib.Path(__file__).absolute().parent / pathlib.Path("req_resp_ras.json")
SPLIT_PACKET_SIZE=100

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
            MsgTypes.VDPCI
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
        "dump_hex": True,
    },
    "thread_kwargs": thread_kwargs,
}


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
            MsgTypes.CTRL
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






DUMP_FILE_NAME='/testing_254.dump'
DEBUG=False
LENGTH_RESTRICT_SIZE = 240 #Incliude the size minus header
COMMAND_SET_RAS=2


PROTOCOL_VERSTION_BYTE1=0x0
PROTOCOL_VERSTION_BYTE2=0x1

CMD_RASSENDLOG = 0x12
CMD_RASLOGREADREQUE = 0x13

SEL_TYPE_LOG = 0x1
CPER_TYPE_LOG = 0x2
MINICRASH_TYPE_LOG = 0x3
UNKNWON_TYPE_LOG = 0xFF

SHA256=0x0
SHA384=0x1
SHA512=0x2

LOGID=0x1111
# DEFAULT_EID_RAS_FILE = pathlib.Path(__file__).absolute().parent / pathlib.Path("req_resp_ras.json")
DEFAULT_EID_RAS_FILE = pathlib.Path(__file__).absolute().parent / pathlib.Path("req_resp_ras.json")

############################
#USER UPDATE FIELD
EID_HSP=0x0E
LOGTYPE=MINICRASH_TYPE_LOG
SHA_TYPE=SHA384

##########################

"""
API for Getting the Digest Hash for the file paased
"""
def hash_file(filename,hashtype):
    if(hashtype == 0):
        print("Hashing for SHA256")
        sha256_hash = hashlib.sha256()
        with open(filename, "rb") as f:
            for byte_block in iter(lambda: f.read(),b""):
                sha256_hash.update(byte_block)
        return sha256_hash.digest()
    elif(hashtype == 1):
        print("Hashing for SHA384")
        sha384_hash = hashlib.sha384()
        with open(filename, "rb") as f:
            for byte_block in iter(lambda: f.read(),b""):
                sha384_hash.update(byte_block)
        return sha384_hash.digest()
    elif(hashtype == 2):
        print("Hashing for SHA512")
        sha512_hash = hashlib.sha512()
        with open(filename, "rb") as f:
            for byte_block in iter(lambda: f.read(),b""):
                sha512_hash.update(byte_block)
        return sha512_hash.digest()


"""
API For sending the #5.1.1	SEND LOG COMMAND
if the filesize is more than medium size, then the log info request will be sent
"""
def On_SendLogCommand():
    print("########################### On_SendLogCommand")
    eid = EID_HSP
    ras_flog_info =0x0
    if(LOGTYPE == CPER_TYPE_LOG or LOGTYPE == MINICRASH_TYPE_LOG):
        script_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_path)
        print(" @@@@@@@@@@@@@@ script_dir ",script_dir)
        print(" @@@@@@@@@@@@@@ script_path ",script_path)
        file_name=script_dir+DUMP_FILE_NAME
        print(" @@@@@@@@@@@@@@ file_name ",file_name)
        file_size = os.path.getsize(file_name)  # Size in bytes
        print("[On_SendLogCommand] => Filename => ",file_name)
        print("[On_SendLogCommand] => file_size => ",file_size)
        print("CPER LOG Processing")
        if(file_size < LENGTH_RESTRICT_SIZE):
            print(" File is less than Expected, Sending the Total File")
            with open(file_name, 'rb') as file:
                file_contents = file.read()
            # mctp_packet = bytes([20, 20, 128, 255, 0x6, 0x0, 0, 0x1, 5,0x0])
            mctp_packet = bytes([20, 20, 128, 255,
                                COMMAND_SET_RAS,
                                PROTOCOL_VERSTION_BYTE1,
                                PROTOCOL_VERSTION_BYTE2,
                                CMD_RASSENDLOG,
                                LOGTYPE, #LogType
                                ras_flog_info, #Bit 0: Log Read Request. If set, the content data contains the log read information rather than actual log data. See below for more detail
                                #Appending the data  whole file contents
                                ])
            pkt= Raw(load=mctp_packet+file_contents)
            rsp_pkt: Optional[AnyPacketType] = None
            print("Sending request: Log File sending")
            hexdump(pkt)
            rsp_pkt = sndrcv_dst(pkt=pkt, dst_eid=eid, msg_type=MsgTypes.VDPCI)
            print(rsp_pkt)
        else:
            #Handling size more than expected sending the Log Info COmmand
            print("Sending request:  size more than expected sending the Log Info COmmand")
            file_hash = hash_file(file_name,SHA_TYPE)
            print("HASH  => ",file_hash)
            print((file_size))
            ras_flog_info =0x1
            logId = LOGID
            print(logId.to_bytes(2,'little'))
            logId=logId.to_bytes(2,'little')
            filelength0 = (file_size >> 24) & 0xFF
            filelength1 = (file_size >> 16) & 0xFF
            filelength2 = (file_size >> 8) & 0xFF
            filelength3 = file_size & 0xFF

            # mctp_packet = bytes([
            #     20, 20, 128, 255, 2, 0, 0, 18, 3, 1, 3, 0, 96, 10, 0, 0, 1, 61, 134, 247, 218, 158, 201, 38, 20, 74, 17, 201, 36, 136, 34, 215, 130, 35, 222, 130, 141, 155, 188, 234, 230, 228, 186, 111, 13, 57, 240, 66, 246, 237, 53, 96, 59, 177, 174, 29, 15, 238, 115, 192, 48, 53, 186,
            #      144, 199
            #                     ])

            mctp_packet = bytes([20, 20, 128, 255,
                                COMMAND_SET_RAS,
                                PROTOCOL_VERSTION_BYTE1,
                                PROTOCOL_VERSTION_BYTE2,
                                CMD_RASSENDLOG,
                                LOGTYPE, #LogType
                                ras_flog_info, #Bit 0: Log Read Request. If set, the content data contains the log read information rather than actual log data. See below for more detail
                                logId[0],
                                logId[1],
                                filelength3,
                                filelength2,
                                filelength1,
                                filelength0,
                                SHA_TYPE
                                ])
            pkt= Raw(load=mctp_packet)/file_hash
            rsp_pkt: Optional[AnyPacketType] = None
            print("Sending request:")
            hexdump(pkt)
            rsp_pkt = sndrcv_dst(pkt=pkt, dst_eid=eid, msg_type=MsgTypes.VDPCI)
            print(rsp_pkt)
            time.sleep(2)
    elif(LOGTYPE == SEL_TYPE_LOG):
        print("SEL LOG Processing")
        mctp_packet = bytes([20, 20, 128, 255,
                                COMMAND_SET_RAS,
                                PROTOCOL_VERSTION_BYTE1,
                                PROTOCOL_VERSTION_BYTE2,
                                CMD_RASSENDLOG,
                                SEL_TYPE_LOG, #LogType
                                ras_flog_info, #Bit 0: Log Read Request. If set, the content data contains the log read information rather than actual log data. See below for more detail
                                #Appending the data  whole file contents
                                ])
        RECORD_ID=bytes([0x2,0x5]) #2 bytes
        RECORD_TYPE=bytes([0x3]) #1byte
        TIMESTAMP=bytes([0x0,0x5,0x6,0x7]) #4 byte
        GENERATOR_ID = bytes([0x5,0x6]) #2 byte
        EVM_REV=bytes([0x3]) #1 bytes
        SENSOR_TYPE =bytes([0x3]) #1 byte
        SENSOR_NUMBER = bytes([0x3]) #1 byte
        EVENT_TYPE = bytes([0x3]) #1 byte
        EVENT_DATA1 =bytes([0x3]) #1 byte
        EVENT_DATA2 =bytes([0x3]) #1 byte
        EVENT_DATA3 = bytes([0x3]) #1 byte


        # selbytes=bytes([0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf])
        selbytes=RECORD_ID+RECORD_TYPE
        pkt= Raw(load=mctp_packet)/RECORD_ID/RECORD_TYPE/TIMESTAMP/GENERATOR_ID/EVM_REV/SENSOR_TYPE/SENSOR_NUMBER/EVENT_TYPE/EVENT_DATA1/EVENT_DATA2/EVENT_DATA3
        rsp_pkt: Optional[AnyPacketType] = None
        print("Sending request: Log File sending")
        hexdump(pkt)
        rsp_pkt = sndrcv_dst(pkt=pkt, dst_eid=eid, msg_type=MsgTypes.VDPCI)
        print(rsp_pkt)
        return
    elif(LOGTYPE == MINICRASH_TYPE_LOG):
        print("MINICRASH LOG Processing")
        return




if __name__ == '__main__':
    send_discovery_notify = (sys.argv[1] in (1, "1", True, "true", "True")) if len(sys.argv) > 1 else False
    start_threads = False

    # fpga0_config["thread_kwargs"] = {
    #     "count": 0,
    #     "timeout": None,
    #     "bg": False,
    # }
    # fpga0 = EndpointManager.from_config(fpga0_config, start_thread=start_threads)

    set_printable_raw_layer()

    # lion1 = EndpointManager.from_config(lion_config, start_thread=start_threads)
    hsp1 = EndpointManager.from_config(hsp1_config, start_thread=start_threads)
    # if len(sys.argv) > 2:
    #     pcap_file = pathlib.Path(sys.argv[2])
    #     import_pcap_dump(pcap_file, False, hsp1.config.context)
    # else:
    #     hsp1.config.context.import_json_responses(DEFAULT_EID_RAS_FILE)
    #
    # if send_discovery_notify:
    #     resp = hsp1.session.sndrcv_control_msg(DiscoveryNotify(), dst_eid=0x0E,
    #                                            dst_phy_addr=Smbus7bitAddress(0x24 >> 1), timeout_s=5)
    #     if resp:
    #         print(f"DiscoveryNotify response: ")
    #         resp.show2()

    print(f"Setup complete....")

    print("performing Sending the CPER Request...")

    time.sleep(2)

    print(f"Debugging....")
    bmc_addr = Smbus7bitAddress(0x24 >> 1)
    sndrcv_dst = functools.partial(hsp1.session.sndrcv_mctp_msg,
                                timeout_s=5,
                                dst_phy_addr=bmc_addr)

    def OnReadDumplog(offset,length):

        script_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_path)
        file_name=script_dir+DUMP_FILE_NAME
        with open(file_name, 'rb') as file:
            file.seek(offset)  # Move to the specified offset
            data = file.read(length)  # Read the specified length of bytes
            # print("File Content")
            print(data)
        return data



    """
    API for Getting the Digest Hash for the file paased
    """
    def hash_databuffer(databuffer,hashtype):
        if(hashtype == 0):
            sha256_hash = hashlib.sha256()
            sha256_hash.update(databuffer)
            return sha256_hash.digest()
        elif(hashtype == 1):
            sha384_hash = hashlib.sha384()
            sha384_hash.update(databuffer)
            return sha384_hash.digest()
        elif(hashtype == 2):
            sha512_hash = hashlib.sha512()
            sha512_hash.update(databuffer)
            return sha512_hash.digest()

    def vdpci_handler(pkt: Packet, ctx: EndpointContext) -> HandlerResponse:
        vdpci_hdr: VdPciHdrPacket = pkt.getlayer(VdPciHdrPacket)
        vdm_req = pkt.getlayer(VdPciHdrPacket)
        hdr_data = bytes(vdpci_hdr)
        data = bytes(vdm_req.payload)
        transport_pkt = pkt.getlayer(TransportHdrPacket)
        print("vdm_req",vdm_req)
        print("data",data)
        print("transport_pkt",transport_pkt)
        global FIRSTTIME
        if (data[0] == COMMAND_SET_RAS and data[3] == CMD_RASSENDLOG):
            return HandlerResponse(stop_processing=True, reply=None)
        if(data[0] == COMMAND_SET_RAS and  data[3] == CMD_RASLOGREADREQUE):
            requestLogType = data [4]
            logId = int.from_bytes(data[5:7], 'little')
            logId=logId.to_bytes(2,'little')
            log_fileOffset =int.from_bytes(data[7:10], 'little')
            print(" @@@@@@@@@@@@@@@@@@ Received Offser==> ",log_fileOffset)
            offset_filedata = OnReadDumplog(log_fileOffset,length=SPLIT_PACKET_SIZE)
            hex_digest_data = hash_databuffer(offset_filedata,SHA256)#hastype SHA256
            bkp_hex_digest_data = hex_digest_data
            print("hex_digest_data",hex_digest_data)


            time.sleep(10 / 1000.0)

            # resp = Raw(bytes([hdr_data[0], hdr_data[1], 0, hdr_data[3]])) / resp_data
            filelength0 = (log_fileOffset >> 24) & 0xFF
            filelength1 = (log_fileOffset >> 16) & 0xFF
            filelength2 = (log_fileOffset >> 8) & 0xFF
            filelength3 = log_fileOffset & 0xFF


            print("hex_digest_data Modified",hex_digest_data)
            # if vendor_id.name == "Msft":
            print("Printing HEader 0",hdr_data[0])
            print("Printing HEader 0",hdr_data[1])
            print("Printing HEader 0",hdr_data[2])
            print("Printing HEader 0",hdr_data[3])

            resp = Raw(bytes([hdr_data[0], hdr_data[1], hdr_data[2], hdr_data[3],COMMAND_SET_RAS,0x0,0x0,CMD_RASLOGREADREQUE,0x0,
                                requestLogType,logId[0],logId[1],filelength3,filelength2,filelength1,filelength0,SHA256])) /hex_digest_data/ offset_filedata
            print(" Byte HEader",resp)


            # pkt= Raw(load=mctp_packet+file_contents)
            # rsp_pkt: Optional[AnyPacketType] = None
            print("Sending request: Log File sending")
            hexdump(resp)
            # rsp_pkt = sndrcv_dst(pkt=resp, dst_eid=EID_HSP, msg_type=MsgTypes.VDPCI)
            # print(rsp_pkt)
            transport_rsp = transport_pkt.build_reply(ctx, resp)

            smbus_hdr: SmbusTransportPacket = pkt.getlayer(SmbusTransportPacket).copy()
            response_pkts = smbus_hdr.build_reply(ctx, transport_rsp)
            return HandlerResponse(stop_processing=True, reply=response_pkts)
            # return HandlerResponse(stop_processing=True, reply=resp)

    hsp1.session.register_handler(VdPciHdrPacket, vdpci_handler)


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


    hsp1.session.register_handler(PldmHdrPacket, pldm_handler)

    # On_SendLogCommand()

    # req = str_to_pkt("01 26 0f c9 01 94 02 51 f2 00 00 00 00 00 00 00 01 f0 00 00 00", TransportHdrPacket)
    # print(f"DEBUG: {req.summary()}")
    # req = str_to_pkt("01 12 0e c1 7e 14 14 80 ff 02 00 00 12 00", TransportHdrPacket)
    #     print(f"DEBUG: {req.summary()}")
    req = str_to_pkt("B0 0F 0E 25 0x01 0x12 0x0E 0xC8 0x01 0x99 0x04 0x02 0x00 0x00 0x00 0x00 0x01 0x22", SmbusTransportPacket)
    print(f"DEBUG: {req.summary()}")

    # this tests the answering machine invokes the "pldm_handler" callback
    hsp1.session.on_packet_received(req)

    # req = str_to_pkt("01 12 0e c8 7e 14 14 80 ff 02 00 00 13 03 11 11 00 00 00 00", TransportHdrPacket)
    # print(f"DEBUG2: {req.summary()}")
    #
    # # this tests the answering machine invokes the "pldm_handler" callback
    # hsp1.session.on_packet_received(req)


