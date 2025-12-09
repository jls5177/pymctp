import argparse
import functools
import sys
import threading
import time

from scapy.packet import Packet, Raw
from scapy.utils import hexdump, linehexdump

from pymctp.automaton.manager import EndpointManager
from pymctp.automaton.sessions import HandlerResponse
from pymctp.exerciser import AardvarkI2CSocket
from pymctp.layers.mctp import *
from pymctp.utils import str_to_bytes
from pymctp.layers.ipmi.transport import SSIFTransportPacket, TransportHdrPacket as IpmiTransportHdrPacket, SsifTransport


DEST_ADDR = Smbus7bitAddress(0x20 >> 1)
DEFAULT_AARDVARK_SERIAL = "2239-233725"
MAX_SSIF_READ_LEN = 32


def send_receive_ipmi_cmd(aardvark: AardvarkI2CSocket, ipmi_pkt: Packet, wait_time:int = 0.2, no_response: bool = False, just_read: bool = False) -> bytes or None:
    ssif_write_pkt = SsifTransport(
        dst_addr=DEST_ADDR,
        command_code=0x02,
        load=ipmi_pkt,
    )
    if not just_read:
        len = aardvark.send(ssif_write_pkt)
        if not len:
            raise SystemExit(f"Failed to send SSIF packet: {len}")

        if no_response:
            return None

        # wait for response to be ready
        time.sleep(wait_time)

    # Issue read command
    ssif_read_pkt = Raw(bytes([DEST_ADDR.write(), 0x03]))
    rsp_data = aardvark.write_read(ssif_read_pkt, MAX_SSIF_READ_LEN)
    if not rsp_data:
        raise SystemExit(f"Failed to read SSIF packet: {rsp_data}")
    print(f"SSIF Read Response: {len} bytes")
    linehexdump(rsp_data)
    return rsp_data


def send_get_sac_chan(aardvark: AardvarkI2CSocket, wait_time:int = 0.2, just_read: bool = False) -> bytes or None:
    ipmi_cmd_hdr = IpmiTransportHdrPacket(net_fn=0x36, cmd=0x92)
    ipmi_get_sac_chan = ipmi_cmd_hdr / Raw(bytes([2]))
    return send_receive_ipmi_cmd(aardvark, ipmi_get_sac_chan, wait_time=wait_time, just_read=just_read)

def main(args) -> int:
    aardvark = AardvarkI2CSocket(
        slave_address=Smbus7bitAddress(0x24 >> 1),
        serial_number=args.aardvark_serial,
        dump_packet=args.verbose,
        dump_hex=args.verbose,
        bitrate=100,
    )

    for i in range(2):
        print(f"Sending SSIF Get SAC Channel command {i}")
        try:
            rsp_data = send_get_sac_chan(aardvark, just_read=False)
            if rsp_data:
                print(f"SSIF Get SAC Channel Response: {len(rsp_data)} bytes")
                linehexdump(rsp_data)
        except:
            pass
        else:
            print("No response received")
        print(f"\n{'=' * 80}", end="\n\n")
        # time.sleep(1)

    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", help="Aardvark serial number",
                        action="store", dest="aardvark_serial", default=DEFAULT_AARDVARK_SERIAL)
    parser.add_argument('-v', '--verbose', dest='verbose', default=False, action=argparse.BooleanOptionalAction)
    args = parser.parse_args()

    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        raise e
