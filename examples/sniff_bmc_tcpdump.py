import argparse
import binascii
from contextlib import contextmanager
import sys
from datetime import datetime
from io import TextIOWrapper
from typing import Optional

import paramiko
import pytz
from scapy.layers.l2 import CookedLinux, CookedLinuxV2
from scapy.config import conf
from scapy.packet import Packet, Raw
from scapy.utils import PcapReader, wrpcap, EDecimal, PcapWriter
from tzlocal import get_localzone_name

from pymctp.utils import set_printable_raw_layer
from pymctp.layers.mctp import TransportHdrPacket


def is_dst_active(zonename: str) -> bool:
    return bool(datetime.now(pytz.timezone(zonename)).dst())


DEFAULT_TZ = pytz.timezone(get_localzone_name())
DEFAULT_DST = is_dst_active(get_localzone_name())


def adjust_packet_time(pkt: Packet, use_local_time: bool = False, adjust_tz: bool = False, utz: bool = False):
    if not use_local_time:
        timestamp = datetime.utcfromtimestamp(float(pkt.time))
        if adjust_tz:
            timestamp = DEFAULT_TZ.localize(timestamp, is_dst=DEFAULT_DST)
        else:
            timestamp = pytz.utc.localize(timestamp)
    else:
        timestamp = DEFAULT_TZ.localize(datetime.now(), is_dst=DEFAULT_DST)
    if use_local_time and utz:
        timestamp = timestamp.astimezone(pytz.utc)
    pkt.timestamp = timestamp
    pkt.time = EDecimal(timestamp.timestamp())
    return pkt


def process_mctp_packet(mctp_packet, add_local_time: bool = False) -> str:
    timestamp = mctp_packet.underlayer.timestamp
    if add_local_time:
        curr_ts = DEFAULT_TZ.localize(datetime.now(), is_dst=DEFAULT_DST)
        return f"{curr_ts.isoformat()}: {timestamp.isoformat()}: {mctp_packet.summary()}"
    # if not use_local_time:
    #     timestamp = datetime.fromtimestamp(float(mctp_packet.time))
    #     timestamp = DEFAULT_TZ.localize(timestamp, is_dst=DEFAULT_DST)
    # else:
    #     timestamp = datetime.now()
    # utc_timestamp = timestamp.astimezone(pytz.utc)
    # mctp_packet.timestamp = utc_timestamp
    # mctp_packet.time = EDecimal(timestamp.timestamp())
    # if mctp_packet.underlayer and mctp_packet.underlayer is CookedLinux:
    #     linux_pkt = mctp_packet.underlayer
    #     linux_pkt.time = EDecimal(timestamp.timestamp())
    return f'{timestamp.isoformat()}: {mctp_packet.summary()}'


def main(args) -> int:
    # set the default raw layer to one that supports printing the raw payload and all upper layers
    set_printable_raw_layer()

    if args.intf == "-":
        input_arg = sys.stdin
        print(f"Connected to STDIN, traffic will stream as it comes in...")
    else:
        print(f"Connecting to {args.host} on {args.intf}, this might take a few seconds...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(policy=paramiko.WarningPolicy())
        ssh.connect(hostname=args.host, port=args.port, username=args.user, password=args.passwd)

        stdin, stdout, stderr = ssh.exec_command(f"tcpdump -i {args.intf} -U -s0 -w -")
        input_arg = stdout
        print(f"Connected, traffic will stream as it comes in...")

    def log_line_to_file(line: str, outfile: TextIOWrapper):
        if outfile:
            outfile.write(f"{line}\n".encode())

    def write_to_pcap_file(pkt: Packet, writer: Optional[PcapWriter]):
        if writer:
            writer.write(pkt)

    def with_pcap_writer(outfile: str):
        if not outfile:
            @contextmanager
            def empty_manager():
                yield None
            return empty_manager()
        return PcapWriter(outfile, append=True, sync=True)
        # writer = PcapWriter(outfile, append=True, sync=True)
        # try:
        #     yield writer
        # finally:
        #     writer.__exit__()

    with PcapReader(input_arg) as fdesc:
        with with_pcap_writer(args.rawfile) as pcapwriter:
            for packet in fdesc:
                packet = adjust_packet_time(packet, use_local_time=False)

                # save packet to pcap file (if requested)
                write_to_pcap_file(packet, pcapwriter)

                if packet.haslayer(TransportHdrPacket):
                    pkt_summary = process_mctp_packet(packet.getlayer(TransportHdrPacket), add_local_time=True)
                    log_line_to_file(pkt_summary, args.outfile)
                    print(pkt_summary)

    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-H", help="BMC hostname", default="localhost", required=False,
                        action="store", dest="host")
    parser.add_argument("-p", "--port", help="BMC SSH port number", default=22, required=False,
                        action="store", dest="port")
    parser.add_argument("-U", help="BMC SSH username", default="admin", required=False,
                        action="store", dest="user")
    parser.add_argument("-P", "--pass", help="BMC SSH password",
                        action="store", dest="passwd")
    parser.add_argument("-i", help="MCTP interface to sniff (e.g., mctpi2c1)",
                        action="store", dest="intf", required=True)
    parser.add_argument("-o", "--outfile", type=argparse.FileType('ab', bufsize=0), default=None,
                        action="store", dest="outfile",
                        help="Store all parsed commands to the specified file")
    parser.add_argument("-r", "--rawfile", type=str, default=None,
                        action="store", dest="rawfile",
                        help="Store all parsed commands to the specified file")
    parser.add_argument('-v', '--verbose', dest='verbose', default=False, action=argparse.BooleanOptionalAction)
    args = parser.parse_args()

    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)
