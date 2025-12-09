import argparse
import binascii
import os.path
import re
import sys
from argparse import ArgumentError
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
from io import TextIOWrapper
from typing import Dict

import pytz
from scapy.config import conf
from tzlocal import get_localzone_name

from pymctp.layers import mctp, ipmi, TransportHdrPacket  # noqa
from pymctp.utils.helpers import set_printable_raw_layer


def is_dst_active(zonename: str) -> bool:
    return bool(datetime.now(pytz.timezone(zonename)).dst())


DEFAULT_TZ = pytz.timezone(get_localzone_name())
DEFAULT_DST = is_dst_active(get_localzone_name())

# This regex parses lines like the following:
# 2011-04-06 01:34:22.396961 LAN - Res Ch:1; Nfn:6; Cmd:1; Data:0 20 1 2 8 2 4f 37 1 0 5d 8 0 0 0 0  -
ipmiLogLineRE = re.compile(
    r"(?P<timestamp>.+?) (?P<intf>LAN|KCS|SSIF|OEM) - "      # timestamp="2011-04-06 01:34:22.396961"
    r"(?P<req_type>Res|Req) "               # req_type="Res"
    r"Ch:(?P<channel>[0-9]{1,2}); "          # channel=1
    r"Nfn:(?P<netfn>[0-9a-fA-F]{1,2}); "     # netfn=6
    r"Cmd:(?P<cmd>[0-9a-fA-F]{1,2}); "       # cmd=1
    r"Data:(?P<data_str>[0-9a-fA-F ]*?)"     # data_str="0 20 1 2 8 2 4f 37 1 0 5d 8 0 0 0 0"
    r"[ ]*?-"
)


@dataclass(frozen=True, order=True)
class IPMILogLine:
    timestamp: datetime
    intf: str
    req_type: str
    channel: int
    netfn: int
    cmd: int
    data_str: str = field(compare=False)
    data: bytearray = field(init=False)

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name == "data":
                continue
            elif field.name == "data_str":
                object.__setattr__(self, field.name, field.type(value))
                value = convert_line_to_bytearray(value)
                object.__setattr__(self, "data", bytearray(value))
                continue
            elif field.name == "timestamp":
                timestamp = datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
                utc_timestamp = pytz.utc.localize(timestamp)
                value = utc_timestamp
                object.__setattr__(self, field.name, value)
                continue

            if type(value) is str and field.type is int:
                value = convert_hex_str_to_integer(value)
            object.__setattr__(self, field.name, field.type(value) if type(value) is not field.type else value)
        if self.req_type == "Res" and self.netfn % 2 == 0:
            object.__setattr__(self, "netfn", self.netfn + 1)

    def __repr__(self):
        return f"{self.req_type}[{self.netfn:02X},{self.cmd:X}]: {self.data_str}"

    def get_data(self):
        return bytearray([self.netfn << 2, self.cmd]) + self.data


def convert_hex_str_to_integer(value: str):
    return int(value, 16)


def convert_line_to_bytearray(line: str):
    return [convert_hex_str_to_integer(b) for b in line.split(" ") if b]


def parse_ipmi_log_line(line: str) -> Dict[datetime, IPMILogLine]:
    parsedData = dict()
    for match in ipmiLogLineRE.finditer(line):
        line_data = match.groupdict()
        ipmi_obj = IPMILogLine(**line_data)
        parsedData[ipmi_obj.timestamp] = ipmi_obj
    return parsedData


def main(args) -> int:
    set_printable_raw_layer()
    # conf.debug_dissector = True

    if args.intf == "-":
        monitor_fd = sys.stdin
    elif os.path.isfile(args.intf):
        monitor_fd = open(args.intf, "r")
    else:
        raise SystemExit(f"Unexpected file path: {args.intf}")

    only_show_mctp_pkts = getattr(args, 'mctp_requests_only', False)
    show_all_pkts = getattr(args, 'show_all_pks', False)

    req_timestamp: datetime or None = None
    rqt_pkt: ipmi.TransportHdrPacket or None = None
    for line in iter(monitor_fd.readline, ""):
        line = line.split("] ")[-1]
        # line = line.split("-05:00:  ")[-1]
        try:
            parsed_data = parse_ipmi_log_line(line)
        except:
            continue
        if not parsed_data:
            continue

        for timestamp, cmd in parsed_data.items():
            ipmi_packet = ipmi.TransportHdrPacket(cmd.get_data())
            # Optionally filter to only packets that contain an MCTP layer (legacy behavior)
            if not show_all_pkts and (not ipmi_packet.payload or isinstance(ipmi_packet.payload, conf.raw_layer)):
                continue
            if only_show_mctp_pkts and not ipmi_packet.haslayer(TransportHdrPacket):
                continue
            # pkt_summary = f"{current_ts.isoformat()}:  {timestamp.isoformat()}: {ipmi_packet.summary()}"
            pkt_summary = f"{timestamp.isoformat()}: {ipmi_packet.summary()}"
            print(pkt_summary)

    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", help="IPMI interface to sniff (e.g., 'oob' or 'inband' or '-' for stdin)",
                        action="store", dest="intf", default="oob")
    parser.add_argument('-v', '--verbose', dest='verbose', default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument('-m', '--mctp', dest='mctp_requests_only', default=False, action=argparse.BooleanOptionalAction,
                        help='Show only MCTP packets (that contain an MCTP layer)')
    parser.add_argument('-a', '--all', dest='show_all_pks', default=False,
                        action=argparse.BooleanOptionalAction,
                        help='Show all IPMI request packets')

    args = parser.parse_args()

    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        raise e
        # import traceback
        #
        # traceback.print_exc()
        # sys.exit(1)
