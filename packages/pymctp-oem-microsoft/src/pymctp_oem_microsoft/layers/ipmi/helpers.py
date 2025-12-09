import argparse
import binascii
import os.path
import re
import sys
from dataclasses import dataclass, field, fields
from datetime import datetime
from io import TextIOWrapper
from typing import Dict

import pytz
from scapy.config import conf
from scapy.packet import Raw
from tzlocal import get_localzone_name

from pymctp.layers import mctp, ipmi  # noqa
from pymctp.utils.helpers import set_printable_raw_layer


def is_dst_active(zonename: str) -> bool:
    return bool(datetime.now(pytz.timezone(zonename)).dst())


DEFAULT_TZ = pytz.timezone(get_localzone_name())
DEFAULT_DST = is_dst_active(get_localzone_name())

# This regex parses lines like the following:
# 2011-04-06 01:34:22.396961 LAN - Res Ch:1; Nfn:6; Cmd:1; Data:0 20 1 2 8 2 4f 37 1 0 5d 8 0 0 0 0  -
ipmiLogLineRE = re.compile(
    r"(?P<timestamp>.+?) (?P<intf>LAN|KCS|SSIF|OEM) - "  # timestamp="2011-04-06 01:34:22.396961"
    r"(?P<req_type>Res|Req) "  # req_type="Res"
    r"Ch:(?P<channel>[0-9]{1,2}); "  # channel=1
    r"Nfn:(?P<netfn>[0-9a-fA-F]{1,2}); "  # netfn=6
    r"Cmd:(?P<cmd>[0-9a-fA-F]{1,2}); "  # cmd=1
    r"Data:(?P<data_str>[0-9a-fA-F ]*?)"  # data_str="0 20 1 2 8 2 4f 37 1 0 5d 8 0 0 0 0"
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
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name == "data":
                continue
            elif f.name == "data_str":
                object.__setattr__(self, f.name, f.type(value))
                value = convert_line_to_bytearray(value)
                object.__setattr__(self, "data", bytearray(value))
                continue
            elif f.name == "timestamp":
                timestamp = datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
                utc_timestamp = pytz.utc.localize(timestamp)
                value = utc_timestamp
                object.__setattr__(self, f.name, value)
                continue

            if type(value) is str and f.type is int:
                value = convert_hex_str_to_integer(value)
            object.__setattr__(self, f.name, f.type(value) if type(value) is not f.type else value)
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


def parse_ipmi_log_line(line: str) -> Dict[str, IPMILogLine]:
    parsedData = dict()
    for match in ipmiLogLineRE.finditer(line):
        line_data = match.groupdict()
        ipmi_obj = IPMILogLine(**line_data)
        parsedData[ipmi_obj.timestamp] = ipmi_obj
    return parsedData
