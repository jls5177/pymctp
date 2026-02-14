# SPDX-FileCopyrightText: 2024 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Analyze IPMI audit log files containing IPMI and MCTP traffic."""

import pathlib
import sys
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
from typing import Dict, TextIO

import click
import pytz
from scapy.config import conf
from tzlocal import get_localzone_name

from pymctp.layers import TransportHdrPacket, ipmi, mctp
from pymctp.utils.helpers import set_printable_raw_layer


def is_dst_active(zonename: str) -> bool:
    """Check if daylight saving time is active for a timezone."""
    return bool(datetime.now(pytz.timezone(zonename)).dst())


DEFAULT_TZ = pytz.timezone(get_localzone_name())
DEFAULT_DST = is_dst_active(get_localzone_name())


@dataclass(frozen=True, order=True)
class IPMILogLine:
    """Represents a parsed IPMI log line."""

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


def convert_hex_str_to_integer(value: str) -> int:
    """Convert hex string to integer."""
    return int(value, 16)


def convert_line_to_bytearray(line: str) -> list:
    """Convert space-separated hex string to bytearray."""
    return [convert_hex_str_to_integer(b) for b in line.split(" ") if b]


def parse_ipmi_log_line(line: str) -> Dict[datetime, IPMILogLine]:
    """Parse a single IPMI log line.

    Parses lines like:
    2011-04-06 01:34:22.396961 LAN - Res Ch:1; Nfn:6; Cmd:1; Data:0 20 1 2 8 2 4f 37 1 0 5d 8 0 0 0 0  -
    """
    import re

    ipmiLogLineRE = re.compile(
        r"(?P<timestamp>.+?) (?P<intf>LAN|KCS|SSIF|OEM) - "
        r"(?P<req_type>Res|Req) "
        r"Ch:(?P<channel>[0-9]{1,2}); "
        r"Nfn:(?P<netfn>[0-9a-fA-F]{1,2}); "
        r"Cmd:(?P<cmd>[0-9a-fA-F]{1,2}); "
        r"Data:(?P<data_str>[0-9a-fA-F ]*?)"
        r"[ ]*?-"
    )

    parsedData = dict()
    for match in ipmiLogLineRE.finditer(line):
        line_data = match.groupdict()
        ipmi_obj = IPMILogLine(**line_data)
        parsedData[ipmi_obj.timestamp] = ipmi_obj
    return parsedData


@click.command()
@click.option(
    "-i",
    "--input",
    "input_file",
    type=click.Path(exists=True, path_type=pathlib.Path),
    default=None,
    help="IPMI audit log file to analyze (default: stdin)",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    default=False,
    help="Enable verbose output",
)
@click.option(
    "-m",
    "--mctp",
    "mctp_only",
    is_flag=True,
    default=False,
    help="Show only MCTP packets (that contain an MCTP layer)",
)
@click.option(
    "-a",
    "--all",
    "show_all",
    is_flag=True,
    default=False,
    help="Show all IPMI request packets",
)
@click.option(
    "--threshold",
    type=float,
    default=500.0,
    help="Response time threshold in milliseconds for logging slow responses (default: 500ms)",
)
@click.option(
    "--no-missing-check",
    is_flag=True,
    default=False,
    help="Disable missing response detection",
)
def analyze_ipmi_audit_log(
    input_file: pathlib.Path | None,
    verbose: bool,
    mctp_only: bool,
    show_all: bool,
    threshold: float,
    no_missing_check: bool,
):
    """Analyze IPMI audit log files containing IPMI and MCTP traffic.

    This tool parses IPMI audit logs and displays packet summaries.
    By default, it filters to show only packets with higher-layer protocol data
    and checks for missing responses.

    When an input file is provided, outputs are written to:
    - <input>.decoded.log - All decoded packets
    - <input>.missing.log - Missing or slow responses

    Examples:

    \b
    # Analyze from stdin (outputs to console only)
    cat audit.log | pymctp analyze-ipmi-audit-log

    \b
    # Analyze a file (creates audit.log.decoded.log and audit.log.missing.log)
    pymctp analyze-ipmi-audit-log -i audit.log

    \b
    # Show only MCTP packets
    pymctp analyze-ipmi-audit-log -i audit.log --mctp

    \b
    # Show all IPMI packets
    pymctp analyze-ipmi-audit-log -i audit.log --all

    \b
    # Adjust response time threshold
    pymctp analyze-ipmi-audit-log -i audit.log --threshold 1000
    """
    set_printable_raw_layer()

    # Determine input source and output files
    if input_file:
        fd = open(input_file, "r")
        decoded_output = open(f"{input_file}.decoded.log", "w")
        missing_output = open(f"{input_file}.missing.log", "w") if not no_missing_check else None
        click.echo(f"Analyzing: {input_file}")
        click.echo(f"Writing decoded packets to: {input_file}.decoded.log")
        if missing_output:
            click.echo(f"Writing missing/slow responses to: {input_file}.missing.log")
    else:
        fd = sys.stdin
        decoded_output = sys.stdout
        missing_output = None
        no_missing_check = True  # Can't track missing responses without file context

    try:
        # Track request/response pairs for missing response detection
        req_timestamp: datetime | None = None
        req_pkt: ipmi.TransportHdrPacket | None = None
        req_intf: str | None = None

        for line in fd:
            # Strip common log prefixes
            line = line.split("] ")[-1]

            try:
                parsed_data = parse_ipmi_log_line(line)
            except Exception:
                continue

            if not parsed_data:
                continue

            for timestamp, cmd in parsed_data.items():
                ipmi_packet = ipmi.TransportHdrPacket(cmd.get_data())

                # Handle missing response detection
                if not no_missing_check:
                    if ipmi_packet.is_request():
                        # Check if previous request is missing a response
                        if req_pkt and req_intf == "KCS":
                            output_line = "Response missing for KCS request\n"
                            output_line += f"{req_timestamp.isoformat()}: {req_pkt.summary()}\n"
                            if missing_output:
                                missing_output.write(output_line)
                            if verbose:
                                click.echo(output_line.strip(), err=True)

                        # Store new request
                        req_timestamp = timestamp
                        req_pkt = ipmi_packet
                        req_intf = cmd.intf
                    else:
                        # This is a response
                        if req_timestamp and req_pkt:
                            elapsed_time: timedelta = timestamp - req_timestamp
                            elapsed_time_ms = elapsed_time.total_seconds() * 1000

                            if elapsed_time_ms > threshold:
                                output_line = f"Slow response: {elapsed_time_ms:.2f} ms\n"
                                output_line += f"{req_timestamp.isoformat()}: {req_pkt.summary()}\n"
                                output_line += f"{timestamp.isoformat()}: {ipmi_packet.summary()}\n"
                                if missing_output:
                                    missing_output.write(output_line)
                                if verbose:
                                    click.echo(output_line.strip(), err=True)

                        # Clear request tracking
                        req_pkt = None
                        req_timestamp = None
                        req_intf = None

                # Filter packets for decoded output
                if not show_all and (not ipmi_packet.payload or isinstance(ipmi_packet.payload, conf.raw_layer)):
                    continue

                if mctp_only and not ipmi_packet.haslayer(TransportHdrPacket):
                    continue

                # Write to decoded output
                pkt_summary = f"{timestamp.isoformat()}: {ipmi_packet.summary()}\n"
                decoded_output.write(pkt_summary)
                if decoded_output == sys.stdout:
                    decoded_output.flush()

    finally:
        # Clean up file handles
        if fd != sys.stdin:
            fd.close()
        if decoded_output != sys.stdout:
            decoded_output.close()
        if missing_output:
            missing_output.close()
