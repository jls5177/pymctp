# SPDX-FileCopyrightText: 2024 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Analyze IPMI audit log files containing IPMI and MCTP traffic."""

import pathlib
import re
import sys
from collections import Counter
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
import binascii

import crc8
import click
import pytz
from scapy.config import conf
from scapy.packet import Raw, Packet
from tzlocal import get_localzone_name

from pymctp.cli.triage import print_triage_report, setup_triage_engine, tally_mctp_packet, triage_options
from pymctp.layers import TransportHdrPacket, ipmi, mctp
from pymctp.utils.helpers import set_printable_raw_layer

from pymctp_oem_microsoft.analyzers import IpmiMissingResponseRule, IpmiSlowResponseRule


def is_dst_active(zonename: str) -> bool:
    """Check if daylight saving time is active for a timezone."""
    return bool(datetime.now(pytz.timezone(zonename)).dst())


DEFAULT_TZ = pytz.timezone(get_localzone_name())
DEFAULT_DST = is_dst_active(get_localzone_name())


class CustomPrintableRawPacket(Raw):
    name = "PRaw"
    __slots__ = ["_mysummary_cls"]
    ALL_1s_BLOCK = bytes([0xFF] * 4096)

    def set_mysummary_classes(self, classes):
        self._mysummary_cls = classes

    def mysummary(self):
        if not len(self.load):
            summary = "Empty"
        elif self.load == CustomPrintableRawPacket.ALL_1s_BLOCK[: len(self.load)]:
            summary = f"Padded [0xff] * {len(self.load)}"
        else:
            # add CRC to make it easy to compare raw payloads
            crc = crc8.crc8()
            crc.update(self.load)
            summary = (
                f"Raw ${crc.hexdigest().upper()} [{len(self.load)}] {binascii.hexlify(self.load, b' ', -1).decode()}"
            )
        if hasattr(self, "_mysummary_cls"):
            return summary, [
                *self._mysummary_cls,
                mctp.SmbusTransportPacket,
                mctp.TransportHdrPacket,
                ipmi.TransportHdrPacket,
            ]
        return summary, [mctp.SmbusTransportPacket, mctp.TransportHdrPacket, ipmi.TransportHdrPacket]


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


_IPMI_LOG_RE = re.compile(
    r"(?P<timestamp>.+?) (?P<intf>LAN|KCS|SSIF|OEM) - "
    r"(?P<req_type>Res|Req) "
    r"Ch:(?P<channel>[0-9]{1,2}); "
    r"Nfn:(?P<netfn>[0-9a-fA-F]{1,2}); "
    r"Cmd:(?P<cmd>[0-9a-fA-F]{1,2}); "
    r"Data:(?P<data_str>[0-9a-fA-F ]*?)"
    r"[ ]*?-"
)


def convert_hex_str_to_integer(value: str) -> int:
    """Convert hex string to integer."""
    return int(value, 16)


def convert_line_to_bytearray(line: str) -> list:
    """Convert space-separated hex string to bytearray."""
    return [convert_hex_str_to_integer(b) for b in line.split(" ") if b]


def parse_ipmi_log_line(line: str) -> dict[datetime, IPMILogLine]:
    """Parse a single IPMI log line.

    Parses lines like:
    2011-04-06 01:34:22.396961 LAN - Res Ch:1; Nfn:6; Cmd:1; Data:0 20 1 2 8 2 4f 37 1 0 5d 8 0 0 0 0  -
    """
    parsed_data: dict[datetime, IPMILogLine] = {}
    for match in _IPMI_LOG_RE.finditer(line):
        line_data = match.groupdict()
        ipmi_obj = IPMILogLine(**line_data)
        parsed_data[ipmi_obj.timestamp] = ipmi_obj
    return parsed_data


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
    help="Response time threshold in milliseconds for IPMI slow response rule (default: 500ms)",
)
@click.option(
    "--no-missing-check",
    is_flag=True,
    default=False,
    help="Disable IPMI missing response detection rule",
)
@triage_options
def analyze_ipmi_audit_log(
    input_file: pathlib.Path | None,
    verbose: bool,
    mctp_only: bool,
    show_all: bool,
    threshold: float,
    no_missing_check: bool,
    triage: bool,
    min_severity: str,
    rules: tuple[str, ...],
    response_timeout: float,
    gap_threshold: float,
    json_report: pathlib.Path | None,
    packet_log: pathlib.Path | None,
):
    """Analyze IPMI audit log files containing IPMI and MCTP traffic.

    This tool parses IPMI audit logs and displays packet summaries.
    By default, it filters to show only packets with higher-layer protocol data
    and checks for missing responses.

    When an input file is provided, outputs are written to:
    - <input>.decoded.log - All decoded packets
    - <input>.missing.log - Missing or slow responses (legacy mode only)

    Use --triage to enable the full analysis engine with all upstream and
    IPMI-specific triage rules.

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

    \b
    # Run full triage analysis
    pymctp analyze-ipmi-audit-log -i audit.log --triage

    \b
    # Triage with JSON report
    pymctp analyze-ipmi-audit-log -i audit.log --triage --json-report report.json
    """
    # set_printable_raw_layer()
    conf.raw_layer = CustomPrintableRawPacket

    # --- Build IPMI-specific rules ---
    extra_rules = []
    if not no_missing_check:
        extra_rules.append(IpmiMissingResponseRule())
    extra_rules.append(IpmiSlowResponseRule(threshold=timedelta(milliseconds=threshold)))

    # --- Set up triage engine ---
    engine, severity_level = setup_triage_engine(
        triage, min_severity, rules, response_timeout, gap_threshold, extra_rules=extra_rules
    )

    # --- Determine input source and output files ---
    if input_file:
        fd = open(input_file, "r")
        click.echo(f"Analyzing: {input_file}")
        if packet_log is None:
            decoded_output = open(f"{input_file}.decoded.log", "w")
            click.echo(f"Writing decoded packets to: {input_file}.decoded.log")
        else:
            decoded_output = None
    else:
        fd = sys.stdin
        decoded_output = sys.stdout

    # Legacy missing output file (when triage is not enabled)
    missing_output = None
    if input_file and not triage and not no_missing_check:
        missing_output = open(f"{input_file}.missing.log", "w")
        click.echo(f"Writing missing/slow responses to: {input_file}.missing.log")

    packet_log_file = packet_log.open("w") if packet_log is not None else None
    type_counts: Counter[str] = Counter()
    pkt_count = 0

    try:
        # Track request/response pairs for legacy (non-triage) missing response detection
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
                pkt_count += 1
                ipmi_packet = ipmi.TransportHdrPacket(cmd.get_data())

                # Store interface info on the packet for IpmiMissingResponseRule
                ipmi_packet.ipmi_intf = cmd.intf

                # Triage mode — feed to engine
                if engine is not None:
                    engine.feed(pkt_count, timestamp, ipmi_packet)

                    # Tally MCTP message types if the packet has an MCTP layer
                    if ipmi_packet.haslayer(TransportHdrPacket):
                        tally_mctp_packet(ipmi_packet.getlayer(TransportHdrPacket), type_counts)
                else:
                    # Legacy mode — inline missing/slow response detection
                    if not no_missing_check:
                        if ipmi_packet.is_request():
                            if req_pkt and req_intf == "KCS":
                                output_line = "Response missing for KCS request\n"
                                output_line += f"{req_timestamp.isoformat()}: {req_pkt.summary()}\n"
                                if missing_output:
                                    missing_output.write(output_line)
                                if verbose:
                                    click.echo(output_line.strip(), err=True)
                            req_timestamp = timestamp
                            req_pkt = ipmi_packet
                            req_intf = cmd.intf
                        else:
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
                            req_pkt = None
                            req_timestamp = None
                            req_intf = None

                # Filter packets for decoded output
                if not show_all and (not ipmi_packet.payload or isinstance(ipmi_packet.payload, conf.raw_layer)):
                    continue

                if mctp_only and not ipmi_packet.haslayer(TransportHdrPacket):
                    continue

                # Build display line
                pkt_summary = f"{timestamp.isoformat()}: {ipmi_packet.summary()}"

                # Print to terminal (suppressed in triage mode)
                if not triage and decoded_output is not None:
                    decoded_output.write(pkt_summary + "\n")
                    if decoded_output == sys.stdout:
                        decoded_output.flush()

                # Write to packet log file if requested
                if packet_log_file is not None:
                    packet_log_file.write(pkt_summary + "\n")

    finally:
        if fd != sys.stdin:
            fd.close()
        if decoded_output is not None and decoded_output != sys.stdout:
            decoded_output.close()
        if missing_output:
            missing_output.close()
        if packet_log_file is not None:
            packet_log_file.close()

    click.echo(f"Total packets: {pkt_count}")

    if packet_log is not None:
        click.echo(f"Packet listing written to: {packet_log}")

    # --- Triage report ---
    if engine is not None:
        print_triage_report(engine, severity_level, type_counts, json_report)
