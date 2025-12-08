# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Analyze MCTP packet captures from tcpdump or pcap files."""

import pathlib
import re
from datetime import datetime
from typing import List, Tuple

import click
import pytz
from scapy.packet import Raw
from scapy.utils import PcapReader

from pymctp.layers.mctp import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import AnyPacketType
from pymctp.utils import set_printable_raw_layer

timestampRE = r"([\d]{2}:[\d]{2}:[\d]{2}\.[\d]{6,9})"
timestampRegex = re.compile(timestampRE)


def parse_timestamp(line: str, timezone_str: str, is_dst: bool, date_str: str) -> datetime | None:
    """Parse timestamp from tcpdump text line.

    Args:
        line: Line to parse timestamp from
        timezone_str: Timezone string (e.g., 'US/Central')
        is_dst: Daylight saving time flag
        date_str: Date string in YYYY-MM-DD format for text dumps without dates

    Returns:
        Parsed timestamp in UTC or None if no timestamp found
    """
    line = line.strip()
    for match in timestampRegex.finditer(line):
        timestampStr = match.group(1)
        dt_obj = datetime.strptime(f"{date_str} {timestampStr}", "%Y-%m-%d %H:%M:%S.%f")
        tz = pytz.timezone(timezone_str)
        dt_obj = tz.localize(dt_obj, is_dst=is_dst)
        return dt_obj.astimezone(pytz.utc)
    return None


def parse_line(line: str) -> tuple[int | None, bytes]:
    """Parse single line of hex dump."""
    line = line.strip()
    if not line.startswith("0x") or line.count("  ") < 2:
        return None, b""
    offset, data_line, *_ = line.split("  ")
    return int(offset[:-1], 16), bytes.fromhex(data_line)


def parse_text_file(
    filename: pathlib.Path, timezone_str: str, is_dst: bool, date_str: str
) -> list[tuple[datetime | None, AnyPacketType]]:
    """Parse text-format tcpdump file.

    Args:
        filename: Path to text dump file
        timezone_str: Timezone string (e.g., 'US/Central')
        is_dst: Daylight saving time flag
        date_str: Date string in YYYY-MM-DD format for text dumps without dates
    """
    packets = []
    next_request = b""
    next_request_timestamp = None
    for line in filename.read_text().splitlines():
        timestamp = parse_timestamp(line, timezone_str, is_dst, date_str)
        if timestamp is not None:
            # next request is started, save previous request
            if next_request:
                try:
                    mctp_packet = TransportHdr(next_request)
                except Exception:
                    mctp_packet = Raw(next_request)
                packets += [(next_request_timestamp, mctp_packet)]
            next_request_timestamp = timestamp
            continue
        offset, data = parse_line(line)
        if offset is None and data is None:
            continue
        if offset == 0:
            next_request = data
        else:
            next_request += data
    if next_request:
        try:
            mctp_packet = TransportHdr(next_request)
        except Exception:
            mctp_packet = Raw(next_request)
        packets += [(next_request_timestamp, mctp_packet)]
    return packets


def parse_pcap_file(filename: pathlib.Path, timezone_str: str, is_dst: bool) -> list[tuple[datetime, AnyPacketType]]:
    """Parse pcap/dump file."""
    packets: list[tuple[datetime, AnyPacketType]] = list()
    tz = pytz.timezone(timezone_str)
    with PcapReader(str(filename.resolve())) as fdesc:
        for packet in fdesc:
            if not packet.haslayer(TransportHdrPacket):
                continue
            timestamp = datetime.fromtimestamp(float(packet.time))
            timestamp = tz.localize(timestamp, is_dst=is_dst)
            utc_timestamp = timestamp.astimezone(pytz.utc)
            packets += [(utc_timestamp, packet.getlayer(TransportHdrPacket))]
    return packets


@click.command()
@click.argument("capture_file", type=click.Path(exists=True, path_type=pathlib.Path))
@click.option(
    "--timezone",
    "-tz",
    default="US/Central",
    help="Timezone for timestamp parsing (default: US/Central)",
)
@click.option(
    "--dst/--no-dst",
    default=True,
    help="Enable/disable daylight saving time adjustment (default: enabled)",
)
@click.option(
    "--date",
    "-d",
    default=None,
    help="Date for text dumps without dates (YYYY-MM-DD format, default: today's date)",
)
def analyze_tcpdump(
    capture_file: pathlib.Path,
    timezone: str,
    dst: bool,
    date: str | None,
):
    """Analyze MCTP packet captures from tcpdump or pcap files.

    CAPTURE_FILE can be either a pcap file (.pcap, .dump) or a text-format
    tcpdump output containing hex dumps of MCTP packets.

    For text dumps, timestamps typically only include time (HH:MM:SS.microseconds)
    without a date. Use --date to specify the date for these captures.

    Examples:

    \b
    # Analyze a pcap file
    pymctp analyze-tcpdump capture.pcap

    \b
    # Analyze text dump with custom timezone and date
    pymctp analyze-tcpdump dump.txt --timezone America/New_York --date 2024-03-20
    """
    set_printable_raw_layer()

    # Determine date string for text dumps
    if date is None:
        # Default to today's date in YYYY-MM-DD format
        date = datetime.now().strftime("%Y-%m-%d")

    # Validate date format
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        click.echo(f"Error: Invalid date format '{date}'. Expected YYYY-MM-DD.", err=True)
        raise click.Abort()

    # Parse the capture file
    packets: list[tuple[datetime | None, AnyPacketType]] = []
    if capture_file.suffix in [".pcap", ".dump"]:
        click.echo(f"Parsing pcap file: {capture_file}")
        packets = parse_pcap_file(capture_file, timezone, dst)
    else:
        click.echo(f"Parsing text dump file: {capture_file}")
        click.echo(f"Using date: {date} (timezone: {timezone}, DST: {dst})")
        packets = parse_text_file(capture_file, timezone, dst, date)

    click.echo(f"Total packets: {len(packets)}")

    # Display packet summaries
    for timestamp, mctp_packet in packets:
        if timestamp:
            mctp_packet.timestamp = timestamp
            click.echo(f"{timestamp.isoformat()}: {mctp_packet.summary()}")
        else:
            click.echo(f"{mctp_packet.summary()}")
