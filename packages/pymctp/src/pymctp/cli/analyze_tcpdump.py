# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Analyze MCTP packet captures from tcpdump or pcap files."""

import binascii
import pathlib
import re
from collections import Counter
from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import List, Tuple

import click
import pytz
from scapy.packet import Raw
from scapy.utils import PcapReader

from pymctp.analyzers import AnalysisEngine, Severity
from pymctp.analyzers.cerberus import CerberusLogTransferRule
from pymctp.analyzers.mctp import FragmentationRule, TagReuseRule
from pymctp.analyzers.plugin_loader import discover_analyzer_rules
from pymctp.analyzers.spdm import (
    SpdmCertChainRule,
    SpdmErrorResponseRule,
    SpdmMeasurementsRule,
    SpdmNegotiationSequenceRule,
)
from pymctp.analyzers.timing import InterPacketGapRule, ResponseTimeoutRule
from pymctp.layers.mctp import TransportHdr, TransportHdrPacket
from pymctp.layers.mctp.types import AnyPacketType, MsgTypes
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
) -> Iterator[tuple[datetime | None, AnyPacketType]]:
    """Parse text-format tcpdump file, yielding packets as they are assembled.

    Args:
        filename: Path to text dump file
        timezone_str: Timezone string (e.g., 'US/Central')
        is_dst: Daylight saving time flag
        date_str: Date string in YYYY-MM-DD format for text dumps without dates

    Yields:
        ``(timestamp, packet)`` tuples as each complete packet is assembled.
    """
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
                yield (next_request_timestamp, mctp_packet)
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
        yield (next_request_timestamp, mctp_packet)


def parse_pcap_file(
    filename: pathlib.Path, timezone_str: str, is_dst: bool
) -> Iterator[tuple[datetime, AnyPacketType]]:
    """Parse pcap/dump file, yielding MCTP packets as they are read.

    Yields:
        ``(timestamp, packet)`` tuples for each MCTP packet in the capture.
    """
    tz = pytz.timezone(timezone_str)
    with PcapReader(str(filename.resolve())) as fdesc:
        for packet in fdesc:
            if not packet.haslayer(TransportHdrPacket):
                continue
            timestamp = datetime.fromtimestamp(float(packet.time))
            timestamp = tz.localize(timestamp, is_dst=is_dst)
            utc_timestamp = timestamp.astimezone(pytz.utc)
            yield (utc_timestamp, packet.getlayer(TransportHdrPacket))


_SEVERITY_CHOICES = [s.name.lower() for s in Severity]


def _build_builtin_rules(
    response_timeout: float,
    gap_threshold: float,
) -> list:
    """Instantiate all built-in analysis rules with the given parameters."""
    return [
        # Timing
        ResponseTimeoutRule(timeout=timedelta(seconds=response_timeout)),
        InterPacketGapRule(threshold=timedelta(seconds=gap_threshold)),
        # MCTP transport
        FragmentationRule(),
        TagReuseRule(),
        # SPDM
        SpdmNegotiationSequenceRule(),
        SpdmErrorResponseRule(),
        SpdmCertChainRule(),
        SpdmMeasurementsRule(),
        # Cerberus
        CerberusLogTransferRule(),
    ]


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
@click.option(
    "--triage/--no-triage",
    default=False,
    help="Run analysis rules to detect protocol issues (default: disabled)",
)
@click.option(
    "--min-severity",
    type=click.Choice(_SEVERITY_CHOICES, case_sensitive=False),
    default="warning",
    help="Minimum severity level to report (default: warning)",
)
@click.option(
    "--rules",
    multiple=True,
    help="Rule IDs to enable (default: all). May be repeated, e.g. --rules TIMING-001 --rules SPDM-SEQ-001",
)
@click.option(
    "--response-timeout",
    type=float,
    default=5.0,
    show_default=True,
    help="Threshold in seconds for delayed response detection",
)
@click.option(
    "--gap-threshold",
    type=float,
    default=10.0,
    show_default=True,
    help="Threshold in seconds for inter-packet gap detection",
)
@click.option(
    "--json-report",
    type=click.Path(path_type=pathlib.Path),
    default=None,
    help="Write triage findings to a JSON file",
)
@click.option(
    "--packet-log",
    type=click.Path(path_type=pathlib.Path),
    default=None,
    help="Write per-packet listing to a file (useful in triage mode where terminal output is suppressed)",
)
def analyze_tcpdump(
    capture_file: pathlib.Path,
    timezone: str,
    dst: bool,
    date: str | None,
    triage: bool,
    min_severity: str,
    rules: tuple[str, ...],
    response_timeout: float,
    gap_threshold: float,
    json_report: pathlib.Path | None,
    packet_log: pathlib.Path | None,
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

    \b
    # Run triage analysis to detect issues
    pymctp analyze-tcpdump capture.pcap --triage

    \b
    # Triage with custom thresholds and JSON output
    pymctp analyze-tcpdump capture.pcap --triage --response-timeout 2.0 --json-report report.json

    \b
    # Only run specific rules
    pymctp analyze-tcpdump capture.pcap --triage --rules SPDM-SEQ-001 --rules TIMING-001

    \b
    # Triage mode with packet listing saved to file
    pymctp analyze-tcpdump capture.pcap --triage --packet-log packets.txt
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

    # Parse the capture file as a lazy iterator
    if capture_file.suffix in [".pcap", ".dump"]:
        click.echo(f"Parsing pcap file: {capture_file}")
        packet_iter = parse_pcap_file(capture_file, timezone, dst)
    else:
        click.echo(f"Parsing text dump file: {capture_file}")
        click.echo(f"Using date: {date} (timezone: {timezone}, DST: {dst})")
        packet_iter = parse_text_file(capture_file, timezone, dst, date)

    # --- Set up triage engine (if needed) before the single-pass loop ---
    engine: AnalysisEngine | None = None
    if triage:
        severity_level = Severity[min_severity.upper()]

        # Build rule set
        all_rules = _build_builtin_rules(response_timeout, gap_threshold)

        # Discover plugin rules from third-party packages
        all_rules.extend(discover_analyzer_rules())

        # Filter to specific rule IDs if requested
        if rules:
            rule_ids = set(rules)
            all_rules = [r for r in all_rules if r.rule_id in rule_ids]
            if not all_rules:
                click.echo(
                    f"Warning: no rules matched the requested IDs: {', '.join(rules)}",
                    err=True,
                )
                return

        engine = AnalysisEngine(all_rules)
        engine.reset()

    # --- Single-pass: parse, display/log, tally, and feed to triage ---
    packet_log_file = packet_log.open("w") if packet_log is not None else None
    type_counts: Counter[str] = Counter()
    pkt_count = 0

    try:
        for pkt_id, (timestamp, mctp_packet) in enumerate(packet_iter, start=1):
            pkt_count += 1
            if timestamp:
                mctp_packet.timestamp = timestamp

            # Tally message types (only SOM packets carry msg_type)
            if hasattr(mctp_packet, "som") and mctp_packet.som:
                try:
                    type_counts[MsgTypes(mctp_packet.msg_type).name] += 1
                except (ValueError, AttributeError):
                    type_counts[f"0x{mctp_packet.msg_type:02X}"] += 1
            elif hasattr(mctp_packet, "som"):
                type_counts["(fragment)"] += 1

            # Build the display line once
            if timestamp:
                line = f"{timestamp.isoformat()}: {mctp_packet.summary()}"
            else:
                line = f"{mctp_packet.summary()}"

            # Print to terminal (suppressed in triage mode)
            if not triage:
                click.echo(line)

            # Write to packet log file if requested
            if packet_log_file is not None:
                packet_log_file.write(line + "\n")

            # Feed to triage engine (zero-based index)
            if engine is not None:
                engine.feed(pkt_id, timestamp, mctp_packet)
    finally:
        if packet_log_file is not None:
            packet_log_file.close()

    click.echo(f"Total packets: {pkt_count}")

    if packet_log is not None:
        click.echo(f"Packet listing written to: {packet_log}")

    # --- Triage report ---
    if engine is not None:
        click.echo(f"\n{'=' * 60}")
        click.echo(f"Triage Report  ({len(engine.rules)} rules active)")
        click.echo(f"{'=' * 60}")

        # Packet type breakdown
        if type_counts:
            breakdown = ", ".join(f"{count} {name}" for name, count in type_counts.most_common())
            click.echo(f"Packet types: {breakdown}")

        engine.finalize_analysis()
        engine.print_report(min_severity=severity_level)

        if json_report is not None:
            json_report.write_text(engine.to_json(min_severity=severity_level))
            click.echo(f"\nJSON report written to: {json_report}")
