#!/usr/bin/env python3
"""
CSV Parser for I2C Transaction Data

This script parses CSV files containing I2C transaction data and extracts
the start_time, address, and data columns. It can process a single file
or all CSV files in a directory.
"""

import csv
import argparse
import os
import re
import sys
from collections import Counter
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from scapy.config import conf

from pymctp.cli.triage import print_triage_report, setup_triage_engine, tally_mctp_packet
from pymctp.layers import SmbusTransport
from pymctp.utils import str_to_bytes, PrintableRawPacket


@dataclass
class I2CTransaction:
    """Represents an I2C transaction parsed from the CSV"""
    start_time: Optional[datetime]
    duration: Optional[float]
    address: str
    data: str
    count: int
    row_num: int


def parse_duration(duration_string):
    """
    Parse duration from Total Phase format and convert to milliseconds

    Supports:
    - Milliseconds: "25.017.100 ms" -> 25.017100 ms
    - Microseconds: "500.123 us" -> 0.500123 ms
    - Seconds: "1.5 s" -> 1500.0 ms

    Returns:
        float: Duration in milliseconds, or None if parsing fails
    """
    if not duration_string or not isinstance(duration_string, str):
        return None

    # Extract the unit (ms, us, s)
    unit_pattern = r'\s*(ms|us|μs|s)\s*$'
    unit_match = re.search(unit_pattern, duration_string.strip())

    if not unit_match:
        return None

    unit = unit_match.group(1).lower()

    # Remove unit and extra whitespace
    number_part = re.sub(unit_pattern, '', duration_string.strip())

    if not number_part:
        return None

    try:
        # Handle Total Phase format: X.XXX.XXX -> X.XXXXXX
        complex_pattern = r'^(\d+)\.(\d{3})\.(\d{3})$'
        match = re.match(complex_pattern, number_part)

        if match:
            whole = match.group(1)
            frac1 = match.group(2)
            frac2 = match.group(3)
            value = float(f"{whole}.{frac1}{frac2}")
        else:
            # Handle normal decimal format
            value = float(number_part)

        # Convert to milliseconds based on unit
        if unit in ['ms']:
            return value
        elif unit in ['us', 'μs']:
            return value / 1000.0  # microseconds to milliseconds
        elif unit == 's':
            return value * 1000.0  # seconds to milliseconds
        else:
            return None

    except ValueError:
        return None


def parse_total_phase_timestamp(timestamp_str, year=2025):
    """
    Parse Total Phase timestamp format into datetime object

    Args:
        timestamp_str (str): Format "Oct 02 16:01:37.417.769"
        year (int): Year to use (default: 2025)

    Returns:
        datetime: Parsed datetime object or None if failed

    Example:
        >>> dt = parse_total_phase_timestamp("Oct 02 16:01:37.417.769")
        >>> print(dt)
        2025-10-02 16:01:37.417769
    """
    if not timestamp_str:
        return None

    try:
        # Pattern: "Oct 02 16:01:37.417.769"
        pattern = r'^(\w{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\.(\d{3})\.(\d{3})$'
        match = re.match(pattern, timestamp_str.strip())

        if not match:
            return None

        month_str, day_str, hour_str, min_str, sec_str, microsec1, microsec2 = match.groups()

        # Month name to number mapping
        months = {
            'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
            'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
        }

        month = months.get(month_str.lower())
        if month is None:
            return None

        # Convert to integers
        day = int(day_str)
        hour = int(hour_str)
        minute = int(min_str)
        second = int(sec_str)

        # Combine microseconds: 417.769 -> 417769 microseconds
        microseconds = int(f"{microsec1}{microsec2}")

        return datetime(year, month, day, hour, minute, second, microseconds)

    except (ValueError, TypeError):
        return None

def parse_csv_file(file_path: str):
    """
    Parse the CSV file and yield each record as it's processed.

    Args:
        file_path: Path to the CSV file

    Yields:
        I2CTransaction containing extracted data for each row
    """
    try:
        with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
            # Total Phase exports may place the CSV header on a commented line.
            # Keep that header while still skipping other comments.
            def filtered_rows():
                for line in csvfile:
                    stripped = line.lstrip()
                    if stripped.startswith('#'):
                        candidate_header = stripped[1:].lstrip()
                        if (
                            'Date h:m:s.ms.us' in candidate_header
                            and 'Addr' in candidate_header
                            and 'Data' in candidate_header
                        ):
                            yield candidate_header
                        continue
                    if not stripped:
                        continue
                    yield line

            reader = csv.DictReader(filtered_rows())

            for row_num, row in enumerate(reader, start=2):  # Start at 2 since header is row 1
                try:
                    # Extract the required columns
                    timestamp = row.get('Date h:m:s.ms.us')
                    timestamp_dt = parse_total_phase_timestamp(timestamp)
                    duration = parse_duration(row.get('Dur', 0))
                    raw_len = row.get('Len', '')
                    if isinstance(raw_len, str):
                        length = int(raw_len.replace(' B', '').strip()) if raw_len.strip() else 0
                    else:
                        length = int(raw_len) if raw_len is not None else 0
                    address = row['Addr'].strip('*"')
                    data = row['Data'].strip('*"')

                    # Parse the timestamp
                    # start_time = datetime.fromtimestamp(timestamp.replace('Z', '+00:00'))

                    # Skip if address is empty
                    if not address:
                        continue

                    yield I2CTransaction(
                        duration=duration,
                        address=address,
                        data=data,
                        count=length,
                        start_time=timestamp_dt,
                        row_num=row_num,
                    )

                except (KeyError, ValueError) as e:
                    print(f"Warning: Error processing row {row_num} in {file_path}: {e}")
                    continue

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return
    except Exception as e:
        print(f"Error: Failed to read file '{file_path}': {e}")
        return


def analyze_data(
    data_generator,
    filename: Optional[str] = None,
    filter_mctp_traffic: bool = False,
    triage: bool = False,
    min_severity: str = "warning",
    rules: tuple[str, ...] = (),
    response_timeout: float = 5.0,
    gap_threshold: float = 10.0,
    json_report: Optional[Path] = None,
    packet_log: Optional[Path] = None,
):
    """
    Analyzes I2C transaction data, gathers statistics, optionally filters
    MCTP traffic, and provides a summary of the processed data. The
    function can also save decoded output to a file if a filename is provided.

    Arguments:
        data_generator: An iterable object providing I2C transaction records.
        filename: str, optional
            Path to a file where the decoded output will be saved. If not provided,
            the output is not written to a file.
        filter_mctp_traffic: bool, optional
            Determines whether to exclude non-MCTP traffic. If True, only MCTP
            packets will be processed. Defaults to False.

    Returns:
        None

    Raises:
        This function does not explicitly raise errors but may propagate exceptions
        from underlying calls, such as file I/O operations or packet parsing.

    Note:
        The function processes one record at a time and gathers statistics on the
        total transactions, unique addresses, transaction counts, and byte counts
        for each address. It also calculates the time range of the transactions.

        Decoded output, if applicable, is written to a new file with a '.decoded.log'
        extension in the same directory as the provided filename.
    """
    # Initialize variables for analysis
    addresses = {}
    earliest = None
    latest = None
    record_count = 0

    # Use basename for display purposes
    display_name = os.path.basename(filename) if filename else None
    file_display = f" ({display_name})" if display_name else ""
    print(f"\nProcessing I2C transactions{file_display}:")
    print("=" * 60)

    # Optional triage setup.
    engine, severity_level = setup_triage_engine(triage, min_severity, rules, response_timeout, gap_threshold)
    type_counts: Counter[str] = Counter()
    packet_log_file = packet_log.open("w", encoding="utf-8") if packet_log is not None else None

    # Open output file if filename is provided - use full path
    output_file = None
    if filename:
        output_filename = Path(filename).with_suffix('.decoded.log')
        try:
            output_file = open(output_filename, 'w', encoding='utf-8')
            print(f"Writing decoded output to: {output_filename}")
        except Exception as e:
            print(f"Warning: Could not open output file {output_filename}: {e}")

    # Process records one at a time
    try:
        for pkt_id, record in enumerate(data_generator, start=1):
            record_count += 1
            addr = record.address
            data_str = record.data
            timestamp = record.start_time

            # Convert data string to bytes
            data = str_to_bytes(data_str, " ")

            # Update address statistics
            if addr not in addresses:
                addresses[addr] = {'count': 0, 'bytes': 0}
            addresses[addr]['count'] += 1
            addresses[addr]['bytes'] += 1 + len(data)

            # Update time range
            if timestamp is not None and (earliest is None or timestamp < earliest):
                earliest = timestamp
            if timestamp is not None and (latest is None or timestamp > latest):
                latest = timestamp

            # parse the MCTP packet, if present
            addr_int = int(addr, 16)
            pkt_data = bytes([addr_int]) + data
            if not addr or addr_int > 0x7f or (filter_mctp_traffic and data and data[0] != 0x0f and addr_int < 0x70):
                continue

            is_mctp = bool(data) and data[0] == 0x0F
            if not is_mctp:
                pkt = PrintableRawPacket(pkt_data)
            else:
                try:
                    pkt = SmbusTransport(pkt_data)
                except Exception:
                    pkt = PrintableRawPacket(pkt_data)

            timestamp_str = timestamp.isoformat() if timestamp is not None else "NO_TIMESTAMP"
            output_line = f"{timestamp_str} [csv_row={record.row_num}] {pkt.summary()}"

            # Print to console (suppressed in triage mode)
            if not triage:
                print(output_line)

            # Write to decoded output file if available
            if output_file:
                output_file.write(output_line + '\n')

            # Also write packet listing when requested
            if packet_log_file is not None:
                packet_log_file.write(output_line + "\n")

            # Feed only MCTP packets to triage rules.
            if engine is not None and is_mctp:
                if timestamp is not None:
                    pkt.timestamp = timestamp
                tally_mctp_packet(pkt, type_counts)
                engine.feed(pkt_id, timestamp, pkt)
    finally:
        if packet_log_file is not None:
            packet_log_file.close()

    # Close output file
    if output_file:
        output_file.close()

    if record_count == 0:
        print("No valid records found.")
        return

    print(f"\nSummary for {display_name or 'processed data'}:")
    print("-" * 40)
    print(f"Total transactions: {record_count}")
    print(f"Unique addresses: {len(addresses)}")

    for addr in sorted(addresses.keys()):
        stats = addresses[addr]
        print(f"  Address {addr}: {stats['count']} transactions, {stats['bytes']} bytes")

    if earliest and latest:
        print(f"\nTime range:")
        print(f"  Start: {earliest.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
        print(f"  End:   {latest.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
        print(f"  Duration: {latest - earliest}")

    if packet_log is not None:
        print(f"Packet listing written to: {packet_log}")

    if engine is not None:
        print_triage_report(engine, severity_level, type_counts, json_report)


def get_csv_files(path: str) -> List[str]:
    """
    Get list of CSV files from a path (file or directory).

    Args:
        path: Path to file or directory

    Returns:
        List of CSV file paths
    """
    path_obj = Path(path)

    if path_obj.is_file():
        if path_obj.suffix.lower() == '.csv':
            return [str(path_obj)]
        else:
            print(f"Warning: '{path}' is not a CSV file")
            return []
    elif path_obj.is_dir():
        csv_files = list(path_obj.glob('*.csv'))
        if not csv_files:
            print(f"Warning: No CSV files found in directory '{path}'")
            return []
        return [str(f) for f in sorted(csv_files)]
    else:
        print(f"Error: '{path}' is not a valid file or directory")
        return []


def main():
    """Main function to run the CSV parser."""
    parser = argparse.ArgumentParser(description="Parse Beagle I2C CSV capture files and decode MCTP traffic.")
    parser.add_argument("input_path", nargs="?", default=".", help="Path to a CSV file or directory of CSV files")
    parser.add_argument("--mctp-only", action="store_true", help="Only process lines that appear to carry MCTP traffic")
    parser.add_argument("--triage", action="store_true", help="Run analyzer rules to detect protocol issues")
    parser.add_argument("--min-severity", default="warning", help="Minimum severity to report (default: warning)")
    parser.add_argument(
        "--rules",
        action="append",
        default=[],
        help="Rule IDs to enable (repeatable), e.g. --rules TIMING-001 --rules SPDM-SEQ-001",
    )
    parser.add_argument(
        "--response-timeout",
        type=float,
        default=5.0,
        help="Threshold in seconds for delayed response detection",
    )
    parser.add_argument(
        "--gap-threshold",
        type=float,
        default=10.0,
        help="Threshold in seconds for inter-packet gap detection",
    )
    parser.add_argument("--json-report", type=Path, default=None, help="Write triage findings to a JSON file")
    parser.add_argument(
        "--packet-log",
        type=Path,
        default=None,
        help="Write a packet listing with CSV row references to a file",
    )
    args = parser.parse_args()

    input_path = args.input_path
    if len(sys.argv) == 1:
        print("No path provided, using current directory")

    print(f"I2C Transaction CSV Parser")
    print(f"Input path: {input_path}")

    # Get list of CSV files to process
    csv_files = get_csv_files(input_path)

    if not csv_files:
        print("No CSV files to process. Exiting.")
        return

    print(f"Found {len(csv_files)} CSV file(s) to process")

    # Configure scapy
    conf.raw_layer = PrintableRawPacket
    conf.debug_dissector = True

    # Process each CSV file
    for csv_file in csv_files:
        try:
            # Create generator for parsing CSV file
            data_generator = parse_csv_file(csv_file)

            # Perform analysis using the generator - pass full path instead of basename
            analyze_data(
                data_generator,
                csv_file,
                filter_mctp_traffic=args.mctp_only,
                triage=args.triage,
                min_severity=args.min_severity,
                rules=tuple(args.rules),
                response_timeout=args.response_timeout,
                gap_threshold=args.gap_threshold,
                json_report=args.json_report,
                packet_log=args.packet_log,
            )
        except Exception as e:
            print(f"Error processing {csv_file}: {e}")
            raise

    print(f"\nProcessing complete. Processed {len(csv_files)} file(s).")


if __name__ == "__main__":
    main()
