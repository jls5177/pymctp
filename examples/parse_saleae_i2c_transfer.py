#!/usr/bin/env python3
"""
CSV Parser for I2C Transaction Data

This script parses CSV files containing I2C transaction data and extracts
the start_time, address, and data columns. It can process a single file
or all CSV files in a directory.
"""

import csv
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Generator
from dataclasses import dataclass

from scapy.config import conf
from scapy.packet import Raw, Packet

from pymctp.layers import SmbusTransport
from pymctp.utils import str_to_bytes, PrintableRawPacket


@dataclass
class I2CTransaction:
    """Dataclass representing an I2C transaction record."""
    name: str
    type: str
    start_time: datetime
    duration: float
    ack: bool
    count: int
    address: str
    data: str


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
            reader = csv.DictReader(csvfile)

            for row_num, row in enumerate(reader, start=2):  # Start at 2 since header is row 1
                try:
                    # Extract the required columns
                    name = row.get('name', '').strip('"')
                    type_str = row.get('type', '').strip('"')
                    start_time_str = row['start_time']
                    duration = float(row.get('duration', 0))
                    ack = row.get('ack', '').strip('"').lower() in ('true', '1', 'yes')
                    count = int(row.get('count', 0))
                    address = row['address'].strip('"')
                    data = row['data'].strip('"')

                    # Parse the timestamp
                    start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))

                    # Skip if address is empty
                    if not address:
                        continue

                    # Extract MM## portion from "MM## Transfers" format for name
                    if name:
                        name = name.upper().split(" ")[0]

                    yield I2CTransaction(
                        name=name,
                        type=type_str,
                        start_time=start_time,
                        duration=duration,
                        ack=ack,
                        count=count,
                        address=address,
                        data=data
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


def analyze_data(data_generator, filename: str = None, filter_mctp_traffic: bool = False):
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
    for record in data_generator:
        record_count += 1
        addr = record.address
        data_str = record.data
        timestamp = record.start_time
        name = record.name

        # Convert data string to bytes
        data = str_to_bytes(data_str, ", ")

        # Update address statistics
        if addr not in addresses:
            addresses[addr] = {'count': 0, 'bytes': 0}
        addresses[addr]['count'] += 1
        addresses[addr]['bytes'] += 1 + len(data)

        # Update time range
        if earliest is None or timestamp < earliest:
            earliest = timestamp
        if latest is None or timestamp > latest:
            latest = timestamp

        # parse the MCTP packet, if present
        addr_int = int(addr, 16) if addr.startswith("0x") else 0xFF
        pkt_data = bytes([addr_int]) + data
        if not addr or addr_int > 0x7f or (filter_mctp_traffic and data and data[0] != 0x0f and addr_int < 0x70):
            continue
        if not data or data[0] != 0x0f:
            pkt = PrintableRawPacket(pkt_data)
        else:
            try:
                pkt = SmbusTransport(pkt_data)
            except:
                pkt = PrintableRawPacket(pkt_data)

        # Include name in the output if it exists
        name_part = f"{name}:" if name else ""
        output_line = f'{timestamp.isoformat()} {name_part} {pkt.summary()}'

        # Print to console
        # print(output_line)

        # Write to file if available
        if output_file:
            output_file.write(output_line + '\n')

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
    # Default path (can be changed as needed)
    default_path = "."

    # Check if path is provided as command line argument
    if len(sys.argv) > 1:
        input_path = sys.argv[1]
    else:
        input_path = default_path
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
            analyze_data(data_generator, csv_file, filter_mctp_traffic=False)
        except Exception as e:
            print(f"Error processing {csv_file}: {e}")
            raise

    print(f"\nProcessing complete. Processed {len(csv_files)} file(s).")


if __name__ == "__main__":
    main()
