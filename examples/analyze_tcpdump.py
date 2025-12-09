import binascii
import pathlib
import re
import sys
from datetime import datetime, timezone
from typing import List, Tuple
from zlib import crc32
import pytz

from scapy.config import conf
from scapy.packet import Raw
from scapy.utils import PcapReader

from pymctp.layers.mctp import *
from pymctp.layers.mctp.pldm import PlatformEventMsgPacket, PollForPlatformEventMsgPacket, PlatformEventMsgClasses
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import PollForPlatformEventOperation, \
    PollForPlatformEventTransferFlag
from pymctp.layers.mctp.types import AnyPacketType
from pymctp.utils import set_printable_raw_layer

FIXED_DATE = '2024-03-20 '
DEFAULT_TZ = pytz.timezone('US/Central')
DEFAULT_DST = True
timestampRE = r"([\d]{2}:[\d]{2}:[\d]{2}\.[\d]{6,9})"
timestampRegex = re.compile(timestampRE)


class PrintableRawPacket(Raw):
    name = "PRaw"
    __slots__ = ["_mysummary_cls"]

    def set_mysummary_classes(self, classes):
        self._mysummary_cls = classes

    def mysummary(self):
        summary = "Raw %r" % binascii.hexlify(self.load, b' ', -2)
        if hasattr(self, "_mysummary_cls"):
            return summary, self._mysummary_cls
        return summary


def parse_timestamp(line: str):
    line = line.strip()
    for match in timestampRegex.finditer(line):
        timestampStr = match.group(1)
        dt_obj = datetime.strptime(FIXED_DATE + timestampStr, "%Y-%m-%d %H:%M:%S.%f")
        return dt_obj
    return None


def parse_line(line: str):
    line = line.strip()
    if not line.startswith('0x') or line.count("  ") < 2:
        return None, bytes()
    offset, data_line, *_ = line.split("  ")
    return int(offset[:-1], 16), bytes.fromhex(data_line)


def parse_file(filename: pathlib.Path) -> List[Tuple[datetime, AnyPacketType]]:
    packets = []
    next_request = bytes()
    next_request_timestamp = None
    for line in filename.read_text().splitlines():
        timestamp = parse_timestamp(line)
        if timestamp is not None:
            # next request is started, save previous request
            if next_request:
                try:
                    mctp_packet = TransportHdr(next_request)
                except:
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
        except:
            mctp_packet = Raw(next_request)
        packets += [(next_request_timestamp, mctp_packet)]
    return packets


def parse_pcap_file(filename: pathlib.Path) -> List[Tuple[datetime, AnyPacketType]]:
    packets: List[Tuple[datetime, AnyPacketType]] = list()
    with PcapReader(str(filename.resolve())) as fdesc:
        for packet in fdesc:
            if not packet.haslayer(TransportHdrPacket):
                continue
            timestamp = datetime.fromtimestamp(float(packet.time))
            timestamp = DEFAULT_TZ.localize(timestamp, is_dst=DEFAULT_DST)
            utc_timestamp = timestamp.astimezone(pytz.utc)
            packets += [(utc_timestamp, packet.getlayer(TransportHdrPacket))]
    # for packet in rdpcap(str(filename.resolve())):
    #     # tx_packet = packet.pkttype == 4
    #     if not packet.haslayer(TransportHdrPacket):
    #         continue
    #     packets += [(None, packet)]
    return packets


if __name__ == '__main__':
    # conf.emph.add(TransportHdr.dst)
    # conf.debug_dissector = True
    # conf.raw_layer = PrintableRawPacket
    set_printable_raw_layer()

    if len(sys.argv) < 2:
        raise SystemExit(f'Usage: {sys.argv[0]} <tcpdump_file>')
    tcpdump_file = pathlib.Path(sys.argv[1])
    if not tcpdump_file.exists():
        raise SystemExit(f'tcpdump file does not exist: {tcpdump_file}')

    packets: List[Tuple[datetime, AnyPacketType]] = []
    if tcpdump_file.suffix in ['.pcap', '.dump']:
        packets = parse_pcap_file(tcpdump_file)
    else:
        packets = parse_file(tcpdump_file)


    crash_dump_index = 0
    crash_dump_data = bytes()
    nextStepAckPPE = False
    running_crc = 0
    eventID = 0
    nextHandle = 0
    print(len(packets))
    for packet in packets:
        if type(packet) is tuple:
            timestamp, mctp_packet = packet
        else:
            timestamp, mctp_packet = None, packet

        # if mctp_packet.haslayer(TransportHdrPacket):
        #     transportHdr = mctp_packet.getlayer(TransportHdrPacket)
        #     if transportHdr.dst != 0x1D and transportHdr.src != 0x1D:
        #         continue

        if timestamp:
            mctp_packet.timestamp = timestamp
            print(f'{timestamp.isoformat()}: {mctp_packet.summary()}')
        else:
            print(f'{mctp_packet.summary()}')

        if not mctp_packet.haslayer(PlatformEventMsgPacket) and not mctp_packet.haslayer(PollForPlatformEventMsgPacket):
            continue

        continue

        if mctp_packet.haslayer(PlatformEventMsgPacket):
            packet = mctp_packet.getlayer(PlatformEventMsgPacket)
            if packet.eventClass == PlatformEventMsgClasses.PLDM_MESSAGE_POLL_EVENT:
                eventID = packet.eventID
                nextStepAckPPE = False
            continue

        # packet is a PPE, but no PlatformEventMsg was previously received, might be a malformed log
        if not eventID and not nextStepAckPPE:
            continue

        pldm_hdr = mctp_packet.getlayer(PldmHdrPacket)
        ppe_packet = mctp_packet.getlayer(PollForPlatformEventMsgPacket)

        if nextStepAckPPE:
            if pldm_hdr.rq == 0:
                eventID = ppe_packet.eventID
                nextStepAckPPE = False
            elif not ppe_packet.TransferOperationFlag == PollForPlatformEventOperation.ACK_ONLY.value:
                print(f"ERROR: expected next PPE to be an ACK operation, got {ppe_packet.TransferOperationFlag}")
            continue

        if ppe_packet.TransferOperationFlag == PollForPlatformEventOperation.GET_FIRST_PART.value:
            assert ppe_packet.DataTransferHandle == 0
            running_crc = 0
            nextHandle = 0
            crash_dump_index += 1
            crash_dump_data = bytes()
            print(f"First PPE packet: resetting state, index={crash_dump_index}")
        # add event data to response
        if pldm_hdr.rq == 0:
            if ppe_packet.eventDataSize != len(ppe_packet.eventData):
                print(f"ERROR: truncated packet: {len(ppe_packet.eventData)} != {ppe_packet.eventDataSize}")
            # skip retried packets if they fall in the middle of the PPE request (to prevent corrupting the CRC)
            if (ppe_packet.NextDataTransferHandle == nextHandle and
                    ppe_packet.TransferFlag == PollForPlatformEventTransferFlag.MIDDLE.value):
                print(f"ERROR: skipping duplicate response packet...")
                continue
            if ppe_packet.TransferFlag == PollForPlatformEventTransferFlag.END.value:
                initial_crc = running_crc
                if ppe_packet.eventDataSize != 0:
                    print(f"PPE end packet has some data, initial crc: {initial_crc}")
                    data = ppe_packet.eventData
                    crash_dump_data += bytes(data)
                    running_crc = crc32(bytes(data), running_crc)
                    if (running_crc != ppe_packet.eventDataIntegrityChecksum and
                            initial_crc == ppe_packet.eventDataIntegrityChecksum):
                        print(f"ERROR: CRC does not include partial data in last packet")
                # end of PPE data
                checksumValid = running_crc == ppe_packet.eventDataIntegrityChecksum
                if not checksumValid:
                    print(f"End of PPE: checksum mismatch: {running_crc} ==? {ppe_packet.eventDataIntegrityChecksum}")
                    crashdump_file = tcpdump_file.parent / f"crash_dump_{eventID}_{crash_dump_index}.bin"
                    with open(crashdump_file, 'wb') as f:
                        f.write(crash_dump_data)
                    print(f"Saved the crash dump ({crash_dump_index}) to {crashdump_file}")
                else:
                    print(f"End of PPE: checksum valid: {running_crc}")
                nextStepAckPPE = True
            else:
                data = ppe_packet.eventData
                crash_dump_data += bytes(data)
                running_crc = crc32(bytes(data), running_crc)
                nextHandle = ppe_packet.NextDataTransferHandle
        elif ppe_packet.DataTransferHandle != nextHandle:
            print(f"Out of order packet: 0x{ppe_packet.DataTransferHandle:08X} != 0x{nextHandle:08X}")
