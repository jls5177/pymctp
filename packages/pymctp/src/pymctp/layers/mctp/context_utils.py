# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT
import binascii
from collections import OrderedDict, defaultdict
from collections import OrderedDict as OrderedDictType
from datetime import datetime, timezone
from pathlib import Path
import re
import pytz

from scapy.compat import raw
from scapy.config import conf
from scapy.packet import Packet, Raw
from scapy.utils import EDecimal, rdpcap, PcapReader
from tzlocal import get_localzone_name

from .control import ControlHdrPacket
from .pldm import PldmControlCmdCodes, PldmHdrPacket, PldmPlatformMonitoringCmdCodes, PldmTypeCodes
from .transport import TransportHdrPacket, TransportHdr
from .types import AnyPacketType, EndpointContext, MctpResponse, MctpResponseList, MsgTypes
from .vdpci import VdPciHdrPacket, VdPCIVendorIds


def is_dst_active(zonename: str) -> bool:
    return bool(datetime.now(pytz.timezone(zonename)).dst())


FIXED_DATE = "2024-03-20 "
DEFAULT_TZ = pytz.timezone(get_localzone_name())
DEFAULT_DST = is_dst_active(get_localzone_name())
timestampRE = r"([\d]{2}:[\d]{2}:[\d]{2}\.[\d]{6,9})"
timestampRegex = re.compile(timestampRE)


# TODO: remove?
def _adjust_packet_time(pkt: Packet, use_local_time: bool = False, adjust_tz: bool = False, utz: bool = False):
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


def _parse_timestamp(line: str):
    line = line.strip()
    for match in timestampRegex.finditer(line):
        timestampStr = match.group(1)
        dt_obj = datetime.strptime(FIXED_DATE + timestampStr, "%Y-%m-%d %H:%M:%S.%f")
        return pytz.utc.localize(dt_obj)
    return None


def _parse_line(line: str):
    line = line.strip()
    if not line.startswith("0x") or line.count("  ") < 2:
        return None, b""
    offset, data_line, *_ = line.split("  ")
    return int(offset[:-1], 16), bytes.fromhex(data_line)


def _read_ascii_file(ascii_file: Path):
    next_request = b""
    next_request_timestamp = None
    with ascii_file.open("r") as f:
        for line in f.readlines():
            timestamp = _parse_timestamp(line)
            if timestamp is not None:
                # next request is started, save previous request
                if next_request:
                    try:
                        mctp_packet = TransportHdr(next_request)
                    except Exception:
                        mctp_packet = Raw(next_request)

                    mctp_packet.timestamp = next_request_timestamp
                    yield mctp_packet
                next_request_timestamp = timestamp
                continue
            offset, data = _parse_line(line)
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
            mctp_packet.timestamp = next_request_timestamp
            yield mctp_packet


def _read_pcap_file(pcap_file: Path):
    with PcapReader(str(pcap_file.resolve())) as fdesc:
        for packet in fdesc:
            yield packet


def import_pcap_dump(
    resp_file: Path, endpoint_dump: bool, ctx: EndpointContext, debug: bool = True
) -> MctpResponseList | None:
    if resp_file.name.endswith(".dump") or resp_file.name.endswith(".pcap"):
        packet_generator = _read_pcap_file(resp_file)
        file_type = "pcap"
    elif resp_file.name.endswith(".txt") or resp_file.name.endswith(".log"):
        packet_generator = _read_ascii_file(resp_file)
        file_type = "txt"
    else:
        return None
    pending_reqs: list[AnyPacketType] = []
    responses: OrderedDictType[int, MctpResponse] = OrderedDict()
    responseList: dict[MsgTypes, list[MctpResponse | dict[str, dict[int, list[MctpResponse]]]]] = defaultdict(list)
    fragments = b""
    for resp_packet in packet_generator:
        if debug:
            if file_type == "pcap":
                tx_packet = resp_packet.pkttype == 4
                prefix = "<TX<" if tx_packet else ">RX>"
            else:
                prefix = ">"
        if not resp_packet.haslayer(TransportHdrPacket):
            continue
        packet = resp_packet.getlayer(TransportHdrPacket)
        if debug:
            print(f"{prefix} {packet.summary()}")
        # Handle a fragmented packet, TODO: support multiple msg reassemblies
        if not (packet.eom and packet.som):
            frag_bytes = bytes(packet)
            if debug:
                print(f" Fragmented packet: {binascii.hexlify(frag_bytes, b' ', -2)}")
            if packet.som:
                fragments = frag_bytes
                continue
            fragments += bytes(frag_bytes[4:])  # strip off the transport header
            if not packet.eom:
                continue
            # we have the full message, process the complete message
            packet = TransportHdrPacket(fragments)
        if (packet.haslayer(ControlHdrPacket) and packet.rq) or (packet.haslayer(PldmHdrPacket) and packet.rq):
            pending_reqs += [packet]
            continue

        # Assume this is a response and search for the request
        original_req: AnyPacketType = None
        for req in pending_reqs:
            if req.tag != packet.tag:
                continue
            if req.msg_type != packet.msg_type:
                continue
            if packet.to == req.to:
                continue
            if req.dst not in (packet.src, 0):
                continue
            original_req = req
            break
        else:
            pending_reqs += [packet]
            continue

        pending_reqs.remove(original_req)

        # TODO: move this code into the msg type packet layer by using an interface
        if packet.msg_type == MsgTypes.CTRL:
            req = raw(original_req.getlayer(ControlHdrPacket))[1:]
            rsp = raw(packet.getlayer(ControlHdrPacket))[1:]
            if req in responses:
                # msg = "Found a duplicate request, stop and fix..."
                # raise SystemExit(msg)
                continue
            mctp_resp = MctpResponse(
                request=list(req),
                response=list(rsp),
                processing_delay=0,
                description=original_req.getlayer(ControlHdrPacket).summary(),
            )
            responses[req] = mctp_resp
            responseList[MsgTypes.CTRL] += [mctp_resp]
        elif packet.msg_type == MsgTypes.PLDM:
            req = raw(original_req.getlayer(PldmHdrPacket))[1:]
            rsp = raw(packet.getlayer(PldmHdrPacket))[1:]
            if req in responses and responses[req].response == rsp:
                # msg = "Found a duplicate request, stop and fix..."
                # raise SystemExit(msg)
                continue
            type_code = PldmTypeCodes(original_req.pldm_type)
            if original_req.pldm_type == PldmTypeCodes.CONTROL:
                cmd_code_str = PldmControlCmdCodes(original_req.cmd_code).name
            elif original_req.pldm_type == PldmTypeCodes.PLATFORM_MONITORING:
                cmd_code_str = PldmPlatformMonitoringCmdCodes(original_req.cmd_code).name
            else:
                cmd_code_str = f"{original_req.cmd_code}({hex(original_req.cmd_code)})"
            mctp_resp = MctpResponse(
                request=list(req),
                response=list(rsp),
                processing_delay=0,
                description=f"PLDM {type_code.name} {cmd_code_str}",
            )
            responses[req] = mctp_resp
            responseList[MsgTypes.PLDM] += [mctp_resp]
        elif packet.msg_type == MsgTypes.VDPCI:
            req_pkt = original_req.getlayer(VdPciHdrPacket)
            rsp_pkt = packet.getlayer(VdPciHdrPacket)
            packet.rq = 0
            req = raw(req_pkt.payload)
            rsp = raw(rsp_pkt.payload)
            if req in responses and responses[req].response == rsp:
                continue
            vendor_id = req_pkt.vendor_id_enum
            vdm_cmd_code = str(req_pkt.vdm_cmd_code)
            mctp_resp = MctpResponse(
                request=list(req),
                response=list(rsp),
                processing_delay=0,
                description=f"{vendor_id.name} {vdm_cmd_code}",
            )
            responses[req] = mctp_resp
            if MsgTypes.VDPCI not in responseList:
                responseList[MsgTypes.VDPCI] = defaultdict(lambda: defaultdict(list))
            responseList[MsgTypes.VDPCI][vendor_id.name][vdm_cmd_code] += [mctp_resp]

    # Add responses to context
    ctx.mctp_responses = MctpResponseList(responses=responseList)
    return MctpResponseList(responses=responseList)
