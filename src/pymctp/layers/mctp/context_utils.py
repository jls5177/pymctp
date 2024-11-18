# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from collections import OrderedDict, defaultdict
from collections import OrderedDict as OrderedDictType
from pathlib import Path

from scapy.compat import raw
from scapy.utils import rdpcap

from .control import ControlHdrPacket
from .pldm import PldmControlCmdCodes, PldmHdrPacket, PldmPlatformMonitoringCmdCodes, PldmTypeCodes
from .transport import TransportHdrPacket
from .types import AnyPacketType, EndpointContext, MctpResponse, MctpResponseList, MsgTypes


def import_pcap_dump(resp_file: Path, endpoint_dump: bool, ctx: EndpointContext) -> MctpResponseList | None:
    if not resp_file.name.endswith(".dump") and not resp_file.name.endswith(".pcap"):
        return
    pending_reqs: list[AnyPacketType] = []
    responses: OrderedDictType[int, MctpResponse] = OrderedDict()
    responseList: dict[MsgTypes, list[MctpResponse]] = defaultdict(list)
    for resp_packet in rdpcap(str(resp_file.resolve())):
        # tx_packet = packet.pkttype == 4
        # prefix = '<TX<' if tx_packet else '>RX>'
        if not resp_packet.haslayer(TransportHdrPacket):
            continue
        packet = resp_packet.getlayer(TransportHdrPacket)
        # print(f"{prefix} {packet.summary()}")
        if (packet.haslayer(ControlHdrPacket) and packet.rq) or (packet.haslayer(PldmHdrPacket) and packet.rq):
            pending_reqs += [packet]
            continue

        # Assume this is a response and search for the request
        original_req: AnyPacketType = None
        for req in pending_reqs:
            if req.tag != packet.tag:
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
                msg = "Found a duplicate request, stop and fix..."
                raise SystemExit(msg)
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
                msg = "Found a duplicate request, stop and fix..."
                raise SystemExit(msg)
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

    # Add responses to context
    ctx.mctp_responses = MctpResponseList(responses=responseList)
    return MctpResponseList(responses=responseList)
