from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import List, Optional, Dict
from typing import OrderedDict as OrderedDictType

import crc8
from scapy.compat import raw
from scapy.layers.l2 import CookedLinux, CookedLinuxV2
from scapy.utils import rdpcap

from .transport import TransportHdrPacket
from .types import AnyPacketType, EndpointContext, MsgTypes, MctpResponseList, MctpResponse
from .control import ControlHdrPacket
from .pldm import PldmHdrPacket, PldmTypeCodes, PldmControlCmdCodes, PldmPlatformMonitoringCmdCodes


def import_pcap_dump(resp_file: Path, endpoint_dump: bool, ctx: EndpointContext) -> Optional[MctpResponseList]:
    if not resp_file.name.endswith(".dump") and not resp_file.name.endswith(".pcap"):
        return
    pending_reqs: List[AnyPacketType] = list()
    responses: OrderedDictType[int, MctpResponse] = OrderedDict()
    responseList: Dict[MsgTypes, List[MctpResponse]] = defaultdict(list)
    for packet in rdpcap(str(resp_file.resolve())):
        tx_packet = packet.pkttype == 4
        # prefix = '<TX<' if tx_packet else '>RX>'
        if not packet.haslayer(TransportHdrPacket):
            continue
        packet = packet.getlayer(TransportHdrPacket)
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
            if req.dst != packet.src and req.dst != 0:
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
                raise SystemExit("Found a duplicate request, stop and fix...")
            mctp_resp = MctpResponse(request=list(req), response=list(rsp), processing_delay=0,
                                     description=original_req.getlayer(ControlHdrPacket).summary())
            responses[req] = mctp_resp
            responseList[MsgTypes.CTRL] += [mctp_resp]
        elif packet.msg_type == MsgTypes.PLDM:
            req = raw(original_req.getlayer(PldmHdrPacket))[1:]
            rsp = raw(packet.getlayer(PldmHdrPacket))[1:]
            if req in responses and responses[req].response == rsp:
                raise SystemExit("Found a duplicate request, stop and fix...")
            type_code = PldmTypeCodes(original_req.pldm_type)
            if original_req.pldm_type == PldmTypeCodes.CONTROL:
                cmd_code_str = PldmControlCmdCodes(original_req.cmd_code).name
            elif original_req.pldm_type == PldmTypeCodes.PLATFORM_MONITORING:
                cmd_code_str = PldmPlatformMonitoringCmdCodes(original_req.cmd_code).name
            else:
                cmd_code_str = f"{original_req.cmd_code}({hex(original_req.cmd_code)})"
            mctp_resp = MctpResponse(request=list(req), response=list(rsp), processing_delay=0,
                                     description=f"PLDM {type_code.name} {cmd_code_str}")
            responses[req] = mctp_resp
            responseList[MsgTypes.PLDM] += [mctp_resp]

    # Add responses to context
    ctx.mctp_responses = MctpResponseList(responses=responseList)
    return MctpResponseList(responses=responseList)
