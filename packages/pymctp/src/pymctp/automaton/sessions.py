# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import threading
import time
from collections.abc import Callable
import random
from typing import TYPE_CHECKING, NamedTuple

from scapy.compat import raw
from scapy.config import conf
from scapy.packet import Packet, Raw
from scapy.plist import PacketList
from scapy.sendrecv import sndrcv
from scapy.sessions import DefaultSession
from scapy.supersocket import SuperSocket
from scapy.utils import hexdump, linehexdump

from ..exerciser import TTYSerialSocket
from ..layers import SmbusTransportPacket, UartTransport
from ..layers.mctp import (
    AnyPhysicalAddress,
    EndpointContext,
    Smbus7bitAddress,
    SmbusTransport,
    TransportHdr,
    TransportHdrPacket,
)
from ..layers.mctp.control import ControlHdr, ControlHdrPacket, IControlMsgPacket
from ..layers.mctp.types import AnyPacketType, MsgTypes

if TYPE_CHECKING:
    from scapy.ansmachine import AnsweringMachine
    from scapy.plist import PacketList


class HandlerResponse(NamedTuple):
    stop_processing: bool
    reply: AnyPacketType


class EndpointSession(DefaultSession):
    """Manages sending and receiving MCTP messages on the specified socket for a single endpoint."""

    def __init__(self, *args, context: EndpointContext, socket: SuperSocket, **kwargs):
        """
        Overloaded the DefaultSession.__init__() to add type hints for class specific parameters.
        :param args: Arguments to pass to DefaultSession
        :param context: MCTP Endpoint content to store runtime state
        :param socket: Socket to send and receive packets
        :param kwargs: Any additional arguments available in Scapy DefaultSession
        """
        super().__init__(*args, **kwargs)
        self.context = context
        self.socket = socket
        self.pending_rqs: list[tuple[Packet, Callable[[Packet], None]]] = []
        self._next_tag_number = 0
        self._next_instance_id = 0
        self._responder_lock = threading.Lock()

        # Not allowed during init due to the AnsweringMachine needing the session to initialize properly.
        # Instead, the AnsweringMachine will register itself during initialization.
        self.am: AnsweringMachine | None = None
        self.default_handlers: dict[type, Callable[[Packet, EndpointContext], HandlerResponse | None]] = {}

    def register_handler(self, layer_cls: type, handler: Callable[[Packet, EndpointContext], HandlerResponse | None]):
        """
        Registers the specified handler to allow the handler to be invoked anytime a msg is received that
        contains the specified layer class.
        :param layer_cls: Class that needs to be present to trigger handler (should be the lowest layer possible)
        :param handler: Callback handler when matching msg is received
        """
        self.default_handlers[layer_cls] = handler

    @property
    def next_tag_number(self) -> int:
        """
        Generates a tag number that automatically increments (and rolls over) on each access
        :return: the next tag number generated
        """
        next_tag = self._next_tag_number
        self._next_tag_number = (next_tag + 1) % 8
        return next_tag

    @property
    def next_instance_id(self) -> int:
        """
        Generates an instance id that automatically increments (and rolls over) on each access

        :return: the next instance id number generated
        """
        next_id = self._next_instance_id
        self._next_instance_id = (next_id + 1) % 32
        return next_id

    def on_packet_received(self, rq_pkt: Packet | None) -> None:
        """
        Will be called by sniff() for each received packet (that passes the filters).

        :param rq_pkt: The received packet
        :return: None
        """
        if not rq_pkt or not rq_pkt.haslayer(TransportHdrPacket):
            return

        mctp_pkt_hdr: TransportHdrPacket | None = rq_pkt.getlayer(TransportHdrPacket)
        is_request = bool(self.am.is_request(rq_pkt))
        som = bool(mctp_pkt_hdr.som)
        eom = bool(mctp_pkt_hdr.eom)
        msg_id = f"{mctp_pkt_hdr.tag}{mctp_pkt_hdr.dst}{mctp_pkt_hdr.src}"

        # handle fragmented packets
        # TODO: see ISOTPSession for an example of how to create a builder pattern
        if not (som and eom):
            frag_bytes = bytes(mctp_pkt_hdr) if som else bytes(mctp_pkt_hdr.payload)
            if som:
                self.context.reassembly_list[msg_id] = frag_bytes
            else:
                self.context.reassembly_list[msg_id] += frag_bytes

            if not eom:
                return

            # collect the full message payload and remove it from the reassembly queue
            msg_payload = self.context.reassembly_list[msg_id]
            mctp_pkt_hdr = TransportHdrPacket(msg_payload)
            del self.context.reassembly_list[msg_id]

            # Special case: treat msg_type==0x7F and unsupported payload as an echo command
            if mctp_pkt_hdr.haslayer(Raw) and (
                mctp_pkt_hdr.msg_type == 0x7F or (mctp_pkt_hdr.msg_type == 0x01 and True)
            ):
                # strip off the transport header from the msg payload
                mctp_pkt_hdr_len = len(mctp_pkt_hdr) - len(mctp_pkt_hdr.payload)
                # fragment the response payload with the transport header
                response_pkts = mctp_pkt_hdr.build_reply(self.context, msg_payload[mctp_pkt_hdr_len:])

                # add the smbus header to each fragment
                smbus_hdr: SmbusTransportPacket = rq_pkt.getlayer(SmbusTransportPacket).copy()
                response_pkts = smbus_hdr.build_reply(self.context, response_pkts)

                # time.sleep(random.uniform(0.250, 0.750))
                # time.sleep(random.uniform(5.0, 15.0))

                # send the responses
                self.am.send_reply(response_pkts)
                return
            rq_pkt = rq_pkt.getlayer(SmbusTransportPacket).copy(mctp_pkt_hdr)
        elif som and eom and mctp_pkt_hdr.haslayer(Raw) and (mctp_pkt_hdr.msg_type == 0x7F):
            # strip off the transport header from the msg payload
            # mctp_pkt_hdr_len = len(mctp_pkt_hdr) - len(mctp_pkt_hdr.payload)
            # fragment the response payload with the transport header
            response_pkts = mctp_pkt_hdr.build_reply(self.context, bytes(mctp_pkt_hdr.payload))

            # add the smbus header to each fragment
            smbus_hdr: SmbusTransportPacket = rq_pkt.getlayer(SmbusTransportPacket).copy()
            response_pkts = smbus_hdr.build_reply(self.context, response_pkts)

            # time.sleep(random.uniform(0.250, 0.750))
            # time.sleep(random.uniform(5.0, 15.0))

            # send the responses
            self.am.send_reply(response_pkts)
            return

        # Lock the session to prevent another thread trying to send a request on the bus before we finish replying
        with self._responder_lock:
            plist = self.pending_rqs

            # 1) look for responses to pending requests
            for i, pending_rq in enumerate(plist):
                sentpkt, callback = pending_rq
                if not rq_pkt.answers(sentpkt):
                    continue
                del self.pending_rqs[i]
                callback(rq_pkt)
                return

            # 2) Check if we have a handler registered for this type of packet
            stop_processing = False
            response_pkts: PacketList = []
            for cls, handler in self.default_handlers.items():
                if cls in rq_pkt or mctp_pkt_hdr.haslayer(cls.__name__):
                    resp: HandlerResponse = handler(rq_pkt, self.context)
                    if not resp:
                        resp = HandlerResponse(False, None)
                    stop_processing = resp.stop_processing
                    if resp.reply:
                        if isinstance(resp.reply, PacketList):
                            response_pkts += resp.reply
                        else:
                            response_pkts.append(resp.reply)
                        if stop_processing:
                            break
                    elif stop_processing:
                        return

            # 3) if a request, use the default reply methods to generate response
            if is_request and not stop_processing:
                reply = self.am.make_reply(rq_pkt)
                if reply:
                    response_pkts += reply

            # send any queued replies
            if response_pkts:
                self.am.send_reply(response_pkts)

    def sndrcv_control_msg(
        self,
        pkt: Packet,
        dst_eid: int,
        *,
        dst_phy_addr: AnyPhysicalAddress = None,
        instance_id: int | None = None,
        timeout_s: float | None = None,
        threaded: bool = False,
    ) -> Packet | None:
        """
        Sends the specified MCTP Control Payload to the destination and waits for a
        response. This method will detect if the ControlHdrPacket, TransportHdrPacket,
        and the SmbusTransportPacket are present and add them if missing.

        Example:

            >>> rsp = sndrcv_control_msg(GetEndpointID(), 0x15, Smbus7bitAddress(0x20 >> 1))

        :param pkt: The MCTP Control Msg packet to send
        :param dst_eid: The destination endpoint id
        :param dst_phy_addr: The physical address of the destination (endpoint or bridge/next hop)
        :param instance_id: The instance to differentiate different MCTP Control requests (autogenerated if not present)
        :param timeout_s: Max time to wait for a response (in seconds)
        :param threaded: Set to `True` if
        :return: the received packet or None
        """
        if not isinstance(pkt, IControlMsgPacket):
            msg = "Packet is malformed, does not implement the IControlMsgPacket protocol"
            raise TypeError(msg)
        cmd_code = pkt.cmd_code

        if not pkt.haslayer(ControlHdrPacket):
            pkt = (
                ControlHdr(
                    rq=True,
                    cmd_code=cmd_code,
                    instance_id=(instance_id or self.next_instance_id),
                )
                / pkt
            )
        return self.sndrcv_mctp_msg(
            pkt=pkt, dst_eid=dst_eid, dst_phy_addr=dst_phy_addr, timeout_s=timeout_s, threaded=threaded
        )

    def sndrcv_mctp_msg(
        self,
        pkt: Packet,
        dst_eid: int,
        *,
        dst_phy_addr: AnyPhysicalAddress = None,
        msg_type: MsgTypes = MsgTypes.CTRL,
        msg_tag: int | None = None,
        timeout_s: float | None = None,
        threaded: bool = False,
    ) -> Packet | None:
        # TODO: handle packet fragments
        pkt = (
            TransportHdr(
                src=self.context.eid,
                dst=dst_eid,
                som=1,
                eom=1,
                pkt_seq=0,
                to=1,
                tag=msg_tag or self.next_tag_number,
                msg_type=msg_type,
            )
            / pkt
        )

        src_phy_addr = self.context.physical_address
        if isinstance(dst_phy_addr, Smbus7bitAddress) and isinstance(src_phy_addr, Smbus7bitAddress):
            pkt = SmbusTransport(dst_addr=dst_phy_addr, src_addr=src_phy_addr, load=pkt)
        elif isinstance(self.socket, TTYSerialSocket):
            pkt = UartTransport(load=pkt)
        else:
            msg = f"Only Smbus7bitAddress are supported: {type(dst_phy_addr)}"
            raise TypeError(msg)

        # hexdump(pkt)
        # if drop_pec:
        #     data = raw(pkt)
        #     pkt = Raw(data[:-1])

        if threaded or (self.am and hasattr(self.am, "sniffer") and self.am.sniffer.running):
            return self.sr1threaded(pkt=pkt, timeout_s=timeout_s)
        return self.sr1(pkt=pkt, timeout_s=timeout_s)

    def sr1(self, pkt: Packet, timeout_s: float | None = None) -> Packet | None:
        """
        Sends and receives one packet on the socket. This method will stall
        the main thread until a response is received or the timeout is reached.

        :param pkt: The packet to send
        :param timeout_s: Max time to wait for a response (in seconds)
        :return: the received packet or None
        """
        with self._responder_lock:
            a, b = sndrcv(self.socket, pkt, timeout=int(timeout_s) if timeout_s else None, session=self)
            if len(a) > 0:
                return a[0][1]
        return None

    def sr1threaded(self, pkt: Packet, timeout_s: float | None = None) -> Packet | None:
        """
        Sends and receives on packet on the socket. This method will queue the response
        handler (callback) and start a timer to handle no response. This method is meant
        to be used when an AnsweringMachine is already running in the session (as there
        can only be one service bound to the socket at a time). The AnsweringMachine will
        invoke the "on_packet_received()" method when a response is received, which will
        check if the response is for a pending request.

        :param pkt: The packet to send
        :param timeout_s: Max time to wait for a response (in seconds)
        :return: The received packet or None
        """
        completed = threading.Event()
        rsp: list[Packet] = []

        # print(f"Sending request using threading")

        def callback(pkt: Packet):
            # print(f"response received, triggering callback")
            rsp.append(pkt)
            completed.set()

        # queue event
        item = (pkt, callback)
        self.pending_rqs.append(item)

        # send event
        with self._responder_lock:
            self.socket.send(pkt)

        # wait for completion
        timed_out = completed.wait(timeout=timeout_s)
        if not timed_out or not rsp:
            # remove the item from the list (ignoring any errors)
            try:
                with self._responder_lock:
                    self.pending_rqs.remove(item)
            finally:
                pass
            return None
        return rsp[0]
