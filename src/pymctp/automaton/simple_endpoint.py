# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import random
import time
from collections.abc import Callable
from typing import cast

from scapy.ansmachine import AnsweringMachine
from scapy.packet import Packet
from scapy.plist import PacketList, _PacketIterable  # imported for type hinting on overloaded methods
from scapy.sendrecv import AsyncSniffer
from scapy.supersocket import SuperSocket

from ..layers.interfaces import AnyPacketType
from ..layers.mctp.control import ControlHdrPacket
from ..layers.mctp.types import EndpointContext, ICanReply
from .sessions import EndpointSession


class SimpleEndpointAM(AnsweringMachine):
    """AnsweringMachine which emulates the basic behavior of a real MCTP endpoint.

    Usage:
        >>> import threading
        >>> from pymctp.automaton import SimpleEndpointAM
        >>> from pymctp.layers.mctp import *
        >>> from pymctp.exerciser import QemuI2CNetDevSocket
        >>> context = EndpointContext(physical_address=Smbus7bitAddress(0x20 >> 1), \
                              supported_msg_types=[MsgTypes.CTRL, MsgTypes.PLDM])
        >>> sock = QemuI2CNetDevSocket(iface="127.0.0.1", in_port=5559, out_port=5558)
        >>> session = EndpointSession(context=context, socket=sock)
        >>> am = SimpleEndpointAM(socket=sock, context=context, session=session)
        >>> sim = threading.Thread(target=am, kwargs={'count': 10, 'timeout':5*60})
        >>> sim.start()
        >>> rsp = session.sndrcv_control_msg(GetEndpointID(), 0x15, Smbus7bitAddress(0x20 >> 1))
        >>> rsp.show2() if rsp else print(f"No response received, timeout?")
    """

    context: EndpointContext
    socket: SuperSocket

    function_name = "simple_bus_owner"
    # removed the "iface", "promisc", "count", and "type" options as they are ethernet specific
    sniff_options_list = [
        "store",
        "opened_socket",
        "count",
        "filter",
        "prn",
        "stop_filter",
        "timeout",  # added timeout to stop sniffer after designated time period
    ]
    # removed the "socket" option to allow it to be passed to "parse_options"
    send_options_list = ["iface", "inter", "loop", "verbose"]

    def __init__(
        self,
        session: EndpointSession | None = None,
        socket: SuperSocket | None = None,
        context: EndpointContext | None = None,
        timeout: float | None = None,
        **kwargs,
    ):
        """
        Overloaded the AnsweringMachine.__init__() to add type hints for class specific parameters.

        :param session: Endpoint Session which oversees AM interactions
        :param socket: Socket to send and receive packets
        :param context: MCTP Endpoint content to store runtime state
        :param timeout: Specifies the sniffing timeout (seconds)
        :param kwargs: Any additional sniff/send options available in Scapy AnsweringMachine
        """
        self.context = context or EndpointContext()
        self.socket = socket
        self.session = session
        if self.session:
            self.session.am = self

        self.sniffer: AsyncSniffer | None = None
        super().__init__(timeout=timeout, **kwargs)

    def sniff(self) -> PacketList | None:
        """
        Overloaded the AnsweringMachine.sniff() method to always capture the sniffer in an instance attribute
        """
        self.sniffer = AsyncSniffer()
        self.sniffer._run(**self.optsniff)  # noqa: SLF001
        return cast(PacketList, self.sniffer.results)

    def parse_options(
        self,
        session: EndpointSession | None = None,
        socket: SuperSocket | None = None,
        timeout: float | None = None,
    ) -> None:
        """
        Sets up any additional sniffing/sending options that are not part of the
        standard AnsweringMachine.

        :param session: Endpoint Session which oversees AM interactions
        :param socket: Socket to send and receive packets
        :param timeout: Specifies the sniffing timeout (seconds)
        """
        if self.session:
            self.sniff_options["session"] = self.session
        self.sniff_options["timeout"] = timeout
        self.sniff_options["opened_socket"] = self.socket

    def is_request(self, req: Packet) -> int:
        """
        Called within AnsweringMachine.reply() to determine if the received
        packet requires a response.
        :param req: The received packet
        :return: 0 if no reply is necessary and 1 if a reply is required.
        """
        if isinstance(req, ICanReply):
            return req.is_request()
        return req.haslayer(ControlHdrPacket) and req.getlayer(ControlHdrPacket).rq == 1

    def make_reply(self, req: Packet | ICanReply) -> _PacketIterable:
        """
        Creates a reply to the incoming request (pre-confirmed by is_request())

        :param req: The received request packet
        :return: The fully formed response packet, or None (if no response can be generated)
        """
        rsp = None
        if isinstance(req, ICanReply):
            rsp = req.make_reply(self.context)
        # TODO: add any custom responses here
        return rsp

    def send_reply(self, reply: _PacketIterable, send_function: Callable[..., None] | None = None) -> None:
        """
        Sends the reply packets (sequentially) on the socket or using the "send_function" (if specified).

        @note This method does not wait for a response before sending the next reply

        :param reply: The fully formed packet(s) to send
        :param send_function: An optional callable method to invoke to send each packet (instead of the socket)
        """
        for p in reply:
            if len(reply) > 1:
                time.sleep(random.uniform(0.001, 0.01))  # noqa: S311
            else:
                time.sleep(random.uniform(0.1, 0.25))  # noqa: S311
            if self.socket:
                self.socket.send(p)

    def print_reply(self, req: AnyPacketType, reply: AnyPacketType) -> None:
        if isinstance(reply, PacketList):
            print("")
            print(f"{req.summary()} ==> {[res.summary() for res in reply]}")
        else:
            print(f"{req.summary()} ==> {reply.summary()}")

    @property
    def sniffer_running(self):
        return self.sniffer.running

    def stop_sniffer(self, join: bool = False) -> PacketList | None:
        if self.sniffer_running:
            return self.sniffer.stop(join=join)
        return None
