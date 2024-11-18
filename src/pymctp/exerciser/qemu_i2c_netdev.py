import socket
import time
from typing import Optional, Tuple

from scapy.compat import raw
from scapy.config import conf
from scapy.data import MTU
from scapy.interfaces import network_name, _GlobInterfaceType
from scapy.packet import Packet
from scapy.plist import SndRcvList, PacketList
from scapy.sendrecv import sndrcv
from scapy.supersocket import SuperSocket
from scapy.utils import linehexdump

from pymctp.layers.mctp import SmbusTransport, SmbusTransportPacket


class QemuI2CNetDevSocket(SuperSocket):
    desc = "read/write to a Qemu NetDev Socket"

    def __init__(self,
                 family: int = socket.AF_INET,
                 type: int = socket.SOCK_DGRAM,
                 proto: int = 0,
                 iface: Optional[_GlobInterfaceType] = None,
                 in_port=0, out_port=None, id_str="", **kwargs):
        self.id_str = id_str
        fd = socket.socket(family, type, proto)
        assert fd != -1
        self.ins = self.outs = fd

        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if iface is not None:
            iface2 = network_name(iface)
            self.iface = iface2
        else:
            self.iface = "any"

        self.ins.bind((iface, in_port))
        if out_port:
            # self.outs.connect((iface, out_port))
            self.out_port = out_port

    def send(self, x: Packet) -> int:
        """Overloaded Packet.send() method to use 'socket.sendto' to connect to the address
        before sending the packet.
        """
        sx = raw(x)
        try:
            x.sent_time = time.time()
        except AttributeError:
            pass

        if not self.outs:
            return 0

        if self.out_port:
            try:
                result = self.outs.sendto(sx, (self.iface, self.out_port))
                print(f"{self.id_str}>TX> {linehexdump(x, onlyhex=1, dump=True)}")
                return result
            except Exception as e:
                print(f"Failed sending data: {e}")
                raise
        return self.outs.send(sx)

    def recv(self, x: int = MTU) -> Optional[Packet]:
        raw_bytes = self.ins.recv(x)
        print(f"{self.id_str}<RX< {linehexdump(raw_bytes, onlyhex=1, dump=True)}")
        if len(raw_bytes) < 7:
            return None
        # TODO: Move this to a config field to support multiple transports
        #       Not needed right now as Qemu only supports I2C/SMBUS payloads
        pkt = SmbusTransport(raw_bytes)
        pkt.time = time.time()
        return pkt


@conf.commands.register
def srqemu(address, pkts, inter=0.1, *args, in_port=0, out_port=None, **kwargs) -> Tuple[SndRcvList, PacketList]:
    """Send and receive using a QEMU I2C socket"""
    s = QemuI2CNetDevSocket(iface=address, in_port=in_port, out_port=out_port)
    a, b = sndrcv(s, pkts, inter=inter, *args, **kwargs)
    s.close()
    return a, b


@conf.commands.register
def srqemu1(address, pkts, inter=0.1, *args, in_port=0, out_port=None, **kwargs) -> Packet:
    """Send and receive 1 packet using a QEMU I2C socket"""
    a, b = srqemu(address, pkts, inter=inter, *args, in_port=in_port, out_port=out_port, **kwargs)
    if len(a) > 0:
        return a[0][1]
