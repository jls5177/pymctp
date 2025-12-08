# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import contextlib
import socket
import struct
import time
from collections import deque
from enum import IntEnum

import crc8
from scapy.base_classes import BasePacket
from scapy.compat import raw
from scapy.data import MTU
from scapy.fields import ByteEnumField, ByteField, FieldLenField, FieldListField, LEIntField, PacketListField
from scapy.packet import Packet, Raw
from scapy.supersocket import SuperSocket

from pymctp.layers.mctp import TransportHdrPacket
from pymctp.layers.mctp.types import AnyPacketType


class I3cCcc(IntEnum):
    I3C_CCC_ENEC = 0x00
    I3C_CCC_DISEC = 0x01
    I3C_CCC_ENTAS0 = 0x02
    I3C_CCC_ENTAS1 = 0x03
    I3C_CCC_ENTAS2 = 0x04
    I3C_CCC_ENTAS3 = 0x05
    I3C_CCC_RSTDAA = 0x06
    I3C_CCC_ENTDAA = 0x07
    I3C_CCC_DEFTGTS = 0x08
    I3C_CCC_SETMWL = 0x09
    I3C_CCC_SETMRL = 0x0A
    I3C_CCC_ENTTM = 0x0B
    I3C_CCC_SETBUSCON = 0x0C
    I3C_CCC_ENDXFER = 0x12
    I3C_CCC_ENTHDR0 = 0x20
    I3C_CCC_ENTHDR1 = 0x21
    I3C_CCC_ENTHDR2 = 0x22
    I3C_CCC_ENTHDR3 = 0x23
    I3C_CCC_ENTHDR4 = 0x24
    I3C_CCC_ENTHDR5 = 0x25
    I3C_CCC_ENTHDR6 = 0x26
    I3C_CCC_ENTHDR7 = 0x27
    I3C_CCC_SETXTIME = 0x28
    I3C_CCC_SETAASA = 0x29
    I3C_CCC_RSTACT = 0x2A
    I3C_CCC_DEFGRPA = 0x2B
    I3C_CCC_RSTGRPA = 0x2C
    I3C_CCC_MLANE = 0x2D

    # Direct CCCs
    I3C_CCCD_ENEC = 0x80
    I3C_CCCD_DISEC = 0x81
    I3C_CCCD_ENTAS0 = 0x82
    I3C_CCCD_ENTAS1 = 0x83
    I3C_CCCD_ENTAS2 = 0x84
    I3C_CCCD_ENTAS3 = 0x85
    I3C_CCCD_SETDASA = 0x87
    I3C_CCCD_SETNEWDA = 0x88
    I3C_CCCD_SETMWL = 0x89
    I3C_CCCD_SETMRL = 0x8A
    I3C_CCCD_GETMWL = 0x8B
    I3C_CCCD_GETMRL = 0x8C
    I3C_CCCD_GETPID = 0x8D
    I3C_CCCD_GETBCR = 0x8E
    I3C_CCCD_GETDCR = 0x8F
    I3C_CCCD_GETSTATUS = 0x90
    I3C_CCCD_GETACCCR = 0x91
    I3C_CCCD_ENDXFER = 0x92
    I3C_CCCD_SETBRGTGT = 0x93
    I3C_CCCD_GETMXDS = 0x94
    I3C_CCCD_GETCAPS = 0x95
    I3C_CCCD_SETROUTE = 0x96
    I3C_CCCD_SETXTIME = 0x98
    I3C_CCCD_GETXTIME = 0x99
    I3C_CCCD_RSTACT = 0x9A
    I3C_CCCD_SETGRPA = 0x9B
    I3C_CCCD_RSTGRPA = 0x9C
    I3C_CCCD_MLANE = 0x9D


def directed_ccc_reads_data(ccc: int) -> bool:
    # bail out if not a directed CCC
    if ccc < 0x80:
        return False
    return ccc in [
        I3cCcc.I3C_CCCD_GETMWL,
        I3cCcc.I3C_CCCD_GETMRL,
        I3cCcc.I3C_CCCD_GETPID,
        I3cCcc.I3C_CCCD_GETBCR,
        I3cCcc.I3C_CCCD_GETDCR,
        I3cCcc.I3C_CCCD_GETACCCR,
        I3cCcc.I3C_CCCD_GETMXDS,
        I3cCcc.I3C_CCCD_GETCAPS,
        I3cCcc.I3C_CCCD_GETXTIME,
    ]


def directed_ccc_requires_data(ccc: int) -> bool:
    # bail out if not a directed CCC
    if ccc < 0x80:
        return False
    return ccc in [
        I3cCcc.I3C_CCCD_ENEC,
        I3cCcc.I3C_CCCD_DISEC,
        I3cCcc.I3C_CCCD_SETDASA,
        I3cCcc.I3C_CCCD_SETNEWDA,
        I3cCcc.I3C_CCCD_SETMWL,
        I3cCcc.I3C_CCCD_SETMRL,
        I3cCcc.I3C_CCCD_SETBRGTGT,
        I3cCcc.I3C_CCCD_SETROUTE,
        I3cCcc.I3C_CCCD_SETXTIME,
    ]


class RemoteI3CEvents(IntEnum):
    # Sent to the remote target
    REMOTE_I3C_START_READ = 1
    REMOTE_I3C_START_WRITE = 2
    REMOTE_I3C_STOP = 3
    REMOTE_I3C_NACK = 4


class RemoteI3CCommands(IntEnum):
    # Sent to the remote target
    REMOTE_I3C_PRIV_READ = 5
    REMOTE_I3C_PRIV_WRITE = 6
    REMOTE_I3C_CCC_WRITE = 7
    REMOTE_I3C_CCC_READ = 8
    REMOTE_I3C_IBI = 9


class RemoteI3cIbiResponses(IntEnum):
    # Sent from remote target
    REMOTE_I3C_IBI_ACK = 0xC0
    REMOTE_I3C_IBI_NACK = 0xC1
    REMOTE_I3C_IBI_DATA_NACK = 0xC2


class RemoteI3CRXEvent(IntEnum):
    REMOTE_I3C_RX_ACK = 0
    REMOTE_I3C_RX_NACK = 1


class REMOTE_I3C_IBI_REQUEST(Packet):
    name = "RemoteI3C-IBI"
    fields_desc = [
        ByteEnumField("opcode", 0, RemoteI3CCommands),
        ByteField("ibi_addr", 0),
        ByteField("rnw", 0),
        FieldLenField("length", None, fmt="<I", count_of="ibi_payload"),
        FieldListField("ibi_payload", [], ByteField("", 0), count_from=lambda pkt: pkt.length),
    ]

    def extract_padding(self, s):
        return b"", s


class I3C_CCC_READ_RESPONSE(Packet):
    # TODO: Support Entdaa CCC command: 07 01 00 00 00 09 03
    name = "CCC-Read-Response"
    fields_desc = [
        ByteEnumField("opcode", RemoteI3CCommands.REMOTE_I3C_CCC_WRITE, RemoteI3CCommands),
        FieldLenField("length", None, fmt="<I", count_of="data"),
        FieldListField("data", [], ByteField("", 0), count_from=lambda pkt: pkt.length),
    ]

    def extract_padding(self, s):
        return b"", s


class I3C_PRIV_READ(Packet):
    # TODO: Support Private Read command: 01 05 00 01 00 00
    name = "Private-Read"
    fields_desc = [
        ByteEnumField("start_event", RemoteI3CEvents.REMOTE_I3C_START_READ, RemoteI3CEvents),
        ByteEnumField("opcode", RemoteI3CCommands.REMOTE_I3C_PRIV_READ, RemoteI3CCommands),
        LEIntField("length", 0),
    ]

    def extract_padding(self, s):
        return b"", s


class I3C_CCC_READ(Packet):
    # TODO: Support CCC Read command: 01 08
    name = "CCC-Read"
    fields_desc = [
        ByteEnumField("start_event", RemoteI3CEvents.REMOTE_I3C_START_READ, RemoteI3CEvents),
        ByteEnumField("opcode", RemoteI3CCommands.REMOTE_I3C_CCC_READ, RemoteI3CCommands),
    ]

    def extract_padding(self, s):
        return b"", s


class I3C_CCC_DIRECT_WRITE(Packet):
    # TODO: Support CCC Read command: 01 08
    name = "CCC-Direct-Write"
    fields_desc = [
        ByteEnumField("start_event", 0, RemoteI3CEvents),
        ByteEnumField("ccc_opcode", RemoteI3CCommands.REMOTE_I3C_CCC_WRITE, RemoteI3CCommands),
        LEIntField("ccc_length", 1),
        ByteEnumField("ccc", None, I3cCcc),
        ByteEnumField("repeated_start_event", None, RemoteI3CEvents),
        ByteEnumField("opcode", None, RemoteI3CCommands),
        FieldLenField("length", None, fmt="<I", count_of="data"),
        FieldListField("data", [], ByteField("", 0), count_from=lambda pkt: pkt.length),
    ]

    def extract_padding(self, s):
        return b"", s


class I3C_CCC_WRITE(Packet):
    # TODO: Support CCC Read command: 01 08
    name = "CCC-Write"
    fields_desc = [
        ByteEnumField("start_event", 0, RemoteI3CEvents),
        ByteEnumField("opcode", RemoteI3CCommands.REMOTE_I3C_CCC_WRITE, RemoteI3CCommands),
        FieldLenField("length", None, fmt="<I", count_of="data", adjust=lambda pkt, x: x - 1),
        ByteEnumField("ccc", 0, I3cCcc),
        FieldListField("data", [], ByteField("", 0), count_from=lambda pkt: pkt.length - 1),
    ]

    def extract_padding(self, s):
        return b"", s


class I3C_PRIV_WRITE(Packet):
    # TODO: Support Private Write command: 02 06 08 00 00 00 01 00 0A C8 00 80 02 B1 03
    name = "Private-Write"
    fields_desc = [
        ByteEnumField("start_event", RemoteI3CEvents.REMOTE_I3C_START_WRITE, RemoteI3CEvents),
        ByteEnumField("opcode", RemoteI3CCommands.REMOTE_I3C_PRIV_WRITE, RemoteI3CCommands),
        FieldLenField("length", None, fmt="<I", count_of="data"),
        FieldListField("data", [], ByteField("", 0), count_from=lambda pkt: pkt.length),
    ]

    def extract_padding(self, s):
        return b"", s


class I3C_IBI_STATUS(Packet):
    # TODO: Support Private Read command: C0
    name = "IBI-Response"
    fields_desc = [
        ByteEnumField("status", 0, RemoteI3cIbiResponses),
    ]

    def extract_padding(self, s):
        return b"", s


class REMOTE_I3C_READ_DATA(Packet):
    name = "RemoteI3C-RX-Response"
    fields_desc = [
        FieldLenField("length", None, fmt="<I", count_of="tx_data"),
        FieldListField("tx_data", [], ByteField("", 0), count_from=lambda pkt: pkt.length),
    ]


class I3C_EVENT(Packet):
    name = "REMOTE_I3C_EVENT"
    fields_desc = [
        ByteEnumField("event", 0, RemoteI3CEvents),
    ]

    def extract_padding(self, s):
        return b"", s


def parse_next_msg(pkt: Packet, lst: list[BasePacket], cur: Packet | None, remain: bytes) -> type[Packet] | None:
    if not remain and len(remain) == 0:
        return None
    # TODO: separate out START event and parse from list to determine next event
    # last_event = None
    # for e in reversed([*lst, cur]):
    #     if not isinstance(e, I3C_EVENT):
    #         continue
    #     last_event = e.event

    event = remain[0]
    if event == RemoteI3CEvents.REMOTE_I3C_START_READ:
        opcode = remain[1] if len(remain) > 1 else None
        if opcode == RemoteI3CCommands.REMOTE_I3C_PRIV_READ:
            # Priv Read: 0x01, 0x05, 0x00, 0x01, 0x00, 0x00
            return I3C_PRIV_READ
        if opcode == RemoteI3CCommands.REMOTE_I3C_CCC_READ:
            # CCC Read (Directed): 0x01, 0x08
            return I3C_CCC_READ
        return I3C_EVENT if len(remain) > 1 else None
    if event == RemoteI3CEvents.REMOTE_I3C_START_WRITE:
        opcode = remain[1] if len(remain) > 1 else None
        if opcode == RemoteI3CCommands.REMOTE_I3C_PRIV_WRITE:
            # Priv Write: 0x02, 0x06, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0A, 0xC8, 0x00, 0x80, 0x02, 0xB1, 0x03
            empty_pkt_size = len(I3C_PRIV_WRITE())
            if len(remain) < empty_pkt_size:
                return None
            pkt = I3C_PRIV_WRITE(remain)
            if len(remain) < (pkt.length + empty_pkt_size):
                return None
            return I3C_PRIV_WRITE
        if opcode == RemoteI3CCommands.REMOTE_I3C_CCC_READ:
            # CCC Read (Broadcast,ENTDAA): 0x02, 0x08
            return I3C_CCC_READ
        if opcode == RemoteI3CCommands.REMOTE_I3C_CCC_WRITE:
            if len(remain) < 6:
                return None
            ccc = remain[6]
            if ccc >= 0x80:
                # check if a directed CCC sends and return if not all data is available
                if directed_ccc_requires_data(ccc) and len(remain) < 13:
                    return None
                # Check if a directed CCC will be followed by a read, ensure the read is not
                # split between receives
                if directed_ccc_reads_data(ccc) and len(remain) < 9:
                    return I3C_CCC_WRITE
                return I3C_CCC_DIRECT_WRITE
            # CCC Write: 0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x07
            return I3C_CCC_WRITE
        return I3C_EVENT if len(remain) > 1 else None
    if event == RemoteI3CEvents.REMOTE_I3C_STOP:
        # Stop event: 0x03
        return I3C_EVENT
    if event == RemoteI3CCommands.REMOTE_I3C_CCC_WRITE:
        # CCC Write after Read (e.g., ENTDAA address assignment)
        if len(remain) < len(I3C_CCC_READ_RESPONSE()):
            return None
        return I3C_CCC_READ_RESPONSE
    if event in iter(RemoteI3cIbiResponses):
        # IBI Resp: 0xC0
        return I3C_IBI_STATUS

    # Fallback to using a Raw packet which will gobble up all remaining bytes
    return None


class REMOTE_I3C(Packet):
    """
    Remote I3C packet
    """

    name = "REMOTE_I3C"

    fields_desc = [
        PacketListField("msgs", [], next_cls_cb=parse_next_msg),
    ]


class QemuI3CCharDevSocket(SuperSocket):
    desc = "read/write to a QEMU CharDev Socket"

    def __init__(
        self,
        family: int = socket.AF_UNIX if hasattr(socket, "AF_UNIX") else socket.AF_INET,
        pid: int = 0,
        bcr: int = 0,
        dcr: int = 0,
        mwl: int = 256,
        mrl: int = 256,
        dynamic_addr: int = 0,
        in_file="",
        id_str="",
        **kwargs,
    ):
        self.id_str = id_str
        fd = socket.socket(family)
        assert fd != -1
        while True:
            try:
                fd.connect(in_file)
                break
            except OSError:
                time.sleep(1)
        self.ins = self.outs = fd

        self.buffer = b""
        self.in_ccc = False
        self.ccc = 0
        self.in_entdaa = False

        self.dynamic_addr = dynamic_addr
        self.bcr = bcr
        self.dcr = dcr
        self.mwl = mwl
        self.mrl = mrl
        self.pid = pid

        self.bus_stopped = True
        self.in_ibi = self.in_rx = self.in_send_cmd = self.rx_pending = False
        self.tx_fifo = deque()

    def send_ibi(self, ipi_payload=None, add_mdb=False):
        if not self.bus_stopped:
            return
        if ipi_payload is None and add_mdb:
            ipi_payload = [0xAE]
            crc = crc8.crc8()
            addr = (self.dynamic_addr << 1) | 1
            crc.update(int.to_bytes(addr, byteorder="little", length=1))
            crc.update(bytes(ipi_payload))
            pec = crc.digest()
            ipi_payload += [int.from_bytes(pec, byteorder="little")]
        self.in_ibi = True
        x = REMOTE_I3C_IBI_REQUEST(
            opcode=RemoteI3CCommands.REMOTE_I3C_IBI, ibi_addr=self.dynamic_addr, rnw=1, ibi_payload=ipi_payload or []
        )
        return self.send(x)

    def send(self, x: Packet) -> int:
        """Overloaded Packet.send() method to use 'socket.sendto' to connect to the address
        before sending the packet.
        """

        # Send IBI to notify controller a TX message is queued for reading
        if not self.in_ccc and not isinstance(x, REMOTE_I3C_READ_DATA) and not isinstance(x, REMOTE_I3C_IBI_REQUEST):
            self.tx_fifo.append(x)
            if not self.in_ibi and not self.rx_pending:
                self.send_ibi()
            return 0

        sx = raw(x)
        with contextlib.suppress(AttributeError):
            x.sent_time = time.time()

        if not self.outs:
            return 0
        return self.outs.send(sx)

    def handle_ccc(self, ccc: I3cCcc | None, data: bytes) -> Packet | None:
        if ccc == I3cCcc.I3C_CCC_ENTDAA:
            # strip top 2 bytes as they are zeros (since big endian)
            data = struct.pack("!Q", self.pid)[2:]
            data += bytes([self.bcr, self.dcr])
            return REMOTE_I3C_READ_DATA(tx_data=list(data))
        if self.ccc == I3cCcc.I3C_CCC_ENTDAA:
            # this is the write byte of the ENTDAA where the
            # dynamic address is written to the target
            self.dynamic_addr = data[0]
            return None
        if ccc == I3cCcc.I3C_CCCD_GETPID:
            # strip top 2 bytes as they are zeros (since big endian)
            data = struct.pack("!Q", self.pid)[2:]
            return REMOTE_I3C_READ_DATA(tx_data=list(data))
        if ccc == I3cCcc.I3C_CCCD_GETBCR:
            return REMOTE_I3C_READ_DATA(tx_data=[self.bcr])
        if ccc == I3cCcc.I3C_CCCD_GETDCR:
            return REMOTE_I3C_READ_DATA(tx_data=[self.dcr])
        if ccc == I3cCcc.I3C_CCCD_GETMRL:
            mrl = struct.pack("!H", self.mrl)
            # Add the max IBI size if IBIs are enabled
            if self.bcr & 2 == 2:
                mrl += bytes(0x0)  # 0 == unlimited number of bytes
            return REMOTE_I3C_READ_DATA(tx_data=list(mrl))
        if ccc == I3cCcc.I3C_CCCD_GETMWL:
            mwl = struct.pack("!H", self.mwl)
            return REMOTE_I3C_READ_DATA(tx_data=list(mwl))
        if ccc == I3cCcc.I3C_CCCD_GETMXDS:
            return REMOTE_I3C_READ_DATA(tx_data=[0, 0])
        return None

    def handle_rx(self) -> AnyPacketType | None:
        parsed = REMOTE_I3C(self.buffer)
        if len(parsed.msgs) == 0:
            return None

        received_packet = None
        self.buffer = parsed.load if parsed.payload else b""
        parsed.show2()
        for pkt in parsed.msgs:
            start_event = "start_event" in pkt.fields
            if isinstance(pkt, I3C_EVENT) and pkt.event in [
                RemoteI3CEvents.REMOTE_I3C_START_WRITE,
                RemoteI3CEvents.REMOTE_I3C_START_READ,
            ]:
                start_event = True
            if start_event and self.bus_stopped:
                self.bus_stopped = self.in_send_cmd = False

            if isinstance(pkt, I3C_IBI_STATUS):
                self.in_ibi = False
                self.rx_pending = True  # don't allow anymore IBIs to be sent
            elif isinstance(pkt, I3C_CCC_DIRECT_WRITE | I3C_CCC_WRITE):
                self.ccc = pkt.ccc
                self.in_ccc = True
                self.in_entdaa = self.ccc == I3cCcc.I3C_CCC_ENTDAA
                self.queued_tx = self.handle_ccc(pkt.ccc or 0, pkt.data)

                # Controller is ready for the response, just send it
                if (
                    isinstance(pkt, I3C_CCC_DIRECT_WRITE)
                    and pkt.repeated_start_event == RemoteI3CEvents.REMOTE_I3C_START_READ
                    and pkt.opcode == RemoteI3CCommands.REMOTE_I3C_CCC_READ
                ):
                    self.send(self.queued_tx)
                    self.queued_tx = None
            elif isinstance(pkt, I3C_CCC_READ_RESPONSE):
                # Pass to CCC handler as it knows what CCC is outstanding
                self.handle_ccc(None, pkt.data)
            elif isinstance(pkt, I3C_CCC_READ):
                # send an empty reponse if none is queued
                rsp_pkt = REMOTE_I3C_READ_DATA(tx_data=[])
                if self.rx_pending and len(self.tx_fifo):
                    assert len(self.tx_fifo)
                    rsp = raw(self.tx_fifo.popleft())
                    # generate the PEC for the request
                    crc = crc8.crc8()
                    addr = (self.dynamic_addr << 1) | 1
                    crc.update(int.to_bytes(addr, byteorder="little", length=1))
                    crc.update(rsp)
                    pec = crc.digest()
                    rsp_pkt = REMOTE_I3C_READ_DATA(tx_data=list(rsp) + list(pec))
                    self.in_rx = True
                    self.rx_pending = False
                elif self.queued_tx:
                    rsp_pkt = self.queued_tx
                    self.queued_tx = None
                self.send(rsp_pkt)
            elif isinstance(pkt, I3C_PRIV_WRITE):
                # handle TX rate limit (where previous RX timeed out while IBI queued)
                if self.rx_pending and len(self.tx_fifo):
                    self.tx_fifo.clear()
                # Push private msg to be handled internally
                # Trim off PEC as it messes with the responses
                self.in_send_cmd = True
                req_pkt = TransportHdrPacket(bytes(pkt.data[:-1]))
                req_pkt.time = time.time()
                received_packet = req_pkt
            elif isinstance(pkt, I3C_PRIV_READ):
                rsp_pkt = REMOTE_I3C_READ_DATA(tx_data=[])
                if self.rx_pending and len(self.tx_fifo):
                    assert len(self.tx_fifo)
                    rsp = raw(self.tx_fifo.popleft())
                    # generate the PEC for the request
                    crc = crc8.crc8()
                    addr = (self.dynamic_addr << 1) | 1
                    crc.update(int.to_bytes(addr, byteorder="little", length=1))
                    crc.update(rsp)
                    pec = crc.digest()
                    rsp_pkt = REMOTE_I3C_READ_DATA(tx_data=list(rsp) + list(pec))
                self.in_rx = True
                self.rx_pending = False
                self.send(rsp_pkt)
            elif isinstance(pkt, I3C_EVENT):
                event = pkt.event
                if event == RemoteI3CEvents.REMOTE_I3C_STOP:
                    self.in_ccc = self.in_entdaa = self.in_rx = self.in_send_cmd = False
                    self.ccc = 0
                    self.queued_tx = None
                    self.bus_stopped = True

        if not self.in_ccc and not self.in_rx and not self.rx_pending and not self.in_ibi and len(self.tx_fifo):
            self.send_ibi()

        return received_packet

    def recv(self, x: int = MTU) -> AnyPacketType | None:
        raw_bytes = self.ins.recv(x)
        if not raw_bytes:
            return None
        self.buffer += raw_bytes
        return self.handle_rx()


if __name__ == "__main__":
    pkts = REMOTE_I3C(bytes([0x02, 0xC0, 0x07]))
    pkts.show2()

    pkts = REMOTE_I3C(bytes([0x02, 0xC0, 0x07, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x08]))
    pkts.show2()

    pkts = REMOTE_I3C(
        bytes(
            [
                0x02,
                0x07,
                0x01,
                0x00,
                0x00,
                0x00,
                0x06,
                0x03,
                0x02,
                0x07,
                0x02,
                0x00,
                0x00,
                0x00,
                0x01,
                0x0B,
                0x03,
                0x02,
                0x07,
                0x01,
                0x00,
                0x00,
                0x00,
                0x07,
                0x02,
                0x08,
                0x07,
                0x01,
                0x00,
                0x00,
                0x00,
                0x09,
                0x03,
            ]
        )
    )
    pkts.show2()

    pkts = REMOTE_I3C(
        bytes([0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x8A, 0x02, 0x07, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0xFF, 0x03])
    )
    pkts.show2()

    # # Broadcast message - ENTDAA
    # frame = RemoteI3CRXFrame(bytes([0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x07, 0x02, 0x08]))
    # frame.show2()
    # assert isinstance(frame.Message, I3cBroadcastCCCEntdaaPacket)
    #
    # frame = RemoteI3CRXFrame(bytes([0x07, 0x01, 0x00, 0x00, 0x00, 0x09, 0x03]))
    # frame.show2()
    # assert isinstance(frame.Message, I3cBroadcastCCCEntdaaResponsePacket)
    #
    # # Broadcast message
    # frame = RemoteI3CRXFrame(bytes([0x02, 0x07, 0x02, 0x00, 0x00, 0x00, 0x01, 0x0B, 0x03]))
    # frame.show2()
    # assert isinstance(frame.Message, I3cBroadcastCCCPacket)
    #
    # # Directed CCC Write
    # frame = RemoteI3CRXFrame(
    #     bytes([0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x80, 0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x01, 0x03]))
    # frame.show2()
    # assert isinstance(frame.Message, I3cDirectedCCCPacket)
    # assert 'end_event' in frame.Message.fields
    # assert frame.Message.opcode == RemoteI3CCommands.REMOTE_I3C_CCC_WRITE
    #
    # # Directed CCC Read
    # frame = RemoteI3CRXFrame(
    #     bytes([0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x8B, 0x01, 0x08]))
    # frame.show2()
    # assert isinstance(frame.Message, I3cDirectedCCCPacket)
    # assert 'end_event' not in frame.Message.fields
    # assert frame.Message.opcode == RemoteI3CCommands.REMOTE_I3C_CCC_READ
    #
    # # Private Write
    # frame = RemoteI3CRXFrame(
    #     bytes([0x02, 0x06, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0A, 0xC8, 0x00, 0x80, 0x02, 0xB1, 0x03]))
    # frame.show2()
    # assert isinstance(frame.Message, I3C_PRIV_WRITE)
    #
    # frames = REMOTE_I3C(
    #     bytes([0x02, 0x06, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0A, 0xC8, 0x00, 0x80, 0x02, 0xB1, 0x03]))
    # frames.show2()
    #
    # # Private Read
    # frame = RemoteI3CRXFrame(
    #     bytes([0x01, 0x05, 0x00, 0x01, 0x00, 0x00]))
    # frame.show2()
    # assert isinstance(frame.Message, I3C_PRIV_READ)
    #
    # # IBI Completion Status
    # frame = RemoteI3CRXFrame(bytes([0xC0]))
    # frame.show2()
    # assert isinstance(frame.Message, I3C_IBI_STATUS)
    #
    # # Private Read Completion Status
    # frame = RemoteI3CRXFrame(bytes([0x03]))
    # frame.show2()
    # assert isinstance(frame.Message, I3cReadResponsePacket)

    # data = [0x02, 0x07, 0x02, 0x00, 0x00, 0x00, 0x01, 0x0B, 0x03, 0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x07, 0x02, 0x08]
    # data = [0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x07, 0x03]
    # data = [0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x07, 0x02, 0x08]
    # data = [0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x06, 0x03, 0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x06, 0x03]
    # data = [0x02, 0x07, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08, 0x03]
    socket = QemuI3CCharDevSocket(in_file="/tmp/remote-i3c-2")  # noqa: S108
    # resp = socket.handle_rx(payload=bytes(data))
    # print(f"Response: {resp}")
    # print(f"Remaining bytes: {binascii.hexlify(socket.buffer)}")
    #
    # data2 = [0x07, 0x01, 0x00, 0x00, 0x00, 0x09, 0x03]
    # resp = socket.handle_rx(payload=bytes(data2))
    # print(f"Response: {resp}")
    # print(f"Remaining bytes: {binascii.hexlify(socket.buffer)}")

    # for data in [[0x02, 0x07, 0x01, 0x00, 0x00, 0x00, 0x8D, 0x01, 0x08],
    #              [0x03],
    #              [0x02],
    #              [0x07, 0x01, 0x00, 0x00, 0x00, 0x8E, 0x01, 0x08]]:
    # for data in [[0x02], [0x07, 0x01, 0x00, 0x00, 0x00, 0x94, 0x01, 0x08],
    #              [0x03],
    #              [0x02],
    #              [0x07, 0x01, 0x00, 0x00, 0x00, 0x8C],
    #              [0x01, 0x08]]:
    # for data in [[0x02], [0x06, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0A, 0xC8, 0x00, 0x80, 0x02, 0xB1, 0x03],
    #              [0xC0],
    #              [0x01, 0x05, 0x00, 0x01, 0x00, 0x00],
    #              [0x03],
    #              [0x02, 0x06, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0A, 0xC8, 0x00, 0x80, 0x02, 0xB1, 0x03]]:
    # for data in [[0x02, 0x06, 0x09, 0x00, 0x00, 0x00, 0x01, 0x0C, 0x0A, 0xC9, 0x01, 0x83, 0x00, 0x04, 0x7E, 0x03],
    #              [0xC0],
    #              [0x01, 0x05, 0x00, 0x01, 0x00, 0x00],
    #              [0x03],
    #              [0x01, 0x05, 0x00, 0x01, 0x00, 0x00],
    #              [0x03],
    #              [0x01, 0x05, 0x00, 0x01, 0x00, 0x00]]:
    for data in [
        [
            0x02,
            0x06,
            0x0E,
            0x00,
            0x00,
            0x00,
            0x01,
            0x0C,
            0x0A,
            0xC9,
            0x01,
            0x8B,
            0x00,
            0x05,
            0x05,
            0x00,
            0xF0,
            0xF1,
            0xF1,
            0x24,
        ],
        [0x03],
        [0x02, 0xC0],
        [0x07, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x08],
    ]:
        socket.buffer += bytes(data)
        resp = socket.handle_rx()
        if resp:
            socket.send(Raw(bytes([0x01, 0x0A, 0x00, 0xD0, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00])))
    while len(socket.buffer):
        resp = socket.handle_rx()
