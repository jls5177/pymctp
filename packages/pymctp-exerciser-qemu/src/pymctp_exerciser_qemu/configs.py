# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Endpoint socket configs for the QEMU exercisers.

Each config subclasses :class:`pymctp.automaton.manager.SupersocketConfig`, so
importing this module auto-registers the config types with core pymctp — no
change to manager.py is needed to add a QEMU transport.
"""

from __future__ import annotations

import dataclasses
import pickle
from dataclasses import field
from typing import Any

from pymctp.automaton.manager import SupersocketConfig

from .qemu_i2c_netdev import QemuI2CNetDevSocket
from .qemu_i2c_stream import QemuI2CStreamSocket
from .qemu_i3c_chardev import QemuI3CCharDevSocket
from .qemu_i3c_netdev import QemuI3CNetDevSocket
from .qemu_i3c_netdev2 import QemuI3CNetDev2Socket
from .qemu_i3c_stream import QemuI3CStreamSocket


@dataclasses.dataclass()
class CharDevSocketConfig(SupersocketConfig):
    type = "chardev"
    in_file: str
    name: str
    pid: int
    bcr: int
    dcr: int
    mwl: int = 256
    mrl: int = 256
    dynamic_addr: int = 0

    socket: QemuI3CCharDevSocket | None = field(
        default=None, init=False, metadata={"serialize": pickle.dumps, "deserialize": pickle.loads}
    )

    def __post_init__(self):
        self.socket = QemuI3CCharDevSocket(
            in_file=self.in_file,
            id_str=self.name,
            pid=self.pid,
            bcr=self.bcr,
            dcr=self.dcr,
            mwl=self.mwl,
            mrl=self.mrl,
            dynamic_addr=self.dynamic_addr,
        )

    def close_socket(self):
        self.socket.close()


@dataclasses.dataclass()
class UdpSocketConfig(SupersocketConfig):
    type = "socket"
    in_port: int
    out_port: int
    name: str
    iface: str | None = None
    iface_out: str | None = None
    dump_hex: bool = True
    dump_packet: bool = False

    socket: QemuI2CNetDevSocket | None = field(
        default=None, init=False, metadata={"serialize": pickle.dumps, "deserialize": pickle.loads}
    )

    def __post_init__(self):
        self.socket = QemuI2CNetDevSocket(
            iface=self.iface,
            iface_out=self.iface_out,
            in_port=self.in_port,
            out_port=self.out_port,
            id_str=self.name,
            dump_hex=self.dump_hex,
            dump_packet=self.dump_packet,
        )

    def close_socket(self):
        self.socket.close()


@dataclasses.dataclass()
class UdpI3CSocketConfig(SupersocketConfig):
    """UDP socket config for QEMU i3c-target-netdev.

    I3C addresses are dynamically assigned, so physical_address is not needed.
    The transport is point-to-point and all address checks are skipped.
    """

    type = "i3c-socket"
    in_port: int
    out_port: int
    name: str
    iface: str | None = None
    iface_out: str | None = None
    dump_hex: bool = True
    dump_packet: bool = False

    socket: Any | None = field(
        default=None, init=False, metadata={"serialize": pickle.dumps, "deserialize": pickle.loads}
    )

    def __post_init__(self):
        self.socket = QemuI3CNetDevSocket(
            iface=self.iface,
            iface_out=self.iface_out,
            in_port=self.in_port,
            out_port=self.out_port,
            id_str=self.name,
            dump_hex=self.dump_hex,
            dump_packet=self.dump_packet,
        )

    def close_socket(self):
        self.socket.close()


@dataclasses.dataclass()
class UdpI3CSocket2Config(SupersocketConfig):
    """UDP socket config for QEMU i3c-target-netdev2.

    Supports the netdev2 protocol with type-tagged frames, SET_REG for device
    registers (PID/BCR/DCR/MWL/MRL), CCC notifications, and PEC-wrapped MCTP
    data.  When ``auto_configure`` is True (the default), SET_REG frames are
    sent to QEMU during socket initialisation for any non-zero register values.
    """

    type = "i3c-socket2"
    in_port: int
    out_port: int
    name: str
    iface: str | None = None
    iface_out: str | None = None
    dump_hex: bool = True
    dump_packet: bool = False
    pid: int = 0
    bcr: int = 0
    dcr: int = 0
    mwl: int = 0
    mrl: int = 0
    static_addr: int = 0
    auto_configure: bool = True

    socket: Any | None = field(
        default=None, init=False, metadata={"serialize": pickle.dumps, "deserialize": pickle.loads}
    )

    def __post_init__(self):
        self.socket = QemuI3CNetDev2Socket(
            iface=self.iface,
            iface_out=self.iface_out,
            in_port=self.in_port,
            out_port=self.out_port,
            id_str=self.name,
            dump_hex=self.dump_hex,
            dump_packet=self.dump_packet,
            pid=self.pid,
            bcr=self.bcr,
            dcr=self.dcr,
            mwl=self.mwl,
            mrl=self.mrl,
            static_addr=self.static_addr,
        )
        if self.auto_configure:
            kwargs = {}
            if self.pid:
                kwargs["pid"] = self.pid
            if self.bcr:
                kwargs["bcr"] = self.bcr
            if self.dcr:
                kwargs["dcr"] = self.dcr
            if self.mwl:
                kwargs["mwl"] = self.mwl
            if self.mrl:
                kwargs["mrl"] = self.mrl
            if self.static_addr:
                kwargs["static_addr"] = self.static_addr
            if kwargs:
                self.socket.configure(**kwargs)
                self.socket.send_hot_join()

    def close_socket(self):
        self.socket.close()


@dataclasses.dataclass()
class I3CStreamSocketConfig(SupersocketConfig):
    """TCP stream socket config for QEMU's I3C "remote target" device.

    Reuses the same netdev2 message semantics (SET_REG, HOT_JOIN, CCC
    notifications, PEC-wrapped MCTP data) as :class:`UdpI3CSocket2Config`,
    but connects as a single TCP client (``host``/``port``) instead of two
    UDP ports. A HELLO frame with the wire protocol version is sent on
    connect. When ``auto_configure`` is True (the default), SET_REG frames
    are sent to QEMU during socket initialisation for any non-zero register
    values.
    """

    type = "i3c-stream"
    host: str
    port: int
    name: str
    dump_hex: bool = True
    dump_packet: bool = False
    connect_timeout: float = 5.0
    pid: int = 0
    bcr: int = 0
    dcr: int = 0
    mwl: int = 0
    mrl: int = 0
    static_addr: int = 0
    auto_configure: bool = True

    socket: Any | None = field(
        default=None, init=False, metadata={"serialize": pickle.dumps, "deserialize": pickle.loads}
    )

    def __post_init__(self):
        self.socket = QemuI3CStreamSocket(
            host=self.host,
            port=self.port,
            id_str=self.name,
            dump_hex=self.dump_hex,
            dump_packet=self.dump_packet,
            connect_timeout=self.connect_timeout,
            pid=self.pid,
            bcr=self.bcr,
            dcr=self.dcr,
            mwl=self.mwl,
            mrl=self.mrl,
            static_addr=self.static_addr,
        )
        if self.auto_configure:
            kwargs = {}
            if self.pid:
                kwargs["pid"] = self.pid
            if self.bcr:
                kwargs["bcr"] = self.bcr
            if self.dcr:
                kwargs["dcr"] = self.dcr
            if self.mwl:
                kwargs["mwl"] = self.mwl
            if self.mrl:
                kwargs["mrl"] = self.mrl
            if self.static_addr:
                kwargs["static_addr"] = self.static_addr
            if kwargs:
                self.socket.configure(**kwargs)
                self.socket.send_hot_join()

    def close_socket(self):
        self.socket.close()


@dataclasses.dataclass()
class I2CStreamSocketConfig(SupersocketConfig):
    """TCP stream socket config for QEMU's I2C "remote target" device.

    Connects as a single TCP client (``host``/``port``) and uses the minimal
    WRITE/READ_REQ/READ_RSP/ALERT/HELLO framing implemented by
    :class:`~pymctp_exerciser_qemu.qemu_i2c_stream.QemuI2CStreamSocket`.

    When ``master`` is True, the socket instead speaks the peer-as-master
    wire format (mirroring the old UDP ``i2c-netdev`` transport): WRITE
    frames are address-prefixed and sent immediately, with no
    READ_REQ/READ_RSP turn-around. ``target_address`` (the BMC's own SMBus
    address) is required in that mode.
    """

    type = "i2c-stream"
    host: str
    port: int
    name: str
    dump_hex: bool = True
    dump_packet: bool = False
    connect_timeout: float = 5.0
    master: bool = False
    target_address: int | None = None

    socket: Any | None = field(
        default=None, init=False, metadata={"serialize": pickle.dumps, "deserialize": pickle.loads}
    )

    def __post_init__(self):
        self.socket = QemuI2CStreamSocket(
            host=self.host,
            port=self.port,
            id_str=self.name,
            dump_hex=self.dump_hex,
            dump_packet=self.dump_packet,
            connect_timeout=self.connect_timeout,
            master=self.master,
            target_address=self.target_address,
        )

    def close_socket(self):
        self.socket.close()
