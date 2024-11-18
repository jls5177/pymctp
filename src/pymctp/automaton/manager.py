# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import dataclasses
import pickle
import threading
from dataclasses import field
from enum import Enum
from threading import Thread
from typing import Any, Protocol, runtime_checkable

from mashumaro import DataClassDictMixin, field_options
from mashumaro.config import BaseConfig
from scapy.supersocket import SuperSocket

from pymctp.automaton import EndpointSession, SimpleEndpointAM
from pymctp.exerciser import AardvarkI2CSocket, QemuI2CNetDevSocket, QemuI3CCharDevSocket
from pymctp.layers.mctp import EndpointContext, Smbus7bitAddress


class ConfigTypes(str, Enum):
    Socket = "socket"
    Aardvark = "aardvark"
    CharDev = "chardev"


@runtime_checkable
class ISessionConfig(Protocol):
    socket: SuperSocket

    def close_socket(self):
        pass


@dataclasses.dataclass()
class CharDevSocketConfig(DataClassDictMixin):
    type = ConfigTypes.CharDev
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
class UdpSocketConfig(DataClassDictMixin):
    type = ConfigTypes.Socket
    in_port: int
    out_port: int
    name: str
    iface: str = "localhost"
    dump_hex: bool = True
    dump_packet: bool = False

    socket: QemuI2CNetDevSocket | None = field(
        default=None, init=False, metadata={"serialize": pickle.dumps, "deserialize": pickle.loads}
    )

    def __post_init__(self):
        self.socket = QemuI2CNetDevSocket(
            iface=self.iface,
            in_port=self.in_port,
            out_port=self.out_port,
            id_str=self.name,
            dump_hex=self.dump_hex,
            dump_packet=self.dump_packet,
        )

    def close_socket(self):
        self.socket.close()


def deserialize_aardvark_address(value: str | int | Smbus7bitAddress) -> Smbus7bitAddress:
    if isinstance(value, Smbus7bitAddress):
        return value
    return Smbus7bitAddress(address=int(value))


@dataclasses.dataclass()
class AardvarkConfig(DataClassDictMixin):
    type = ConfigTypes.Aardvark
    slave_addr: Smbus7bitAddress = field(metadata=field_options(alias="slave_address"))
    serial_number: str
    name: str
    dump_hex: bool = True
    dump_packet: bool = False

    socket: AardvarkI2CSocket | None = field(
        default=None, init=False, metadata={"serialize": pickle.dumps, "deserialize": pickle.loads}
    )

    class Config(BaseConfig):
        serialization_strategy = {Smbus7bitAddress: {"deserialize": deserialize_aardvark_address}}

    def __post_init__(self):
        self.socket = AardvarkI2CSocket(
            slave_address=self.slave_addr,
            serial_number=self.serial_number,
            id_str=self.name,
            dump_hex=self.dump_hex,
            dump_packet=self.dump_packet,
        )

    def create_session(self) -> EndpointSession:
        pass

    def close_socket(self):
        self.socket.close()


def deserialize_supersocket(value: dict) -> AardvarkConfig | UdpSocketConfig | CharDevSocketConfig:
    config_type = value.get("type")
    if config_type == ConfigTypes.Socket:
        return UdpSocketConfig.from_dict(value)
    if config_type == ConfigTypes.Aardvark:
        return AardvarkConfig.from_dict(value)
    if config_type == ConfigTypes.CharDev:
        return CharDevSocketConfig.from_dict(value)
    msg = f"Unknown config type {config_type}"
    raise ValueError(msg)


@dataclasses.dataclass()
class EndpointConfig(DataClassDictMixin):
    context: EndpointContext
    config: AardvarkConfig | UdpSocketConfig | CharDevSocketConfig
    thread_kwargs: dict[str, Any] = field(default_factory=dict)

    class Config(BaseConfig):
        serialization_strategy = {
            AardvarkConfig | UdpSocketConfig | CharDevSocketConfig: {"deserialize": deserialize_supersocket}
        }


@dataclasses.dataclass()
class EndpointManager:
    config: EndpointConfig
    session: EndpointSession
    socket: SuperSocket
    thread: Thread
    am: SimpleEndpointAM

    @classmethod
    def from_config(cls, config: dict[Any, Any], start_thread=True, verbose: bool = False):
        cfg = EndpointConfig.from_dict(config)
        print(f"DEBUG: {cfg or 'None'}")
        socket = cfg.config.socket
        session = EndpointSession(context=cfg.context, socket=socket)

        am = SimpleEndpointAM(socket=socket, context=cfg.context, session=session, verbose=verbose)
        if cfg.context.is_bus_owner:
            # TODO: add discovery flow answering machine here
            pass
        thread = threading.Thread(target=am, kwargs=cfg.thread_kwargs)
        if start_thread:
            thread.start()
        return EndpointManager(
            socket=socket,
            config=cfg,
            session=session,
            thread=thread,
            am=am,
        )

    @property
    def context(self) -> EndpointContext:
        return self.config.context

    @property
    def supersocket(self) -> SuperSocket:
        return self.config.config.socket

    def stop_sniffer(self):
        if self.am.sniffer.running:
            self.am.stop()
