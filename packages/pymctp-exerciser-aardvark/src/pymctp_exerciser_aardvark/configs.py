# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Endpoint socket config for the Aardvark I2C exerciser.

Subclassing :class:`pymctp.automaton.manager.SupersocketConfig` auto-registers
this config with core pymctp, so no change to manager.py is needed.
"""

from __future__ import annotations

import dataclasses
import pickle
from dataclasses import field

from mashumaro import field_options
from mashumaro.config import BaseConfig

from pymctp.automaton import EndpointSession
from pymctp.automaton.manager import SupersocketConfig
from pymctp.layers.mctp import Smbus7bitAddress

from .aardvark_i2c import AardvarkI2CSocket


def deserialize_aardvark_address(value: str | int | Smbus7bitAddress) -> Smbus7bitAddress:
    if isinstance(value, Smbus7bitAddress):
        return value
    return Smbus7bitAddress(address=int(value))


@dataclasses.dataclass()
class AardvarkConfig(SupersocketConfig):
    type = "aardvark"
    slave_addr: Smbus7bitAddress = field(metadata=field_options(alias="slave_address"))
    serial_number: str
    name: str
    dump_hex: bool = True
    dump_packet: bool = False
    enable_pullups: bool = False
    enable_target_power: bool = False
    slave_only: bool = False
    poll_period_ms: int = 10
    bitrate: int = 400

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
            enable_i2c_pullups=self.enable_pullups,
            enable_target_power=self.enable_target_power,
            poll_period_ms=self.poll_period_ms,
            slave_only=self.slave_only,
            bitrate=self.bitrate,
        )

    def create_session(self) -> EndpointSession:
        pass

    def close_socket(self):
        self.socket.close()
