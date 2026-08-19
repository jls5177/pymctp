# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Endpoint socket config for the TTY/serial exerciser.

Subclassing :class:`pymctp.automaton.manager.SupersocketConfig` auto-registers
this config with core pymctp, so no change to manager.py is needed.
"""

from __future__ import annotations

import dataclasses
import pickle
from dataclasses import field

from pymctp.automaton.manager import SupersocketConfig

from .tty_serial import TTYSerialSocket


@dataclasses.dataclass()
class TTYSocketConfig(SupersocketConfig):
    type = "tty"
    tty: str
    name: str
    baudrate: int = 115200
    dump_hex: bool = True
    dump_packet: bool = False

    socket: TTYSerialSocket | None = field(
        default=None, init=False, metadata={"serialize": pickle.dumps, "deserialize": pickle.loads}
    )

    def __post_init__(self):
        self.socket = TTYSerialSocket(
            tty=self.tty,
            id_str=self.name,
            baudrate=self.baudrate,
            dump_hex=self.dump_hex,
            dump_packet=self.dump_packet,
        )

    def close_socket(self):
        self.socket.close()
