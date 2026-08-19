# SPDX-FileCopyrightText: 2026 Justin Simon <justin.simon@microsoft.com>
#
# SPDX-License-Identifier: MIT

"""Endpoint config for the NPCM8xx TIP mailbox transport.

Subclassing :class:`pymctp.automaton.manager.SupersocketConfig` auto-registers
this config under its ``type`` discriminator (``"tip-mbox-stream"``), so
``EndpointManager.from_config`` can build a TIP endpoint without any change to
core ``manager.py``. This demonstrates the pluggable config-type registry: the
Microsoft-specific config lives next to its transport, in this package.
"""

from __future__ import annotations

import dataclasses
import pickle
from dataclasses import field
from typing import Any

from pymctp.automaton.manager import SupersocketConfig

from .qemu_tip_mbox_stream import QemuTipMboxStreamSocket

TIP_MBOX_STREAM_TYPE = "tip-mbox-stream"


@dataclasses.dataclass()
class TipMboxStreamSocketConfig(SupersocketConfig):
    """TCP stream socket config for QEMU's NPCM8xx TIP mailbox device.

    Connects as a single TCP client (``host``/``port``) to a QEMU server that
    forwards the BMC's mailbox window packets. RX DATA bodies may start at
    SMBus command code ``0x0F`` or include a leading destination address byte;
    :class:`QemuTipMboxStreamSocket` validates PEC accordingly.
    """

    type = TIP_MBOX_STREAM_TYPE
    host: str
    port: int
    name: str
    dump_hex: bool = True
    dump_packet: bool = False
    bmc_addr: int = 0x10
    tip_addr: int = 0x41
    rx_window_has_addr: bool | None = None
    connect_timeout: float = 5.0

    socket: Any | None = field(
        default=None, init=False, metadata={"serialize": pickle.dumps, "deserialize": pickle.loads}
    )

    def __post_init__(self):
        self.socket = QemuTipMboxStreamSocket(
            host=self.host,
            port=self.port,
            id_str=self.name,
            dump_hex=self.dump_hex,
            dump_packet=self.dump_packet,
            bmc_addr=self.bmc_addr,
            tip_addr=self.tip_addr,
            rx_window_has_addr=self.rx_window_has_addr,
            connect_timeout=self.connect_timeout,
        )

    def close_socket(self):
        self.socket.close()
