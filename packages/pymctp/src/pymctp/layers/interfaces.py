# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from typing import Protocol, TypeVar, runtime_checkable

from scapy.packet import Packet
from scapy.plist import PacketList

AnyPacketType = TypeVar("AnyPacketType", Packet, PacketList, None)


@runtime_checkable
class ICanSetMySummaryClasses(Protocol):
    def set_mysummary_classes(self, classes):
        pass


@runtime_checkable
class ICanVerifyIfRequest(Protocol):
    def is_request(self, check_payload: bool = True) -> bool:
        pass
