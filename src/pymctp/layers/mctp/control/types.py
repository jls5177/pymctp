# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from enum import IntEnum
from typing import Protocol, TypeVar, runtime_checkable

from ..types import AnyPacketType, EndpointContext


class ContrlCmdCodes(IntEnum):
    Reserved = 0x00
    SetEndpointID = 0x01
    GetEndpointID = 0x02
    GetEndpointUUID = 0x03
    GetMCTPVersionSupport = 0x04
    GetMessageTypeSupport = 0x05
    GetVendorDefinedMessageSupport = 0x06
    ResolveEndpointID = 0x07
    AllocateEndpointIDs = 0x08
    RoutingInformationUpdate = 0x09
    GetRoutingTableEntries = 0x0A
    PrepareForEndpointDiscovery = 0x0B
    EndpointDiscovery = 0x0C
    DiscoveryNotify = 0x0D
    GetNetworkID = 0x0E
    QueryHop = 0x0F
    ResolveUUID = 0x10
    QueryRateLimit = 0x11
    RequestTXRateLimit = 0x12
    UpdateRateLimit = 0x13
    QuerySupportedInterfaces = 0x14
    Unknown = 0xFF


class CompletionCodes(IntEnum):
    SUCCESS = 0
    """The Request was accepted and completed normally."""

    ERROR = 1
    """This is a generic failure message. (It should not be used
    when a more specific result code applies.)"""

    ERROR_INVALID_DATA = 2
    """The packet payload contained invalid data or an illegal
    parameter value."""

    ERROR_INVALID_LENGTH = 3
    """The message length was invalid. (The Message body
    was larger or smaller than expected for the particular
    request.)"""

    ERROR_NOT_READY = 4
    """The Receiver is in a transient state where it is not ready
    to receive the corresponding message."""

    ERROR_UNSUPPORTED_CMD = 5
    """The command field in the control type of the received
    message is unspecified or not supported on this
    endpoint. This completion code shall be returned for any
    unsupported command values received in MCTP control
    Request messages."""


CompletionCode = TypeVar("CompletionCode", CompletionCodes, int)


@runtime_checkable
class IControlMsgCanReply(Protocol):
    def make_ctrl_reply(self, ctx: EndpointContext) -> tuple[CompletionCode, AnyPacketType]:
        pass


@runtime_checkable
class IControlMsgPacket(Protocol):
    cmd_code: ContrlCmdCodes
