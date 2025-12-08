# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

import struct
import pytest

from pymctp.layers import EndpointContext
from pymctp.layers.mctp.pldm import *
from pymctp.utils import str_to_bytes

def test_request_with_default_values():
    pkt = GetSensorReadingPacket()
    data = bytes(pkt)
    assert not pkt.fields
    assert len(data) == 0
