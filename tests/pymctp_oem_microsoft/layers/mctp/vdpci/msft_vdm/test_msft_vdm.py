# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from pymctp.layers.mctp.transport import TransportHdrPacket
from pymctp.layers.mctp.vdpci.vdpci import VdPciHdrPacket

from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.msft_vdm import MsftVdmProtocolPacket
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm.base import (
    CmdSetSupportRequestPacket,
    CmdSetSupportResponsePacket,
)

# Ensure bind_layers are registered
from pymctp_oem_microsoft.layers.mctp.vdpci.msft_vdm import base, bmc, rot  # noqa: F401


def _parse(hex_str: str) -> TransportHdrPacket:
    raw = bytes.fromhex(hex_str.replace(" ", ""))
    return TransportHdrPacket(raw)


class TestCmdSetSupportWireData:
    """Tests using actual captured wire data for CMD_SET_SUPPORT."""

    def test_request_dissection(self):
        # 0140 0ac8 7e14 1480 ff00 0000 0100
        parsed = _parse("01400ac87e14148 0ff00000001 00")
        assert parsed.haslayer(VdPciHdrPacket)
        assert parsed.haslayer(MsftVdmProtocolPacket)
        assert parsed.haslayer(CmdSetSupportRequestPacket)

        vdpci = parsed.getlayer(VdPciHdrPacket)
        assert vdpci.vendor_id == 0x1414
        assert vdpci.rq == 1
        assert vdpci.vdm_cmd_code == 0xFF

        vdm = parsed.getlayer(MsftVdmProtocolPacket)
        assert vdm.cmd_set == 0  # BASE
        assert vdm.cmd == 1  # CMD_SET_SUPPORT
        assert not hasattr(vdm, "completion_code") or vdm.completion_code is None

        req = parsed.getlayer(CmdSetSupportRequestPacket)
        assert req.list_entry_start == 0

    def test_response_dissection(self):
        # 010a 40c0 7e14 1480 ff00 0000 0100 ff04 0001 0000 0201 0000 0301 0000 0501 0000
        parsed = _parse(
            "010a40c07e14148 0ff00000001 00ff04 0001 0000 0201 0000 0301 0000 0501 0000"
        )
        assert parsed.haslayer(VdPciHdrPacket)
        assert parsed.haslayer(MsftVdmProtocolPacket)
        assert parsed.haslayer(CmdSetSupportResponsePacket)

        vdm = parsed.getlayer(MsftVdmProtocolPacket)
        assert vdm.cmd_set == 0  # BASE
        assert vdm.cmd == 1  # CMD_SET_SUPPORT
        assert vdm.completion_code == 0  # SUCCESS

        rsp = parsed.getlayer(CmdSetSupportResponsePacket)
        assert rsp.next_list_entry == 0xFF
        assert rsp.entry_count == 4
        assert len(rsp.entries) == 4

        # Verify each entry
        entries = rsp.entries
        assert entries[0].cmd_set_id == 0  # BASE
        assert entries[0].version_count == 1
        assert entries[0].versions[0].major == 0
        assert entries[0].versions[0].minor == 0

        assert entries[1].cmd_set_id == 2  # ROT
        assert entries[2].cmd_set_id == 3
        assert entries[3].cmd_set_id == 5

    def test_response_summary(self):
        parsed = _parse(
            "010a40c07e14148 0ff00000001 00ff04 0001 0000 0201 0000 0301 0000 0501 0000"
        )
        rsp = parsed.getlayer(CmdSetSupportResponsePacket)
        summary = rsp.mysummary()[0]
        assert "next=END" in summary
        assert "0(BASE)(v=[0.0])" in summary
        assert "2(ROT)(v=[0.0])" in summary

    def test_response_has_no_trailing_raw(self):
        """Ensure all bytes are consumed — no Raw layer after the response."""
        parsed = _parse(
            "010a40c07e14148 0ff00000001 00ff04 0001 0000 0201 0000 0301 0000 0501 0000"
        )
        from scapy.packet import Raw
        rsp = parsed.getlayer(CmdSetSupportResponsePacket)
        assert not rsp.haslayer(Raw)
