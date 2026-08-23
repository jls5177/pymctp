# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for loading PLDM sensor/PDR models from Python Terminus references."""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from typing import Any

import pytest
from scapy.packet import Raw
from scapy.plist import PacketList

from pymctp.automaton.behaviors.pldm_responder import (
    GetPDRTransferFlag,
    GetPDRTransferOperation,
    NumericSensorPdr,
    PdrRepository,
    PldmSensorBehavior,
    SensorDefinition,
)
from pymctp.automaton.roles import get_behaviors_for_roles, normalize_roles
from pymctp.layers.mctp.pldm import PldmHdr, PldmHdrPacket
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import (
    GetSensorReadingDataSizeEnum,
    PldmPlatformMonitoringCmdCodes,
)
from pymctp.layers.mctp.pldm.types import CompletionCodes, PldmTypeCodes
from pymctp.layers.mctp.transport import SmbusTransport, TransportHdr
from pymctp.layers.mctp.types import EndpointContext, MsgTypes, Smbus7bitAddress
from pymctp.pldm.model import Terminus, TemperatureSensor
from pymctp.topology import DeviceSpec, EidMap, MachineSpec, dump_machine_spec, load_machine_spec


def _ctx() -> EndpointContext:
    return EndpointContext(
        physical_address=Smbus7bitAddress(0x10),
        assigned_eid=0x10,
        supported_msg_types=[MsgTypes.CTRL, MsgTypes.PLDM],
    )


def _request(cmd_code: int, payload: bytes) -> SmbusTransport:
    transport = TransportHdr(
        msg_type=MsgTypes.PLDM,
        dst=0x10,
        src=0x20,
        som=True,
        eom=True,
        to=True,
        tag=3,
    )
    pldm = PldmHdr(
        rq=True,
        instance_id=7,
        hdr_ver=0,
        pldm_type=PldmTypeCodes.PLATFORM_MONITORING,
        cmd_code=cmd_code,
    )
    pkt = SmbusTransport(
        dst_addr=Smbus7bitAddress(0x10),
        src_addr=Smbus7bitAddress(0x20),
        load=transport / (pldm / payload),
    )
    return SmbusTransport(bytes(pkt))


def _single_pldm(reply: PacketList) -> PldmHdrPacket:
    assert len(reply) == 1
    pldm = SmbusTransport(bytes(reply[0])).getlayer(PldmHdrPacket)
    assert pldm is not None
    return pldm


def _get_reply(behavior: PldmSensorBehavior, pkt: SmbusTransport) -> PacketList:
    response = behavior.handle(pkt, _ctx())
    assert response is not None
    assert response.stop_processing is True
    assert isinstance(response.reply, PacketList)
    return response.reply


def _pdr_request(record_handle: int = 0) -> bytes:
    return struct.pack("<IIBHH", record_handle, 0, int(GetPDRTransferOperation.GET_FIRST_PART), 4096, 0)


def _read_pdr(behavior: PldmSensorBehavior, record_handle: int = 0) -> tuple[int, int, int, bytes, bytes]:
    pldm = _single_pldm(_get_reply(behavior, _request(PldmPlatformMonitoringCmdCodes.GetPDR, _pdr_request(record_handle))))
    assert pldm.completion_code == CompletionCodes.SUCCESS
    data = bytes(pldm.payload.load if isinstance(pldm.payload, Raw) else pldm.payload)
    next_record_handle, next_data_transfer_handle, transfer_flag, response_count = struct.unpack_from("<IIBH", data)
    start = struct.calcsize("<IIBH")
    end = start + response_count
    return next_record_handle, next_data_transfer_handle, transfer_flag, data[start:end], data[end:]


def _write_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, source: str) -> str:
    module_path = tmp_path / f"{name}.py"
    module_path.write_text(source, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop(name, None)
    return name


def _model_source(expression: str = "MODEL") -> str:
    return f"""
from __future__ import annotations

from pymctp.pldm.model import Terminus, TemperatureSensor

MODEL = Terminus(
    eid=17,
    tid=1,
    items=[
        TemperatureSensor(name="Inlet Temp", sensor_id=0x1001),
        TemperatureSensor(name="Outlet Temp", sensor_id=0x1002),
    ],
)

def factory():
    return Terminus(eid=17, tid=1, items=[TemperatureSensor(name="Factory Temp", sensor_id=0x2001)])

bad_value = 42

def bad_factory():
    return 42

hcp = {expression}
"""


def _sensor_behavior_from_config(config: dict[str, Any]) -> PldmSensorBehavior:
    behaviors = get_behaviors_for_roles(("pldm-sensor", config["role_options"]["pldm-sensor"]))
    sensor = behaviors[-1]
    assert isinstance(sensor, PldmSensorBehavior)
    return sensor


def test_pdrs_model_module_attribute_loads_and_serves_get_pdr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = _write_module(tmp_path, monkeypatch, "attribute_model", _model_source())
    behavior = PldmSensorBehavior(pdrs_model=f"{module_name}:hcp")
    expected = Terminus(eid=17, tid=1, items=[TemperatureSensor(name="Inlet Temp", sensor_id=0x1001)]).build()

    next_handle, next_transfer, transfer_flag, record_data, crc = _read_pdr(behavior)

    assert next_handle == 1
    assert next_transfer == 0
    assert transfer_flag == GetPDRTransferFlag.START_AND_END
    assert crc == b""
    assert record_data == expected.pdr_repository.get_record(0)


def test_pdrs_model_zero_argument_callable_loads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = _write_module(tmp_path, monkeypatch, "factory_model", _model_source("factory"))
    behavior = PldmSensorBehavior(pdrs_model=f"{module_name}:hcp")
    expected = Terminus(eid=17, tid=1, items=[TemperatureSensor(name="Factory Temp", sensor_id=0x2001)]).build()

    _, _, _, record_data, _ = _read_pdr(behavior)

    assert record_data == expected.pdr_repository.get_record(0)


def test_pdrs_model_keeps_loaded_repository_and_explicit_sensors_override_per_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Python model owns PDR layout; explicit sensor values only replace matching runtime readings."""
    module_name = _write_module(tmp_path, monkeypatch, "override_model", _model_source())
    behavior = PldmSensorBehavior(
        pdrs_model=f"{module_name}:hcp",
        sensors={0x1002: SensorDefinition(sensor_id=0x1002, reading=99, data_size=GetSensorReadingDataSizeEnum.SINT32)},
    )
    expected = Terminus(eid=17, tid=1, items=[TemperatureSensor(name="Inlet Temp", sensor_id=0x1001)]).build()

    assert set(behavior.profile.sensors) == {0x1001, 0x1002}
    assert behavior.profile.sensors[0x1001].next_reading() == 0
    assert behavior.profile.sensors[0x1002].next_reading() == 99
    assert behavior.profile.pdr_repository.get_record(0) == expected.pdr_repository.get_record(0)


def test_explicit_pdr_repository_beats_pdrs_model(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module_name = _write_module(tmp_path, monkeypatch, "repository_model", _model_source())
    explicit_record = NumericSensorPdr(record_handle=9, sensor_id=9)

    behavior = PldmSensorBehavior(pdrs_model=f"{module_name}:hcp", pdr_repository=PdrRepository([explicit_record]))
    _, _, _, record_data, _ = _read_pdr(behavior)

    assert record_data == explicit_record.to_bytes()


def test_pdrs_from_and_pdrs_model_together_are_a_configuration_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two loaders have different maintenance contracts, so choosing both must not be ambiguous."""
    module_name = _write_module(tmp_path, monkeypatch, "exclusive_model", _model_source())

    with pytest.raises(ValueError, match="pdrs_from.*pdrs_model.*mutually exclusive.*<unknown>"):
        PldmSensorBehavior(pdrs_from=str(tmp_path / "unused.json"), pdrs_model=f"{module_name}:hcp")


def test_bad_pdrs_model_references_name_option_reference_and_device(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = _write_module(tmp_path, monkeypatch, "bad_model", _model_source())
    spec = MachineSpec(
        name="bad-references",
        eids=EidMap({"dev": 0x10}),
        devices=[
            DeviceSpec(
                name="dev",
                transport={"type": "fake"},
                supported_msg_types=["CTRL", "PLDM"],
                roles=["pldm-sensor"],
                role_options={"pldm-sensor": {"pdrs_model": "missing_module:hcp"}},
            )
        ],
    )
    config = spec.device("dev").to_endpoint_config(spec, spec.eids)

    with pytest.raises(ValueError, match="pdrs_model.*missing_module:hcp.*device 'dev'.*could not import module"):
        _sensor_behavior_from_config(config)

    config["role_options"]["pldm-sensor"]["pdrs_model"] = f"{module_name}:missing"
    with pytest.raises(ValueError, match=f"pdrs_model.*{module_name}:missing.*device 'dev'.*no attribute"):
        _sensor_behavior_from_config(config)

    config["role_options"]["pldm-sensor"]["pdrs_model"] = f"{module_name}:bad_value"
    with pytest.raises(ValueError, match=f"pdrs_model.*{module_name}:bad_value.*device 'dev'.*Terminus.*got int"):
        _sensor_behavior_from_config(config)

    config["role_options"]["pldm-sensor"]["pdrs_model"] = f"{module_name}:bad_factory"
    with pytest.raises(ValueError, match=f"pdrs_model.*{module_name}:bad_factory.*device 'dev'.*Terminus.*got int"):
        _sensor_behavior_from_config(config)


def test_pdrs_model_round_trip_is_verbatim_and_not_path_resolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unlike pdrs_from, pdrs_model is an import reference and must not follow cwd-dependent path rules."""
    module_name = _write_module(tmp_path, monkeypatch, "roundtrip_model", _model_source())
    spec = MachineSpec(
        name="roundtrip",
        eids=EidMap({"dev": 0x10}),
        devices=[
            DeviceSpec(
                name="dev",
                transport={"type": "fake"},
                supported_msg_types=["CTRL", "PLDM"],
                roles=["pldm-sensor"],
                role_options={"pldm-sensor": {"pdrs_model": f"{module_name}:hcp"}},
            )
        ],
    )
    machine_dir = tmp_path / "machine"
    other_dir = tmp_path / "other"
    machine_dir.mkdir()
    other_dir.mkdir()
    spec_path = machine_dir / "machine.json"
    roundtrip_path = machine_dir / "roundtrip.json"
    dump_machine_spec(spec, spec_path)

    monkeypatch.chdir(other_dir)
    loaded = load_machine_spec(spec_path)
    config = loaded.device("dev").to_endpoint_config(loaded, loaded.eids)
    behavior = _sensor_behavior_from_config(config)
    dump_machine_spec(loaded, roundtrip_path)
    reloaded = load_machine_spec(roundtrip_path)

    assert config["role_options"]["pldm-sensor"]["pdrs_model"] == f"{module_name}:hcp"
    assert json.loads(roundtrip_path.read_text(encoding="utf-8"))["devices"][0]["role_options"]["pldm-sensor"][
        "pdrs_model"
    ] == f"{module_name}:hcp"
    assert reloaded.device("dev").role_options["pldm-sensor"]["pdrs_model"] == f"{module_name}:hcp"
    assert behavior.profile.pdr_repository.get_record(0) is not None


def test_fru_is_advertised_only_when_the_model_has_a_table(tmp_path: Path, monkeypatch) -> None:
    """The advertisement has to track the actual capability, in both directions.

    Claiming Type 4 with no table makes a requester reject the response and drop
    the terminus; staying silent about a table we do have means it is never
    asked for. Both halves are asserted here because each has bitten in
    production.
    """
    module = tmp_path / "fru_models.py"
    module.write_text(
        "from pymctp.pldm.model import Terminus, FruRecordItem, FruField, TemperatureSensor\n"
        "bare = Terminus(eid=9, tid=1, items=[TemperatureSensor(name='T', sensor_id=1)])\n"
        "stocked = Terminus(eid=9, tid=1, items=[TemperatureSensor(name='T', sensor_id=1)])\n"
        "stocked.add_fru(FruRecordItem(name='board', record_set_identifier=1, record_type=1,\n"
        "    fields=[FruField(field_type=1, value=b'PART-1')]))\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))

    for attribute, expect_fru in (("bare", False), ("stocked", True)):
        behaviors = {
            behavior.name: behavior
            for behavior in get_behaviors_for_roles(
                *normalize_roles(["pldm-sensor"], {"pldm-sensor": {"pdrs_model": f"fru_models:{attribute}"}})
            )
        }
        advertised = int(PldmTypeCodes.FRU) in behaviors["pldm-base"].profile.supported_types
        served = bool(behaviors["pldm-sensor"].profile.fru_repository.records)

        assert advertised == expect_fru, attribute
        assert served == expect_fru, attribute
        assert advertised == served, "advertisement and capability must not diverge"
