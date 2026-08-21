# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for loading PLDM sensor/PDR models from JSON artifacts."""

from __future__ import annotations

import json
import struct
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
from pymctp.automaton.roles import get_behaviors_for_roles
from pymctp.layers.mctp.pldm import GetSensorReadingPacket, PldmHdr, PldmHdrPacket
from pymctp.layers.mctp.pldm.pdr import decode_pdr, pdr_to_dict
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import (
    GetSensorReadingDataSizeEnum,
    PldmPlatformMonitoringCmdCodes,
)
from pymctp.layers.mctp.pldm.types import CompletionCodes, PldmTypeCodes
from pymctp.layers.mctp.transport import SmbusTransport, TransportHdr
from pymctp.layers.mctp.types import EndpointContext, MsgTypes, Smbus7bitAddress
from pymctp.topology import DeviceSpec, EidMap, MachineSpec, dump_machine_spec, load_machine_spec


def _ctx() -> EndpointContext:
    return EndpointContext(
        physical_address=Smbus7bitAddress(0x10),
        assigned_eid=0x10,
        supported_msg_types=[MsgTypes.CTRL, MsgTypes.PLDM],
    )


def _request(cmd_code: int, payload=None):
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
        load=transport / (pldm / payload if payload is not None else pldm),
    )
    return SmbusTransport(bytes(pkt))


def _single_pldm(reply: PacketList) -> PldmHdrPacket:
    assert len(reply) == 1
    pldm = SmbusTransport(bytes(reply[0])).getlayer(PldmHdrPacket)
    assert pldm is not None
    return pldm


def _get_reply(behavior: PldmSensorBehavior, pkt, ctx: EndpointContext) -> PacketList:
    response = behavior.handle(pkt, ctx)
    assert response is not None
    assert response.stop_processing is True
    assert isinstance(response.reply, PacketList)
    return response.reply


def _pdr_request(record_handle: int = 0) -> bytes:
    return struct.pack("<IIBHH", record_handle, 0, int(GetPDRTransferOperation.GET_FIRST_PART), 4096, 0)


def _parse_pdr_response(pldm: PldmHdrPacket) -> tuple[int, int, int, bytes, bytes]:
    data = bytes(pldm.payload.load if isinstance(pldm.payload, Raw) else pldm.payload)
    next_record_handle, next_data_transfer_handle, transfer_flag, response_count = struct.unpack_from("<IIBH", data)
    start = struct.calcsize("<IIBH")
    end = start + response_count
    return next_record_handle, next_data_transfer_handle, transfer_flag, data[start:end], data[end:]


def _read_pdr(behavior: PldmSensorBehavior, record_handle: int = 0) -> tuple[int, int, int, bytes, bytes]:
    pldm = _single_pldm(
        _get_reply(
            behavior,
            _request(PldmPlatformMonitoringCmdCodes.GetPDR, _pdr_request(record_handle)),
            _ctx(),
        )
    )
    assert pldm.completion_code == CompletionCodes.SUCCESS
    return _parse_pdr_response(pldm)


def _write_artifact(
    path: Path,
    records: list[Any],
    sensors: dict[str, dict[str, Any]] | None = None,
    repository_info: dict[str, Any] | None = None,
) -> None:
    path.write_text(
        json.dumps(
            {
                "eid": 17,
                "tid": 1,
                "source": "unit-test",
                "repository_info": repository_info,
                "pdrs": [pdr_to_dict(record) for record in records],
                "sensors": sensors or {},
                "warnings": [],
            }
        ),
        encoding="utf-8",
    )


def test_pdrs_from_loads_repository_in_order_and_get_pdr_returns_exact_bytes(tmp_path: Path) -> None:
    first = NumericSensorPdr(record_handle=0x20, sensor_id=0x1001, data_size=GetSensorReadingDataSizeEnum.UINT16)
    second = NumericSensorPdr(record_handle=0x10, sensor_id=0x1002, data_size=GetSensorReadingDataSizeEnum.UINT8)
    artifact = tmp_path / "model.json"
    _write_artifact(artifact, [first, second])

    behavior = PldmSensorBehavior(pdrs_from=str(artifact))
    next_handle, next_transfer, transfer_flag, record_data, crc = _read_pdr(behavior)
    final_next, _, final_flag, final_record, _ = _read_pdr(behavior, next_handle)

    assert next_handle == second.record_handle
    assert next_transfer == 0
    assert transfer_flag == GetPDRTransferFlag.START_AND_END
    assert crc == b""
    assert record_data == first.to_bytes()
    assert final_next == 0
    assert final_flag == GetPDRTransferFlag.START_AND_END
    assert final_record == second.to_bytes()


def test_pdrs_from_loads_sensor_simulation_for_get_sensor_reading(tmp_path: Path) -> None:
    artifact = tmp_path / "model.json"
    _write_artifact(
        artifact,
        [NumericSensorPdr(record_handle=1, sensor_id=4097, data_size=GetSensorReadingDataSizeEnum.UINT16)],
        {
            "4097": {
                "data_size": int(GetSensorReadingDataSizeEnum.UINT16),
                "simulation": {
                    "minimum": 30,
                    "maximum": 47,
                    "step": 1,
                    "warning_high": 85,
                    "warning_low": None,
                    "critical_high": 95,
                    "critical_low": None,
                },
            }
        },
    )
    behavior = PldmSensorBehavior(pdrs_from=str(artifact))

    pldm = _single_pldm(
        _get_reply(
            behavior,
            _request(
                PldmPlatformMonitoringCmdCodes.GetSensorReading,
                GetSensorReadingPacket(sensorID=4097, rearmEventState=0),
            ),
            _ctx(),
        )
    )
    reading = pldm.getlayer(GetSensorReadingPacket)

    assert pldm.completion_code == CompletionCodes.SUCCESS
    assert reading.sensorDataSize == GetSensorReadingDataSizeEnum.UINT16
    assert 30 <= reading.presentReading16 <= 47


def test_explicit_sensors_override_only_matching_ids_and_keep_loaded_pdrs(tmp_path: Path) -> None:
    """Passing sensors normally regenerates PDRs, but pdrs_from must keep the captured repository."""
    artifact = tmp_path / "model.json"
    captured = NumericSensorPdr(record_handle=0x44, sensor_id=1, data_size=GetSensorReadingDataSizeEnum.UINT8)
    _write_artifact(
        artifact,
        [captured],
        {
            "1": {"data_size": int(GetSensorReadingDataSizeEnum.UINT8), "simulation": {"minimum": 10, "maximum": 12}},
            "2": {"data_size": int(GetSensorReadingDataSizeEnum.UINT8), "simulation": {"minimum": 20, "maximum": 22}},
        },
    )

    behavior = PldmSensorBehavior(
        pdrs_from=str(artifact),
        sensors={2: SensorDefinition(sensor_id=2, reading=99, data_size=GetSensorReadingDataSizeEnum.UINT8)},
    )

    assert set(behavior.profile.sensors) == {1, 2}
    assert behavior.profile.sensors[1].simulation is not None
    assert behavior.profile.sensors[2].next_reading() == 99
    assert behavior.profile.pdr_repository.get_record(0) == captured.to_bytes()


def test_explicit_pdr_repository_beats_file(tmp_path: Path) -> None:
    artifact = tmp_path / "model.json"
    file_record = NumericSensorPdr(record_handle=1, sensor_id=1)
    explicit_record = NumericSensorPdr(record_handle=9, sensor_id=9)
    _write_artifact(artifact, [file_record])

    behavior = PldmSensorBehavior(pdrs_from=str(artifact), pdr_repository=PdrRepository([explicit_record]))
    _, _, _, record_data, _ = _read_pdr(behavior)

    assert record_data == explicit_record.to_bytes()


def test_repository_info_from_artifact_is_reported(tmp_path: Path) -> None:
    artifact = tmp_path / "model.json"
    _write_artifact(
        artifact,
        [NumericSensorPdr(record_handle=1, sensor_id=1)],
        repository_info={
            "record_count": 25,
            "repository_size": 1980,
            "largest_record_size": 105,
            "repository_state": 3,
            "data_transfer_handle_timeout": 7,
        },
    )
    behavior = PldmSensorBehavior(pdrs_from=str(artifact))

    pldm = _single_pldm(_get_reply(behavior, _request(PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo), _ctx()))
    data = bytes(pldm.payload.load if isinstance(pldm.payload, Raw) else pldm.payload)
    record_count, repository_size, largest_record_size, timeout = struct.unpack_from("<IIIB", data, 27)

    assert pldm.completion_code == CompletionCodes.SUCCESS
    assert data[0] == 3
    assert (record_count, repository_size, largest_record_size, timeout) == (25, 1980, 105, 7)


def test_opaque_pdr_survives_load_and_get_pdr_byte_for_byte(tmp_path: Path) -> None:
    body = b"\xde\xad\xbe\xef"
    raw = struct.pack("<IBBHH", 0xABC, 1, 0x99, 3, len(body)) + body
    artifact = tmp_path / "opaque.json"
    _write_artifact(artifact, [decode_pdr(raw)])

    behavior = PldmSensorBehavior(pdrs_from=str(artifact))
    _, _, _, record_data, _ = _read_pdr(behavior)

    assert record_data == raw


def test_relative_pdrs_from_resolves_against_machine_spec_and_round_trips(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Relative model paths should survive dumps and not depend on the process cwd."""
    machine_dir = tmp_path / "machine"
    machine_dir.mkdir()
    artifact = machine_dir / "model.json"
    record = NumericSensorPdr(record_handle=0x51, sensor_id=0x51)
    _write_artifact(artifact, [record])
    spec = MachineSpec(
        name="relative",
        eids=EidMap({"dev": 0x10}),
        devices=[
            DeviceSpec(
                name="dev",
                transport={"type": "fake"},
                supported_msg_types=["CTRL", "PLDM"],
                roles=["pldm-sensor"],
                role_options={"pldm-sensor": {"pdrs_from": "model.json"}},
            )
        ],
    )
    spec_path = machine_dir / "machine.json"
    roundtrip_path = machine_dir / "roundtrip.json"
    dump_machine_spec(spec, spec_path)

    monkeypatch.chdir(Path(__file__).parent)
    loaded = load_machine_spec(spec_path)
    raw_config = loaded.device("dev").to_endpoint_config(loaded, loaded.eids)
    behavior = _sensor_behavior_from_config(raw_config)
    _, _, _, record_data, _ = _read_pdr(behavior)
    dump_machine_spec(loaded, roundtrip_path)
    reloaded = load_machine_spec(roundtrip_path)
    roundtrip_config = reloaded.device("dev").to_endpoint_config(reloaded, reloaded.eids)

    assert record_data == record.to_bytes()
    assert json.loads(roundtrip_path.read_text(encoding="utf-8"))["devices"][0]["role_options"]["pldm-sensor"][
        "pdrs_from"
    ] == "model.json"
    assert _sensor_behavior_from_config(roundtrip_config).profile.pdr_repository.get_record(0) == record.to_bytes()


def test_absolute_pdrs_from_path_is_used_as_is(tmp_path: Path) -> None:
    artifact = tmp_path / "absolute.json"
    record = NumericSensorPdr(record_handle=0x61, sensor_id=0x61)
    _write_artifact(artifact, [record])
    spec = MachineSpec(
        name="absolute",
        eids=EidMap({"dev": 0x10}),
        devices=[
            DeviceSpec(
                name="dev",
                transport={"type": "fake"},
                roles=["pldm-sensor"],
                role_options={"pldm-sensor": {"pdrs_from": str(artifact.resolve())}},
            )
        ],
    )

    raw_config = spec.device("dev").to_endpoint_config(spec, spec.eids)
    behavior = _sensor_behavior_from_config(raw_config)

    assert raw_config["role_options"]["pldm-sensor"]["pdrs_from"] == str(artifact.resolve())
    assert behavior.profile.pdr_repository.get_record(0) == record.to_bytes()


def test_missing_relative_pdrs_from_names_option_path_and_device(tmp_path: Path) -> None:
    spec_path = tmp_path / "machine.json"
    spec_path.write_text(
        json.dumps(
            {
                "name": "missing",
                "eids": {"eids": {"dev": 16}, "assignments": []},
                "devices": [
                    {
                        "name": "dev",
                        "transport": {"type": "fake"},
                        "roles": ["pldm-sensor"],
                        "role_options": {"pldm-sensor": {"pdrs_from": "missing.json"}},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    spec = load_machine_spec(spec_path)

    with pytest.raises(ValueError, match="dev.*pdrs_from.*missing\\.json"):
        spec.device("dev").to_endpoint_config(spec, spec.eids)


def test_malformed_json_reports_pdrs_from_path(tmp_path: Path) -> None:
    artifact = tmp_path / "bad.json"
    artifact.write_text("{", encoding="utf-8")

    with pytest.raises(ValueError, match="pdrs_from.*bad\\.json.*malformed JSON"):
        PldmSensorBehavior(pdrs_from=str(artifact))


def test_unknown_pdr_type_without_opaque_data_reports_entry_index(tmp_path: Path) -> None:
    artifact = tmp_path / "bad-pdr.json"
    artifact.write_text(
        json.dumps({"pdrs": [{"pdr_type": 250, "record_handle": 1}], "sensors": {}, "repository_info": None}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="pdrs\\[0\\].*unknown pdr_type 250"):
        PldmSensorBehavior(pdrs_from=str(artifact))


def _sensor_behavior_from_config(config: dict[str, Any]) -> PldmSensorBehavior:
    behaviors = get_behaviors_for_roles(("pldm-sensor", config["role_options"]["pldm-sensor"]))
    sensor = behaviors[-1]
    assert isinstance(sensor, PldmSensorBehavior)
    return sensor
