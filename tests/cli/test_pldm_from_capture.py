# SPDX-FileCopyrightText: 2026 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import struct
from collections.abc import Iterable
from pathlib import Path

import pytest
from click.testing import CliRunner
from scapy.compat import raw
from scapy.packet import Raw

from pymctp.automaton.behaviors.pldm_responder import NumericSensorPdr, SensorSimulation
from pymctp.cli.main import cli
from pymctp.layers.mctp.pldm import PldmHdr
from pymctp.layers.mctp.pldm.pdr import PDR_TYPE_NUMERIC_SENSOR, PDR_TYPE_SENSOR_AUXILIARY_NAMES
from pymctp.layers.mctp.pldm.pdr import PdrNameString, SensorAuxiliaryNamesEntry, SensorAuxiliaryNamesPdr
from pymctp.layers.mctp.pldm.type_2_platform_monitoring import (
    GetSensorReadingDataSizeEnum,
    PldmPlatformMonitoringCmdCodes,
)
from pymctp.layers.mctp.pldm.types import CompletionCodes, PldmControlCmdCodes, PldmTypeCodes
from pymctp.layers.mctp.transport import TransportHdr
from pymctp.layers.mctp.types import MsgTypes


REQUESTER_EID = 0x20
TERMINUS_EID = 0x11
SECOND_TERMINUS_EID = 0x12
TAG = 3
SENSOR_WITH_PDR = 0x1001
SENSOR_WITHOUT_PDR = 0x1002


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _write_capture(path: Path, packets: Iterable[object]) -> None:
    lines = [f"12:00:00.000000 0x0000: {raw(packet).hex()}\n" for packet in packets]
    path.write_text("".join(lines), encoding="utf-8")


def _mctp_packet(
    *,
    src: int,
    dst: int,
    to: bool,
    payload: bytes,
    tag: int = TAG,
):
    return TransportHdr(
        msg_type=MsgTypes.PLDM,
        dst=dst,
        src=src,
        som=True,
        eom=True,
        to=to,
        tag=tag,
    ) / Raw(payload)


def _pldm_bytes(
    *,
    rq: bool,
    pldm_type: int,
    cmd_code: int,
    instance_id: int,
    completion_code: int = CompletionCodes.SUCCESS,
    payload: bytes = b"",
) -> bytes:
    pldm = PldmHdr(
        rq=rq,
        instance_id=instance_id,
        pldm_type=pldm_type,
        cmd_code=cmd_code,
        completion_code=None if rq else completion_code,
    )
    if payload:
        pldm /= Raw(payload)
    return raw(pldm)


def _request(
    payload: bytes,
    *,
    dst: int = TERMINUS_EID,
    pldm_type: int = PldmTypeCodes.PLATFORM_MONITORING,
    cmd_code: int = PldmPlatformMonitoringCmdCodes.GetPDR,
    instance_id: int = 1,
):
    return _mctp_packet(
        src=REQUESTER_EID,
        dst=dst,
        to=True,
        payload=_pldm_bytes(
            rq=True,
            pldm_type=pldm_type,
            cmd_code=cmd_code,
            instance_id=instance_id,
            payload=payload,
        ),
    )


def _response(
    payload: bytes,
    *,
    src: int = TERMINUS_EID,
    pldm_type: int = PldmTypeCodes.PLATFORM_MONITORING,
    cmd_code: int = PldmPlatformMonitoringCmdCodes.GetPDR,
    instance_id: int = 1,
):
    return _mctp_packet(
        src=src,
        dst=REQUESTER_EID,
        to=False,
        payload=_pldm_bytes(
            rq=False,
            pldm_type=pldm_type,
            cmd_code=cmd_code,
            instance_id=instance_id,
            payload=payload,
        ),
    )


def _get_tid_exchange(*, tid: int = 1, instance_id: int = 1, eid: int = TERMINUS_EID) -> list[object]:
    return [
        _request(
            b"",
            dst=eid,
            pldm_type=PldmTypeCodes.CONTROL,
            cmd_code=PldmControlCmdCodes.GetTID,
            instance_id=instance_id,
        ),
        _response(
            bytes([tid]),
            src=eid,
            pldm_type=PldmTypeCodes.CONTROL,
            cmd_code=PldmControlCmdCodes.GetTID,
            instance_id=instance_id,
        ),
    ]


def _repository_info_exchange(
    *,
    record_count: int,
    repository_size: int = 128,
    largest_record_size: int = 64,
    instance_id: int = 2,
    eid: int = TERMINUS_EID,
) -> list[object]:
    response = (
        bytes([0])
        + bytes(range(13))
        + bytes(range(13, 26))
        + struct.pack("<IIIB", record_count, repository_size, largest_record_size, 0)
    )
    return [
        _request(
            b"",
            dst=eid,
            cmd_code=PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo,
            instance_id=instance_id,
        ),
        _response(
            response,
            src=eid,
            cmd_code=PldmPlatformMonitoringCmdCodes.GetPDRRepositoryInfo,
            instance_id=instance_id,
        ),
    ]


def _get_pdr_exchange(record: bytes, *, record_handle: int, instance_id: int, eid: int = TERMINUS_EID) -> list[object]:
    request = struct.pack("<IIBHH", record_handle, 0, 0, 0xFFFF, 0)
    response = struct.pack("<IIBH", 0, 0, 5, len(record)) + record
    return [
        _request(request, dst=eid, cmd_code=PldmPlatformMonitoringCmdCodes.GetPDR, instance_id=instance_id),
        _response(response, src=eid, cmd_code=PldmPlatformMonitoringCmdCodes.GetPDR, instance_id=instance_id),
    ]


def _sensor_reading_exchange(
    sensor_id: int,
    reading: int,
    *,
    data_size: GetSensorReadingDataSizeEnum = GetSensorReadingDataSizeEnum.UINT16,
    instance_id: int,
    eid: int = TERMINUS_EID,
) -> list[object]:
    formats = {
        GetSensorReadingDataSizeEnum.UINT8: "<B",
        GetSensorReadingDataSizeEnum.SINT8: "<b",
        GetSensorReadingDataSizeEnum.UINT16: "<H",
        GetSensorReadingDataSizeEnum.SINT16: "<h",
        GetSensorReadingDataSizeEnum.UINT32: "<I",
        GetSensorReadingDataSizeEnum.SINT32: "<i",
    }
    request = struct.pack("<HB", sensor_id, 0)
    response = bytes([int(data_size), 0, 0, 1, 1, 1]) + struct.pack(formats[data_size], reading)
    return [
        _request(
            request,
            dst=eid,
            cmd_code=PldmPlatformMonitoringCmdCodes.GetSensorReading,
            instance_id=instance_id,
        ),
        _response(
            response,
            src=eid,
            cmd_code=PldmPlatformMonitoringCmdCodes.GetSensorReading,
            instance_id=instance_id,
        ),
    ]


def _synthetic_packets() -> list[object]:
    numeric = NumericSensorPdr(
        record_handle=1,
        sensor_id=SENSOR_WITH_PDR,
        data_size=GetSensorReadingDataSizeEnum.UINT16,
        warning_high=85,
        critical_high=95,
    ).to_bytes()
    name = SensorAuxiliaryNamesPdr(
        record_handle=2,
        pldm_terminus_handle=0,
        sensor_id=SENSOR_WITH_PDR,
        sensors=[SensorAuxiliaryNamesEntry(names=[PdrNameString(language_tag="en", name="TEST_SENSOR")])],
    ).to_bytes()
    return [
        *_get_tid_exchange(),
        *_repository_info_exchange(
            record_count=2,
            repository_size=len(numeric) + len(name),
            largest_record_size=max(len(numeric), len(name)),
        ),
        *_get_pdr_exchange(numeric, record_handle=1, instance_id=3),
        *_get_pdr_exchange(name, record_handle=2, instance_id=4),
        *_sensor_reading_exchange(SENSOR_WITH_PDR, 42, instance_id=5),
        *_sensor_reading_exchange(SENSOR_WITH_PDR, 42, instance_id=6),
        *_sensor_reading_exchange(SENSOR_WITHOUT_PDR, 7, instance_id=7),
    ]


def _load_artifact(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_end_to_end_writes_artifact_with_expected_schema(runner: CliRunner, tmp_path: Path) -> None:
    capture = tmp_path / "synthetic.tcpdump.log"
    output_dir = tmp_path / "out"
    _write_capture(capture, _synthetic_packets())

    result = runner.invoke(cli, ["pldm-from-capture", str(capture), "--output", str(output_dir), "--date", "2026-01-02"])

    assert result.exit_code == 0, result.output
    artifact = _load_artifact(output_dir / f"pldm-terminus-{TERMINUS_EID}.json")
    assert list(artifact) == ["eid", "tid", "source", "repository_info", "pdrs", "sensors", "warnings"]
    assert artifact["eid"] == TERMINUS_EID
    assert artifact["tid"] == 1
    assert artifact["source"] == capture.name
    assert set(artifact["repository_info"]) == {
        "record_count",
        "repository_size",
        "largest_record_size",
        "repository_state",
        "data_transfer_handle_timeout",
    }
    assert [pdr["pdr_type"] for pdr in artifact["pdrs"]] == [PDR_TYPE_NUMERIC_SENSOR, PDR_TYPE_SENSOR_AUXILIARY_NAMES]
    assert set(artifact["sensors"]) == {str(SENSOR_WITH_PDR), str(SENSOR_WITHOUT_PDR)}
    assert "TEST_SENSOR" in result.output


def test_sensor_simulations_construct_sensor_simulation(runner: CliRunner, tmp_path: Path) -> None:
    capture = tmp_path / "synthetic.tcpdump.log"
    output_dir = tmp_path / "out"
    _write_capture(capture, _synthetic_packets())

    result = runner.invoke(cli, ["pldm-from-capture", str(capture), "--output", str(output_dir), "--date", "2026-01-02"])

    assert result.exit_code == 0, result.output
    artifact = _load_artifact(output_dir / f"pldm-terminus-{TERMINUS_EID}.json")
    for sensor in artifact["sensors"].values():
        SensorSimulation(**sensor["simulation"])


def test_thresholds_are_lifted_from_numeric_sensor_pdr_when_present(runner: CliRunner, tmp_path: Path) -> None:
    capture = tmp_path / "synthetic.tcpdump.log"
    output_dir = tmp_path / "out"
    _write_capture(capture, _synthetic_packets())

    result = runner.invoke(cli, ["pldm-from-capture", str(capture), "--output", str(output_dir), "--date", "2026-01-02"])

    assert result.exit_code == 0, result.output
    sensors = _load_artifact(output_dir / f"pldm-terminus-{TERMINUS_EID}.json")["sensors"]
    assert sensors[str(SENSOR_WITH_PDR)]["simulation"] == {
        "minimum": 39,
        "maximum": 45,
        "step": 1,
        "warning_high": 85,
        "warning_low": None,
        "critical_high": 95,
        "critical_low": None,
    }
    assert sensors[str(SENSOR_WITHOUT_PDR)]["simulation"]["warning_high"] is None
    assert sensors[str(SENSOR_WITHOUT_PDR)]["simulation"]["critical_high"] is None


def test_all_identical_readings_are_widened_to_avoid_constant_sensors(runner: CliRunner, tmp_path: Path) -> None:
    """Short captures often see one repeated value; the generated model should still exercise state changes."""
    capture = tmp_path / "synthetic.tcpdump.log"
    output_dir = tmp_path / "out"
    _write_capture(capture, _synthetic_packets())

    result = runner.invoke(cli, ["pldm-from-capture", str(capture), "--output", str(output_dir), "--date", "2026-01-02"])

    assert result.exit_code == 0, result.output
    simulation = _load_artifact(output_dir / f"pldm-terminus-{TERMINUS_EID}.json")["sensors"][str(SENSOR_WITH_PDR)][
        "simulation"
    ]
    assert simulation["minimum"] != simulation["maximum"]


def test_two_termini_write_two_files_and_eid_filters_to_one(runner: CliRunner, tmp_path: Path) -> None:
    capture = tmp_path / "two-termini.tcpdump.log"
    output_dir = tmp_path / "out"
    filtered_dir = tmp_path / "filtered"
    packets = [
        *_get_pdr_exchange(b"first", record_handle=1, instance_id=1, eid=TERMINUS_EID),
        *_get_pdr_exchange(b"second", record_handle=1, instance_id=2, eid=SECOND_TERMINUS_EID),
    ]
    _write_capture(capture, packets)

    result = runner.invoke(cli, ["pldm-from-capture", str(capture), "--output", str(output_dir), "--date", "2026-01-02"])
    filtered = runner.invoke(
        cli,
        [
            "pldm-from-capture",
            str(capture),
            "--output",
            str(filtered_dir),
            "--eid",
            str(SECOND_TERMINUS_EID),
            "--date",
            "2026-01-02",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (output_dir / f"pldm-terminus-{TERMINUS_EID}.json").exists()
    assert (output_dir / f"pldm-terminus-{SECOND_TERMINUS_EID}.json").exists()
    assert filtered.exit_code == 0, filtered.output
    assert not (filtered_dir / f"pldm-terminus-{TERMINUS_EID}.json").exists()
    assert (filtered_dir / f"pldm-terminus-{SECOND_TERMINUS_EID}.json").exists()


def test_record_count_mismatch_warning_appears_in_output(runner: CliRunner, tmp_path: Path) -> None:
    capture = tmp_path / "mismatch.tcpdump.log"
    output_dir = tmp_path / "out"
    pdr = NumericSensorPdr(record_handle=1, sensor_id=SENSOR_WITH_PDR).to_bytes()
    _write_capture(
        capture,
        [
            *_repository_info_exchange(record_count=2),
            *_get_pdr_exchange(pdr, record_handle=1, instance_id=3),
        ],
    )

    result = runner.invoke(cli, ["pldm-from-capture", str(capture), "--output", str(output_dir), "--date", "2026-01-02"])

    assert result.exit_code == 0, result.output
    assert "WARNING: recovered 1 of 2 PDR records; capture may be truncated" in result.output


def test_no_pldm_traffic_exits_nonzero(runner: CliRunner, tmp_path: Path) -> None:
    capture = tmp_path / "no-pldm.tcpdump.log"
    output_dir = tmp_path / "out"
    packet = TransportHdr(msg_type=MsgTypes.CTRL, dst=TERMINUS_EID, src=REQUESTER_EID, som=True, eom=True) / Raw(b"\x00")
    _write_capture(capture, [packet])

    result = runner.invoke(cli, ["pldm-from-capture", str(capture), "--output", str(output_dir), "--date", "2026-01-02"])

    assert result.exit_code != 0
    assert "no PLDM terminus found" in result.output


def test_existing_output_file_requires_force(runner: CliRunner, tmp_path: Path) -> None:
    capture = tmp_path / "synthetic.tcpdump.log"
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    artifact = output_dir / f"pldm-terminus-{TERMINUS_EID}.json"
    artifact.write_text("do not replace", encoding="utf-8")
    _write_capture(capture, _synthetic_packets())

    refused = runner.invoke(cli, ["pldm-from-capture", str(capture), "--output", str(output_dir), "--date", "2026-01-02"])

    assert refused.exit_code != 0
    assert "refusing to overwrite" in refused.output
    assert artifact.read_text(encoding="utf-8") == "do not replace"

    overwritten = runner.invoke(
        cli,
        ["pldm-from-capture", str(capture), "--output", str(output_dir), "--date", "2026-01-02", "--force"],
    )

    assert overwritten.exit_code == 0, overwritten.output
    assert _load_artifact(artifact)["eid"] == TERMINUS_EID


def test_artifact_round_trips_through_json_unchanged(runner: CliRunner, tmp_path: Path) -> None:
    capture = tmp_path / "synthetic.tcpdump.log"
    output_dir = tmp_path / "out"
    _write_capture(capture, _synthetic_packets())

    result = runner.invoke(cli, ["pldm-from-capture", str(capture), "--output", str(output_dir), "--date", "2026-01-02"])

    assert result.exit_code == 0, result.output
    artifact = _load_artifact(output_dir / f"pldm-terminus-{TERMINUS_EID}.json")
    assert json.loads(json.dumps(artifact)) == artifact
