import struct
import pytest

from pymctp.layers import EndpointContext
from pymctp.layers.mctp.control import (
    GetEndpointID,
    GetEndpointIDResponse,
    EndpointType,
    EndpointIDType,
    CompletionCodes,
)
from pymctp.utils import str_to_bytes


def test_request_fn_without_args_has_default_values():
    pkt = GetEndpointID()
    data = bytes(pkt)
    assert not pkt.fields
    assert len(data) == 0


def test_request_with_bytes_id_decoded():
    pkt = GetEndpointID(b"")
    data = bytes(pkt)
    assert not pkt.fields
    assert len(data) == 0


def test_response_fn_without_args_has_default_values():
    pkt = GetEndpointIDResponse()
    assert pkt.eid == 0
    assert pkt.endpoint_type == EndpointType.SIMPLE
    assert pkt.endpoint_id_type == EndpointIDType.DYNAMIC
    assert pkt.medium_specific == 0


def test_response_with_bytes_is_decoded():
    data = "44 00 00"
    pkt = GetEndpointIDResponse(str_to_bytes(data))
    assert pkt.eid == 0x44
    assert pkt.endpoint_type == EndpointType.SIMPLE
    assert pkt.endpoint_id_type == EndpointIDType.DYNAMIC
    assert pkt.medium_specific == 0


@pytest.mark.parametrize(
    ("expected_summary", "pkt_kwargs"),
    [
        ("GetEndpointID (eid: 44, type: simple, eid_type: dynamic)", {}),
        ("GetEndpointID (eid: 44, type: busowner, eid_type: dynamic)", dict(endpoint_type=EndpointType.BUS_OWNER)),
        (
            "GetEndpointID (eid: 44, type: simple, eid_type: static_eid_supported)",
            dict(endpoint_id_type=EndpointIDType.STATIC_EID_SUPPORTED),
        ),
        (
            "GetEndpointID (eid: 44, type: simple, eid_type: static_eid_match)",
            dict(endpoint_id_type=EndpointIDType.STATIC_EID_MATCH),
        ),
        (
            "GetEndpointID (eid: 44, type: simple, eid_type: static_eid_mismatch)",
            dict(endpoint_id_type=EndpointIDType.STATIC_EID_MISMATCH),
        ),
    ],
)
def test_pkt_summary(expected_summary, pkt_kwargs):
    default_kwargs = dict(eid=0x44, endpoint_type=EndpointType.SIMPLE, endpoint_id_type=EndpointIDType.DYNAMIC)
    kwargs = dict(default_kwargs, **pkt_kwargs)
    assert GetEndpointIDResponse(**kwargs).summary() == expected_summary


@pytest.mark.parametrize(
    ("ctx_args", "expected_eid", "expected_endpoint_type", "expected_endpoint_id_type"),
    [
        (
            dict(),  # use default values
            0x44,
            EndpointType.SIMPLE,
            EndpointIDType.STATIC_EID_MATCH,
        ),
        (
            dict(assigned_eid=0x80),
            0x80,
            EndpointType.SIMPLE,
            EndpointIDType.STATIC_EID_MISMATCH,
        ),
        (
            dict(static_eid=0x44, assigned_eid=None),
            0x44,
            EndpointType.SIMPLE,
            EndpointIDType.STATIC_EID_SUPPORTED,
        ),
        (
            dict(static_eid=None, assigned_eid=0x44),
            0x44,
            EndpointType.SIMPLE,
            EndpointIDType.DYNAMIC,
        ),
        (
            dict(static_eid=None, assigned_eid=0x44, is_bus_owner=True),
            0x44,
            EndpointType.BUS_OWNER,
            EndpointIDType.DYNAMIC,
        ),
    ],
)
def test_reply_with_various_eid_types(ctx_args, expected_eid, expected_endpoint_type, expected_endpoint_id_type):
    default_kwargs = dict(physical_address=0x20, static_eid=0x44, assigned_eid=0x44)
    kwargs = dict(default_kwargs, **ctx_args)
    ctx = EndpointContext(**kwargs)
    rq = GetEndpointID(b"")
    ccode, resp = rq.make_ctrl_reply(ctx)
    assert ccode == CompletionCodes.SUCCESS
    assert resp
    assert resp.eid == expected_eid
    assert resp.endpoint_type == expected_endpoint_type
    assert resp.endpoint_id_type == expected_endpoint_id_type
    assert resp.medium_specific == 0


def test_response_with_invalid_data_throws_exception():
    data = "FF FF"
    with pytest.raises(struct.error):
        GetEndpointIDResponse(str_to_bytes(data))
