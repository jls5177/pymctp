"""An endpoint may deliberately not implement Get Endpoint UUID."""

import uuid

from pymctp.layers.mctp.control import CompletionCodes, GetEndpointUUID
from pymctp.layers.mctp.types import EndpointContext


def test_uuid_unavailable_from_config_returns_unsupported():
    context = EndpointContext.from_dict({"endpoint_uuid": None})

    code, payload = GetEndpointUUID().make_ctrl_reply(context)

    assert context.endpoint_uuid is None
    assert code == CompletionCodes.ERROR_UNSUPPORTED_CMD
    assert payload is None


def test_default_uuid_still_supported():
    context = EndpointContext.from_dict({})
    code, payload = GetEndpointUUID().make_ctrl_reply(context)

    assert code == CompletionCodes.SUCCESS
    assert isinstance(context.endpoint_uuid, uuid.UUID)
    assert payload.uuid == context.endpoint_uuid
