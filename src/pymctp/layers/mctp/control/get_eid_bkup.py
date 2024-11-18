import dataclasses
from enum import Enum
from typing import Optional, Type

from scapy.fields import BitEnumField, BitField, XByteField
from scapy.packet import Packet

from .control import AutobindControlMsg, ContrlCmdCodes, RqBit


@AutobindControlMsg(ContrlCmdCodes.GetEndpointID, RqBit.REQUEST)
class GetEndpointID(Packet):
    fields_desc = []


class EndpointType(Enum):
    SIMPLE = 0
    """Simple Endpoint"""

    BUS_OWNER = 1
    """Bus Owner and/or Bridge"""


class EndpointIDType(Enum):
    DYNAMIC = 0
    """The endpoint uses a dynamic EID only"""

    STATIC_EID_SUPPORTED = 1
    """The EID returned by this command reflects the present setting and may or
    may not match the static EID value."""

    STATIC_EID_MATCH = 2
    """The endpoint has been configured with a static EID. The present value is
    the same as the static value."""

    STATIC_EID_MISMATCH = 3
    """ Endpoint has been configured with a static EID. The present value is
    different than the static value"""


import sys
from dataclasses import (  # type: ignore
    _FIELD,
    _FIELD_INITVAR,
    _FIELDS,
    _HAS_DEFAULT_FACTORY,
    _POST_INIT_NAME,
    MISSING,
    _create_fn,
    _field_init,
    _get_field,
    _init_fn,
    _init_param,
    _process_class,
    _set_new_attribute,
)


def get_class_fields(cls, /, *, kw_only=False):
    cls_annotations = cls.__dict__.get('__annotations__', {})
    cls_fields = []
    for name, type in cls_annotations.items():
        f = _get_field(cls, name, type, kw_only)
        cls_fields.append(f)
    return cls_fields


def datapacketclass_wrapper(cls=None, /, *, init=True, repr=True, eq=True, order=False,
                            unsafe_hash=False, frozen=False, match_args=True,
                            kw_only=False, slots=False, weakref_slot=False):
    print("DC2 decorator called")

    def wrap(cls):
        # convert all fields to initvars to prevent trying to set the value in the generated init method
        # for f in get_class_fields(cls, kw_only=kw_only):
        #     # default = getattr(cls, f.name, MISSING)
        #     # f._field_type = _FIELD_INITVAR
        #     f.default = MISSING
        #     # setattr(cls, f.name, default if isinstance(default, dataclasses.Field) else f)
        #     setattr(cls, f.name, f)

        # add_post_init_fn(cls)
        add_custom_init_fn(cls)

        return _process_class(cls, False, repr, eq, order, unsafe_hash,
                              frozen, match_args, kw_only, slots,
                              weakref_slot)

    if cls is None:
        return wrap
    return wrap(cls)


def datapacketclass(cls=None, /, *, kw_only=False):
    print("DC decorator called")

    def wrap(cls):
        return add_custom_init_fn(cls)

    if cls is None:
        return wrap
    return wrap(cls)


def datapacketclass3(cls=None, /, *, packet_cls_name: str | None = None):
    print("DC3 decorator called")

    def wrap(cls):
        return add_new_fn(cls, packet_cls_name=packet_cls_name)

    if cls is None:
        return wrap
    return wrap(cls)


def add_post_init_fn(cls: type[Packet], /, *, kw_only=False):
    fields = get_class_fields(cls, kw_only=kw_only)
    globals_ = sys.modules[cls.__module__].__dict__
    # setattr(cls, _FIELDS, fields)

    self_name = "__dataclass_self__" if "self" in fields else "self"

    locals = {f'_type_{f.name}': f.type for f in fields}
    locals.update({
        'MISSING': MISSING,
        '_HAS_DEFAULT_FACTORY': _HAS_DEFAULT_FACTORY,
        '__class__': cls
    })

    body_lines = ['vals = list(args)']
    for _idx, f in enumerate(fields):
        line = f'kwargs["{f.name}"] = vals.pop(0) if len(vals) else None'
        if line:
            body_lines.append(line)
    body_lines += ['super().__init__(*vals, **kwargs)']

    _init_params = [f'{f.name}:_type_{f.name}=None' for f in fields]

    _set_new_attribute(
        cls,
        "__original_init__",
        cls.__init__
    )

    _set_new_attribute(
        cls,
        "__post_init__",
        _create_fn('__post_init__',
                   [self_name, '*args', *_init_params, '**kwargs'],
                   body_lines,
                   locals=locals,
                   globals=globals_,
                   return_type=None)
    )

    # JS-TODO: add a __post_init__ function

    return cls


def add_custom_init_fn(cls: type[Packet]):
    # fields = [
    #     _get_field(cls, f.name, type(f), True) for f in cls.fields_desc
    # ]
    fields = get_class_fields(cls, kw_only=True)
    globals_ = sys.modules[cls.__module__].__dict__
    # setattr(cls, _FIELDS, fields)

    self_name = "__dataclass_self__" if "self" in fields else "self"

    locals = {f'_type_{f.name}': f.type for f in fields}
    locals.update({
        'MISSING': MISSING,
        '_HAS_DEFAULT_FACTORY': _HAS_DEFAULT_FACTORY,
        '__class__': cls
    })

    body_lines = []
    for f in fields:
        line = f'kwargs["{f.name}"] = {f.name}'
        _ = _field_init(f, frozen=False, globals=locals, self_name=self_name, slots=False)
        if line:
            body_lines.append(line)
    body_lines += ['super().__init__(*args, **kwargs)']
    if hasattr(cls, _POST_INIT_NAME):
        body_lines.append(f'{self_name}.{_POST_INIT_NAME}()')

    # _init_params = [f'{f.name}:_type_{f.name}={}' for f in fields]
    _init_params = [_init_param(f) for f in fields]

    _set_new_attribute(
        cls,
        "__dataclass_init__",
        cls.__init__
    )

    _set_new_attribute(
        cls,
        "__init__",
        _create_fn('__init__',
                   [self_name, '*args', *_init_params, '**kwargs'],
                   body_lines,
                   locals=locals,
                   globals=globals_,
                   return_type=None)
    )

    # JS-TODO: add a __post_init__ function

    return cls


def add_new_fn(cls: type[Packet], /, *, packet_cls_name: str | None = None):
    # fields = [
    #     _get_field(cls, f.name, type(f), True) for f in cls.fields_desc
    # ]
    fields = get_class_fields(cls, kw_only=True)
    globals_ = sys.modules[cls.__module__].__dict__
    # setattr(cls, _FIELDS, fields)

    self_name = "__dataclass_self__" if "self" in fields else "self"

    locals = {f'_type_{f.name}': f.type for f in fields}
    locals.update({
        'MISSING': MISSING,
        '_HAS_DEFAULT_FACTORY': _HAS_DEFAULT_FACTORY,
        '__class__': cls
    })

    _init_params = []
    for f in fields:
        _ = _field_init(f, frozen=False, globals=locals, self_name=self_name, slots=False)
        # f.default = None if
        _init_params.append(_init_param(f))

    body_lines = []
    if not packet_cls_name:
        packet_cls_name = f'{cls.__name__}Packet'
    kwargs = ', '.join(f"{f.name}={f.name}" for f in fields)
    body_lines += [f"return {cls.__name__}.{packet_cls_name}({kwargs})"]

    _set_new_attribute(
        cls,
        "__new__",
        _create_fn('__new__',
                   [self_name, '*args', *_init_params, '**kwargs'],
                   body_lines,
                   locals=locals,
                   globals=globals_,
                   return_type=None)
    )

    # JS-TODO: add a __post_init__ function

    return cls


@dataclasses.dataclass(kw_only=True)
class GetEndpointIDResponseV2(Packet):
    # eid: int = dataclasses.field()
    eid: int
    endpoint_type: EndpointType
    endpoint_id_type: EndpointIDType
    medium_specific: int

    fields_desc = [
        XByteField("eid", 0),
        BitField("unused", 0, 2),
        BitEnumField("endpoint_type", 0, 2, EndpointType),
        BitField("unused2", 0, 2),
        BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
        XByteField("medium_specific", 0),
    ]


@dataclasses.dataclass(kw_only=True)
class GetEndpointIDResponseV22(Packet):
    eid: int
    endpoint_type: EndpointType
    endpoint_id_type: EndpointIDType
    medium_specific: int

    fields_desc = [
        XByteField("eid", 0),
        BitField("unused", 0, 2),
        BitEnumField("endpoint_type", 0, 2, EndpointType),
        BitField("unused2", 0, 2),
        BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
        XByteField("medium_specific", 0),
    ]


# @add_custom_init_fn
class GetEndpointIDResponseV3(Packet):
    fields_desc = [
        XByteField("eid", 0),
        BitField("unused", 0, 2),
        BitEnumField("endpoint_type", 0, 2, EndpointType),
        BitField("unused2", 0, 2),
        BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
        XByteField("medium_specific", 0),
    ]

    # def __init__(self, *args, eid: int = None,
    #              endpoint_type: EndpointType = None,
    #              endpoint_id_type: EndpointIDType = None,
    #              medium_specific: int = None,
    #              **kwargs):
    #     kwargs["eid"] = eid
    #     kwargs["endpoint_type"] = endpoint_type
    #     kwargs["endpoint_id_type"] = endpoint_id_type
    #     kwargs["medium_specific"] = medium_specific
    #     super().__init__(*args, **kwargs)


class GetEndpointIDResponseV4(Packet):
    fields_desc = [
        XByteField("eid", 0),
        BitField("unused", 0, 2),
        BitEnumField("endpoint_type", 0, 2, EndpointType),
        BitField("unused2", 0, 2),
        BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
        XByteField("medium_specific", 0),
    ]


class GetEndpointIDResponseV6(Packet):
    fields_desc = [
        XByteField("eid", 0),
        BitField("unused", 0, 2),
        BitEnumField("endpoint_type", 0, 2, EndpointType),
        BitField("unused2", 0, 2),
        BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
        XByteField("medium_specific", 0),
    ]

    __annotations__ = {
        "eid": int,
        "endpoint_type": EndpointType,
        "endpoint_id_type": EndpointIDType,
        "medium_specific": int,
    }


# @add_custom_init_fn
class GetEndpointIDResponseV8(Packet):
    fields_desc = [
        XByteField("eid", 0),
        BitField("unused", 0, 2),
        BitEnumField("endpoint_type", 0, 2, EndpointType),
        BitField("unused2", 0, 2),
        BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
        XByteField("medium_specific", 0),
    ]

    __annotations__ = {
        "eid": int,
        "endpoint_type": EndpointType,
        "endpoint_id_type": EndpointIDType,
        "medium_specific": int,
    }


@dataclasses.dataclass(init=False, kw_only=True)
# @datapacketclass(kw_only=True)
class GetEndpointIDResponseV9(Packet):
    eid: int
    endpoint_type: EndpointType
    endpoint_id_type: EndpointIDType
    medium_specific: int

    fields_desc = [
        XByteField("eid", 0),
        BitField("unused", 0, 2),
        BitEnumField("endpoint_type", 0, 2, EndpointType),
        BitField("unused2", 0, 2),
        BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
        XByteField("medium_specific", 0),
    ]

    # def __init__(self, *args, eid: int = None,
    #              endpoint_type: EndpointType = None,
    #              endpoint_id_type: EndpointIDType = None,
    #              medium_specific: int = None,
    #              **kwargs):
    #     super().__init__(*args, **kwargs)
    # self.__post_init__(*args, **kwargs)


# @dataclasses.dataclass(init=False)
@datapacketclass_wrapper(kw_only=True)
class GetEndpointIDResponseV9b(Packet):
    # eid: int = dataclasses.field(init=True)
    # endpoint_type: EndpointType = dataclasses.field(init=True)
    # endpoint_id_type: EndpointIDType = dataclasses.field(init=True)
    # medium_specific: int = dataclasses.field(init=True)

    eid: dataclasses.InitVar[int]
    endpoint_type: dataclasses.InitVar[EndpointType | None]
    endpoint_id_type: dataclasses.InitVar[EndpointIDType | None]
    medium_specific: dataclasses.InitVar[int | None]

    fields_desc = [
        XByteField("eid", 0),
        BitField("unused", 0, 2),
        BitEnumField("endpoint_type", 0, 2, EndpointType),
        BitField("unused2", 0, 2),
        BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
        XByteField("medium_specific", 0),
    ]

    # def __init__(self, *args, eid: int = None,
    #              endpoint_type: EndpointType = None,
    #              endpoint_id_type: EndpointIDType = None,
    #              medium_specific: int = None,
    #              **kwargs):
    #     super().__init__(*args, **kwargs)
    # self.__post_init__(*args, **kwargs)


@dataclasses.dataclass()
# @datapacketclass(kw_only=True)
# @datapacketclass3(packet_cls_name='GetEndpointIDResponsePacket')
class GetEndpointIDResponseV9c:
    eid: int
    endpoint_type: EndpointType | None
    endpoint_id_type: EndpointIDType | None
    medium_specific: int | None

    class GetEndpointIDResponsePacket(Packet):
        fields_desc = [
            XByteField("eid", 0),
            BitField("unused", 0, 2),
            BitEnumField("endpoint_type", 0, 2, EndpointType),
            BitField("unused2", 0, 2),
            BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
            XByteField("medium_specific", 0),
        ]

    # def __new__(cls, *args, eid: int,
    #             endpoint_type: Optional[EndpointType] = None,
    #             endpoint_id_type: Optional[EndpointIDType] = None,
    #             medium_specific: Optional[int] = None, **kwargs):
    #     return GetEndpointIDResponseV9c.GetEndpointIDResponsePacket(eid=eid, endpoint_type=endpoint_type,
    #                                                                 endpoint_id_type=endpoint_id_type,
    #                                                                 medium_specific=medium_specific)

    # def __post_init__(self, eid: int, endpoint_type: Optional[EndpointType], endpoint_id_type: Optional[EndpointIDType],
    #                   medium_specific: Optional[int]):
    #     self = GetEndpointIDResponseV9c.GetEndpointIDResponsePacket(eid=eid, endpoint_type=endpoint_type,
    #                                                                 endpoint_id_type=endpoint_id_type,
    #                                                                 medium_specific=medium_specific)


# @dataclasses.dataclass()
# @datapacketclass3(packet_cls_name='GetEndpointIDResponsePacket')
class GetEndpointIDResponseV9d:
    class GetEndpointIDResponsePacket(Packet):
        fields_desc = [
            XByteField("eid", 0),
            BitField("unused", 0, 2),
            BitEnumField("endpoint_type", 0, 2, EndpointType),
            BitField("unused2", 0, 2),
            BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
            XByteField("medium_specific", 0),
        ]

    def __new__(cls, eid: int,
                endpoint_type: EndpointType | None = None,
                endpoint_id_type: EndpointIDType | None = None,
                medium_specific: int | None = None):
        return GetEndpointIDResponseV9c.GetEndpointIDResponsePacket(eid=eid,
                                                                    endpoint_type=endpoint_type,
                                                                    endpoint_id_type=endpoint_id_type,
                                                                    medium_specific=medium_specific)


# @add_custom_init_fn
class GetEndpointIDResponseV5(Packet):
    eid: int = dataclasses.field()
    endpoint_type: EndpointType
    endpoint_id_type: EndpointIDType
    medium_specific: int

    def __init__(self, *args, eid: int | None = None,
                 endpoint_type: EndpointType = None,
                 endpoint_id_type: EndpointIDType = None,
                 medium_specific: int | None = None,
                 **kwargs):
        super().__init__(*args, **kwargs)
    # self.__post_init__(*args, **kwargs)


# @dataclasses.dataclass(kw_only=True)
# @add_custom_init_fn
@AutobindControlMsg(ContrlCmdCodes.GetEndpointID, RqBit.RESPONSE)
class GetEndpointIDResponse(Packet):
    fields_desc = [
        # ConditionalField(ByteField("completion_code", 0), lambda pkt: pkt.underlayer[Control_HDR].rq == 0),
        XByteField("eid", 0),
        BitField("unused", 0, 2),
        BitEnumField("endpoint_type", 0, 2, EndpointType),
        BitField("unused2", 0, 2),
        BitEnumField("endpoint_id_type", 0, 2, EndpointIDType),
        XByteField("medium_specific", 0),
    ]

    # def __init__(self, *args, eid: int = None,
    #              endpoint_type: EndpointType = None,
    #              endpoint_id_type: EndpointIDType = None,
    #              medium_specific: int = None,
    #              **kwargs):
    #     super().__init__(*args, **kwargs)
    # self.__post_init__(*args, **kwargs)
    #
    # def __post_init__(self, *args, **kwargs):
    #     super().__init__(*args, **kwargs)
    #     # pass

    # __annotations__ = {
    #     "eid": int,
    #     "endpoint_type": EndpointType,
    #     "endpoint_id_type": EndpointIDType,
    #     "medium_specific": int,
    # }

    #
    # __slots__ = [
    #     "eid",
    #     "endpoint_type",
    #     "endpoint_id_type",
    #     "medium_specific",
    # ]
