# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

from scapy.config import conf
from scapy.packet import Packet

from .interfaces import (
    AnyPacketType,
    ICanSetMySummaryClasses,
    ICanVerifyIfRequest,
)


class AllowRawSummary:
    def do_dissect_payload(self, s: bytes) -> None:
        if not s:
            return
        cls = self.guess_payload_class(s)
        try:
            p = cls(s, _internal=1, _underlayer=self)
        except KeyboardInterrupt:
            raise
        except Exception:
            if conf.debug_dissector and cls is not None:
                raise
            p = conf.raw_layer(s, _internal=1, _underlayer=self)
        self.add_payload(p)
        if isinstance(p, ICanSetMySummaryClasses):
            p.set_mysummary_classes([self.__class__, self.underlayer.__class__])

    def _do_summary(self):
        # type: () -> Tuple[int, str, List[Any]]
        if "load" in self.fields:
            found, s, needed = self.load._do_summary()  # noqa: SLF001
            if self.payload and self.payload.original:
                pld = conf.raw_layer(self.payload.original)
                s = f"{s} / {pld}"
        else:
            found, s, needed = self.payload._do_summary()  # noqa: SLF001
        ret = ""
        # if not found or self.__class__ in needed:
        ret = self.mysummary()
        if isinstance(ret, tuple):
            ret, n = ret
            needed += n
        if ret or needed:
            found = 1
        if not ret:
            ret = self.__class__.__name__ if self.show_summary else ""
        if self.__class__ in conf.emph:
            impf = [f"{f.name}={f.i2repr(self, self.getfieldval(f.name))}" for f in self.fields_desc if f in conf.emph]
            ret = f"{ret} [{' '.join(impf)}]"
        ret = f"{ret} / {s}" if ret and s else f"{ret}{s}"
        return found, ret, needed
