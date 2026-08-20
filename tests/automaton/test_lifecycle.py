# SPDX-FileCopyrightText: 2024 Justin Simon <justin@simonctl.com>
#
# SPDX-License-Identifier: MIT

"""Tests for the endpoint answering-machine lifecycle.

These cover the ordering hazards between starting and stopping an endpoint.
``AsyncSniffer`` has two startup windows that silently swallow a stop:

* ``running`` is set at the top of ``_run()`` but ``stop_cb`` — which
  ``stop()`` needs — is installed several statements later, so an early
  ``stop()`` raises ``Scapy_Exception``.
* ``continue_sniff`` is assigned ``True`` *after* ``started_callback`` fires,
  so a stop landing in that window is undone.

Both used to leave an endpoint sniffing until its own timeout expired.
"""

from __future__ import annotations

import threading
import time

import pytest
from scapy.error import Scapy_Exception

from pymctp.automaton.behaviors.base import Behavior
from pymctp.automaton.role_endpoint import RoleBasedEndpointAM
from pymctp.automaton.simple_endpoint import SimpleEndpointAM
from pymctp.layers.mctp.types import EndpointContext, MsgTypes, Smbus7bitAddress


@pytest.fixture
def ctx():
    return EndpointContext(
        physical_address=Smbus7bitAddress(0x10),
        assigned_eid=0x08,
        supported_msg_types=[MsgTypes.CTRL],
    )


class FakeSniffer:
    """Stands in for scapy's AsyncSniffer, reproducing its startup windows."""

    def __init__(self, *, install_stop_cb: bool = True, rearm_after_start: bool = False) -> None:
        self.running = False
        self.continue_sniff = False
        self.results = None
        self.stop_calls = 0
        self._install_stop_cb = install_stop_cb
        self._rearm_after_start = rearm_after_start
        self._exit = threading.Event()

    def _run(self, started_callback=None, **kwargs):
        self.running = True
        if self._install_stop_cb:
            self.stop_cb = self._stop_cb
        if started_callback:
            started_callback()
        if self._rearm_after_start:
            # scapy does exactly this, undoing a stop issued from the callback
            self.continue_sniff = True
        else:
            self.continue_sniff = True
        try:
            while self.continue_sniff and not self._exit.is_set():
                time.sleep(0.002)
        finally:
            self.running = False

    def _stop_cb(self):
        self.continue_sniff = False

    def stop(self, join=False):
        self.stop_calls += 1
        if not self.running:
            msg = "Not running ! (check .running attr)"
            raise Scapy_Exception(msg)
        if not hasattr(self, "stop_cb"):
            msg = "Unsupported (offline or unsupported socket)"
            raise Scapy_Exception(msg)
        self.stop_cb()
        return self.results


def make_am(cls, ctx, sniffer: FakeSniffer, **kwargs):
    am = cls(context=ctx, **kwargs)
    am.optsniff = {}

    def sniff():
        am.sniffer = sniffer
        am._sniff_ready.clear()
        am._sniff_started.clear()
        if am._stop_requested.is_set():
            return None
        try:
            sniffer._run(started_callback=am._sniff_started_callback)
        finally:
            am._sniff_ready.clear()
            am._sniff_started.clear()
            am._on_sniff_stopped()
        return sniffer.results

    am.sniff = sniff
    return am


@pytest.fixture
def run_endpoint():
    """Run an AM's sniff loop on a daemon thread, always torn down.

    Daemon threads keep a failing assertion from hanging the whole suite.
    """
    threads: list[tuple[threading.Thread, SimpleEndpointAM]] = []

    def _run(am):
        thread = threading.Thread(target=am.sniff, daemon=True)
        thread.start()
        threads.append((thread, am))
        return thread

    yield _run

    for thread, am in threads:
        am.stop_sniffer(join=True, timeout=2.0)
        thread.join(3.0)


class TestStopSnifferRaces:
    def test_stop_before_thread_starts_prevents_sniffing(self, ctx, run_endpoint):
        sniffer = FakeSniffer()
        am = make_am(SimpleEndpointAM, ctx, sniffer)

        # Stop lands before the endpoint thread ever reaches the sniff loop.
        am.stop_sniffer(join=True, timeout=1.0)
        thread = run_endpoint(am)
        thread.join(2.0)

        assert not thread.is_alive()
        assert sniffer.running is False

    def test_stop_during_startup_is_reasserted(self, ctx, run_endpoint):
        """scapy re-arms continue_sniff after started_callback; stop must stick."""
        sniffer = FakeSniffer(rearm_after_start=True)
        am = make_am(SimpleEndpointAM, ctx, sniffer)

        thread = run_endpoint(am)
        assert am.wait_until_started(2.0)

        am.stop_sniffer(join=True, timeout=2.0)
        thread.join(3.0)

        assert not thread.is_alive(), "sniffer kept running after stop()"
        assert sniffer.running is False

    def test_stop_retries_until_stop_cb_is_installed(self, ctx, run_endpoint):
        """A stop issued before stop_cb exists must not be silently dropped."""
        sniffer = FakeSniffer(install_stop_cb=False)
        am = make_am(SimpleEndpointAM, ctx, sniffer)

        thread = run_endpoint(am)
        assert am.wait_until_started(2.0)

        # stop() raises Scapy_Exception every time; install stop_cb midway so a
        # retrying implementation succeeds and a single-shot one hangs.
        def install_later():
            time.sleep(0.05)
            sniffer.stop_cb = sniffer._stop_cb

        threading.Thread(target=install_later, daemon=True).start()
        am.stop_sniffer(join=True, timeout=2.0)
        thread.join(3.0)

        assert not thread.is_alive()
        assert sniffer.stop_calls > 1, "stop() was not retried"

    def test_stop_is_idempotent(self, ctx, run_endpoint):
        sniffer = FakeSniffer()
        am = make_am(SimpleEndpointAM, ctx, sniffer)

        thread = run_endpoint(am)
        am.wait_until_started(2.0)

        am.stop_sniffer(join=True, timeout=2.0)
        thread.join(3.0)
        am.stop_sniffer(join=True, timeout=2.0)  # must not raise or hang

        assert not thread.is_alive()

    def test_stop_without_ever_running_returns_promptly(self, ctx):
        am = SimpleEndpointAM(context=ctx)

        started = time.monotonic()
        assert am.stop_sniffer(join=True, timeout=5.0) is None
        assert time.monotonic() - started < 1.0


class RecordingBehavior(Behavior):
    def __init__(self) -> None:
        self.events: list[str] = []
        self.bound_am = None

    @property
    def name(self) -> str:
        return "recording"

    def can_handle(self, pkt, ctx) -> bool:
        return False

    def handle(self, pkt, ctx):
        return None

    def on_bind(self, am, ctx) -> None:
        self.bound_am = am
        self.events.append("bind")

    def on_attach(self, ctx) -> None:
        self.events.append("attach")

    def on_start(self, am, ctx) -> None:
        self.events.append("start")

    def on_stop(self, am, ctx) -> None:
        self.events.append("stop")

    def on_detach(self, ctx) -> None:
        self.events.append("detach")


class ExplodingBehavior(RecordingBehavior):
    @property
    def name(self) -> str:
        return "exploding"

    def on_start(self, am, ctx) -> None:
        super().on_start(am, ctx)
        msg = "boom"
        raise RuntimeError(msg)


class TestBehaviorLifecycle:
    def test_on_bind_receives_the_answering_machine(self, ctx):
        behavior = RecordingBehavior()
        am = RoleBasedEndpointAM(behaviors=[behavior], context=ctx)

        assert behavior.bound_am is am
        assert behavior.events == ["bind", "attach"]

    def test_full_lifecycle_order(self, ctx, run_endpoint):
        behavior = RecordingBehavior()
        sniffer = FakeSniffer()
        am = make_am(RoleBasedEndpointAM, ctx, sniffer, behaviors=[behavior])

        thread = run_endpoint(am)
        assert am.wait_until_started(2.0)
        am.stop_sniffer(join=True, timeout=2.0)
        thread.join(3.0)
        am.remove_behavior(behavior)

        assert behavior.events == ["bind", "attach", "start", "stop", "detach"]

    def test_behaviors_are_not_started_when_stopping_during_startup(self, ctx, run_endpoint):
        behavior = RecordingBehavior()
        sniffer = FakeSniffer()
        am = make_am(RoleBasedEndpointAM, ctx, sniffer, behaviors=[behavior])

        am.stop_sniffer(join=True, timeout=1.0)
        thread = run_endpoint(am)
        thread.join(2.0)

        assert "start" not in behavior.events
        assert "stop" not in behavior.events

    def test_behavior_added_while_running_is_started(self, ctx, run_endpoint):
        sniffer = FakeSniffer()
        am = make_am(RoleBasedEndpointAM, ctx, sniffer)

        thread = run_endpoint(am)
        assert am.wait_until_started(2.0)

        behavior = RecordingBehavior()
        am.add_behavior(behavior)
        assert behavior.events == ["bind", "attach", "start"]

        am.stop_sniffer(join=True, timeout=2.0)
        thread.join(3.0)
        assert behavior.events[-1] == "stop"

    def test_failing_on_start_does_not_kill_the_endpoint(self, ctx, run_endpoint):
        exploding = ExplodingBehavior()
        healthy = RecordingBehavior()
        sniffer = FakeSniffer()
        am = make_am(RoleBasedEndpointAM, ctx, sniffer, behaviors=[exploding, healthy])

        thread = run_endpoint(am)
        assert am.wait_until_started(2.0)

        # the healthy behavior still gets started despite its neighbour raising
        assert "start" in healthy.events

        am.stop_sniffer(join=True, timeout=2.0)
        thread.join(3.0)
        assert not thread.is_alive()

    def test_get_behavior_by_name(self, ctx):
        behavior = RecordingBehavior()
        am = RoleBasedEndpointAM(behaviors=[behavior], context=ctx)

        assert am.get_behavior("recording") is behavior
        assert am.get_behavior("nope") is None
