"""Drive the real ZenithFence driver (over the mock WDK) from Python.

    from zfsim import Sim, Flow, Verdict

    with Sim() as sim:
        sim.serve("ZenithFence")                  # the agent's named pipe
        assert sim.wait_agent(timeout=60)         # start the agent now
        flow = Flow("tcp", "10.0.0.5", 50000, "1.1.1.1", 443)
        sim.ale_connect(flow, pid=1234)           # the "OS" starts a connection
        verdict = wait_verdict(sim, flow)         # the agent decides

Modules: `traffic` (connections the way the OS drives them, seeded random
flows), `payloads` (DNS / TLS / HTTP bytes), `agents` (attach a Python or the
Go agent to `Sim.serve()`). See sim/README.md. Build the extension first with
`just sim-build`.
"""
from __future__ import annotations

import time
from typing import Callable, TypeVar

from ._native import (
    FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT,
    CalloutOutcome,
    Command,
    Event,
    EventStream,
    Flow,
    Injected,
    Sim,
    verdict_command,
)
from .traffic import wait_verdict
from .verdict import Verdict

# The public names; type checkers treat only these as re-exported (py.typed).
__all__ = [
    "FWP_ACTION_BLOCK",
    "FWP_ACTION_PERMIT",
    "CalloutOutcome",
    "Command",
    "Event",
    "EventStream",
    "Flow",
    "Injected",
    "Sim",
    "Verdict",
    "verdict_command",
    "wait_event",
    "wait_for",
    "wait_verdict",
]

T = TypeVar("T")


def wait_for(predicate: Callable[[], T], timeout: float = 5.0, interval: float = 0.005) -> T | None:
    """Poll `predicate()` until it returns something truthy; return that value,
    or None after `timeout` seconds."""
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)


def wait_event(sim: Sim, predicate: Callable[[Event], bool], timeout: float = 5.0) -> Event | None:
    """Consume events until `predicate(event)` is true and return that event
    (events that don't match are dropped); None if it doesn't show up in time."""
    deadline = time.monotonic() + timeout
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        event = sim.next_event(timeout=left)
        if event is None:
            return None
        if predicate(event):
            return event
