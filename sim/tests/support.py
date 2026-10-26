"""Shared test setup: the driver served on its pipe with an agent attached.

Every test drives the driver the way it runs for real: a `Sim` serves it on a
fresh endpoint and an agent connects over the pipe / Unix socket. The agent is
`zfsim.agents.PipeAgent` (Python, so each test picks its policy) unless a test
starts the Go one.
"""
from __future__ import annotations

import itertools
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from zfsim import Event, Sim, Verdict
from zfsim.agents import PipeAgent

_names = itertools.count()


def endpoint_name() -> str:
    """A logical endpoint name no other test (or test run) uses."""
    return f"zfsim-test-{os.getpid()}-{next(_names)}"


def accept_all(event: Event) -> int | None:
    return Verdict.PERMANENT_ACCEPT if event.kind == "connection" else None


@contextmanager
def attached(policy: Callable[[Event], int | None] = accept_all) -> Iterator[tuple[Sim, PipeAgent]]:
    """A loaded `Sim` with a `PipeAgent` answering by `policy`. On exit the sim
    closes (the agent sees the endpoint go away) and the agent is joined, which
    re-raises a `policy` exception."""
    with Sim() as sim:
        agent = PipeAgent(sim.serve(endpoint_name()), policy)
        if not sim.wait_agent(timeout=5):
            raise TimeoutError("PipeAgent did not attach")
        yield sim, agent
    agent.join()
