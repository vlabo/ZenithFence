"""Connections the way the OS drives them through WFP, and seeded random ones.

A `FlowPlan` is one connection's life: ALE authorization (pends; the agent
decides), data packets through the IP packet layer, endpoint closure, and
optionally the local port's release. `run_flow` plays it against a `Sim` and
checks the driver enforces whatever verdict the agent gave; `random_flows`
yields an endless, reproducible stream of plans from a seed.

The agent attached with `Sim.serve()` answers the events.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Literal
from collections.abc import Iterator

from . import payloads
from ._native import FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, CalloutOutcome, Flow, Sim
from .verdict import Verdict

Dir = Literal["outbound", "inbound"]


class TrafficError(AssertionError):
    """The driver did not do what it owes the verdict it got."""


@dataclass
class Burst:
    direction: Dir
    payload: bytes


@dataclass
class FlowPlan:
    name: str
    flow: Flow
    direction: Dir = "outbound"  # of the ALE authorization: connect / accept
    pid: int = 0
    first_payload: bytes = b""  # rides the pended ALE packet to the agent
    bursts: list[Burst] = field(default_factory=list)
    reauth_after: int | None = None  # reauthorize before this burst index
    release_port: bool = False

    def __str__(self) -> str:
        return f"{self.name} {self.flow!r} {self.direction} pid={self.pid}"


@dataclass
class FlowResult:
    plan: FlowPlan
    verdict: Verdict | None = None  # None: the agent never decided in time
    packets: int = 0


def _ale(sim: Sim, plan: FlowPlan, reauth: bool = False) -> CalloutOutcome:
    run = sim.ale_connect if plan.direction == "outbound" else sim.ale_accept
    return run(plan.flow, pid=plan.pid, reauth=reauth, payload=plan.first_payload)


def _enforced(verdict: Verdict, outcome: CalloutOutcome) -> bool:
    """Whether a data packet got the action the driver owes `verdict`."""
    if verdict == Verdict.PERMANENT_ACCEPT:
        return outcome.action == FWP_ACTION_PERMIT
    if verdict == Verdict.PERMANENT_BLOCK:
        return outcome.action == FWP_ACTION_BLOCK and not outcome.absorb
    if verdict in (Verdict.PERMANENT_DROP, Verdict.UNDETERMINABLE, Verdict.FAILED):
        return outcome.action == FWP_ACTION_BLOCK and outcome.absorb
    # Temporary and redirect verdicts: the driver decides per packet.
    return True


def wait_verdict(sim: Sim, flow: Flow, timeout: float = 5.0, interval: float = 0.005) -> Verdict | None:
    """Wait until the connection cache holds a verdict for `flow` (the agent's
    decision landing, whoever sent it); `None` after `timeout` seconds."""
    deadline = time.monotonic() + timeout
    while True:
        verdict = sim.verdict_for(flow)
        if verdict:  # UNDECIDED (0) is falsy: not decided yet
            return verdict
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)


def run_flow(sim: Sim, plan: FlowPlan, timeout: float = 5.0) -> FlowResult:
    """Play `plan` against `sim`: authorize, wait up to `timeout` seconds for
    the verdict, send the bursts checking each is enforced, close, release.
    Raises `TrafficError` on a driver misbehaviour; a verdict that never comes
    is not an error (`FlowResult.verdict` is None) and the flow is closed, as
    an application would give up."""
    result = FlowResult(plan)
    outcome = _ale(sim, plan)
    if not outcome.absorb:
        raise TrafficError(f"{plan}: new connection did not pend at ALE ({outcome!r})")

    result.verdict = wait_verdict(sim, plan.flow, timeout)
    if result.verdict is not None:
        for i, burst in enumerate(plan.bursts):
            if plan.reauth_after == i and result.verdict == Verdict.PERMANENT_ACCEPT:
                again = _ale(sim, plan, reauth=True)
                if again.action != FWP_ACTION_PERMIT:
                    raise TrafficError(f"{plan}: reauthorization not permitted ({again!r})")
            outcome = sim.packet(plan.flow, burst.direction, burst.payload)
            if not _enforced(result.verdict, outcome):
                raise TrafficError(
                    f"{plan}: burst {i} not enforced under {result.verdict.name} ({outcome!r})"
                )
            result.packets += 1

    sim.endpoint_close(plan.flow, pid=plan.pid)
    if plan.release_port:
        sim.resource_release(plan.flow.protocol, plan.flow.local_port, v6=plan.flow.is_v6)
    return result


def replay_injected(sim: Sim) -> int:
    """Do with the packets the driver injected what the OS would for network
    injects: they re-enter the packet layer marked as the driver's own (it must
    permit them). Transport injects (a released ALE connect / accept) are only
    drained: an outbound one starts at its transport header, the IP layer would
    add the rest; an inbound one goes up and never passes the network layer
    again. Returns how many packets were re-presented."""
    count = 0
    for packet in sim.drain_injected():
        if packet.transport:
            continue
        direction: Dir = "inbound" if packet.inbound else "outbound"
        outcome = sim.packet_bytes(packet.data, direction, injected_by_self=True)
        if outcome.action != FWP_ACTION_PERMIT:
            raise TrafficError(f"self-injected packet not permitted: {packet!r} ({outcome!r})")
        count += 1
    return count


# ---- Random flows -------------------------------------------------------------


def _remote_v4(rng: random.Random) -> str:
    # Public-ish: steer clear of what the driver special-cases (1.1.1.1 & co,
    # 127/8 loopback, multicast/reserved), so flows take the normal pend path.
    first = rng.randint(11, 222)
    first += first >= 127
    return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def random_flow(rng: random.Random, seq: int) -> FlowPlan:
    """One random plan. `seq` (0..2047) picks the local port, so keep it
    cycling: a port is closed and released before it recurs."""
    lport = 20000 + seq % 2048
    local = f"10.1.0.{rng.randint(2, 250)}"
    remote = _remote_v4(rng)
    roll = rng.randrange(100)
    if roll < 25:
        qid = rng.getrandbits(16)
        return FlowPlan(
            "dns",
            Flow("udp", local, lport, remote, 53),
            first_payload=payloads.dns_query(id=qid),
            bursts=[Burst("inbound", payloads.dns_response(id=qid))],
            release_port=rng.random() < 0.5,
        )
    if roll < 55:
        bursts = [Burst("outbound", payloads.tls_client_hello())]
        for _ in range(rng.randint(1, 7)):
            direction: Dir = "inbound" if rng.random() < 0.6 else "outbound"
            bursts.append(Burst(direction, b"\x17" * rng.randint(1, 1400)))
        return FlowPlan(
            "https",
            Flow("tcp", local, lport, remote, 443),
            bursts=bursts,
            release_port=rng.random() < 0.3,
        )
    if roll < 70:
        return FlowPlan(
            "http",
            Flow("tcp", local, lport, remote, 80),
            bursts=[Burst("outbound", payloads.http_get()), Burst("inbound", payloads.http_response())],
            reauth_after=1 if rng.random() < 0.2 else None,
        )
    if roll < 80:
        bursts = [
            Burst(rng.choice(("inbound", "outbound")), b"\x40" * rng.randint(40, 1200))
            for _ in range(rng.randint(1, 4))
        ]
        return FlowPlan(
            "udp",
            Flow("udp", local, lport, remote, rng.randint(1024, 65000)),
            first_payload=b"\x40" * rng.randint(24, 200),
            bursts=bursts,
            release_port=rng.random() < 0.5,
        )
    if roll < 90:
        # The remote's random interface id keeps keys fresh when ports recur.
        remote6 = "2606:4700:" + ":".join(f"{rng.getrandbits(16):x}" for _ in range(4)) + "::1"
        return FlowPlan(
            "v6",
            Flow("tcp", f"2001:db8::{rng.randint(1, 250):x}", lport, remote6, 443),
            bursts=[
                Burst("outbound", payloads.tls_client_hello()),
                Burst("inbound", b"\x17" * rng.randint(100, 1400)),
            ],
        )
    return FlowPlan(
        "inbound",
        Flow("tcp", local, lport, remote, rng.randint(1024, 65000)),
        direction="inbound",
        first_payload=b"\x17" * rng.randint(1, 250),
        bursts=[Burst("inbound", b"\x17" * rng.randint(1, 1000))],
    )


def random_flows(seed: int | str | bytes, count: int | None = None) -> Iterator[FlowPlan]:
    """`count` random plans (endless if None), reproducible from `seed`."""
    rng = random.Random(seed)
    seq = 0
    while count is None or seq < count:
        yield random_flow(rng, seq)
        seq += 1
