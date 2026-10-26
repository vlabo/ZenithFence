"""Serve the mock driver to a real agent, with traffic slow enough to follow.

    python sim/scripts/serve.py

Waits for an agent on \\\\.\\pipe\\ZenithFence (Unix: the ZenithFence socket).
Then, every second, this process "browses" to the next site in SITES:

  1. DNS: a real lookup against the machine's resolver. The query rides the
     pended ALE connect to the agent; once allowed it goes out for real, and the
     real response is presented inbound for the agent's DNS parsing.
  2. HTTPS: a faked TLS connection to the address the response carried, with a
     ClientHello naming the site (SNI).

Every packet carries this process's PID, so the agent attributes the traffic
to a real process (python). When the agent disconnects, the driver is
reloaded and the script waits for the next one. Ctrl+C stops.
"""
import itertools
import os
import random
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))

from zfsim import Flow, Sim, Verdict, payloads
from zfsim.dns import answer_ip, default_resolver
from zfsim.traffic import replay_injected, wait_verdict

PIPE = "ZenithFence"
SITES = ["example.com", "wikipedia.org", "github.com", "cloudflare.com", "python.org", "nexufend.com"]
VERDICT_TIMEOUT = 10.0
PID = os.getpid()
ALLOWED = {Verdict.ACCEPT, Verdict.PERMANENT_ACCEPT, Verdict.REDIRECT_NAME_SERVER, Verdict.REDIRECT_TUNNEL}


def log(message):
    print(f"{time.strftime('%H:%M:%S')} {message}", flush=True)


def describe(outcome):
    if outcome.absorb:
        return "pended for the agent" if not outcome.block else "dropped"
    return "permitted" if outcome.permit else "blocked"


def show_agent_traffic(sim):
    """Print what passed between the driver and the agent since last time."""
    while (event := sim.next_event(timeout=0)) is not None:
        if event.kind == "connection":
            log(f"    driver -> agent: packet {event.id} {event.direction} {event.flow!r} pid={event.pid}")
        elif event.kind == "log":
            log(f"    driver log: {event.message}")
        else:
            log(f"    driver -> agent: {event!r}")
    while (command := sim.next_command(timeout=0)) is not None:
        if command.name == "verdict":
            log(f"    agent -> driver: packet {command.id} {Verdict(command.verdict).name}")
        else:
            log(f"    agent -> driver: {command.name}")


def authorize(sim, flow, payload=b""):
    """ALE connect: the connection pends until the agent decides."""
    outcome = sim.ale_connect(flow, pid=PID, payload=payload)
    if not outcome.absorb:
        log(f"  connect {describe(outcome)} without asking the agent")
        return Verdict.PERMANENT_ACCEPT if outcome.permit else Verdict.PERMANENT_BLOCK
    deadline = time.monotonic() + VERDICT_TIMEOUT
    verdict = None
    while verdict is None and sim.agent_connected and time.monotonic() < deadline:
        verdict = wait_verdict(sim, flow, timeout=0.1)
    show_agent_traffic(sim)
    log(f"  verdict: {verdict.name if verdict is not None else 'none (timed out)'}")
    replay_injected(sim)
    return verdict


def close(sim, flow):
    sim.endpoint_close(flow, pid=PID)
    sim.resource_release(flow.protocol, flow.local_port, v6=flow.is_v6)
    show_agent_traffic(sim)


def lookup(sim, site, resolver):
    """Real DNS lookup of `site`, shown to the driver. Returns the A address."""
    with socket.socket(socket.AF_INET6 if ":" in resolver else socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.connect((resolver, 53))  # picks the real local address and port
        local, lport = sock.getsockname()[:2]
        flow = Flow("udp", local, lport, resolver, 53)
        query = payloads.dns_query(site, id=random.getrandbits(16))
        log(f"DNS   {site} via {resolver} ({flow!r})")
        try:
            if authorize(sim, flow, query) not in ALLOWED:
                return None
            sock.send(query)
            try:
                response = sock.recv(1500)
            except OSError as err:
                log(f"  resolver did not answer: {err}")
                return None
            outcome = sim.packet(flow, "inbound", response)
            show_agent_traffic(sim)
            address = answer_ip(response)
            log(f"  response {len(response)} bytes -> {address or 'no A record'} ({describe(outcome)})")
            replay_injected(sim)
            return address
        finally:
            close(sim, flow)


def browse(sim, site, address, local, lport):
    """A faked HTTPS connection to the address DNS returned."""
    flow = Flow("tcp", local, lport, address, 443)
    log(f"HTTPS {site} ({flow!r})")
    try:
        if authorize(sim, flow) not in ALLOWED:
            return
        hello = sim.packet(flow, "outbound", payloads.tls_client_hello(site))
        reply = sim.packet(flow, "inbound", b"\x16\x03\x03" + b"\x00" * 90)
        show_agent_traffic(sim)
        log(f"  ClientHello {describe(hello)}, server reply {describe(reply)}")
        replay_injected(sim)
    finally:
        close(sim, flow)


def session(resolver):
    with Sim() as sim:
        log(f"waiting for the agent on {sim.serve(PIPE)} ...")
        while not sim.wait_agent(timeout=0.5):
            pass
        log(f"agent connected; this process is pid {PID}")
        ports = itertools.cycle(range(50000, 60000))
        for site in itertools.cycle(SITES):
            if not sim.agent_connected:
                break
            started = time.monotonic()
            address = lookup(sim, site, resolver)
            if address and sim.agent_connected:
                browse(sim, site, address, _local_v4(address), next(ports))
            time.sleep(max(0.0, 1.0 - (time.monotonic() - started)))
        log("agent disconnected; reloading the driver")


def _local_v4(remote):
    """This machine's address towards `remote` (no packet is sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((remote, 443))
        return sock.getsockname()[0]


def main():
    resolver = default_resolver()
    if resolver is None:
        print("no DNS server configured on this machine", file=sys.stderr)
        return 1
    try:
        while True:
            session(resolver)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
