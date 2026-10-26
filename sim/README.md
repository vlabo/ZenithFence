# zfsim: the mock driver, driven from Python

`zfsim` loads the **real** driver, compiled over the mock WDK (`mock/`), into a
Python process and serves it to a real agent on the agent's named pipe (a Unix
socket on Linux/macOS). The Rust side (`src/`) is only an interface: it exposes
the driver's callouts, its user-space channel and its state. Scenarios,
traffic, seeds and assertions all live in Python scripts.

```
python script ── import zfsim ──▶ _native (PyO3, src/lib.rs) ─▶ mock/harness ─▶ real driver over mock WDK
                                        │
                                pipe / Unix socket ◀──▶ agent (nexufend, kext_tester, PipeAgent)
```

## Build and test

```bash
just sim-build      # cargo build + copy to python/zfsim/_native.pyd (.so)
just sim-test       # builds the extension and kext_tester, runs tests/
```

No maturin and no install step: put `sim/python` on `PYTHONPATH`. The module
uses the stable ABI, so any Python 3.9+ works.

## A scenario

```python
import os
from zfsim import Flow, Sim, wait_verdict

with Sim() as sim:                      # loads the driver; one Sim per process
    sim.serve("ZenithFence")            # the agent's named pipe
    assert sim.wait_agent(timeout=60)   # now start the agent
    flow = Flow("tcp", "10.0.0.5", 50000, "1.1.1.1", 443)
    assert sim.ale_connect(flow, pid=os.getpid()).absorb  # the OS starts a connection; it pends
    verdict = wait_verdict(sim, flow, timeout=10)         # the agent decides
    assert verdict is not None, "agent did not answer"
    outcome = sim.packet(flow, "outbound", b"data")       # the driver enforces it
```

A callout that pends returns at once, so a single-threaded script works.

## What a `Sim` offers

| | |
|---|---|
| Traffic (the OS) | `ale_connect`, `ale_accept`, `packet`, `packet_bytes`, `endpoint_close`, `resource_release` → `CalloutOutcome(action, absorb, permit, block)` |
| Agent | `serve(name)` → endpoint, `wait_agent(timeout)`, `agent_connected`, `next_event` / `next_command` (the tee), `send(raw_command)` |
| Driver state | `verdict_for(flow)` → `Verdict`, `packet_cache_len`, `active_conn_count`, `live_ids()`, `drain_injected()`, `reset()`, `filter_engine()` |

Options after the flow are keyword-only (`ale_connect(flow, pid=1234)`, not
`ale_connect(flow, 1234)`). Types and docs for the extension are in
`python/zfsim/_native.pyi`; keep it in sync with `src/lib.rs` and check with
`python -m mypy.stubtest zfsim._native`. Lint config is in `pyproject.toml`.

Helpers in Python:

- `zfsim.traffic`: `FlowPlan` and `run_flow` (authorize, wait for the verdict,
  data packets checked against the verdict, close, release), `replay_injected`
  (re-presents injected packets the way the OS would), and `random_flows(seed)`.
- `zfsim.payloads`: DNS query / response, TLS ClientHello, HTTP bytes.
- `zfsim.agents`: `PipeAgent` (a small agent in Python over the real pipe, what
  the tests in `tests/` attach) and `start_kext_tester(name)` (the Go test agent).

## A real agent

```bash
just mock-serve     # scripts/serve.py: one DNS lookup + HTTPS connection per second
just sim-attach     # kext_tester, or nexufend built with `just agent build-mock-kext`
```

`serve.py` takes no arguments. Every second it looks up the next site in
`SITES` for real: the query rides the pended ALE connect to the agent, and once
allowed it goes to the machine's resolver; the real response is then presented
inbound. Next comes a faked HTTPS connection to the address in the answer, with
a ClientHello naming the site. All of it carries the script's own PID, so the
agent attributes it to a real process. Each step, and every event and verdict
between driver and agent, is logged. The driver is reloaded for each agent
session.

For your own scenarios against the real agent, write a script around
`sim.serve()` the same way; `serve.py` is the example.

## Notes

- One `Sim` at a time per process (the driver is a global). Opening a second
  one raises.
- A driver panic takes the Python process down with it.
- An event's `payload` is the pended packet from its IP header on.
