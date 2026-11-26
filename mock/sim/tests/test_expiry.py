"""A packet nobody answers is blocked only once it has waited the driver's verdict timeout
(PACKET_VERDICT_TIMEOUT_MS, 30 s), however early after the driver's load it was queued, and then
it is: the packet is released blocked and its connection marked FAILED."""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import unittest

from zfsim import Verdict

TIMEOUT_MS = 30_000

# Each scenario runs in a process of its own. The mock clock counts from its first read in the
# process (mock/wdk get_monotonic_ms), so only a fresh process queues its first packet at clock 0;
# and `Sim.advance_clock` moves the clock for the rest of the process. Loading the driver does not
# read the clock; the ALE connect's queueing is the first read. The maintenance pass that expires
# packets runs once a second, the first one a second after the load.
#
# The flows are UDP with a payload: a pended UDP connect keeps its datagram, so its release shows
# up in `drain_injected`; a TCP connect carries no data and releases nothing the mock records.
PRELUDE = textwrap.dedent("""
    import json
    import time
    from zfsim import Flow, Sim

    def state(sim, flow, injected):
        verdict = sim.verdict_for(flow)
        return {
            "pending": sim.packet_cache_len,
            "verdict": None if verdict is None else int(verdict),
            "injected": injected,
        }
""")


def run_isolated(body: str) -> dict:
    """Runs `body` (after PRELUDE) in a fresh Python process; returns the JSON it prints last."""
    script = PRELUDE + textwrap.dedent(body)
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
    )
    if result.returncode != 0:
        raise AssertionError(f"scenario failed:\n{result.stderr}")
    return json.loads(result.stdout.strip().splitlines()[-1])


class ExpiryTest(unittest.TestCase):
    def test_first_packet_waits_out_the_timeout(self):
        # During the clock's first 30 s the expiry cutoff saturates to 0. A packet queued at clock 0
        # must not count as older than that: it has waited no time at all, and expiring it marks its
        # connection FAILED within a second while the agent may still be deciding.
        state = run_isolated("""
            with Sim() as sim:
                flow = Flow("udp", "10.0.0.5", 50000, "93.184.215.14", 443)
                assert sim.ale_connect(flow, pid=1234, payload=b"hello").absorb, "the connect did not pend"
                # Long enough for two maintenance passes.
                time.sleep(2.5)
                print(json.dumps(state(sim, flow, len(sim.drain_injected()))))
        """)
        self.assertEqual(state["pending"], 1, "the packet must still wait for its verdict")
        self.assertEqual(state["verdict"], Verdict.UNDECIDED, "the connection must be undecided")
        self.assertEqual(state["injected"], 0, "nothing may be released yet")

    def test_packet_waits_just_under_the_timeout(self):
        # Close to the timeout but short of it, with the margin covering the real time the scenario
        # takes (well under the 5 s left).
        state = run_isolated(f"""
            with Sim() as sim:
                flow = Flow("udp", "10.0.0.5", 50001, "93.184.215.14", 443)
                assert sim.ale_connect(flow, pid=1234, payload=b"hello").absorb, "the connect did not pend"
                sim.advance_clock({TIMEOUT_MS - 5_000})
                time.sleep(2.5)
                print(json.dumps(state(sim, flow, len(sim.drain_injected()))))
        """)
        self.assertEqual(state["pending"], 1, "the packet must still wait for its verdict")
        self.assertEqual(state["verdict"], Verdict.UNDECIDED, "the connection must be undecided")
        self.assertEqual(state["injected"], 0, "nothing may be released yet")

    def test_unanswered_packet_expires_after_the_timeout(self):
        # Nobody answers: once the packet has waited past the timeout the next maintenance pass
        # takes it out, fails its connection and releases the pended connect (blocked by the
        # FAILED verdict when it is classified again).
        state = run_isolated(f"""
            with Sim() as sim:
                flow = Flow("udp", "10.0.0.5", 50002, "93.184.215.14", 443)
                assert sim.ale_connect(flow, pid=1234, payload=b"hello").absorb, "the connect did not pend"
                sim.advance_clock({TIMEOUT_MS + 1_000})
                # The release is the expiry's last step (after taking the packet out and failing
                # the connection), so wait for it.
                injected = 0
                deadline = time.monotonic() + 5
                while not injected and time.monotonic() < deadline:
                    time.sleep(0.05)
                    injected += len(sim.drain_injected())
                time.sleep(0.2)  # room for a wrong second release to show
                injected += len(sim.drain_injected())
                print(json.dumps(state(sim, flow, injected)))
        """)
        self.assertEqual(state["pending"], 0, "the packet must have expired")
        self.assertEqual(state["verdict"], Verdict.FAILED, "the connection must be FAILED")
        self.assertEqual(state["injected"], 1, "the pended connect must be released")


if __name__ == "__main__":
    unittest.main()
