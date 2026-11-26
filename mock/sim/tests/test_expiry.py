"""A packet nobody answers is blocked only once it has waited the driver's verdict timeout
(PACKET_VERDICT_TIMEOUT_MS, 30 s), however early after the driver's load it was queued."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import unittest

# Run in a process of its own: the mock clock counts from its first read in the process (mock/wdk
# get_monotonic_ms), so only a fresh process queues its first packet at clock 0. Loading the driver
# does not read the clock; the ALE connect's queueing is the first read.
FIRST_PACKET = textwrap.dedent("""
    import time
    from zfsim import Flow, Sim

    with Sim() as sim:
        flow = Flow("tcp", "10.0.0.5", 50000, "93.184.215.14", 443)
        assert sim.ale_connect(flow, pid=1234).absorb, "the connect did not pend"
        # Long enough for two maintenance passes (one a second).
        time.sleep(2.5)
        print(int(sim.verdict_for(flow) or 0))
""")


class FirstPacketTest(unittest.TestCase):
    def test_first_packet_waits_out_the_timeout(self):
        # During the clock's first 30 s the expiry cutoff saturates to 0. A packet queued at clock 0
        # must not count as older than that: it has waited no time at all, and expiring it marks its
        # connection FAILED within a second while the agent may still be deciding.
        result = subprocess.run(
            [sys.executable, "-c", FIRST_PACKET], capture_output=True, text=True, timeout=60,
            env={**os.environ},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        verdict = int(result.stdout.strip().splitlines()[-1])
        self.assertEqual(verdict, 0, "the connection must still be undecided, not FAILED (10)")


if __name__ == "__main__":
    unittest.main()
