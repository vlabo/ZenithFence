"""Seeded random traffic (`zfsim.traffic`) against the driver."""
import unittest
from collections import Counter

from support import attached

from zfsim import Verdict
from zfsim.traffic import random_flows, replay_injected, run_flow


class TrafficTests(unittest.TestCase):
    def test_same_seed_same_flows(self):
        first = [repr(plan.flow) for plan in random_flows(7, count=50)]
        again = [repr(plan.flow) for plan in random_flows(7, count=50)]
        other = [repr(plan.flow) for plan in random_flows(8, count=50)]
        self.assertEqual(first, again)
        self.assertNotEqual(first, other)

    def test_random_flows_are_enforced(self):
        # Alternate verdicts so both the accept and the block paths run.
        decided = Counter()

        def policy(event):
            if event.kind != "connection":
                return None
            verdict = Verdict.PERMANENT_BLOCK if event.id % 3 == 0 else Verdict.PERMANENT_ACCEPT
            decided[verdict] += 1
            return verdict

        with attached(policy) as (sim, _agent):
            kinds = Counter()
            for plan in random_flows(0x5EED, count=200):
                result = run_flow(sim, plan)
                self.assertIsNotNone(result.verdict, plan)
                replay_injected(sim)
                kinds[plan.name] += 1
            self.assertEqual(set(kinds), {"dns", "https", "http", "udp", "v6", "inbound"})
            self.assertTrue(decided[Verdict.PERMANENT_BLOCK] and decided[Verdict.PERMANENT_ACCEPT])
            self.assertEqual(sim.packet_cache_len, 0)


if __name__ == "__main__":
    unittest.main()
