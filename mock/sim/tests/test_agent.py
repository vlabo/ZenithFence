"""The basics: loading the driver, the pend -> agent -> verdict round trip over
the pipe, and the `Sim` lifecycle."""
import threading
import unittest

from support import attached

from zfsim import Flow, Sim, Verdict, wait_verdict


class AgentTests(unittest.TestCase):
    def test_registers_production_callouts(self):
        with Sim() as sim:
            engine = sim.filter_engine()
            self.assertTrue(engine["committed"])
            self.assertEqual(len(engine["callouts"]), 12)
            self.assertTrue(all(filter_id != 0 for _, _, filter_id in engine["callouts"]))

    def test_outbound_connect_pends_until_the_agent_decides(self):
        release = threading.Event()

        def policy(event):
            release.wait(5)  # hold the decision until the test has looked
            return Verdict.PERMANENT_ACCEPT if event.kind == "connection" else None

        with attached(policy) as (sim, _agent):
            flow = Flow("tcp", "10.0.0.5", 50000, "1.1.1.1", 443)

            outcome = sim.ale_connect(flow, pid=1234)
            self.assertTrue(outcome.absorb, "first packet is pended for the agent")

            event = sim.next_event(timeout=5)
            assert event is not None, "driver asked the agent"
            self.assertEqual(event.kind, "connection")
            self.assertEqual(event.flow, flow)
            self.assertEqual(event.pid, 1234)
            self.assertEqual(event.direction, "outbound")
            self.assertEqual(sim.packet_cache_len, 1)
            self.assertEqual(sim.verdict_for(flow), Verdict.UNDECIDED)

            release.set()
            self.assertEqual(wait_verdict(sim, flow), Verdict.PERMANENT_ACCEPT)
            self.assertEqual(sim.packet_cache_len, 0)

    def test_agent_policy_decides(self):
        def policy(event):
            if event.kind != "connection" or event.flow is None:
                return None
            blocked = event.flow.remote == "1.1.1.1"
            return Verdict.PERMANENT_BLOCK if blocked else Verdict.PERMANENT_ACCEPT

        with attached(policy) as (sim, _agent):
            bad = Flow("tcp", "10.0.0.5", 50001, "1.1.1.1", 443)
            good = Flow("udp", "10.0.0.5", 50002, "9.9.9.9", 53)
            sim.ale_connect(bad, pid=1)
            sim.ale_connect(good, pid=1)

            self.assertEqual(wait_verdict(sim, bad), Verdict.PERMANENT_BLOCK)
            self.assertEqual(wait_verdict(sim, good), Verdict.PERMANENT_ACCEPT)

    def test_ipv6_flow(self):
        with attached() as (sim, _agent):
            flow = Flow("tcp", "fd00::5", 50003, "2606:4700::1111", 443)
            self.assertTrue(sim.ale_connect(flow, pid=7).absorb)
            event = sim.next_event(timeout=5)
            assert event is not None and event.flow is not None
            self.assertEqual(event.flow, flow)
            self.assertTrue(event.flow.is_v6)

    def test_only_one_sim_at_a_time(self):
        with Sim(), self.assertRaisesRegex(RuntimeError, "already open"):
            Sim()
        Sim().close()  # free again once the first is closed

    def test_dropped_sim_unloads_the_driver(self):
        Sim()  # never closed: garbage
        with Sim() as sim:
            self.assertTrue(sim.filter_engine()["committed"])

    def test_close_is_idempotent_and_ends_queues(self):
        sim = Sim()
        sim.close()
        sim.close()
        self.assertIsNone(sim.next_event(timeout=0.1))
        with self.assertRaises(RuntimeError):
            sim.ale_connect(Flow("tcp", "10.0.0.5", 1, "1.1.1.1", 2))


if __name__ == "__main__":
    unittest.main()
