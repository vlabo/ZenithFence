"""`Sim.serve()`: an agent attached over the real pipe / Unix socket, with the
script observing the events and verdicts that pass between them."""
import subprocess
import time
import unittest

from support import accept_all, endpoint_name

from zfsim import Flow, Sim, Verdict, wait_for, wait_verdict
from zfsim.agents import PipeAgent, kext_tester_path, start_kext_tester


class ServeTests(unittest.TestCase):
    def test_tee_shows_events_and_verdicts(self):
        with Sim() as sim:
            agent = PipeAgent(sim.serve(endpoint_name()), accept_all)
            self.assertTrue(sim.wait_agent(timeout=5))
            self.assertTrue(sim.agent_connected)

            flow = Flow("tcp", "10.0.0.5", 50000, "93.184.216.34", 443)
            self.assertTrue(sim.ale_connect(flow, pid=9).absorb)
            self.assertEqual(wait_verdict(sim, flow), Verdict.PERMANENT_ACCEPT)

            event = sim.next_event(timeout=5)
            self.assertEqual((event.kind, event.flow), ("connection", flow))
            command = sim.next_command(timeout=5)
            self.assertEqual(
                (command.name, command.id, command.verdict),
                ("verdict", event.id, Verdict.PERMANENT_ACCEPT),
            )
            self.assertEqual([e.id for e in agent.events], [event.id])
        agent.join()

    def test_agent_hanging_up_is_visible(self):
        with Sim() as sim:
            agent = PipeAgent(sim.serve(endpoint_name()))
            self.assertTrue(sim.wait_agent(timeout=5))
            agent.stop()
            self.assertTrue(wait_for(lambda: not sim.agent_connected), "agent gone")

    def test_close_without_an_agent_does_not_hang(self):
        started = time.monotonic()
        with Sim() as sim:
            sim.serve(endpoint_name())
            self.assertFalse(sim.wait_agent(timeout=0.1))
        self.assertLess(time.monotonic() - started, 5)
        # The driver was unloaded: the next Sim loads it again.
        with Sim() as sim:
            self.assertTrue(sim.filter_engine()["committed"])

    @unittest.skipUnless(kext_tester_path(), "kext_tester not built (just sim-build-agent)")
    def test_kext_tester_policy(self):
        """The Go test agent blocks outbound to 1.1.1.1 and accepts the rest."""
        name = endpoint_name()
        with Sim() as sim:
            sim.serve(name)
            agent = start_kext_tester(name, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            try:
                self.assertTrue(sim.wait_agent(timeout=10), "kext_tester attached")
                blocked = Flow("tcp", "10.0.0.5", 50001, "1.1.1.1", 443)
                allowed = Flow("udp", "10.0.0.5", 50002, "9.9.9.9", 53)
                sim.ale_connect(blocked, pid=1)
                sim.ale_connect(allowed, pid=1)
                self.assertEqual(wait_verdict(sim, blocked), Verdict.PERMANENT_BLOCK)
                self.assertEqual(wait_verdict(sim, allowed), Verdict.PERMANENT_ACCEPT)
            finally:
                sim.close()
                try:
                    agent.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    agent.kill()
                    raise


if __name__ == "__main__":
    unittest.main()
