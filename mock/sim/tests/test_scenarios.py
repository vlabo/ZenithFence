"""The old CBOR sample scenarios, as scripts that also check the outcome. The
script plays the OS (injecting traffic); a PipeAgent on the pipe decides."""
import unittest

from support import accept_all, attached

from zfsim import Flow, Verdict, payloads, wait_for, wait_verdict


class Scenarios(unittest.TestCase):
    def test_basic_v4(self):
        """One outbound TCP flow: authorize, data both ways, close, release."""
        with attached(accept_all) as (sim, _agent):
            flow = Flow("tcp", "10.0.0.5", 40001, "93.184.216.34", 443)

            self.assertTrue(sim.ale_connect(flow, pid=1000).absorb)
            self.assertEqual(wait_verdict(sim, flow), Verdict.PERMANENT_ACCEPT)

            self.assertTrue(sim.packet(flow, "outbound", b"GET / HTTP/1.1\r\n\r\n").permit)
            self.assertTrue(sim.packet(flow, "inbound", b"HTTP/1.1 200 OK\r\n").permit)

            sim.endpoint_close(flow, pid=1000)
            sim.resource_release("tcp", 40001)

            first = sim.next_event(timeout=5)
            self.assertEqual((first.kind, first.flow, first.pid), ("connection", flow, 1000))
            self.assertEqual(sim.packet_cache_len, 0)

    def test_mixed_v4v6_parallel(self):
        """Three connections authorized back to back, data, then all closed."""
        flows = [
            Flow("tcp", "10.0.0.1", 40001, "93.184.216.34", 443),
            Flow("tcp", "10.0.0.2", 40002, "8.8.8.8", 53),
            Flow("tcp", "2001:db8::1", 40003, "2606:4700::64", 443),
        ]
        with attached(accept_all) as (sim, _agent):
            for pid, flow in enumerate(flows, start=1001):
                self.assertTrue(sim.ale_connect(flow, pid=pid).absorb, flow)
            for flow in flows:
                self.assertEqual(wait_verdict(sim, flow), Verdict.PERMANENT_ACCEPT, flow)
            for flow in flows:
                self.assertTrue(sim.packet(flow, "outbound", b"GET /").permit, flow)
            for pid, flow in enumerate(flows, start=1001):
                sim.endpoint_close(flow, pid=pid)

            asked = set()
            while len(asked) < len(flows):
                event = sim.next_event(timeout=5)
                self.assertIsNotNone(event, f"events for {set(flows) - asked}")
                if event.kind == "connection":
                    asked.add(event.flow)
            self.assertEqual(asked, set(flows))

    def test_icmp_burst(self):
        """ICMP isn't connection-tracked: every packet pends on its own and is
        re-injected once the agent accepts it."""
        with attached(accept_all) as (sim, _agent):
            for i in range(32):
                flow = Flow("icmp", f"10.0.1.{i}", 0, "10.0.1.254", 0)
                self.assertTrue(sim.packet(flow, "outbound", b"\x08\x00\x00\x00").absorb, i)

            injected = []
            wait_for(lambda: injected.extend(sim.drain_injected()) or len(injected) >= 32)
            self.assertEqual(len(injected), 32)
            self.assertEqual(sim.packet_cache_len, 0)
            self.assertIsNone(sim.verdict_for(Flow("icmp", "10.0.1.0", 0, "10.0.1.254", 0)))

    def test_dns_then_connect(self):
        """A DNS lookup whose query reaches the agent, then a connection to the
        address the answer carried; the policy blocks that address."""
        resolved = "1.1.1.1"

        def policy(event):
            if event.kind != "connection":
                return None
            if event.flow.remote == resolved:
                return Verdict.PERMANENT_BLOCK
            return Verdict.PERMANENT_ACCEPT

        with attached(policy) as (sim, _agent):
            dns = Flow("udp", "10.0.0.5", 50000, "9.9.9.9", 53)
            query = payloads.dns_query("one.one.one.one", id=7)
            self.assertTrue(sim.ale_connect(dns, pid=42, payload=query).absorb)
            self.assertEqual(wait_verdict(sim, dns), Verdict.PERMANENT_ACCEPT)
            response = payloads.dns_response("one.one.one.one", bytes([1, 1, 1, 1]), id=7)
            self.assertTrue(sim.packet(dns, "inbound", response).permit)
            sim.endpoint_close(dns, pid=42)
            sim.resource_release("udp", 50000)

            event = sim.next_event(timeout=5)
            # The event carries the pended packet from its IP header on.
            self.assertTrue(event.payload.endswith(query), "the agent sees the query it decides on")

            https = Flow("tcp", "10.0.0.5", 50001, resolved, 443)
            self.assertTrue(sim.ale_connect(https, pid=42, payload=payloads.tls_client_hello()).absorb)
            self.assertEqual(wait_verdict(sim, https), Verdict.PERMANENT_BLOCK)
            outcome = sim.packet(https, "outbound", payloads.tls_client_hello())
            self.assertTrue(outcome.block and not outcome.absorb, outcome)


if __name__ == "__main__":
    unittest.main()
