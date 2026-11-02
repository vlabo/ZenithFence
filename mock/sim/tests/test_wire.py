"""What the agent receives must parse like real traffic: the payload layers and
headers of pended packets, and the connection updates it asks for."""
import struct
import time
import unittest

from support import accept_all, attached

from zfsim import Flow, Verdict, payloads, wait_verdict

TRANSPORT, NETWORK = 4, 3


def accept_temporarily(event):
    """ACCEPT is a temporary verdict: the connection's packets keep pending, so
    each reaches the agent."""
    return Verdict.ACCEPT if event.kind == "connection" else None


def udp_payload(segment):
    """The payload of a UDP segment, checking its length field."""
    length = struct.unpack_from(">H", segment, 4)[0]
    assert length == len(segment), (length, len(segment))
    return segment[8:]


class PayloadTests(unittest.TestCase):
    def test_outbound_ale_payload_starts_at_the_transport_header(self):
        query = payloads.dns_query("example.com", id=7)
        with attached() as (sim, _agent):
            flow = Flow("udp", "10.0.0.5", 50000, "1.1.1.1", 53)
            sim.ale_connect(flow, pid=1, payload=query)
            event = sim.next_event(timeout=5)
            self.assertEqual(event.payload_layer, TRANSPORT)
            self.assertEqual(struct.unpack_from(">HH", event.payload), (50000, 53))
            self.assertEqual(udp_payload(event.payload), query)

    def test_inbound_packet_is_a_whole_ip_packet(self):
        response = payloads.dns_response("example.com", bytes([1, 2, 3, 4]), id=7)
        with attached(accept_temporarily) as (sim, _agent):
            flow = Flow("udp", "10.0.0.5", 50000, "1.1.1.1", 53)
            sim.ale_connect(flow, pid=1)
            sim.next_event(timeout=5)  # the ALE connect's event
            wait_verdict(sim, flow)
            self.assertTrue(sim.packet(flow, "inbound", response).absorb)
            event = sim.next_event(timeout=5)
            self.assertEqual(event.payload_layer, NETWORK)
            ip = event.payload
            self.assertEqual(ip[0] >> 4, 4)
            header_len = (ip[0] & 0xF) * 4
            self.assertEqual(struct.unpack_from(">H", ip, 2)[0], len(ip))
            self.assertEqual(struct.unpack_from(">HH", ip, header_len), (53, 50000))
            self.assertEqual(udp_payload(ip[header_len:]), response)

    def test_inbound_ale_payload_is_labelled_network(self):
        with attached() as (sim, _agent):
            flow = Flow("tcp", "10.0.0.5", 443, "93.184.216.34", 50123)
            self.assertTrue(sim.ale_accept(flow, pid=1, payload=b"hello").absorb)
            event = sim.next_event(timeout=5)
            self.assertEqual(event.payload_layer, NETWORK)
            self.assertEqual(event.payload[0] >> 4, 4, "starts at the IP header")
            self.assertTrue(event.payload.endswith(b"hello"))

    def test_tcp_header_is_well_formed(self):
        with attached(accept_temporarily) as (sim, _agent):
            flow = Flow("tcp", "2001:db8::5", 50001, "2606:4700::1", 443)
            sim.ale_connect(flow, pid=1)  # a connect carries no data: empty payload
            sim.next_event(timeout=5)  # the ALE connect's event
            wait_verdict(sim, flow)
            self.assertTrue(sim.packet(flow, "outbound", b"x").absorb)
            event = sim.next_event(timeout=5)
            self.assertEqual((event.payload_layer, event.payload[0] >> 4), (NETWORK, 6))
            self.assertEqual(struct.unpack_from(">H", event.payload, 4)[0], len(event.payload) - 40)
            sport, dport, _, _, offset = struct.unpack_from(">HHIIB", event.payload, 40)
            self.assertEqual((sport, dport, offset >> 4), (50001, 443, 5))
            self.assertEqual(event.payload[60:], b"x")


class ConnectionUpdateTests(unittest.TestCase):
    def updates(self, sim, cursor):
        """GetConnectionsUpdate from `cursor` (0, or the last update_end's
        timestamp): the flows reported, and the cursor for the next one."""
        sim.send(struct.pack("<BQ", 5, cursor))
        flows = []
        while (event := sim.next_event(timeout=5)) is not None:
            if event.kind == "update_end":
                assert event.timestamp is not None
                return flows, event.timestamp
            if event.kind == "connection_update":
                flows.append(event.flow)
        self.fail("no update_end")

    def test_reports_active_connections_only(self):
        with attached(accept_all) as (sim, _agent):
            active = Flow("tcp", "10.0.0.5", 50010, "93.184.216.34", 443)
            ended = Flow("tcp", "10.0.0.5", 50011, "93.184.216.35", 443)
            idle = Flow("tcp", "10.0.0.5", 50012, "93.184.216.36", 443)
            for flow in (active, ended, idle):
                sim.ale_connect(flow, pid=1)
                self.assertEqual(wait_verdict(sim, flow), Verdict.PERMANENT_ACCEPT)
            while sim.next_event(timeout=0.2) is not None:
                pass

            first, cursor = self.updates(sim, 0)
            self.assertCountEqual(first, [active, ended, idle])
            time.sleep(0.05)  # the cursor is inclusive: step past its millisecond
            sim.packet(active, "outbound", b"data")
            sim.packet(ended, "outbound", b"data")
            sim.endpoint_close(ended, pid=1)
            while sim.next_event(timeout=0.2) is not None:
                pass

            second, cursor = self.updates(sim, cursor)
            self.assertEqual(second, [active], "touched since, not ended")
            time.sleep(0.05)
            self.assertEqual(self.updates(sim, cursor)[0], [], "nothing touched since")


if __name__ == "__main__":
    unittest.main()
