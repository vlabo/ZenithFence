"""The payload builders and the DNS answer reader (no driver, no network)."""
import struct
import unittest

from zfsim import payloads
from zfsim.dns import answer_ip


class PayloadTests(unittest.TestCase):
    def test_answer_ip_reads_a_and_aaaa(self):
        a = payloads.dns_response("example.com", bytes([93, 184, 216, 34]))
        self.assertEqual(answer_ip(a), "93.184.216.34")
        self.assertIsNone(answer_ip(a, v6=True))
        v6 = bytes([0x26, 0x06, 0x47, 0] + [0] * 11 + [0x64])
        aaaa = payloads.dns_response("example.com", v6)
        self.assertEqual(answer_ip(aaaa, v6=True), "2606:4700::64")
        self.assertIsNone(answer_ip(aaaa))

    def test_answer_ip_follows_cname_and_compression(self):
        m = struct.pack(">HHHHHH", 0xABCD, 0x8180, 1, 2, 0, 0)
        m += b"\x03www\x07example\x03com\x00" + b"\x00\x01\x00\x01"
        m += bytes([0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 0x10])  # CNAME
        m += bytes([0xC0, 0x10, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4])  # A
        self.assertEqual(answer_ip(m), "1.2.3.4")

    def test_answer_ip_rejects_malformed(self):
        self.assertIsNone(answer_ip(b""))
        self.assertIsNone(answer_ip(b"\x00" * 8))
        self.assertIsNone(answer_ip(payloads.dns_response()[:-2]))

    def test_client_hello_is_well_formed(self):
        hello = payloads.tls_client_hello("github.com")
        record_type, _, record_len = struct.unpack_from(">BHH", hello)
        self.assertEqual((record_type, record_len), (0x16, len(hello) - 5))
        self.assertEqual(hello[5], 0x01)  # ClientHello
        self.assertEqual(int.from_bytes(hello[6:9], "big"), len(hello) - 9)
        # Walk to the extensions and find the SNI.
        i = 9 + 2 + 32
        i += 1 + hello[i]  # session id
        i += 2 + struct.unpack_from(">H", hello, i)[0]  # cipher suites
        i += 1 + hello[i]  # compression
        ext_len = struct.unpack_from(">H", hello, i)[0]
        i += 2
        self.assertEqual(i + ext_len, len(hello))
        ext_type, _length = struct.unpack_from(">HH", hello, i)
        self.assertEqual(ext_type, 0)
        name_len = struct.unpack_from(">H", hello, i + 4 + 3)[0]
        self.assertEqual(hello[i + 4 + 5 : i + 4 + 5 + name_len], b"github.com")


if __name__ == "__main__":
    unittest.main()
