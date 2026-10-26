"""Real-looking application payloads for the packets a script injects.

Payloads that ride a pended packet reach the agent inside the event, so keep
those small (the Go agent reads events through a 1 KiB buffer).
"""
from __future__ import annotations

import struct


def _qname(domain: str) -> bytes:
    out = bytearray()
    for label in filter(None, domain.split(".")):
        raw = label.encode()[:63]
        out += bytes([len(raw)]) + raw
    return bytes(out + b"\x00")


def dns_query(domain: str = "example.com", id: int = 0x1234, v6: bool = False) -> bytes:
    """A recursion-desired DNS query for `domain`, type A (or AAAA if `v6`)."""
    qtype = 28 if v6 else 1
    header = struct.pack(">HHHHHH", id, 0x0100, 1, 0, 0, 0)
    return header + _qname(domain) + struct.pack(">HH", qtype, 1)


def dns_response(domain: str = "example.com", ip: bytes = b"\x5d\xb8\xd8\x22", id: int = 0x1234) -> bytes:
    """The matching response: the question echoed plus one answer carrying
    `ip` (4 bytes: an A record, 16 bytes: AAAA)."""
    v6 = len(ip) == 16
    qtype = 28 if v6 else 1
    header = struct.pack(">HHHHHH", id, 0x8180, 1, 1, 0, 0)
    question = _qname(domain) + struct.pack(">HH", qtype, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 60, len(ip)) + bytes(ip)
    return header + question + answer


def tls_client_hello(server_name: str = "example.com") -> bytes:
    """A well-formed TLS ClientHello record carrying `server_name` in the SNI
    extension (and TLS 1.3 / 1.2 in supported_versions), as a parser expects."""
    name = server_name.encode()
    sni = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name  # list: host_name entry
    versions = bytes([4, 0x03, 0x04, 0x03, 0x03])
    extensions = struct.pack(">HH", 0x0000, len(sni)) + sni
    extensions += struct.pack(">HH", 0x002B, len(versions)) + versions
    suites = (0x1301, 0x1302, 0xC02F)  # AES128-GCM, AES256-GCM, ECDHE-RSA-AES128-GCM
    body = (
        b"\x03\x03"  # legacy_version TLS 1.2
        + bytes((i * 7) & 0xFF for i in range(32))  # random
        + b"\x00"  # no session id
        + struct.pack(">H", 2 * len(suites))
        + b"".join(struct.pack(">H", s) for s in suites)
        + b"\x01\x00"  # compression: null
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def http_get(host: str = "example.com") -> bytes:
    return (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: zfsim\r\nAccept: */*\r\n\r\n"
    ).encode()


def http_response(body_len: int = 512) -> bytes:
    head = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {body_len}\r\n\r\n"
    return head.encode() + b"x" * body_len
