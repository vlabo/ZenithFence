"""Real DNS: the machine's configured resolver, and reading answers out of a
response. Building queries / responses is in `zfsim.payloads`."""
from __future__ import annotations

import ipaddress
import os
import struct
import sys


def default_resolver() -> str | None:
    """The first DNS server the OS is configured with (IPv4 on Windows), or
    None if none can be read. `$ZF_DNS_SERVER` overrides it (e.g. in a
    container, whose own resolver is a loopback stub)."""
    if os.environ.get("ZF_DNS_SERVER"):
        return os.environ["ZF_DNS_SERVER"]
    if sys.platform == "win32":
        return _windows_resolver()
    try:
        with open("/etc/resolv.conf") as conf:
            for line in conf:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1].split("%")[0]
    except OSError:
        pass
    return None


def _windows_resolver() -> str | None:
    import ctypes
    from ctypes import POINTER, Structure, byref, c_char, c_uint32, c_ulong

    class IP_ADDR_STRING(Structure):
        pass

    IP_ADDR_STRING._fields_ = [
        ("Next", POINTER(IP_ADDR_STRING)),
        ("IpAddress", c_char * 16),
        ("IpMask", c_char * 16),
        ("Context", c_uint32),
    ]

    class FIXED_INFO(Structure):
        _fields_ = [
            ("HostName", c_char * 132),
            ("DomainName", c_char * 132),
            ("CurrentDnsServer", POINTER(IP_ADDR_STRING)),
            ("DnsServerList", IP_ADDR_STRING),
            ("NodeType", c_uint32),
            ("ScopeId", c_char * 260),
            ("EnableRouting", c_uint32),
            ("EnableProxy", c_uint32),
            ("EnableDns", c_uint32),
        ]

    get_network_params = ctypes.windll.iphlpapi.GetNetworkParams
    size = c_ulong(0)
    get_network_params(None, byref(size))  # sizes the buffer
    buf = ctypes.create_string_buffer(max(size.value, ctypes.sizeof(FIXED_INFO)))
    if get_network_params(buf, byref(size)) != 0:
        return None
    entry = FIXED_INFO.from_buffer(buf).DnsServerList
    while True:
        address = entry.IpAddress.decode(errors="ignore")
        if address and address != "0.0.0.0":
            return address
        if not entry.Next:
            return None
        entry = entry.Next.contents


def _skip_name(msg: bytes, i: int) -> int:
    while True:
        length = msg[i]
        if length & 0xC0 == 0xC0:  # compression pointer ends the name
            return i + 2
        if length & 0xC0:
            raise ValueError("reserved label type")
        i += 1 + length
        if length == 0:
            return i


def answer_ip(response: bytes, v6: bool = False) -> str | None:
    """The first A (or AAAA if `v6`) address in a DNS response, as a string;
    None if there is none or the message is malformed. Copes with CNAME chains
    and name compression, so it reads real resolver replies."""
    try:
        qdcount, ancount = struct.unpack_from(">HH", response, 4)
        i = 12
        for _ in range(qdcount):
            i = _skip_name(response, i) + 4
        want_type, want_len = (28, 16) if v6 else (1, 4)
        for _ in range(ancount):
            i = _skip_name(response, i)
            rtype, _, _, rdlen = struct.unpack_from(">HHIH", response, i)
            i += 10
            if rtype == want_type and rdlen == want_len:
                return str(ipaddress.ip_address(bytes(response[i : i + rdlen])))
            i += rdlen
    except (IndexError, struct.error, ValueError):
        return None
    return None
