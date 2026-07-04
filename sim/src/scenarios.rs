//! Traffic scenarios: what the fake OS "does" on the network.
//!
//! A [`FlowPlan`] is one connection's whole life, mirroring how the OS drives
//! WFP: resource assignment -> ALE authorization (pends, the agent decides) ->
//! data packets through the IP packet layer -> endpoint closure -> resource
//! release.
//!
//! The default run generates seeded random flows from weighted templates
//! ([`random_flow`]) and never stops. The hand-authored deterministic scenarios
//! (DNS, TLS, blocked remote, loopback, v6, ICMP, reauth, port reuse) each live
//! as their own function in the [`deterministic`] module, currently unwired --
//! kept for when we decide how to schedule them alongside the random loop.
//!
//! Payload realism: first packets carry real-looking application bytes (DNS
//! query/response, TLS ClientHello, HTTP GET). Payloads that reach the agent
//! (the pended first packet) are kept small (<= 256 bytes) because the agent
//! reads events through a 1 KiB pipe buffer.

use std::net::{Ipv4Addr, Ipv6Addr};

use driver::fuzz_api::{Direction, TupleSpecV4, TupleSpecV6};

use crate::rng::SplitMix64;

const TCP: u8 = 6;
const UDP: u8 = 17;

/// A short human label for an IP protocol number, for diagnostics.
pub fn proto_label(protocol: u8) -> String {
    match protocol {
        1 => "ICMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        58 => "ICMPv6".to_string(),
        other => format!("proto{other}"),
    }
}

/// What the agent's policy (kext_tester `handleInfo`) is expected to decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// Verdict lands asynchronously as Accept/PermanentAccept.
    Accepted,
    /// Outbound to 1.1.1.1: the agent replies PermanentBlock.
    Blocked,
    /// Inbound loopback: ALE itself sets Accept and permits, no pend.
    ImmediateAccept,
    /// Not connection-tracked (ICMP): every packet pends on its own, no
    /// connection verdict ever lands in the cache.
    NoVerdict,
}

#[derive(Clone, Copy, Debug)]
pub enum Tuple {
    V4(TupleSpecV4),
    V6(TupleSpecV6),
}

impl Tuple {
    pub fn protocol(&self) -> u8 {
        match self {
            Tuple::V4(t) => t.protocol,
            Tuple::V6(t) => t.protocol,
        }
    }

    pub fn local_port(&self) -> u16 {
        match self {
            Tuple::V4(t) => t.local_port,
            Tuple::V6(t) => t.local_port,
        }
    }

    /// "PROTO local=addr:port remote=addr:port" for diagnostics (v6 bracketed).
    pub fn endpoints(&self) -> String {
        match self {
            Tuple::V4(t) => format!(
                "{} local={}:{} remote={}:{}",
                proto_label(t.protocol),
                Ipv4Addr::from(t.local),
                t.local_port,
                Ipv4Addr::from(t.remote),
                t.remote_port,
            ),
            Tuple::V6(t) => format!(
                "{} local=[{}]:{} remote=[{}]:{}",
                proto_label(t.protocol),
                Ipv6Addr::from(t.local),
                t.local_port,
                Ipv6Addr::from(t.remote),
                t.remote_port,
            ),
        }
    }
}

/// One data packet after authorization.
#[derive(Clone, Debug)]
pub struct Burst {
    pub direction: Direction,
    pub payload: Vec<u8>,
}

fn out(payload: Vec<u8>) -> Burst {
    Burst {
        direction: Direction::Outbound,
        payload,
    }
}

fn inb(payload: Vec<u8>) -> Burst {
    Burst {
        direction: Direction::Inbound,
        payload,
    }
}

/// One connection's planned life.
#[derive(Clone, Debug)]
pub struct FlowPlan {
    /// Scenario label for the summary (template name for random flows).
    pub name: &'static str,
    pub tuple: Tuple,
    /// Direction of the authorization: Outbound = ALE connect, Inbound = ALE accept.
    pub direction: Direction,
    pub process_id: u64,
    /// Payload carried by the ALE authorization packet (reaches the agent).
    pub first_payload: Vec<u8>,
    /// Data packets exchanged once the flow is authorized.
    pub bursts: Vec<Burst>,
    pub expect: Expect,
    /// Fire a reauthorization ALE classify after this many bursts.
    pub reauth_after: Option<usize>,
    /// Report the local port released to the resource-release callout at the end.
    pub release_port: bool,
    /// After closing, open a follow-up flow reusing the local port against a
    /// different remote (same-key reuse would hit the ended-connection cache
    /// entry; see the connection-cache stale-lookup semantic).
    pub follow_up_reuse: bool,
}

impl FlowPlan {
    /// One-line identity for failure messages: scenario, 5-tuple, direction, pid.
    pub fn describe(&self) -> String {
        format!(
            "{} [{} {} pid={}]",
            self.name,
            self.tuple.endpoints(),
            self.direction,
            self.process_id,
        )
    }
}

fn v4(protocol: u8, local: [u8; 4], lport: u16, remote: [u8; 4], rport: u16) -> Tuple {
    Tuple::V4(TupleSpecV4 {
        protocol,
        local,
        local_port: lport,
        remote,
        remote_port: rport,
    })
}

fn v6(protocol: u8, local16: u8, lport: u16, remote16: u8, rport: u16) -> Tuple {
    let mut local = [0u8; 16];
    local[0] = 0x20;
    local[1] = 0x01;
    local[15] = local16;
    let mut remote = [0u8; 16];
    remote[0] = 0x26;
    remote[1] = 0x06;
    remote[15] = remote16;
    Tuple::V6(TupleSpecV6 {
        protocol,
        local,
        local_port: lport,
        remote,
        remote_port: rport,
    })
}

// ---- Application payloads ---------------------------------------------------

/// Encode a domain as a DNS QNAME: each dot-separated label prefixed by its
/// length byte, terminated by a zero (root) byte. Labels are clamped to the
/// 63-byte label limit and empty labels (e.g. a trailing dot) are dropped.
fn encode_qname(domain: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 2);
    for label in domain.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0); // root label terminates the name
    out
}

/// A real-shaped DNS query for `domain`: a standard recursion-desired query with
/// one question, type A (`v6` false) or AAAA (`v6` true) in class IN.
pub fn dns_query_for(id: u16, domain: &str, v6: bool) -> Vec<u8> {
    let qname = encode_qname(domain);
    let qtype: u16 = if v6 { 28 } else { 1 }; // AAAA / A
    let mut p = Vec::with_capacity(12 + qname.len() + 4);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00]); // flags: RD
    p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1, AN/NS/AR=0
    p.extend_from_slice(&qname);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&[0, 1]); // class IN
    p
}

/// A matching DNS response for `domain`: the question echoed back plus one
/// answer carrying `ip` -- a 4-byte A record or a 16-byte AAAA record (the
/// record type follows `ip`'s width).
pub fn dns_response_for(id: u16, domain: &str, ip: &[u8]) -> Vec<u8> {
    let v6 = ip.len() == 16;
    let mut p = dns_query_for(id, domain, v6);
    p[2] = 0x81; // QR + RD
    p[3] = 0x80; // RA
    p[7] = 1; // AN=1
    p.extend_from_slice(&[0xC0, 0x0C]); // answer name: pointer to the question
    let qtype: u16 = if v6 { 28 } else { 1 };
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&[0, 1]); // class IN
    p.extend_from_slice(&[0, 0, 0, 0x3C]); // TTL 60s
    p.extend_from_slice(&(ip.len() as u16).to_be_bytes()); // RDLENGTH
    p.extend_from_slice(ip); // RDATA
    p
}

/// A real-shaped DNS query: header + QD for `example.com` A IN.
pub fn dns_query(id: u16) -> Vec<u8> {
    dns_query_for(id, "example.com", false)
}

/// A matching DNS response: query echo + one A answer (93.184.216.34).
pub fn dns_response(id: u16) -> Vec<u8> {
    dns_response_for(id, "example.com", &[93, 184, 216, 34])
}

/// Read the first answer of the requested family out of a DNS response: the A
/// record (`want_v6 == false`, 4 bytes) or AAAA (`want_v6 == true`, 16 bytes).
/// Walks the real message -- header counts, the question section, then each
/// answer -- following/skipping name compression, so it copes with CNAME chains
/// and multi-record replies from a live resolver, not just our own fabricated
/// ones. Returns `None` if no answer of that family is present or the buffer is
/// malformed. This is how a resolved address flows from the response into a
/// follow-on connection, the way a client reads the answer and dials it.
pub fn dns_answer_ip(response: &[u8], want_v6: bool) -> Option<Vec<u8>> {
    if response.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;

    let mut i = 12; // past the fixed header
    for _ in 0..qdcount {
        i = skip_name(response, i)?;
        i = i.checked_add(4)?; // QTYPE (2) + QCLASS (2)
    }

    let (want_type, want_len) = if want_v6 { (28u16, 16usize) } else { (1u16, 4usize) };
    for _ in 0..ancount {
        i = skip_name(response, i)?;
        let rtype = u16::from_be_bytes([*response.get(i)?, *response.get(i + 1)?]);
        // After the name: TYPE (2) + CLASS (2) + TTL (4), then RDLENGTH (2), RDATA.
        let rdlen = u16::from_be_bytes([*response.get(i + 8)?, *response.get(i + 9)?]) as usize;
        let rdata = i.checked_add(10)?;
        if rtype == want_type && rdlen == want_len {
            return Some(response.get(rdata..rdata.checked_add(rdlen)?)?.to_vec());
        }
        i = rdata.checked_add(rdlen)?;
    }
    None
}

/// Advance past a DNS name starting at `i`, returning the index just after it.
/// Handles the three label forms: the zero root label ends the name, a `0xC0`
/// compression pointer is two bytes and also ends it, and a normal label is a
/// length byte plus that many octets. `None` on a truncated or reserved name.
fn skip_name(msg: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *msg.get(i)?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Some(i + 1);
                }
                i = i.checked_add(1 + len as usize)?;
            }
            0xC0 => {
                msg.get(i + 1)?; // the pointer's second byte must exist
                return Some(i + 2);
            }
            _ => return None, // 0x40 / 0x80 are reserved label types
        }
    }
}

/// The first bytes of a TLS 1.2/1.3 ClientHello record, truncated to fit the
/// agent's pipe read buffer when it rides a pended packet.
pub fn tls_client_hello() -> Vec<u8> {
    let mut p = vec![
        0x16, 0x03, 0x01, 0x00, 0xF8, // record: handshake, TLS1.0, len
        0x01, 0x00, 0x00, 0xF4, // ClientHello, len
        0x03, 0x03, // TLS1.2
    ];
    p.extend((0u8..32).map(|i| i.wrapping_mul(7))); // "random"
    p.resize(200, 0xA5); // extensions padding
    p
}

pub fn http_get() -> Vec<u8> {
    b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: zf-sim\r\nAccept: */*\r\n\r\n".to_vec()
}

pub fn http_response() -> Vec<u8> {
    let mut p =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 512\r\n\r\n".to_vec();
    p.resize(p.len() + 512, b'x');
    p
}

// ---- Deterministic scenarios (currently unwired) -----------------------------
//
// One hand-authored flow per interesting driver path, each its own function.
// Nothing schedules them yet; they wait here until we decide how to interleave
// them with the random loop. They use local addresses (10.0.1.x, loopback)
// distinct from the random flows' 10.1.x, so their connection keys never collide
// (a shared key would coalesce two flows into one connection).
#[allow(dead_code)]
pub mod deterministic {
    use super::*;

    const ICMP: u8 = 1;

    fn icmp_echo(seq: u16) -> Vec<u8> {
        let mut p = vec![8, 0, 0, 0]; // type 8 (echo), code 0, checksum 0
        p.extend_from_slice(&[0, 1]); // identifier
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(b"abcdefghijklmnopqrstuvwabcdefghi"); // classic 32-byte ping
        p
    }

    /// DNS query over UDP to a public resolver; the verdict lands asynchronously.
    pub fn dns_udp() -> FlowPlan {
        FlowPlan {
            name: "dns-udp",
            tuple: v4(UDP, [10, 0, 1, 10], 54321, [8, 8, 8, 8], 53),
            direction: Direction::Outbound,
            process_id: 0,
            first_payload: dns_query(0x1234),
            bursts: vec![inb(dns_response(0x1234))],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: true,
            follow_up_reuse: false,
        }
    }

    /// Outbound HTTPS: TLS handshake, then application data both ways.
    pub fn https_tcp() -> FlowPlan {
        FlowPlan {
            name: "https-tcp",
            tuple: v4(TCP, [10, 0, 1, 11], 49152, [93, 184, 216, 34], 443),
            direction: Direction::Outbound,
            process_id: 0,
            first_payload: Vec::new(), // outbound TCP connect carries no data
            bursts: vec![
                out(tls_client_hello()),
                inb(vec![0x16; 1400]), // ServerHello + cert chain
                inb(vec![0x16; 1400]),
                out(vec![0x14; 51]),  // ChangeCipherSpec/Finished
                inb(vec![0x17; 900]), // application data
                out(vec![0x17; 120]),
            ],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: true,
            follow_up_reuse: false,
        }
    }

    /// Plain HTTP GET / 200 OK.
    pub fn http_get_flow() -> FlowPlan {
        FlowPlan {
            name: "http-get",
            tuple: v4(TCP, [10, 0, 1, 12], 49200, [203, 0, 113, 80], 80),
            direction: Direction::Outbound,
            process_id: 0,
            first_payload: Vec::new(),
            bursts: vec![out(http_get()), inb(http_response())],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        }
    }

    /// Outbound to 1.1.1.1: the agent replies PermanentBlock; the packet layer
    /// must hard-block.
    pub fn blocked_cloudflare() -> FlowPlan {
        FlowPlan {
            name: "blocked-cloudflare",
            tuple: v4(TCP, [10, 0, 1, 13], 49300, [1, 1, 1, 1], 443),
            direction: Direction::Outbound,
            process_id: 0,
            first_payload: Vec::new(),
            bursts: vec![out(tls_client_hello())], // must be blocked at the packet layer
            expect: Expect::Blocked,
            reauth_after: None,
            release_port: true,
            follow_up_reuse: false,
        }
    }

    /// Loopback client half.
    pub fn loopback_out() -> FlowPlan {
        FlowPlan {
            name: "loopback-out",
            tuple: v4(TCP, [127, 0, 0, 1], 49400, [127, 0, 0, 1], 8080),
            direction: Direction::Outbound,
            process_id: 0,
            first_payload: Vec::new(),
            bursts: vec![out(http_get()), inb(http_response())],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        }
    }

    /// Loopback server half: ALE accepts inbound loopback immediately.
    pub fn loopback_in() -> FlowPlan {
        FlowPlan {
            name: "loopback-in",
            tuple: v4(TCP, [127, 0, 0, 1], 8080, [127, 0, 0, 1], 49401),
            direction: Direction::Inbound,
            process_id: 0,
            first_payload: http_get(),
            bursts: vec![inb(http_get()), out(http_response())],
            expect: Expect::ImmediateAccept,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        }
    }

    /// IPv6 HTTPS.
    pub fn https_v6() -> FlowPlan {
        FlowPlan {
            name: "https-v6",
            tuple: v6(TCP, 0x10, 49500, 0x63, 443),
            direction: Direction::Outbound,
            process_id: 0,
            first_payload: Vec::new(),
            bursts: vec![out(tls_client_hello()), inb(vec![0x17; 1200])],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: true,
            follow_up_reuse: false,
        }
    }

    /// IPv6 DNS.
    pub fn dns_v6() -> FlowPlan {
        FlowPlan {
            name: "dns-v6",
            tuple: v6(UDP, 0x11, 49600, 0x88, 53),
            direction: Direction::Outbound,
            process_id: 0,
            first_payload: dns_query(0x77AA),
            bursts: vec![inb(dns_response(0x77AA))],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        }
    }

    /// ICMP echo: not connection-tracked, so every packet pends on its own.
    pub fn icmp_echo_flow() -> FlowPlan {
        FlowPlan {
            name: "icmp-echo",
            tuple: v4(ICMP, [10, 0, 1, 14], 0, [203, 0, 113, 7], 0),
            direction: Direction::Outbound,
            process_id: 0,
            first_payload: Vec::new(),
            bursts: vec![out(icmp_echo(1)), out(icmp_echo(2))],
            expect: Expect::NoVerdict,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        }
    }

    /// Mid-flow reauthorization: an accepted connection is re-classified by ALE.
    pub fn reauth_mid_flow() -> FlowPlan {
        FlowPlan {
            name: "reauth-mid-flow",
            tuple: v4(TCP, [10, 0, 1, 15], 49700, [198, 51, 100, 23], 443),
            direction: Direction::Outbound,
            process_id: 0,
            first_payload: Vec::new(),
            bursts: vec![
                out(tls_client_hello()),
                inb(vec![0x17; 800]),
                out(vec![0x17; 90]),
            ],
            expect: Expect::Accepted,
            reauth_after: Some(2),
            release_port: false,
            follow_up_reuse: false,
        }
    }

    /// Port reuse: release the local port, then reopen it against a new remote
    /// (see [`super::reuse_follow_up`]).
    pub fn port_reuse() -> FlowPlan {
        FlowPlan {
            name: "port-reuse",
            tuple: v4(TCP, [10, 0, 1, 16], 49800, [198, 51, 100, 40], 443),
            direction: Direction::Outbound,
            process_id: 0,
            first_payload: Vec::new(),
            bursts: vec![out(vec![0x17; 200])],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: true,
            follow_up_reuse: true,
        }
    }

    /// Inbound TCP to a local listener (non-loopback).
    pub fn inbound_tcp() -> FlowPlan {
        FlowPlan {
            name: "inbound-tcp",
            tuple: v4(TCP, [10, 0, 1, 17], 8443, [198, 51, 100, 77], 52344),
            direction: Direction::Inbound,
            process_id: 0,
            first_payload: tls_client_hello(),
            bursts: vec![inb(vec![0x17; 600]), out(vec![0x17; 300])],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        }
    }
}

/// The follow-up flow for `follow_up_reuse`: same local port, different remote
/// (a fresh key, like a new socket bound to the just-released port).
pub fn reuse_follow_up(plan: &FlowPlan) -> Option<FlowPlan> {
    if !plan.follow_up_reuse {
        return None;
    }
    let Tuple::V4(t) = plan.tuple else {
        return None;
    };
    let mut remote = t.remote;
    remote[3] = remote[3].wrapping_add(1);
    Some(FlowPlan {
        name: "port-reuse(2)",
        tuple: Tuple::V4(TupleSpecV4 { remote, ..t }),
        direction: Direction::Outbound,
        process_id: plan.process_id,
        first_payload: Vec::new(),
        bursts: vec![out(vec![0x17; 150])],
        expect: Expect::Accepted,
        reauth_after: None,
        release_port: true,
        follow_up_reuse: false,
    })
}

// ---- Random flows --------------------------------------------------------------

/// A seeded random flow for `worker`. Cross-worker keys stay disjoint via the
/// per-worker local-port window (`20000 + worker*2048 + seq`, `seq < 2048`).
/// Within a worker that window is reused every 2048 flows, so a flow's *remote*
/// address must carry enough entropy that the reused (port, local) pair still
/// yields a fresh key -- otherwise the driver treats the repeat as an existing
/// connection and permits it without pending. The v4 remote is 3 random octets;
/// the v6 remote is a random 64-bit interface id for the same reason. Templates
/// are weighted toward the common real-world mix; the costly/special paths
/// (blocked, loopback, ICMP) stay in the deterministic set.
pub fn random_flow(rng: &mut SplitMix64, worker: usize, seq: u16) -> FlowPlan {
    let local_port = 20000 + (worker as u16) * 2048 + seq;
    let local = [10, 1, worker as u8 + 1, rng.range(2, 250) as u8];
    // Public-ish remote. Steer clear of the ranges the driver special-cases, so
    // these templates only exercise the normal pend path: 1.1.1.1 & co (first
    // octet < 11), 127.0.0.0/8 loopback (an inbound loopback connection is
    // accepted at ALE *without pending* -- that path is covered by the
    // deterministic loopback scenarios), and multicast/reserved (>= 224).
    let first_octet = {
        // [11, 222] with 127 skipped, so no loopback remote is ever produced.
        let octet = rng.range(11, 222) as u8;
        if octet < 127 {
            octet
        } else {
            octet + 1
        }
    };
    let remote = [
        first_octet,
        rng.range(0, 255) as u8,
        rng.range(0, 255) as u8,
        rng.range(1, 254) as u8,
    ];
    let process_id = 0; //2000 + rng.range(0, 12) * 111;

    let roll = rng.range(0, 100);
    if roll < 25 {
        // DNS lookup
        let id = rng.next_u64() as u16;
        FlowPlan {
            name: "rnd-dns",
            tuple: v4(UDP, local, local_port, remote, 53),
            direction: Direction::Outbound,
            process_id,
            first_payload: dns_query(id),
            bursts: vec![inb(dns_response(id))],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: rng.chance(50),
            follow_up_reuse: false,
        }
    } else if roll < 55 {
        // HTTPS session with a variable-size exchange
        let mut bursts = vec![out(tls_client_hello())];
        for _ in 0..rng.range(1, 8) {
            let size = rng.range(1, 1400) as usize;
            if rng.chance(60) {
                bursts.push(inb(vec![0x17; size]));
            } else {
                bursts.push(out(vec![0x17; size]));
            }
        }
        FlowPlan {
            name: "rnd-https",
            tuple: v4(TCP, local, local_port, remote, 443),
            direction: Direction::Outbound,
            process_id,
            first_payload: Vec::new(),
            bursts,
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: rng.chance(30),
            follow_up_reuse: false,
        }
    } else if roll < 70 {
        // Plain HTTP
        FlowPlan {
            name: "rnd-http",
            tuple: v4(TCP, local, local_port, remote, 80),
            direction: Direction::Outbound,
            process_id,
            first_payload: Vec::new(),
            bursts: vec![out(http_get()), inb(http_response())],
            expect: Expect::Accepted,
            reauth_after: if rng.chance(20) { Some(1) } else { None },
            release_port: false,
            follow_up_reuse: false,
        }
    } else if roll < 80 {
        // Generic UDP exchange (QUIC-ish sizes)
        let mut bursts = Vec::new();
        for _ in 0..rng.range(1, 5) {
            let size = rng.range(40, 1200) as usize;
            if rng.chance(50) {
                bursts.push(inb(vec![0x40; size]));
            } else {
                bursts.push(out(vec![0x40; size]));
            }
        }
        FlowPlan {
            name: "rnd-udp",
            tuple: v4(
                UDP,
                local,
                local_port,
                remote,
                rng.range(1024, 65000) as u16,
            ),
            direction: Direction::Outbound,
            process_id,
            first_payload: vec![0x40; rng.range(24, 200) as usize],
            bursts,
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: rng.chance(50),
            follow_up_reuse: false,
        }
    } else if roll < 90 {
        // IPv6 HTTPS. The v6 address is only one meaningful byte per side, so
        // once a worker's local-port window wraps (every 2048 flows) those keys
        // start repeating -- and a repeated key looks like an existing
        // connection to the driver, which permits it without pending ("did not
        // pend at ALE"). Give the remote a wide random interface id (like the v4
        // remote's random octets) so a reused (port, local) still makes a fresh
        // key; put the worker in the local address to mirror v4's isolation.
        let mut local6 = [0u8; 16];
        local6[0] = 0x20;
        local6[1] = 0x01;
        local6[8] = worker as u8;
        local6[15] = rng.range(1, 250) as u8;
        let mut remote6 = [0u8; 16];
        remote6[0] = 0x26;
        remote6[1] = 0x06;
        remote6[8..16].copy_from_slice(&rng.next_u64().to_be_bytes());
        FlowPlan {
            name: "rnd-v6",
            tuple: Tuple::V6(TupleSpecV6 {
                protocol: TCP,
                local: local6,
                local_port,
                remote: remote6,
                remote_port: 443,
            }),
            direction: Direction::Outbound,
            process_id,
            first_payload: Vec::new(),
            bursts: vec![
                out(tls_client_hello()),
                inb(vec![0x17; rng.range(100, 1400) as usize]),
            ],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        }
    } else {
        // Inbound TCP (a listener receiving a connection): the agent accepts
        // inbound immediately, so these are cheap.
        FlowPlan {
            name: "rnd-inbound",
            tuple: v4(
                TCP,
                local,
                local_port,
                remote,
                rng.range(1024, 65000) as u16,
            ),
            direction: Direction::Inbound,
            process_id,
            first_payload: vec![0x17; rng.range(1, 250) as usize],
            bursts: vec![inb(vec![0x17; rng.range(1, 1000) as usize])],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answer_ip_reads_a_and_aaaa() {
        let a = dns_response_for(0x1234, "example.com", &[93, 184, 216, 34]);
        assert_eq!(dns_answer_ip(&a, false), Some(vec![93, 184, 216, 34]));
        assert_eq!(dns_answer_ip(&a, true), None); // no AAAA in an A reply

        let v6 = [0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64];
        let aaaa = dns_response_for(0x1234, "example.com", &v6);
        assert_eq!(dns_answer_ip(&aaaa, true), Some(v6.to_vec()));
        assert_eq!(dns_answer_ip(&aaaa, false), None);
    }

    #[test]
    fn answer_ip_skips_cname_and_follows_compression() {
        // A real-shaped reply for www.example.com: a CNAME answer, then the A.
        // The question qname sits at offset 12, so a pointer to the "example.com"
        // suffix is 0xC010 and to the full name 0xC00C.
        let mut m = Vec::new();
        m.extend_from_slice(&0xABCDu16.to_be_bytes()); // id
        m.extend_from_slice(&[0x81, 0x80]); // response, RD+RA
        m.extend_from_slice(&[0, 1, 0, 2, 0, 0, 0, 0]); // QD=1, AN=2
        m.extend_from_slice(b"\x03www\x07example\x03com\x00"); // qname @ offset 12
        m.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        // Answer 1: CNAME www.example.com -> example.com (rdata is a pointer).
        m.extend_from_slice(&[0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xC0, 0x10]);
        // Answer 2: A example.com -> 1.2.3.4.
        m.extend_from_slice(&[0xC0, 0x10, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);

        assert_eq!(dns_answer_ip(&m, false), Some(vec![1, 2, 3, 4]));
        assert_eq!(dns_answer_ip(&m, true), None);
    }

    #[test]
    fn answer_ip_rejects_malformed() {
        assert_eq!(dns_answer_ip(&[], false), None);
        assert_eq!(dns_answer_ip(&[0; 8], false), None); // shorter than a header
    }
}
