//! Traffic scenarios: what the fake OS "does" on the network.
//!
//! A [`FlowPlan`] is one connection's whole life, mirroring how the OS drives
//! WFP: resource assignment -> ALE authorization (pends, the agent decides) ->
//! data packets through the IP packet layer -> endpoint closure -> resource
//! release. A fixed deterministic set always runs (guaranteed coverage of the
//! interesting paths: DNS, TLS, blocked remote, loopback, v6, ICMP, reauth,
//! port reuse); on top of it the producer generates N seeded random flows from
//! weighted templates.
//!
//! Payload realism: first packets carry real-looking application bytes (DNS
//! query/response, TLS ClientHello, HTTP GET). Payloads that reach the agent
//! (the pended first packet) are kept small (<= 256 bytes) because the agent
//! reads events through a 1 KiB pipe buffer.

use driver::fuzz_api::{Direction, TupleSpecV4, TupleSpecV6};

use crate::rng::SplitMix64;

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;

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
}

/// One data packet after authorization.
#[derive(Clone, Debug)]
pub struct Burst {
    pub direction: Direction,
    pub payload: Vec<u8>,
}

fn out(payload: Vec<u8>) -> Burst {
    Burst { direction: Direction::Outbound, payload }
}

fn inb(payload: Vec<u8>) -> Burst {
    Burst { direction: Direction::Inbound, payload }
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

/// A real-shaped DNS query: header + QD for `example.com` A IN.
pub fn dns_query(id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(29);
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&[0x01, 0x00]); // RD
    p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1
    p.extend_from_slice(b"\x07example\x03com\x00");
    p.extend_from_slice(&[0, 1, 0, 1]); // A IN
    p
}

/// A matching DNS response: query echo + one A answer.
pub fn dns_response(id: u16) -> Vec<u8> {
    let mut p = dns_query(id);
    p[2] = 0x81; // QR + RD
    p[3] = 0x80; // RA
    p[7] = 1; // AN=1
    p.extend_from_slice(&[0xC0, 0x0C]); // name pointer
    p.extend_from_slice(&[0, 1, 0, 1]); // A IN
    p.extend_from_slice(&[0, 0, 0, 0x3C]); // TTL 60
    p.extend_from_slice(&[0, 4, 93, 184, 216, 34]); // RDATA
    p
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
    let mut p = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 512\r\n\r\n".to_vec();
    p.resize(p.len() + 512, b'x');
    p
}

fn icmp_echo(seq: u16) -> Vec<u8> {
    let mut p = vec![8, 0, 0, 0]; // type 8 (echo), code 0, checksum 0
    p.extend_from_slice(&[0, 1]); // identifier
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(b"abcdefghijklmnopqrstuvwabcdefghi"); // classic 32-byte ping
    p
}

// ---- Deterministic scenario set ----------------------------------------------
//
// Local ports stay below 20000: the random flows use 20000+ so keys never
// collide across the two sets (a shared key would coalesce into one connection).

pub fn deterministic() -> Vec<FlowPlan> {
    vec![
        FlowPlan {
            name: "dns-udp",
            tuple: v4(UDP, [10, 0, 1, 10], 54321, [8, 8, 8, 8], 53),
            direction: Direction::Outbound,
            process_id: 1001,
            first_payload: dns_query(0x1234),
            bursts: vec![inb(dns_response(0x1234))],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: true,
            follow_up_reuse: false,
        },
        FlowPlan {
            name: "https-tcp",
            tuple: v4(TCP, [10, 0, 1, 11], 49152, [93, 184, 216, 34], 443),
            direction: Direction::Outbound,
            process_id: 1002,
            first_payload: Vec::new(), // outbound TCP connect carries no data
            bursts: vec![
                out(tls_client_hello()),
                inb(vec![0x16; 1400]), // ServerHello + cert chain
                inb(vec![0x16; 1400]),
                out(vec![0x14; 51]), // ChangeCipherSpec/Finished
                inb(vec![0x17; 900]), // application data
                out(vec![0x17; 120]),
            ],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: true,
            follow_up_reuse: false,
        },
        FlowPlan {
            name: "http-get",
            tuple: v4(TCP, [10, 0, 1, 12], 49200, [203, 0, 113, 80], 80),
            direction: Direction::Outbound,
            process_id: 1003,
            first_payload: Vec::new(),
            bursts: vec![out(http_get()), inb(http_response())],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        },
        FlowPlan {
            name: "blocked-cloudflare",
            tuple: v4(TCP, [10, 0, 1, 13], 49300, [1, 1, 1, 1], 443),
            direction: Direction::Outbound,
            process_id: 1004,
            first_payload: Vec::new(),
            bursts: vec![out(tls_client_hello())], // must be blocked at the packet layer
            expect: Expect::Blocked,
            reauth_after: None,
            release_port: true,
            follow_up_reuse: false,
        },
        FlowPlan {
            name: "loopback-out",
            tuple: v4(TCP, [127, 0, 0, 1], 49400, [127, 0, 0, 1], 8080),
            direction: Direction::Outbound,
            process_id: 1005,
            first_payload: Vec::new(),
            bursts: vec![out(http_get()), inb(http_response())],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        },
        FlowPlan {
            name: "loopback-in",
            tuple: v4(TCP, [127, 0, 0, 1], 8080, [127, 0, 0, 1], 49401),
            direction: Direction::Inbound,
            process_id: 1006,
            first_payload: http_get(),
            bursts: vec![inb(http_get()), out(http_response())],
            expect: Expect::ImmediateAccept,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        },
        FlowPlan {
            name: "https-v6",
            tuple: v6(TCP, 0x10, 49500, 0x63, 443),
            direction: Direction::Outbound,
            process_id: 1007,
            first_payload: Vec::new(),
            bursts: vec![out(tls_client_hello()), inb(vec![0x17; 1200])],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: true,
            follow_up_reuse: false,
        },
        FlowPlan {
            name: "dns-v6",
            tuple: v6(UDP, 0x11, 49600, 0x88, 53),
            direction: Direction::Outbound,
            process_id: 1001,
            first_payload: dns_query(0x77AA),
            bursts: vec![inb(dns_response(0x77AA))],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        },
        FlowPlan {
            name: "icmp-echo",
            tuple: v4(ICMP, [10, 0, 1, 14], 0, [203, 0, 113, 7], 0),
            direction: Direction::Outbound,
            process_id: 1008,
            first_payload: Vec::new(),
            bursts: vec![out(icmp_echo(1)), out(icmp_echo(2))],
            expect: Expect::NoVerdict,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        },
        FlowPlan {
            name: "reauth-mid-flow",
            tuple: v4(TCP, [10, 0, 1, 15], 49700, [198, 51, 100, 23], 443),
            direction: Direction::Outbound,
            process_id: 1009,
            first_payload: Vec::new(),
            bursts: vec![out(tls_client_hello()), inb(vec![0x17; 800]), out(vec![0x17; 90])],
            expect: Expect::Accepted,
            reauth_after: Some(2),
            release_port: false,
            follow_up_reuse: false,
        },
        FlowPlan {
            name: "port-reuse",
            tuple: v4(TCP, [10, 0, 1, 16], 49800, [198, 51, 100, 40], 443),
            direction: Direction::Outbound,
            process_id: 1010,
            first_payload: Vec::new(),
            bursts: vec![out(vec![0x17; 200])],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: true,
            follow_up_reuse: true,
        },
        FlowPlan {
            name: "inbound-tcp",
            tuple: v4(TCP, [10, 0, 1, 17], 8443, [198, 51, 100, 77], 52344),
            direction: Direction::Inbound,
            process_id: 1011,
            first_payload: tls_client_hello(),
            bursts: vec![inb(vec![0x17; 600]), out(vec![0x17; 300])],
            expect: Expect::Accepted,
            reauth_after: None,
            release_port: false,
            follow_up_reuse: false,
        },
    ]
}

/// The follow-up flow for `follow_up_reuse`: same local port, different remote
/// (a fresh key, like a new socket bound to the just-released port).
pub fn reuse_follow_up(plan: &FlowPlan) -> Option<FlowPlan> {
    if !plan.follow_up_reuse {
        return None;
    }
    let Tuple::V4(t) = plan.tuple else { return None };
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

/// A seeded random flow for `worker`, using a per-worker disjoint local-port
/// range so keys never collide across workers. Templates are weighted toward
/// the common real-world mix; the costly/special paths (blocked, loopback,
/// ICMP) stay in the deterministic set.
pub fn random_flow(rng: &mut SplitMix64, worker: usize, seq: u16) -> FlowPlan {
    let local_port = 20000 + (worker as u16) * 2048 + seq;
    let local = [10, 1, worker as u8 + 1, rng.range(2, 250) as u8];
    // Public-ish remote, avoiding the special-cased ranges (1.1.1.1, loopback,
    // multicast/reserved >= 224).
    let remote = [
        rng.range(11, 223) as u8,
        rng.range(0, 255) as u8,
        rng.range(0, 255) as u8,
        rng.range(1, 254) as u8,
    ];
    let process_id = 2000 + rng.range(0, 12) * 111;

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
            tuple: v4(UDP, local, local_port, remote, rng.range(1024, 65000) as u16),
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
        // IPv6 HTTPS
        FlowPlan {
            name: "rnd-v6",
            tuple: v6(
                TCP,
                rng.range(1, 250) as u8,
                local_port,
                rng.range(1, 250) as u8,
                443,
            ),
            direction: Direction::Outbound,
            process_id,
            first_payload: Vec::new(),
            bursts: vec![out(tls_client_hello()), inb(vec![0x17; rng.range(100, 1400) as usize])],
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
            tuple: v4(TCP, local, local_port, remote, rng.range(1024, 65000) as u16),
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
