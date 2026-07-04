//! CBOR scenario-file executor.
//!
//! Replays an authored scenario file against the driver instead of the seeded
//! random [`crate::producer`]. The file is either **CBOR** (`.cbor`: a sequence
//! of record maps per RFC 8742, compact) or **JSON Lines** (`.json`: one record
//! object per line / NDJSON, human-readable for debugging) -- chosen by extension.
//! Both are decoded as a LAZY STREAM: exactly one record is parsed at a time and
//! dispatched before the next is read, so the whole file is never buffered and a
//! scenario can be arbitrarily long. Each record carries an absolute timestamp
//! (`ts`, microseconds since scenario start) and one command.
//!
//! Execution is *global-timeline dispatch*: a single scheduler thread reads the
//! file in order, sleeps the delta between consecutive records' timestamps, then
//! hands each command to the next free worker in a pool. Workers run the matching
//! [`driver::fuzz_api`] callout entry point immediately, so records that share a
//! timestamp (delta 0) are injected in parallel -- genuine OS threads hammering
//! the one global device, which is what surfaces concurrency bugs.
//!
//! Verdicts are out of scope here: the real Go agent still answers them over the
//! pipe (see [`crate::main`]); this module only *injects* the scenario.
//!
//! Each record is a flat map/object so it is trivial to author from any language
//! -- Python CBOR: `cbor2.dump({"ts": 0, "op": "ale_connect", ...}, f)` per record;
//! or just hand-write one JSON object per line. Only the fields relevant to `op`
//! need be present; the rest default. `ts` and `op` are always required. Byte
//! fields (`local`/`remote`/`payload`/`bytes`/`resolver`) are CBOR byte strings,
//! and arrays of byte values in JSON.
//!
//! ## High-level `dns` op
//!
//! Beyond the one-callout-per-record ops above, `dns` is a *live* macro op: one
//! record names a `domain` and, at replay time, performs a REAL DNS lookup
//! against the machine's default resolver (the OS-configured server, auto-detected;
//! override with `resolver`), then expands into the callout sequence that lookup
//! is made of -- ALE connect (UDP, carrying the real query so a domain-aware policy
//! sees it on the pended event), the real query datagram outbound, the real
//! response datagram inbound, then endpoint close + resource release. Set
//! `tcp_connect` to append a TCP session (`tcp_port`, default 443) to the address
//! the response actually resolved to. `v6` asks for AAAA and connects over IPv6;
//! the query itself reaches the resolver over whatever family that server uses.
//! The sub-steps run through [`execute`] like hand-authored records, so they
//! validate and tally identically. Unlike every other op this one touches the
//! network: it is non-deterministic, needs connectivity, and a failed lookup is
//! recorded as a failure rather than faked. Because the lookup blocks on the
//! network (tens of ms) on its worker, space `dns` records by more than that in
//! `ts` (milliseconds) if you want them paced distinctly -- tighter deltas just
//! overlap on the worker pool. See [`run_dns`].

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, ErrorKind, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use crossbeam_channel::unbounded;
use serde::{Deserialize, Serialize};

use driver::fuzz_api::{
    self as api, CalloutResult, Direction, TupleSpecV4, TupleSpecV6, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT,
};

use crate::rng::mix;
use crate::scenarios;

/// One scenario command ("line"). See the module docs for the field vocabulary.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
struct Record {
    /// Miliseconds since scenario start (absolute point on the timeline).
    ts: u64,
    /// Command selector: `ale_connect` | `ale_accept` | `packet` |
    /// `packet_bytes` | `endpoint_close` | `resource_release` | `dns`.
    op: String,
    /// Address family: `false` => IPv4, `true` => IPv6. For `dns`, selects the
    /// record type asked for (AAAA vs A) and the family of the `tcp_connect`.
    #[serde(default, skip_serializing_if = "is_default")]
    v6: bool,
    /// IP protocol number (6 TCP, 17 UDP, 1 ICMP, ...).
    #[serde(default, skip_serializing_if = "is_default")]
    proto: u8,
    /// Local address, as a byte string (4 bytes for v4, 16 for v6).
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Vec::is_empty")]
    local: Vec<u8>,
    #[serde(default, skip_serializing_if = "is_default")]
    lport: u16,
    /// Remote address, as a byte string (4 bytes for v4, 16 for v6).
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Vec::is_empty")]
    remote: Vec<u8>,
    #[serde(default, skip_serializing_if = "is_default")]
    rport: u16,
    /// Process id carried into `ale_*` / `endpoint_close` callouts.
    #[serde(default, skip_serializing_if = "is_default")]
    pid: u64,
    /// `ale_*`: reauthorization flag.
    #[serde(default, skip_serializing_if = "is_default")]
    reauth: bool,
    /// `packet` / `packet_bytes`: direction, 0 = Outbound, 1 = Inbound.
    #[serde(default, skip_serializing_if = "is_default")]
    dir: u8,
    /// `ale_*` / `packet`: upper-layer payload a structured packet is built around.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Vec::is_empty")]
    payload: Vec<u8>,
    /// `packet_bytes`: full raw packet bytes, starting at the IP header.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Vec::is_empty")]
    bytes: Vec<u8>,
    /// `packet_bytes`: mark the NBL as network-injected by the driver itself.
    #[serde(default, skip_serializing_if = "is_default")]
    injected_by_self: bool,
    /// `resource_release`: the local port to release.
    #[serde(default, skip_serializing_if = "is_default")]
    port: u16,

    // ---- High-level `dns` op ----
    /// `dns`: the domain to look up for real. A non-empty `domain` is all a `dns`
    /// record needs; every other field below has a default. It is resolved live
    /// against the default resolver, and the address that comes back is what
    /// `tcp_connect` then dials -- see [`run_dns`].
    #[serde(default, skip_serializing_if = "is_default")]
    domain: String,
    /// `dns`: the DNS server to query, as a byte string (4 bytes for v4, 16 for
    /// v6). Defaults to the machine's OS-configured default resolver.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Vec::is_empty")]
    resolver: Vec<u8>,
    /// `dns`: after the lookup, also open a TCP session to the address the
    /// response resolved to.
    #[serde(default, skip_serializing_if = "is_default")]
    tcp_connect: bool,
    /// `dns`: destination port for `tcp_connect` (defaults to 443).
    #[serde(default, skip_serializing_if = "is_default")]
    tcp_port: u16,
}

/// `skip_serializing_if` predicate: omit a field that still holds its zero value,
/// so emitted sample files only carry the fields that matter for each `op`.
fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

/// An explicit 5-tuple resolved from a record, ready for the `*_tuple` runners.
enum Tuple {
    V4(TupleSpecV4),
    V6(TupleSpecV6),
}

/// Build the 5-tuple from a record, validating the address widths for the family.
fn tuple(rec: &Record) -> Result<Tuple, String> {
    let bad = |field: &str, got: usize, want: usize| {
        format!(
            "op `{}`: {field} address must be {want} bytes, got {got}",
            rec.op
        )
    };
    if rec.v6 {
        let local: [u8; 16] = rec
            .local
            .as_slice()
            .try_into()
            .map_err(|_| bad("local", rec.local.len(), 16))?;
        let remote: [u8; 16] = rec
            .remote
            .as_slice()
            .try_into()
            .map_err(|_| bad("remote", rec.remote.len(), 16))?;
        Ok(Tuple::V6(TupleSpecV6 {
            protocol: rec.proto,
            local,
            local_port: rec.lport,
            remote,
            remote_port: rec.rport,
        }))
    } else {
        let local: [u8; 4] = rec
            .local
            .as_slice()
            .try_into()
            .map_err(|_| bad("local", rec.local.len(), 4))?;
        let remote: [u8; 4] = rec
            .remote
            .as_slice()
            .try_into()
            .map_err(|_| bad("remote", rec.remote.len(), 4))?;
        Ok(Tuple::V4(TupleSpecV4 {
            protocol: rec.proto,
            local,
            local_port: rec.lport,
            remote,
            remote_port: rec.rport,
        }))
    }
}

fn direction(dir: u8) -> Direction {
    if dir == 0 {
        Direction::Outbound
    } else {
        Direction::Inbound
    }
}

/// Delta between the previous timestamp and this one, in microseconds. The first
/// record (no previous) is 0; a non-monotonic timestamp clamps to 0 via
/// `saturating_sub`, so a mis-ordered file never panics or sleeps backwards.
fn delta_milis(prev: Option<u64>, ts: u64) -> u64 {
    prev.map_or(0, |p| ts.saturating_sub(p))
}

/// Run one command against the driver via the real callout entry points.
fn execute(rec: &Record, sum: &ScenarioSummary) {
    let result: Option<CalloutResult> = match rec.op.as_str() {
        "ale_connect" => match tuple(rec) {
            Ok(Tuple::V4(s)) => Some(api::run_ale_connect_v4_tuple(
                s,
                rec.reauth,
                rec.pid,
                &rec.payload,
            )),
            Ok(Tuple::V6(s)) => Some(api::run_ale_connect_v6_tuple(
                s,
                rec.reauth,
                rec.pid,
                &rec.payload,
            )),
            Err(e) => return sum.fail(e),
        },
        "ale_accept" => match tuple(rec) {
            Ok(Tuple::V4(s)) => Some(api::run_ale_accept_v4_tuple(
                s,
                rec.reauth,
                rec.pid,
                &rec.payload,
            )),
            Ok(Tuple::V6(s)) => Some(api::run_ale_accept_v6_tuple(
                s,
                rec.reauth,
                rec.pid,
                &rec.payload,
            )),
            Err(e) => return sum.fail(e),
        },
        "packet" => match tuple(rec) {
            Ok(Tuple::V4(s)) => Some(api::run_packet_v4_tuple(
                s,
                direction(rec.dir),
                &rec.payload,
            )),
            Ok(Tuple::V6(s)) => Some(api::run_packet_v6_tuple(
                s,
                direction(rec.dir),
                &rec.payload,
            )),
            Err(e) => return sum.fail(e),
        },
        "packet_bytes" => {
            let d = direction(rec.dir);
            Some(if rec.v6 {
                api::run_packet_bytes_v6(&rec.bytes, d, rec.injected_by_self)
            } else {
                api::run_packet_bytes_v4(&rec.bytes, d, rec.injected_by_self)
            })
        }
        "endpoint_close" => {
            match tuple(rec) {
                Ok(Tuple::V4(s)) => api::run_endpoint_close_v4_tuple(s, rec.pid),
                Ok(Tuple::V6(s)) => api::run_endpoint_close_v6_tuple(s, rec.pid),
                Err(e) => return sum.fail(e),
            }
            None
        }
        "resource_release" => {
            if rec.v6 {
                api::run_resource_release_v6_port(rec.proto, rec.port);
            } else {
                api::run_resource_release_v4_port(rec.proto, rec.port);
            }
            None
        }
        // Macro op: performs a real DNS lookup, then injects the callout sequence
        // (+ optional TCP session) through this same `execute`. Tallies its own
        // sub-steps, so return before the single-result tally below.
        "dns" => return run_dns(rec, sum),
        other => return sum.fail(format!("unknown op `{other}`")),
    };
    sum.tally(&rec.op, result);
}

// ---- High-level `dns` op --------------------------------------------------------
//
// A `dns` record is a convenience macro: it names a `domain`, resolves it for
// real against the OS default resolver (see [`crate::dns`]), and expands, inline
// on the worker, into the low-level records that lookup is made of -- built around
// the actual query/response bytes -- then runs each through `execute`. Nothing
// here waits for verdicts (that stays the agent's job over the pipe, as for every
// op) -- it only injects the sequence a real lookup produced.

const TCP: u8 = 6;
const UDP: u8 = 17;

/// Resolve a `dns` record's domain live, build the callout sequence from the real
/// query/response bytes, run each sub-step through [`execute`], then tally the
/// lookup (and any TCP session). A bad record, an unreachable resolver, or a
/// domain with no address of the requested family is recorded as a failure --
/// this op depends on the network, so those are real, reportable outcomes.
fn run_dns(rec: &Record, sum: &ScenarioSummary) {
    if rec.domain.is_empty() {
        return sum.fail("op `dns`: `domain` must not be empty".into());
    }
    let resolver = match rec.resolver.len() {
        0 => None,
        4 | 16 => crate::dns::ip_from_bytes(&rec.resolver),
        n => {
            return sum.fail(format!(
                "op `dns`: resolver address must be 4 or 16 bytes, got {n}"
            ))
        }
    };

    // The one network-touching step: a real query against the default resolver.
    let resolution = match crate::dns::resolve(&rec.domain, rec.v6, resolver) {
        Ok(resolution) => resolution,
        Err(e) => return sum.fail(format!("op `dns`: lookup of `{}` failed: {e}", rec.domain)),
    };

    let records = match build_dns_records(rec, &resolution) {
        Ok(records) => records,
        Err(e) => return sum.fail(e),
    };
    for r in &records {
        execute(r, sum);
    }
    sum.dns_lookups.fetch_add(1, Ordering::Relaxed);
    if rec.tcp_connect {
        sum.tcp_sessions.fetch_add(1, Ordering::Relaxed);
    }
}

/// Build the low-level records a completed lookup expands into, around the real
/// wire bytes in `res` -- ALE connect (carrying the actual query so the agent sees
/// the domain on the pended event), the query datagram outbound, the response
/// datagram inbound, then endpoint close + resource release -- plus, when
/// `tcp_connect` is set, a follow-on TCP session to the address the response
/// resolved to. Each sub-flow's family follows the address it actually uses (the
/// resolver for the lookup, the resolved host for the connect), so a v6 record can
/// legitimately query a v4 resolver and then connect over IPv6. The local port is
/// a per-domain ephemeral so distinct domains stay distinct connection keys.
///
/// Pure and device-free (it only shapes records from `res`), so it is unit tested
/// directly; [`run_dns`] is the part that does the live lookup and injection.
fn build_dns_records(rec: &Record, res: &crate::dns::Resolution) -> Result<Vec<Record>, String> {
    let lport = if rec.lport != 0 {
        rec.lport
    } else {
        derived_port(mix_domain(&rec.domain, rec.ts))
    };

    let resolver = ip_to_bytes(res.resolver);
    let resolver_v6 = res.resolver.is_ipv6();
    let dns_local = local_for(&rec.local, resolver_v6);

    let mut out = Vec::with_capacity(if rec.tcp_connect { 10 } else { 5 });

    // --- DNS lookup over UDP to resolver:53, carrying the real query/response ---
    // ALE connect carries the query, so a domain policy can decide on the pend.
    let mut connect = sub_record(
        "ale_connect",
        resolver_v6,
        UDP,
        &dns_local,
        lport,
        &resolver,
        53,
    );
    connect.pid = rec.pid;
    connect.payload = res.query.clone();
    out.push(connect);
    // The query datagram at the packet layer, then the resolver's real response.
    let mut query_pkt = sub_record("packet", resolver_v6, UDP, &dns_local, lport, &resolver, 53);
    query_pkt.dir = 0; // outbound
    query_pkt.payload = res.query.clone();
    out.push(query_pkt);
    let mut response_pkt = sub_record("packet", resolver_v6, UDP, &dns_local, lport, &resolver, 53);
    response_pkt.dir = 1; // inbound
    response_pkt.payload = res.response.clone();
    out.push(response_pkt);
    // Socket teardown (release keys on protocol + local port, not the tuple).
    let mut close = sub_record(
        "endpoint_close",
        resolver_v6,
        UDP,
        &dns_local,
        lport,
        &resolver,
        53,
    );
    close.pid = rec.pid;
    out.push(close);
    out.push(release_record(resolver_v6, UDP, lport));

    // --- Optional TCP session to the address the lookup resolved to ---
    if rec.tcp_connect {
        let resolved = res.resolved.ok_or_else(|| {
            format!(
                "op `dns`: `{}` did not resolve to a{} address to connect to",
                rec.domain,
                if rec.v6 { "n IPv6" } else { " IPv4" }
            )
        })?;
        let remote = ip_to_bytes(resolved);
        let resolved_v6 = resolved.is_ipv6();
        let tcp_local = local_for(&rec.local, resolved_v6);
        let tcp_port = if rec.tcp_port != 0 { rec.tcp_port } else { 443 };
        // TCP vs the UDP lookup are distinct keys (protocol + remote differ), so
        // reusing the same local port for both is fine.
        let mut connect = sub_record(
            "ale_connect",
            resolved_v6,
            TCP,
            &tcp_local,
            lport,
            &remote,
            tcp_port,
        );
        connect.pid = rec.pid;
        out.push(connect); // an outbound TCP connect carries no data
        let mut hello = sub_record(
            "packet",
            resolved_v6,
            TCP,
            &tcp_local,
            lport,
            &remote,
            tcp_port,
        );
        hello.dir = 0; // outbound: the ClientHello is the first packet
        hello.payload = scenarios::tls_client_hello();
        out.push(hello);
        let mut reply = sub_record(
            "packet",
            resolved_v6,
            TCP,
            &tcp_local,
            lport,
            &remote,
            tcp_port,
        );
        reply.dir = 1; // inbound
        reply.payload = vec![0x16; 128]; // ServerHello-ish handshake bytes
        out.push(reply);
        let mut close = sub_record(
            "endpoint_close",
            resolved_v6,
            TCP,
            &tcp_local,
            lport,
            &remote,
            tcp_port,
        );
        close.pid = rec.pid;
        out.push(close);
        out.push(release_record(resolved_v6, TCP, lport));
    }
    Ok(out)
}

/// One low-level tuple-bearing record for the `dns` expansion; caller then fills
/// in `dir`/`payload`/`pid` as the sub-step needs.
fn sub_record(
    op: &str,
    v6: bool,
    proto: u8,
    local: &[u8],
    lport: u16,
    remote: &[u8],
    rport: u16,
) -> Record {
    Record {
        op: op.to_string(),
        v6,
        proto,
        local: local.to_vec(),
        lport,
        remote: remote.to_vec(),
        rport,
        ..Default::default()
    }
}

/// A `resource_release` record (keys on protocol + local port, no tuple).
fn release_record(v6: bool, proto: u8, port: u16) -> Record {
    Record {
        op: "resource_release".to_string(),
        v6,
        proto,
        port,
        ..Default::default()
    }
}

/// The local client address for a sub-flow of the given family: the record's
/// `local` override when it is set to a matching-width address, else a stable
/// default. A `dns` record's ephemeral local *port* is what keeps distinct
/// domains on distinct connection keys, so a shared local address is fine.
fn local_for(provided: &[u8], v6: bool) -> Vec<u8> {
    let want = if v6 { 16 } else { 4 };
    if provided.len() == want {
        provided.to_vec()
    } else {
        default_local(v6)
    }
}

/// The default local client address for the family (documentation ranges).
fn default_local(v6: bool) -> Vec<u8> {
    if v6 {
        // 2001:db8::1 (documentation prefix).
        vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    } else {
        vec![10, 0, 0, 1]
    }
}

/// An [`IpAddr`](std::net::IpAddr) as the 4- or 16-byte string a record carries.
fn ip_to_bytes(ip: std::net::IpAddr) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// Fold a domain (salted by the record timestamp, so repeats of the same name
/// stay distinct) into a well-mixed 64-bit value seeding the DNS transaction id,
/// the local port, and any synthesized address -- all deterministic, so a
/// scenario replays identically.
fn mix_domain(domain: &str, ts: u64) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ ts; // FNV-1a offset basis, salted by ts
    for b in domain.bytes() {
        h = (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3); // FNV-1a prime
    }
    mix(h)
}

/// An ephemeral local port (49152-65151) derived from the domain hash.
fn derived_port(h: u64) -> u16 {
    49152 + (h % 16000) as u16
}

// ---- Summary ------------------------------------------------------------------

/// Counters gathered across the run, plus any failures (validation errors, parse
/// errors, worker panics). Shared behind an `Arc` across the worker pool.
#[derive(Default)]
pub struct ScenarioSummary {
    dispatched: AtomicU64,
    executed: AtomicU64,
    pended: AtomicU64,
    permitted: AtomicU64,
    blocked: AtomicU64,
    /// High-level `dns` records expanded, and TCP sessions appended to them.
    dns_lookups: AtomicU64,
    tcp_sessions: AtomicU64,
    by_op: Mutex<BTreeMap<String, u64>>,
    failures: Mutex<Vec<String>>,
}

impl ScenarioSummary {
    fn tally(&self, op: &str, result: Option<CalloutResult>) {
        self.executed.fetch_add(1, Ordering::Relaxed);
        *self
            .by_op
            .lock()
            .unwrap()
            .entry(op.to_string())
            .or_insert(0) += 1;
        if let Some(r) = result {
            if r.absorb {
                self.pended.fetch_add(1, Ordering::Relaxed);
            }
            if r.action == FWP_ACTION_PERMIT {
                self.permitted.fetch_add(1, Ordering::Relaxed);
            } else if r.action == FWP_ACTION_BLOCK {
                self.blocked.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn fail(&self, msg: String) {
        eprintln!("[scenario] FAIL: {msg}");
        self.failures.lock().unwrap().push(msg);
    }

    /// True if the scenario replayed with no validation errors or worker panics.
    pub fn ok(&self) -> bool {
        self.failures.lock().unwrap().is_empty()
    }

    pub fn print(&self) {
        println!(
            "[scenario] dispatched={} executed={} pended={} permitted={} blocked={}",
            self.dispatched.load(Ordering::Relaxed),
            self.executed.load(Ordering::Relaxed),
            self.pended.load(Ordering::Relaxed),
            self.permitted.load(Ordering::Relaxed),
            self.blocked.load(Ordering::Relaxed),
        );
        let dns = self.dns_lookups.load(Ordering::Relaxed);
        let tcp = self.tcp_sessions.load(Ordering::Relaxed);
        if dns > 0 || tcp > 0 {
            println!("[scenario] dns lookups={dns} tcp sessions={tcp}");
        }
        for (op, n) in self.by_op.lock().unwrap().iter() {
            println!("[scenario]   {op}: {n}");
        }
        let failures = self.failures.lock().unwrap();
        if failures.is_empty() {
            println!("[scenario] OK: no failures");
        } else {
            println!("[scenario] {} FAILURE(S):", failures.len());
            for f in failures.iter() {
                println!("[scenario]   - {f}");
            }
        }
    }
}

// ---- Executor -----------------------------------------------------------------

/// Replay a CBOR scenario file. Never panics on I/O -- file and parse errors are
/// recorded as failures on the returned summary. Worker panics (a driver
/// invariant blowing up, which is exactly what we hunt) are caught at join and
/// recorded too. Worker count comes from `ZF_SIM_THREADS` (default 4).
pub fn run(path: &str) -> Arc<ScenarioSummary> {
    let summary = Arc::new(ScenarioSummary::default());
    run_into(path, &summary, true);
    summary
}

/// The heart of both [`run`] and [`run_loop`]: stream `path` and dispatch every
/// record into `summary` on a worker pool, so a caller can accumulate across
/// runs. `announce` prints the one-line "streaming ..." banner (the loop
/// suppresses it, keeping per-iteration output quiet). Never panics on I/O.
fn run_into(path: &str, summary: &Arc<ScenarioSummary>, announce: bool) {
    let threads = std::env::var("ZF_SIM_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(4);

    // Open a streaming record iterator (codec chosen by extension). Records are
    // parsed and dispatched one at a time -- the whole file is never held in
    // memory, and a scenario can be arbitrarily long.
    let records = match open_records(path) {
        Ok(records) => records,
        Err(e) => {
            summary.fail(e);
            return;
        }
    };

    // Scheduler -> worker pool. One sender (this thread); each worker owns a
    // clone of the receiver, so whichever worker is free takes the next command.
    let (tx, rx) = unbounded::<Record>();
    let workers: Vec<_> = (0..threads)
        .map(|i| {
            let rx = rx.clone();
            let sum = Arc::clone(summary);
            thread::Builder::new()
                .name(format!("scenario-worker-{i}"))
                .spawn(move || {
                    for rec in rx.iter() {
                        execute(&rec, &sum);
                    }
                })
                .expect("spawn scenario worker")
        })
        .collect();
    drop(rx); // only the workers hold receivers now

    if announce {
        println!("[scenario] streaming `{path}` on {threads} worker(s) ...");
    }
    let mut prev: Option<u64> = None;
    for item in records {
        let rec = match item {
            Ok(rec) => rec,
            Err(e) => {
                summary.fail(e);
                break;
            }
        };
        let delta = delta_milis(prev, rec.ts);
        if delta > 0 {
            thread::sleep(Duration::from_millis(delta));
        }
        prev = Some(rec.ts);
        summary.dispatched.fetch_add(1, Ordering::Relaxed);
        if tx.send(rec).is_err() {
            summary.fail("all workers exited before the scenario finished".into());
            break;
        }
    }
    drop(tx); // close the channel: workers drain the queue, then exit

    for (i, w) in workers.into_iter().enumerate() {
        if w.join().is_err() {
            summary.fail(format!(
                "worker {i} panicked (driver invariant violated -- see backtrace above)"
            ));
        }
    }
}

// ---- Loop mode ----------------------------------------------------------------
//
// `run_loop` replays a file forever, resetting the driver between passes so each
// is an INDEPENDENT scenario (never a continuation carrying the previous pass's
// cached verdicts), and accumulating one running total that is printed only when
// the process is stopped (Ctrl+C) -- never per iteration.

/// The running total across every loop pass, published for [`ctrl_handler`].
static LOOP_TOTAL: OnceLock<Arc<ScenarioSummary>> = OnceLock::new();
/// Passes started so far, so the Ctrl+C summary can report the count.
static LOOP_ITERS: AtomicU64 = AtomicU64::new(0);

/// Replay `path` on repeat until the process is stopped. Diverges: on Ctrl+C the
/// [`ctrl_handler`] prints the accumulated totals once and exits. Between passes
/// the driver's per-connection state is wiped (see [`api::reset_device_state`]),
/// so an iteration re-pends everything instead of inheriting the last pass's
/// verdicts -- each pass is the same scenario run afresh, not a continuation.
pub fn run_loop(path: &str) -> ! {
    let total = Arc::new(ScenarioSummary::default());
    let _ = LOOP_TOTAL.set(Arc::clone(&total));
    install_ctrl_handler();
    loop {
        LOOP_ITERS.fetch_add(1, Ordering::Relaxed);
        // api::reset_device_state();
        // println!("[scenario] --- iteration {n} ---");
        run_into(path, &total, false);
    }
}

/// Ctrl+C handler: print the loop's running totals once, then exit. Registered by
/// [`run_loop`] via `SetConsoleCtrlHandler` (raw FFI, like the pipe server).
unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> i32 {
    let code = match LOOP_TOTAL.get() {
        Some(total) => {
            println!(
                "\n[scenario] stopped after {} iteration(s) -- totals:",
                LOOP_ITERS.load(Ordering::Relaxed)
            );
            total.print();
            if total.ok() {
                0
            } else {
                1
            }
        }
        None => 0,
    };
    let _ = io::stdout().flush();
    std::process::exit(code);
}

fn install_ctrl_handler() {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(
            handler: Option<unsafe extern "system" fn(u32) -> i32>,
            add: i32,
        ) -> i32;
    }
    unsafe {
        SetConsoleCtrlHandler(Some(ctrl_handler), 1);
    }
}

/// A lazy stream of records; each `next()` parses exactly one record from the
/// underlying reader, so the file is never fully buffered.
type RecordStream = Box<dyn Iterator<Item = Result<Record, String>>>;

/// Open a scenario file as a [`RecordStream`], choosing the codec by extension:
/// * `.json` => **JSON Lines** (one record object per line / whitespace-separated
///   JSON values), decoded with serde_json's streaming `StreamDeserializer`.
///   NOTE: this is NDJSON, deliberately NOT a single JSON array (arrays can't be
///   streamed a value at a time).
/// * anything else (e.g. `.cbor`) => a CBOR sequence (RFC 8742) of record maps,
///   read one top-level item at a time until EOF.
fn open_records(path: &str) -> Result<RecordStream, String> {
    let file = File::open(path).map_err(|e| format!("cannot open scenario `{path}`: {e}"))?;
    let reader = BufReader::new(file);
    let is_jsonl = std::path::Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("jsonl"));
    if is_jsonl {
        let iter = serde_json::Deserializer::from_reader(reader)
            .into_iter::<Record>()
            .map(|r| r.map_err(|e| format!("JSON parse error: {e}")));
        Ok(Box::new(iter))
    } else {
        let mut reader = reader;
        let iter = std::iter::from_fn(move || {
            match ciborium::from_reader::<Record, _>(&mut reader) {
                Ok(rec) => Some(Ok(rec)),
                // A clean boundary between items (or a truncated tail) reports EOF.
                Err(ciborium::de::Error::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => None,
                Err(e) => Some(Err(format!("CBOR parse error: {e}"))),
            }
        });
        Ok(Box::new(iter))
    }
}

// ---- Sample scenarios ---------------------------------------------------------

/// Write the reference sample scenarios into `dir`, creating it if needed. They
/// double as living documentation of the wire format and as round-trip fixtures.
pub fn emit_samples(dir: &str) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    for (name, records) in [
        ("basic_v4", basic_v4()),
        ("mixed_v4v6_parallel", mixed_v4v6_parallel()),
        ("icmp_burst", icmp_burst()),
        ("dns_and_connect", dns_flows()),
    ] {
        write_cbor(&format!("{dir}/{name}.cbor"), &records)?;
        write_json(&format!("{dir}/{name}.jsonl"), &records)?;
    }
    Ok(())
}

/// Write records as a CBOR sequence (compact; for real runs and Python authoring).
fn write_cbor(path: &str, records: &[Record]) -> io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    for rec in records {
        ciborium::into_writer(rec, &mut out)
            .map_err(|e| io::Error::new(ErrorKind::Other, format!("CBOR encode: {e}")))?;
    }
    out.flush()?;
    println!("[scenario] wrote {} records -> {path}", records.len());
    Ok(())
}

/// Write records as JSON Lines (one compact record object per line; NDJSON) --
/// streamable and diff/grep-friendly. Byte fields render as arrays of byte values.
fn write_json(path: &str, records: &[Record]) -> io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    for rec in records {
        let line = serde_json::to_string(rec)
            .map_err(|e| io::Error::new(ErrorKind::Other, format!("JSON encode: {e}")))?;
        out.write_all(line.as_bytes())?;
        out.write_all(b"\n")?;
    }
    out.flush()?;
    println!("[scenario] wrote {} records -> {path}", records.len());
    Ok(())
}

/// Base record with just the timeline point and the op set; the rest defaults.
fn at(ts: u64, op: &str) -> Record {
    Record {
        ts,
        op: op.to_string(),
        ..Default::default()
    }
}

/// One outbound TCP flow to 1.1.1.1:443: authorize, two data packets, close, release.
fn basic_v4() -> Vec<Record> {
    let local = vec![10, 0, 0, 5];
    let remote = vec![1, 1, 1, 1];
    vec![
        Record {
            proto: 6,
            local: local.clone(),
            lport: 40001,
            remote: remote.clone(),
            rport: 443,
            pid: 1000,
            payload: b"hello".to_vec(),
            ..at(0, "ale_connect")
        },
        Record {
            proto: 6,
            dir: 0,
            local: local.clone(),
            lport: 40001,
            remote: remote.clone(),
            rport: 443,
            payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            ..at(5_000, "packet")
        },
        Record {
            proto: 6,
            dir: 1,
            local: local.clone(),
            lport: 40001,
            remote: remote.clone(),
            rport: 443,
            payload: b"HTTP/1.1 200 OK\r\n".to_vec(),
            ..at(15_000, "packet")
        },
        Record {
            proto: 6,
            local: local.clone(),
            lport: 40001,
            remote: remote.clone(),
            rport: 443,
            pid: 1000,
            ..at(50_000, "endpoint_close")
        },
        Record {
            proto: 6,
            port: 40001,
            ..at(50_100, "resource_release")
        },
    ]
}

/// Three connections authorized at the same instant (delta 0 => injected in
/// parallel on different workers), staggered data, then simultaneous closes.
fn mixed_v4v6_parallel() -> Vec<Record> {
    let v6l = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let v6r = vec![
        0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64,
    ];
    vec![
        Record {
            proto: 6,
            local: vec![10, 0, 0, 1],
            lport: 40001,
            remote: vec![1, 1, 1, 1],
            rport: 443,
            pid: 1001,
            ..at(0, "ale_connect")
        },
        Record {
            proto: 6,
            local: vec![10, 0, 0, 2],
            lport: 40002,
            remote: vec![8, 8, 8, 8],
            rport: 53,
            pid: 1002,
            ..at(0, "ale_connect")
        },
        Record {
            v6: true,
            proto: 6,
            local: v6l.clone(),
            lport: 40003,
            remote: v6r.clone(),
            rport: 443,
            pid: 1003,
            ..at(0, "ale_connect")
        },
        Record {
            proto: 6,
            dir: 0,
            local: vec![10, 0, 0, 1],
            lport: 40001,
            remote: vec![1, 1, 1, 1],
            rport: 443,
            payload: b"GET /".to_vec(),
            ..at(1_000, "packet")
        },
        Record {
            proto: 6,
            dir: 0,
            local: vec![10, 0, 0, 2],
            lport: 40002,
            remote: vec![8, 8, 8, 8],
            rport: 53,
            payload: vec![0x12, 0x34],
            ..at(1_000, "packet")
        },
        Record {
            v6: true,
            proto: 6,
            dir: 0,
            local: v6l.clone(),
            lport: 40003,
            remote: v6r.clone(),
            rport: 443,
            payload: b"GET /".to_vec(),
            ..at(2_000, "packet")
        },
        Record {
            proto: 6,
            local: vec![10, 0, 0, 1],
            lport: 40001,
            remote: vec![1, 1, 1, 1],
            rport: 443,
            pid: 1001,
            ..at(10_000, "endpoint_close")
        },
        Record {
            proto: 6,
            local: vec![10, 0, 0, 2],
            lport: 40002,
            remote: vec![8, 8, 8, 8],
            rport: 53,
            pid: 1002,
            ..at(10_000, "endpoint_close")
        },
        Record {
            v6: true,
            proto: 6,
            local: v6l,
            lport: 40003,
            remote: v6r,
            rport: 443,
            pid: 1003,
            ..at(10_000, "endpoint_close")
        },
    ]
}

/// A burst of 32 ICMP packets all stamped ts 0, so they are dispatched
/// back-to-back and pend concurrently across the pool -- a small concurrency probe.
fn icmp_burst() -> Vec<Record> {
    (0..32u8)
        .map(|i| Record {
            proto: 1,
            dir: 0,
            local: vec![10, 0, 1, i],
            remote: vec![10, 0, 1, 254],
            payload: vec![8, 0, 0, 0],
            ..at(0, "packet")
        })
        .collect()
}

/// High-level `dns` records: resolve a real domain, optionally opening a TCP
/// session to the resolved address. Each performs a live lookup at replay time
/// and expands into a full ALE/packet/close/release callout sequence (see
/// [`run_dns`]) -- the "set a domain and go" authoring path. Being live, these
/// need connectivity; the domains below are chosen to actually resolve.
fn dns_flows() -> Vec<Record> {
    // `ts` is milliseconds since scenario start, and the scheduler paces DISPATCH
    // to it. A live `dns` lookup then blocks on the network for tens of ms on a
    // worker, so records spaced tighter than that would overlap on the pool rather
    // than run in sequence. These are 1 s apart (1000 ms) so each lookup finishes
    // well before the next is dispatched -- the timeline is plainly visible even
    // against real DNS latency.
    vec![
        // Bare lookup against the machine's default resolver.
        Record {
            domain: "example.com".to_string(),
            ..at(0, "dns")
        },
        // +1 s: lookup via an explicit resolver (1.1.1.1), then a TLS session on
        // 443 to the address it resolved to.
        Record {
            domain: "cloudflare.com".to_string(),
            resolver: vec![1, 1, 1, 1],
            tcp_connect: true,
            tcp_port: 443,
            pid: 4242,
            ..at(1000, "dns")
        },
        // +2 s: AAAA lookup (via the default resolver), then connect over IPv6.
        Record {
            v6: true,
            domain: "google.com".to_string(),
            tcp_connect: true,
            ..at(2000, "dns")
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(records: &[Record]) -> Vec<u8> {
        let mut buf = Vec::new();
        for r in records {
            ciborium::into_writer(r, &mut buf).unwrap();
        }
        buf
    }

    fn decode(mut bytes: &[u8]) -> Vec<Record> {
        let mut out = Vec::new();
        loop {
            match ciborium::from_reader::<Record, _>(&mut bytes) {
                Ok(r) => out.push(r),
                Err(ciborium::de::Error::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("decode error: {e}"),
            }
        }
        out
    }

    #[test]
    fn record_sequence_roundtrips() {
        for records in [basic_v4(), mixed_v4v6_parallel(), icmp_burst(), dns_flows()] {
            let back = decode(&encode(&records));
            assert_eq!(records, back);
        }
    }

    #[test]
    fn json_lines_roundtrips() {
        for records in [basic_v4(), mixed_v4v6_parallel(), icmp_burst(), dns_flows()] {
            // Encode as JSON Lines, then stream-decode it back one value at a time.
            let mut jsonl = String::new();
            for r in &records {
                jsonl.push_str(&serde_json::to_string(r).unwrap());
                jsonl.push('\n');
            }
            let back: Vec<Record> = serde_json::Deserializer::from_str(&jsonl)
                .into_iter::<Record>()
                .map(|r| r.unwrap())
                .collect();
            assert_eq!(records, back);
        }
    }

    #[test]
    fn delta_is_monotonic_zero_and_clamped() {
        assert_eq!(delta_milis(None, 100), 0); // first record: no previous
        assert_eq!(delta_milis(Some(100), 250), 150); // forward delta
        assert_eq!(delta_milis(Some(250), 250), 0); // equal ts => parallel, no sleep
        assert_eq!(delta_milis(Some(250), 100), 0); // non-monotonic => clamped
    }

    #[test]
    fn tuple_validates_address_width() {
        let mut r = at(0, "packet");
        r.proto = 6;
        r.local = vec![10, 0, 0, 1];
        r.remote = vec![1, 1, 1, 1];
        assert!(matches!(tuple(&r), Ok(Tuple::V4(_))));
        r.remote = vec![0; 16]; // v4 with a 16-byte address is rejected
        assert!(tuple(&r).is_err());

        let mut r6 = at(0, "packet");
        r6.v6 = true;
        r6.local = vec![0; 16];
        r6.remote = vec![0; 16];
        assert!(matches!(tuple(&r6), Ok(Tuple::V6(_))));
        r6.local = vec![0; 4]; // v6 with a 4-byte address is rejected
        assert!(tuple(&r6).is_err());
    }

    /// A completed lookup with the given resolver/resolved addresses and wire
    /// bytes -- lets the pure record builder be tested with no network.
    fn fake_resolution(
        resolver: &str,
        resolved: Option<&str>,
        query: Vec<u8>,
        response: Vec<u8>,
    ) -> crate::dns::Resolution {
        crate::dns::Resolution {
            resolver: resolver.parse().unwrap(),
            resolved: resolved.map(|s| s.parse().unwrap()),
            query,
            response,
        }
    }

    #[test]
    fn dns_builds_the_lookup_sequence_from_wire_bytes() {
        let rec = Record {
            domain: "example.com".to_string(),
            ..at(0, "dns")
        };
        let query = crate::scenarios::dns_query_for(0x1234, "example.com", false);
        let response =
            crate::scenarios::dns_response_for(0x1234, "example.com", &[93, 184, 216, 34]);
        let res = fake_resolution(
            "8.8.8.8",
            Some("93.184.216.34"),
            query.clone(),
            response.clone(),
        );
        let recs = build_dns_records(&rec, &res).unwrap();

        let ops: Vec<&str> = recs.iter().map(|r| r.op.as_str()).collect();
        assert_eq!(
            ops,
            [
                "ale_connect",
                "packet",
                "packet",
                "endpoint_close",
                "resource_release"
            ]
        );

        // Every lookup step is UDP to the resolver we actually queried, on :53,
        // from one per-domain ephemeral local port off a stable client address.
        let lport = derived_port(mix_domain("example.com", 0));
        for r in &recs[..4] {
            assert!(!r.v6);
            assert_eq!(r.proto, UDP);
            assert_eq!(r.remote, vec![8, 8, 8, 8]);
            assert_eq!(r.rport, 53);
            assert_eq!(r.lport, lport);
            assert_eq!(r.local, vec![10, 0, 0, 1]);
        }
        // The real query goes out; the real response comes back in.
        assert_eq!(recs[1].dir, 0);
        assert_eq!(recs[2].dir, 1);
        assert_eq!(recs[0].payload, query); // pended connect carries the query
        assert_eq!(recs[1].payload, query);
        assert_eq!(recs[2].payload, response);
        // Release frees this flow's UDP local port.
        let release = recs.last().unwrap();
        assert_eq!(release.proto, UDP);
        assert_eq!(release.port, lport);
    }

    #[test]
    fn dns_tcp_connect_dials_the_resolved_answer() {
        let rec = Record {
            domain: "api.example.org".to_string(),
            tcp_connect: true,
            tcp_port: 8443,
            pid: 4242,
            ..at(0, "dns")
        };
        let query = crate::scenarios::dns_query_for(0x1, "api.example.org", false);
        let response =
            crate::scenarios::dns_response_for(0x1, "api.example.org", &[203, 0, 113, 7]);
        let res = fake_resolution("8.8.8.8", Some("203.0.113.7"), query, response);
        let recs = build_dns_records(&rec, &res).unwrap();
        assert_eq!(recs.len(), 10, "5 lookup steps + 5 TCP session steps");

        let tcp = &recs[5..];
        let ops: Vec<&str> = tcp.iter().map(|r| r.op.as_str()).collect();
        assert_eq!(
            ops,
            [
                "ale_connect",
                "packet",
                "packet",
                "endpoint_close",
                "resource_release"
            ]
        );
        // The session dials exactly the address the lookup resolved to.
        for r in &tcp[..4] {
            assert_eq!(r.proto, TCP);
            assert_eq!(r.remote, vec![203, 0, 113, 7]);
            assert_eq!(r.rport, 8443);
        }
        // pid rides the ALE connect and the endpoint close (the packet-layer
        // callout ignores it, so the datagram records leave it default).
        assert_eq!(tcp[0].pid, 4242);
        assert_eq!(tcp[3].pid, 4242);
        // An outbound TCP connect carries no data; the ClientHello is the first packet.
        assert!(tcp[0].payload.is_empty());
        assert_eq!(tcp[1].dir, 0);
        assert_eq!(tcp[1].payload, crate::scenarios::tls_client_hello());
        assert_eq!(tcp[2].dir, 1);
    }

    #[test]
    fn dns_v6_record_can_query_v4_and_connect_over_v6() {
        // A v6 record asks for AAAA, but the query still reaches whatever family
        // the resolver is -- here a v4 server -- and only the connect is v6.
        let rec = Record {
            v6: true,
            domain: "google.com".to_string(),
            tcp_connect: true,
            ..at(0, "dns")
        };
        let query = crate::scenarios::dns_query_for(0x1, "google.com", true);
        let v6 = [0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64];
        let response = crate::scenarios::dns_response_for(0x1, "google.com", &v6);
        let res = fake_resolution("8.8.8.8", Some("2606:4700::64"), query, response);
        let recs = build_dns_records(&rec, &res).unwrap();
        assert_eq!(recs.len(), 10);

        // The lookup sub-flow follows the (v4) resolver we queried.
        assert!(!recs[0].v6);
        assert_eq!(recs[0].remote, vec![8, 8, 8, 8]);
        assert_eq!(recs[0].local.len(), 4);
        // The connect sub-flow follows the (v6) resolved address.
        let tcp = &recs[5..];
        assert!(tcp[0].v6);
        assert_eq!(
            tcp[0].remote,
            "2606:4700::64"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(tcp[0].local.len(), 16);
        assert_eq!(tcp[0].rport, 443);
    }

    #[test]
    fn dns_tcp_connect_needs_a_resolved_address() {
        // The resolver answered, but with no address of the requested family.
        let query = crate::scenarios::dns_query_for(0x1, "nope.invalid", false);
        let res = fake_resolution("8.8.8.8", None, query, vec![0u8; 12]);

        let want_connect = Record {
            domain: "nope.invalid".to_string(),
            tcp_connect: true,
            ..at(0, "dns")
        };
        assert!(build_dns_records(&want_connect, &res)
            .unwrap_err()
            .contains("did not resolve"));

        // Without tcp_connect a missing address is fine -- just the lookup steps.
        let lookup_only = Record {
            domain: "nope.invalid".to_string(),
            ..at(0, "dns")
        };
        assert_eq!(build_dns_records(&lookup_only, &res).unwrap().len(), 5);
    }
}
