//! Fake OS-side network traffic.
//!
//! Drives semi-realistic flows through the real driver callout entry points,
//! the way the OS does: ALE authorization first (which pends and emits an event
//! the agent answers over the pipe), then data packets through the IP packet
//! layer, then endpoint closure and resource release. The default run generates
//! seeded random flows ([`crate::scenarios::random_flow`]) forever.
//!
//! Concurrency mirrors the kernel: several producer workers classify flows at
//! the same time (WFP classify callbacks fire on many threads), and one
//! reinjector thread models the OS re-presenting driver-injected packets to the
//! packet-layer callouts (network injects re-enter marked injected-by-self;
//! outbound transport injects descend the stack unmarked; inbound transport
//! injects re-indicate upward and never pass the network layer again).
//!
//! Everything is reproducible from the fixed [`SEED`]: just rerun.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use driver::fuzz_api::{
    self as api, CalloutResult, Direction, Verdict, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
};

use crate::rng::{mix, SplitMix64};
use crate::scenarios::{self, Expect, FlowPlan, Tuple};

const VERDICT_POLL: Duration = Duration::from_millis(5);
const REINJECT_POLL: Duration = Duration::from_millis(2);

// ---- Hardcoded run parameters ------------------------------------------------

/// Fixed run seed. The traffic is fully reproducible across runs -- rerun to
/// reproduce a failure. The RNG stream is infinite, so one seed still yields
/// endless distinct flows.
const SEED: u64 = 0x0BAD_C0DE_5EED_1234;

/// Producer worker threads (WFP classify fires on many threads at once). Kept
/// small so each worker's disjoint local-port window -- 2048 ports starting at
/// `20000 + worker * 2048` -- stays inside a u16.
const THREADS: usize = 4;

/// Per-flow budget for the agent's verdict and any mid-burst upgrades before the
/// flow is counted as a timeout/failure.
const FLOW_TIMEOUT: Duration = Duration::from_secs(15);

/// How often the monitor thread prints a liveness line and checks invariants.
const HEARTBEAT: Duration = Duration::from_secs(5);

// ---- Summary ------------------------------------------------------------------

#[derive(Default)]
pub struct Summary {
    pub flows_ok: AtomicU64,
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
    /// Network-injected packets that re-entered the packet layer marked
    /// injected-by-self and were permitted (the driver's self-inject branch).
    pub loopback_permits: AtomicU64,
    /// Outbound transport injects replayed down the stack and permitted.
    pub transport_replays: AtomicU64,
    pub verdict_timeouts: AtomicU64,
    pub by_scenario: Mutex<BTreeMap<&'static str, u64>>,
    pub failures: Mutex<Vec<String>>,
}

impl Summary {
    fn fail(&self, msg: String) {
        // Attach a stack trace when RUST_BACKTRACE is set (`Backtrace::capture`
        // is a no-op otherwise), so `RUST_BACKTRACE=1` pinpoints the failing site.
        let backtrace = std::backtrace::Backtrace::capture();
        let msg = if backtrace.status() == std::backtrace::BacktraceStatus::Captured {
            format!("{msg}\n  stack:\n{backtrace}")
        } else {
            msg
        };
        if let Ok(mut failures) = self.failures.lock() {
            // Cap the list; one broken invariant tends to repeat per flow.
            if failures.len() < 64 {
                failures.push(msg);
            }
        }
    }

    fn count_scenario(&self, name: &'static str) {
        if let Ok(mut map) = self.by_scenario.lock() {
            *map.entry(name).or_insert(0) += 1;
        }
    }

    pub fn is_ok(&self) -> bool {
        self.verdict_timeouts.load(Ordering::Relaxed) == 0
            && self.failures.lock().map(|f| f.is_empty()).unwrap_or(false)
    }

    /// Compact one-line liveness snapshot for the periodic monitor.
    pub fn heartbeat(&self) {
        println!(
            "[sim] alive: flows ok={} | packets={} bytes={} | self-inject={} transport={} | pended={} timeouts={}",
            self.flows_ok.load(Ordering::Relaxed),
            self.packets.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
            self.loopback_permits.load(Ordering::Relaxed),
            self.transport_replays.load(Ordering::Relaxed),
            api::packet_cache_len(),
            self.verdict_timeouts.load(Ordering::Relaxed),
        );
    }

    pub fn print(&self) {
        println!(
            "[sim] flows ok={} | packets={} bytes={} | self-inject permits={} transport replays={} | verdict timeouts={}",
            self.flows_ok.load(Ordering::Relaxed),
            self.packets.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
            self.loopback_permits.load(Ordering::Relaxed),
            self.transport_replays.load(Ordering::Relaxed),
            self.verdict_timeouts.load(Ordering::Relaxed),
        );
        if let Ok(map) = self.by_scenario.lock() {
            let list: Vec<String> = map.iter().map(|(name, n)| format!("{name}={n}")).collect();
            println!("[sim] scenarios: {}", list.join(" "));
        }
        if let Ok(failures) = self.failures.lock() {
            for failure in failures.iter() {
                eprintln!("[sim] FAILURE: {failure}");
            }
        }
    }
}

// ---- Driving ---------------------------------------------------------------------

/// Generate random flows forever across [`THREADS`] workers. Never returns: a
/// healthy run ends when the user stops it, and a broken invariant ends it via
/// the monitor's non-zero `process::exit`. Each worker owns a disjoint IP/port
/// window and a private RNG stream, and runs one flow fully -- ALE authorization,
/// the agent's verdict, data bursts, closure, release -- before starting the
/// next, so a worker can never outpace the agent it waits on.
pub fn drive() {
    println!(
        "[sim] producer: seed=0x{SEED:016x} threads={THREADS}; generating random flows forever (Ctrl+C to stop)"
    );

    let summary = Arc::new(Summary::default());

    // Reinjector: models the OS re-presenting driver-injected packets.
    {
        let summary = Arc::clone(&summary);
        thread::spawn(move || reinject_loop(&summary));
    }

    // Monitor: periodic liveness line + fail-fast on the first broken invariant.
    {
        let summary = Arc::clone(&summary);
        thread::spawn(move || monitor_loop(&summary));
    }

    let workers: Vec<_> = (0..THREADS)
        .map(|worker| {
            let summary = Arc::clone(&summary);
            thread::spawn(move || {
                let mut rng = SplitMix64::new(mix(SEED ^ worker as u64));
                let mut counter: u64 = 0;
                loop {
                    // Keep the sequence inside the worker's 2048-port window; a
                    // flow closes and releases its port before that port recurs,
                    // so the reuse is always safe.
                    let seq = (counter % 2048) as u16;
                    let plan = scenarios::random_flow(&mut rng, worker, seq);
                    let deadline = Instant::now() + FLOW_TIMEOUT;
                    run_flow(&plan, &summary, deadline);
                    counter = counter.wrapping_add(1);
                }
            })
        })
        .collect();

    // Blocks forever: the workers never return.
    for worker in workers {
        let _ = worker.join();
    }
}

/// Print a liveness line every [`HEARTBEAT`]; the moment an invariant breaks,
/// dump the full summary and exit non-zero. The seed is fixed, so a failing run
/// reproduces exactly on the next launch.
fn monitor_loop(summary: &Summary) -> ! {
    loop {
        thread::sleep(HEARTBEAT);
        summary.heartbeat();
        if !summary.is_ok() {
            summary.print();
            eprintln!("[sim] FAIL: traffic invariant violated (seed=0x{SEED:016x}); exiting");
            std::process::exit(1);
        }
    }
}

// ---- One flow's life ------------------------------------------------------------

fn run_flow(plan: &FlowPlan, summary: &Summary, deadline: Instant) {
    summary.count_scenario(plan.name);

    // 1. ALE authorization: connect (outbound) or accept (inbound).
    let result = run_ale(plan, false);
    let mut ok = match plan.expect {
        Expect::ImmediateAccept => {
            // Inbound loopback: ALE itself accepts, nothing pends.
            let permitted = result.action == FWP_ACTION_PERMIT;
            if !permitted {
                summary.fail(format!("{}: inbound loopback not permitted at ALE", plan.describe()));
            }
            permitted
        }
        Expect::NoVerdict => true, // ICMP: ALE not involved for the packet path below
        Expect::Accepted | Expect::Blocked => {
            // New TCP/UDP connection: the original classify is absorbed and the
            // flow pends until the agent's verdict.
            if !result.absorb {
                summary.fail(format!("{}: new connection did not pend at ALE", plan.describe()));
            }
            result.absorb
        }
    };

    // 2. Wait for the agent's verdict (like the OS holding the pended classify).
    if ok && matches!(plan.expect, Expect::Accepted | Expect::Blocked) {
        match wait_verdict(plan, deadline) {
            Some(verdict) => {
                let expected_block = plan.expect == Expect::Blocked;
                let got_block = verdict == Verdict::PermanentBlock as u8;
                let accept_ish =
                    verdict == Verdict::Accept as u8 || verdict == Verdict::PermanentAccept as u8;
                if expected_block && !got_block {
                    summary.fail(format!("{}: expected block, got verdict {verdict}", plan.describe()));
                    ok = false;
                } else if !expected_block && !accept_ish {
                    summary.fail(format!("{}: expected accept, got verdict {verdict}", plan.describe()));
                    ok = false;
                }
            }
            None => {
                summary.verdict_timeouts.fetch_add(1, Ordering::Relaxed);
                summary.fail(format!("{}: verdict timed out", plan.describe()));
                return;
            }
        }
    }

    // 3. Data packets.
    if ok {
        match plan.expect {
            Expect::Blocked => {
                // The OS wouldn't send more on a blocked outbound flow, but a
                // leftover packet must be blocked (and not absorbed) here.
                if let Some(burst) = plan.bursts.first() {
                    let result = run_packet(plan, burst.direction, &burst.payload);
                    if result.action != FWP_ACTION_BLOCK || result.absorb {
                        summary.fail(format!(
                            "{}: blocked flow's packet not hard-blocked (action={:#x} absorb={})",
                            plan.describe(), result.action, result.absorb
                        ));
                        ok = false;
                    }
                }
            }
            Expect::NoVerdict => {
                // ICMP: every packet pends on its own; the agent resolves each
                // and the accepted clone comes back via the reinjector.
                for burst in &plan.bursts {
                    let result = run_packet(plan, burst.direction, &burst.payload);
                    if !result.absorb {
                        summary.fail(format!("{}: ICMP packet did not pend", plan.describe()));
                        ok = false;
                        break;
                    }
                    count_packet(summary, &burst.payload);
                }
            }
            Expect::Accepted | Expect::ImmediateAccept => {
                ok &= run_bursts(plan, summary, deadline);
            }
        }
    }

    // 4. Endpoint closure + resource release (the socket goes away).
    if plan.expect != Expect::NoVerdict {
        close_flow(plan);
    }
    if plan.release_port {
        release_port(plan);
    }

    if ok {
        summary.flows_ok.fetch_add(1, Ordering::Relaxed);
    }

    // 5. Optional port-reuse follow-up: a fresh flow on the just-released port.
    if let Some(follow_up) = scenarios::reuse_follow_up(plan) {
        run_flow(&follow_up, summary, deadline);
    }
}

/// Data exchange for an authorized flow. A permanent accept permits packets
/// outright; a temporary Accept (inbound loopback's initial state) pends each
/// packet until the agent upgrades the verdict, so both outcomes are legal --
/// what's illegal is a hard block or a missing action.
fn run_bursts(plan: &FlowPlan, summary: &Summary, deadline: Instant) -> bool {
    for (i, burst) in plan.bursts.iter().enumerate() {
        if plan.reauth_after == Some(i) && !reauthorize(plan, summary) {
            return false;
        }

        let verdict = current_verdict(plan);
        let result = run_packet(plan, burst.direction, &burst.payload);
        if verdict == Some(Verdict::PermanentAccept as u8) {
            if result.action != FWP_ACTION_PERMIT {
                summary.fail(format!(
                    "{}: burst {i} not permitted under PermanentAccept (action={:#x})",
                    plan.describe(), result.action
                ));
                return false;
            }
        } else if result.absorb {
            // Temporary verdict: the packet pended; wait for the agent to
            // upgrade the flow before sending more (the pended clone itself is
            // delivered by injection, observed by the reinjector).
            if wait_for(deadline, || {
                current_verdict(plan).filter(|&v| v == Verdict::PermanentAccept as u8)
            })
            .is_none()
            {
                summary.verdict_timeouts.fetch_add(1, Ordering::Relaxed);
                summary.fail(format!("{}: burst {i} verdict timed out", plan.describe()));
                return false;
            }
        } else if result.action != FWP_ACTION_PERMIT {
            summary.fail(format!(
                "{}: burst {i} neither permitted nor pended (action={:#x})",
                plan.describe(), result.action
            ));
            return false;
        }
        count_packet(summary, &burst.payload);
    }
    true
}

fn reauthorize(plan: &FlowPlan, summary: &Summary) -> bool {
    // Mid-flow reauthorization classify (as the OS does on policy change): the
    // connection exists with a permanent verdict, so ALE must decide directly.
    let result = run_ale(plan, true);
    if result.action != FWP_ACTION_PERMIT {
        summary.fail(format!(
            "{}: reauthorization of an accepted flow not permitted (action={:#x})",
            plan.describe(), result.action
        ));
        return false;
    }
    true
}

// ---- Callout adapters ----------------------------------------------------------

fn run_ale(plan: &FlowPlan, reauthorize: bool) -> CalloutResult {
    match (plan.tuple, plan.direction) {
        (Tuple::V4(t), Direction::Outbound) => {
            api::run_ale_connect_v4_tuple(t, reauthorize, plan.process_id, &plan.first_payload)
        }
        (Tuple::V4(t), Direction::Inbound) => {
            api::run_ale_accept_v4_tuple(t, reauthorize, plan.process_id, &plan.first_payload)
        }
        (Tuple::V6(t), Direction::Outbound) => {
            api::run_ale_connect_v6_tuple(t, reauthorize, plan.process_id, &plan.first_payload)
        }
        (Tuple::V6(t), Direction::Inbound) => {
            api::run_ale_accept_v6_tuple(t, reauthorize, plan.process_id, &plan.first_payload)
        }
    }
}

fn run_packet(plan: &FlowPlan, direction: Direction, payload: &[u8]) -> CalloutResult {
    match plan.tuple {
        Tuple::V4(t) => api::run_packet_v4_tuple(t, direction, payload),
        Tuple::V6(t) => api::run_packet_v6_tuple(t, direction, payload),
    }
}

fn close_flow(plan: &FlowPlan) {
    match plan.tuple {
        Tuple::V4(t) => api::run_endpoint_close_v4_tuple(t, plan.process_id),
        Tuple::V6(t) => api::run_endpoint_close_v6_tuple(t, plan.process_id),
    }
}

fn release_port(plan: &FlowPlan) {
    match plan.tuple {
        Tuple::V4(_) => api::run_resource_release_v4_port(plan.tuple.protocol(), plan.tuple.local_port()),
        Tuple::V6(_) => api::run_resource_release_v6_port(plan.tuple.protocol(), plan.tuple.local_port()),
    }
}

fn current_verdict(plan: &FlowPlan) -> Option<u8> {
    match plan.tuple {
        Tuple::V4(t) => api::verdict_for_key_v4(t),
        Tuple::V6(t) => api::verdict_for_key_v6(t),
    }
}

fn wait_verdict(plan: &FlowPlan, deadline: Instant) -> Option<u8> {
    wait_for(deadline, || {
        current_verdict(plan).filter(|&v| v != Verdict::Undecided as u8)
    })
}

/// Poll `cond` until it yields `Some` or the deadline passes.
fn wait_for<T>(deadline: Instant, mut cond: impl FnMut() -> Option<T>) -> Option<T> {
    loop {
        if let Some(value) = cond() {
            return Some(value);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(VERDICT_POLL);
    }
}

fn count_packet(summary: &Summary, payload: &[u8]) {
    summary.packets.fetch_add(1, Ordering::Relaxed);
    summary.bytes.fetch_add(payload.len() as u64, Ordering::Relaxed);
}

// ---- Reinjector -------------------------------------------------------------------
//
// Models what the OS does with packets the driver injects:
//   * network injects re-enter the packet-layer callouts carrying the FWPS
//     injection state -- the driver must recognize itself and permit;
//   * outbound transport injects (a released ALE defer) descend the full stack
//     and hit the outbound packet layer as INJECTED_BY_OTHER, i.e. unmarked;
//   * inbound transport injects re-indicate upward from the transport layer and
//     never traverse the network layer again.

fn reinject_loop(summary: &Summary) -> ! {
    loop {
        let injected = api::drain_injected();
        if injected.is_empty() {
            thread::sleep(REINJECT_POLL);
            continue;
        }
        for packet in injected {
            if packet.transport {
                if packet.inbound {
                    continue; // re-indicated upward, skips the network layer
                }
                let result = if packet.ipv6 {
                    api::run_packet_bytes_v6(&packet.data, Direction::Outbound, false)
                } else {
                    api::run_packet_bytes_v4(&packet.data, Direction::Outbound, false)
                };
                // The agent only hands out permanent verdicts, so by the time
                // the defer was released the flow is permanently accepted.
                if result.action == FWP_ACTION_PERMIT {
                    summary.transport_replays.fetch_add(1, Ordering::Relaxed);
                } else {
                    summary.fail(format!(
                        "transport re-inject not permitted: {} (action={:#x} absorb={})",
                        describe_injected(&packet),
                        result.action,
                        result.absorb
                    ));
                }
            } else {
                let direction = if packet.inbound { Direction::Inbound } else { Direction::Outbound };
                let result = if packet.ipv6 {
                    api::run_packet_bytes_v6(&packet.data, direction, true)
                } else {
                    api::run_packet_bytes_v4(&packet.data, direction, true)
                };
                if result.action == FWP_ACTION_PERMIT {
                    summary.loopback_permits.fetch_add(1, Ordering::Relaxed);
                } else {
                    summary.fail(format!(
                        "self-injected packet not permitted: {} (action={:#x} absorb={})",
                        describe_injected(&packet),
                        result.action,
                        result.absorb
                    ));
                }
            }
        }
    }
}

/// Best-effort one-line identity for a drained injected packet: parses the IP
/// header for the 5-tuple, falling back to flags + length when the bytes are not
/// a parsable IP packet (e.g. a raw transport segment).
fn describe_injected(packet: &api::InjectedPacket) -> String {
    let kind = if packet.transport { "transport" } else { "network" };
    let dir = if packet.inbound { "inbound" } else { "outbound" };
    let loopback = if packet.loopback { " loopback" } else { "" };
    match describe_ip_packet(&packet.data, packet.ipv6) {
        Some(tuple) => format!("{tuple} [{kind} {dir}{loopback} len={}]", packet.data.len()),
        None => format!(
            "<unparsable {} packet> [{kind} {dir}{loopback} len={}]",
            if packet.ipv6 { "v6" } else { "v4" },
            packet.data.len(),
        ),
    }
}

/// Pull "PROTO src=addr:port dst=addr:port" out of a raw IP packet, or `None` if
/// the header is too short or its version nibble does not match `ipv6`.
fn describe_ip_packet(data: &[u8], ipv6: bool) -> Option<String> {
    if ipv6 {
        if data.len() < 40 || data[0] >> 4 != 6 {
            return None;
        }
        let proto = data[6];
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?);
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?);
        Some(match ports_at(data, 40, proto) {
            Some((s, d)) => {
                format!("{} src=[{src}]:{s} dst=[{dst}]:{d}", scenarios::proto_label(proto))
            }
            None => format!("{} src=[{src}] dst=[{dst}]", scenarios::proto_label(proto)),
        })
    } else {
        if data.len() < 20 || data[0] >> 4 != 4 {
            return None;
        }
        let ihl = (data[0] & 0x0f) as usize * 4;
        if ihl < 20 {
            return None;
        }
        let proto = data[9];
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        Some(match ports_at(data, ihl, proto) {
            Some((s, d)) => format!("{} src={src}:{s} dst={dst}:{d}", scenarios::proto_label(proto)),
            None => format!("{} src={src} dst={dst}", scenarios::proto_label(proto)),
        })
    }
}

/// The source/destination ports at `offset` for TCP/UDP, if the bytes are there.
fn ports_at(data: &[u8], offset: usize, proto: u8) -> Option<(u16, u16)> {
    if !matches!(proto, 6 | 17) {
        return None;
    }
    let src = data.get(offset..offset + 2)?;
    let dst = data.get(offset + 2..offset + 4)?;
    Some((
        u16::from_be_bytes([src[0], src[1]]),
        u16::from_be_bytes([dst[0], dst[1]]),
    ))
}
