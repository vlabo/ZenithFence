//! Fake OS-side network traffic.
//!
//! Drives semi-realistic flows through the real driver callout entry points,
//! the way the OS does: ALE authorization first (which pends and emits an event
//! the agent answers over the pipe), then data packets through the IP packet
//! layer, then endpoint closure and resource release. A deterministic scenario
//! set always runs; N seeded random flows run on top ([`crate::scenarios`]).
//!
//! Concurrency mirrors the kernel: several producer workers classify flows at
//! the same time (WFP classify callbacks fire on many threads), and one
//! reinjector thread models the OS re-presenting driver-injected packets to the
//! packet-layer callouts (network injects re-enter marked injected-by-self;
//! outbound transport injects descend the stack unmarked; inbound transport
//! injects re-indicate upward and never pass the network layer again).
//!
//! Everything is reproducible from the printed seed (`ZF_SIM_SEED`).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use driver::fuzz_api::{
    self as api, CalloutResult, Direction, Verdict, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
};

use crate::rng::{mix, SplitMix64};
use crate::scenarios::{self, Expect, FlowPlan, Tuple};

const VERDICT_POLL: Duration = Duration::from_millis(5);
const REINJECT_POLL: Duration = Duration::from_millis(2);

// ---- Config -----------------------------------------------------------------

pub struct Config {
    pub seed: u64,
    pub random_flows: u32,
    pub threads: usize,
    /// Soft cap: workers start no new flows after this much wall time.
    pub duration: Option<Duration>,
}

impl Config {
    pub fn from_env() -> Config {
        let seed = std::env::var("ZF_SIM_SEED")
            .ok()
            .and_then(|s| parse_u64(&s))
            .unwrap_or_else(|| {
                mix(SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0x5EED))
            });
        let random_flows = std::env::var("ZF_SIM_FLOWS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(24);
        let threads = std::env::var("ZF_SIM_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n: &usize| n >= 1)
            .unwrap_or(4);
        let duration = std::env::var("ZF_SIM_DURATION")
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Duration::from_secs);
        Config {
            seed,
            random_flows,
            threads,
            duration,
        }
    }
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

// ---- Summary ------------------------------------------------------------------

#[derive(Default)]
pub struct Summary {
    pub flows_ok: AtomicU64,
    pub flows_skipped: AtomicU64,
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

    pub fn print(&self) {
        println!(
            "[sim] flows ok={} skipped={} | packets={} bytes={} | self-inject permits={} transport replays={} | verdict timeouts={}",
            self.flows_ok.load(Ordering::Relaxed),
            self.flows_skipped.load(Ordering::Relaxed),
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

/// Run the whole traffic plan. Returns once every flow ran, the agent's
/// verdicts resolved every pended packet, and the reinjector drained every
/// injected packet (or the deadline passed, which is recorded as a failure).
pub fn drive(cfg: &Config) -> Summary {
    let mut plans = scenarios::deterministic();
    let mut rng = SplitMix64::new(cfg.seed);
    for seq in 0..cfg.random_flows {
        let worker = (seq as usize) % cfg.threads;
        plans.push(scenarios::random_flow(&mut rng, worker, seq as u16));
    }

    // The agent handles events on one goroutine and sleeps 200 ms per accepted
    // outbound-v4 event, so the wait budget is global and scales with the plan.
    let deadline = Instant::now()
        + Duration::from_millis(250 * plans.len() as u64)
        + Duration::from_secs(15);
    let soft_stop = cfg.duration.map(|d| Instant::now() + d);

    let summary = Arc::new(Summary::default());
    let stop_reinjector = Arc::new(AtomicBool::new(false));

    let reinjector = {
        let summary = Arc::clone(&summary);
        let stop = Arc::clone(&stop_reinjector);
        thread::spawn(move || reinject_loop(&summary, &stop))
    };

    // Round-robin whole flows to workers; each worker runs its flows in order.
    let mut buckets: Vec<Vec<FlowPlan>> = (0..cfg.threads).map(|_| Vec::new()).collect();
    for (i, plan) in plans.into_iter().enumerate() {
        buckets[i % cfg.threads].push(plan);
    }
    let workers: Vec<_> = buckets
        .into_iter()
        .map(|bucket| {
            let summary = Arc::clone(&summary);
            thread::spawn(move || {
                for plan in bucket {
                    if soft_stop.is_some_and(|t| Instant::now() > t) {
                        summary.flows_skipped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    run_flow(&plan, &summary, deadline);
                }
            })
        })
        .collect();
    for worker in workers {
        let _ = worker.join();
    }

    // Quiesce: every pended packet answered, every injected packet replayed.
    while (api::packet_cache_len() > 0 || api::injected_len() > 0) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    if api::packet_cache_len() > 0 {
        summary.fail(format!(
            "{} packets still pended after the verdict deadline",
            api::packet_cache_len()
        ));
    }

    stop_reinjector.store(true, Ordering::Relaxed);
    let _ = reinjector.join();
    match Arc::try_unwrap(summary) {
        Ok(summary) => summary,
        Err(_) => unreachable!("all summary holders joined"),
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
                summary.fail(format!("{}: inbound loopback not permitted at ALE", plan.name));
            }
            permitted
        }
        Expect::NoVerdict => true, // ICMP: ALE not involved for the packet path below
        Expect::Accepted | Expect::Blocked => {
            // New TCP/UDP connection: the original classify is absorbed and the
            // flow pends until the agent's verdict.
            if !result.absorb {
                summary.fail(format!("{}: new connection did not pend at ALE", plan.name));
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
                    summary.fail(format!("{}: expected block, got verdict {verdict}", plan.name));
                    ok = false;
                } else if !expected_block && !accept_ish {
                    summary.fail(format!("{}: expected accept, got verdict {verdict}", plan.name));
                    ok = false;
                }
            }
            None => {
                summary.verdict_timeouts.fetch_add(1, Ordering::Relaxed);
                summary.fail(format!("{}: verdict timed out", plan.name));
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
                            plan.name, result.action, result.absorb
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
                        summary.fail(format!("{}: ICMP packet did not pend", plan.name));
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
                    plan.name, result.action
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
                summary.fail(format!("{}: burst {i} verdict timed out", plan.name));
                return false;
            }
        } else if result.action != FWP_ACTION_PERMIT {
            summary.fail(format!(
                "{}: burst {i} neither permitted nor pended (action={:#x})",
                plan.name, result.action
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
            plan.name, result.action
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

fn reinject_loop(summary: &Summary, stop: &AtomicBool) {
    loop {
        let injected = api::drain_injected();
        if injected.is_empty() {
            if stop.load(Ordering::Relaxed) {
                return;
            }
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
                        "transport re-inject not permitted (action={:#x} absorb={})",
                        result.action, result.absorb
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
                        "self-injected packet not permitted (action={:#x} absorb={})",
                        result.action, result.absorb
                    ));
                }
            }
        }
    }
}
