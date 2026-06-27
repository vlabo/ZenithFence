//! Fuzz-target bodies. Each takes a raw `&[u8]` (what libFuzzer / the replay
//! runner provide) and runs the code under test plus its oracles. A violated
//! oracle panics, which libFuzzer reports as a crash and the replay runner
//! surfaces as a process abort.

/// The set of valid target names (kept in sync with the functions below).
pub const NAMES: &[&str] = &["callouts", "callouts_mt", "simulation"];

/// Dispatch by name. Returns `false` for an unknown target.
pub fn run(name: &str, data: &[u8]) -> bool {
    match name {
        "callouts" => callouts(data),
        "callouts_mt" => callouts_mt(data),
        "simulation" => simulation(data),
        _ => return false,
    }
    true
}

/// Number of op variants the byte decoder recognizes.
const N_OPS: u8 = 18;

// Self-drain thresholds. With one persistent device across inputs, an op stream
// that pends flows but never answers them would grow the packet cache, and one
// that opens connections but never ends them would grow the connection cache,
// without bound -- draining here keeps that growth from being mistaken for a
// leak. Both caches are keyed by the small fuzz address pool, so these limits
// are only a backstop and are rarely hit in practice.
const PACKET_CACHE_LIMIT: usize = 8192;
const CONN_CACHE_LIMIT: usize = 8192;

/// Minimal byte-stream reader for the op grammar. Reads past the end yield
/// `0`/empty; the loop stops once the cursor passes the end, so a truncated
/// final op simply runs with zeroed fields (still fully deterministic, which
/// keeps hand-authored corpus seeds stable).
struct Stream<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Stream<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn done(&self) -> bool {
        self.pos >= self.data.len()
    }
    fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
    fn take(&mut self, n: usize) -> &'a [u8] {
        let start = self.pos.min(self.data.len());
        let end = (self.pos + n).min(self.data.len());
        self.pos += n;
        &self.data[start..end]
    }
}

// Map one length byte to a payload size. Wider than a single header (0..=510)
// so the `raw` packet path stresses the in-callout parser with arbitrary,
// larger packet data, and structured packets carry varied payloads.
fn payload_len(b: u8) -> usize {
    (b as usize) * 2
}

/// Stateful callout pipeline -- the main reason this harness exists. Decodes the
/// input into a sequence of operations replayed against one persistent mock
/// `Device`: ALE callouts pend flows, `Verdict`/`Update` commands resolve them,
/// and packet-layer callouts then read the resulting verdict. Oracles:
///   * Tier 1: no panic / no OOB / no UB (libFuzzer + ASAN).
///   * Tier 2: ALE + structured packet callouts always set an action; after a
///     `Shutdown` op the packet cache is empty.
///   * Tier 3: for a structured TCP/UDP flow carrying a permanent verdict, the
///     packet-layer action matches that verdict.
pub fn callouts(data: &[u8]) {
    driver::fuzz_api::ensure_device();
    let mut s = Stream::new(data);
    drive_ops(&mut s, false);
}

/// Multithreaded callout stress -- one shared persistent `Device`, many worker
/// threads driving the callouts at the same time, in all combinations.
///
/// Layout of `data`: byte 0 selects the worker count (2..=8); the rest is one
/// op stream. Every worker runs the *whole* op stream, phase-shifted by a
/// distinct rotation, so all workers hammer overlapping connection-pool slots
/// concurrently with varied op orders -- maximizing contention on the same RCU
/// ports / packet cache. Workers are released together by a barrier.
///
/// Oracles under concurrency are interleaving-independent:
///   * Tier 1: no panic / no ASAN / no ThreadSanitizer report (the main one).
///   * Tier 2 (per call): ALE + structured packet callouts always set an action.
///   * Post-join quiesce: with no worker running, a `Shutdown` must fully drain
///     the packet cache.
/// The Tier-3 cross-layer verdict mapping and the mid-stream "Shutdown -> empty"
/// assert are dropped here: another thread can change a verdict or pend a packet
/// between the observation and the check, so they are not race-stable.
pub fn callouts_mt(data: &[u8]) {
    use driver::fuzz_api as api;
    api::ensure_device();

    if data.len() < 2 {
        // Too short for a header + body; still run a single pass so the input
        // isn't wasted (and the empty/short cases get exercised).
        let mut s = Stream::new(data);
        drive_ops(&mut s, true);
        return;
    }

    let n_threads = 2 + (data[0] as usize % 7); // 2..=8 workers
    let body: Vec<u8> = data[1..].to_vec();
    let len = body.len();
    if len == 0 {
        return;
    }
    // Spread each worker's starting phase across the body.
    let step = (len / n_threads).max(1);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(n_threads));
    let mut handles = Vec::with_capacity(n_threads);
    for i in 0..n_threads {
        let mut chunk = body.clone();
        let rot = (i * step) % len;
        chunk.rotate_left(rot);
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            // Release all workers at once for maximum overlap.
            barrier.wait();
            let mut s = Stream::new(&chunk);
            drive_ops(&mut s, true);
        }));
    }

    // Join all workers; a worker panic (oracle violation) surfaces as a join
    // error, which we re-raise on the main thread so libFuzzer records a crash.
    // (Memory/race errors abort the whole process via the sanitizer directly.)
    let mut panicked = false;
    for h in handles {
        if h.join().is_err() {
            panicked = true;
        }
    }
    if panicked {
        panic!("callouts_mt: a worker thread panicked (oracle violation / crash)");
    }

    // Quiesce oracle: nothing is running now, so a shutdown must fully drain the
    // packet cache regardless of how the threads interleaved.
    api::device_shutdown();
    assert_eq!(
        api::packet_cache_len(),
        0,
        "packet cache not drained after MT quiesce + shutdown"
    );
}

/// Full-driver simulation -- the highest-fidelity target. Loads the *real*
/// driver via `DriverEntry` (over the mocked WDK), then runs the asynchronous
/// channel pipeline with real OS threads:
///   * a "kernel" producer (this thread) drives event-producing callouts from
///     the op stream -- ALE/packet callouts pend flows and push events, endpoint
///     closures and resource events fire;
///   * a user-space consumer thread blocks on `DriverConnection::read`, parses
///     the event stream, and writes `Verdict` commands back over the channel
///     (the verdict bytes come from the fuzz input, so all verdict kinds --
///     accept/block/drop/redirect and the permanent variants -- get explored).
///
/// This exercises the full lifecycle (load -> dispatch -> unload), the blocking
/// event queue, the IRP read/write path, and the pend -> event -> verdict ->
/// inject loop under genuine producer/consumer concurrency (so ThreadSanitizer
/// sees real races if any exist).
///
/// Oracles (interleaving-independent):
///   * Tier 1: no panic / no ASAN / no ThreadSanitizer report.
///   * Tier 2 (per call): ALE + structured packet callouts always set an action.
///   * Post-shutdown quiesce: once the producer is done and the driver is shut
///     down, the packet cache is empty (every pended flow was resolved or drained).
pub fn simulation(data: &[u8]) {
    use driver::sim;

    // Each input gets a fresh driver: full DriverEntry -> run -> unload lifecycle.
    let Ok(simulation) = sim::Simulation::start() else {
        return;
    };

    // User-space side: reply to each connection event with a fuzz-chosen verdict.
    // `Device::write` pops the pended packet for any verdict byte (valid kinds
    // inject, invalid ones just drop it), so the packet cache drains as events
    // flow regardless of the bytes.
    let verdict_seed: Vec<u8> = data.to_vec();
    let mut vc: usize = 0;
    let consumer = sim::spawn_consumer(
        simulation.connect(),
        move |_event| {
            let verdict = if verdict_seed.is_empty() {
                3 // PermanentAccept
            } else {
                let b = verdict_seed[vc % verdict_seed.len()];
                vc = vc.wrapping_add(1);
                b
            };
            Some(verdict)
        },
        None,
    );

    // "Kernel" side: drive the event-producing callouts from the op stream.
    let mut s = Stream::new(data);
    drive_producer(&mut s);

    // Quiesce: resolve pending packets and run down the queue so the consumer's
    // blocking read returns end-of-file, then wait for it to finish.
    simulation.shutdown();
    let stats = consumer.join_timeout(std::time::Duration::from_secs(60));
    assert!(
        stats.is_some(),
        "simulation: consumer thread did not exit after shutdown (hang)"
    );

    // With the producer done and the driver shut down, nothing remains pended.
    assert_eq!(
        driver::fuzz_api::packet_cache_len(),
        0,
        "simulation: packet cache not drained after shutdown"
    );

    drop(simulation);
}

/// Number of producer (event-generating) op variants for the simulation target.
const N_PRODUCER_OPS: u8 = 12;

/// Decode and run only the event-*producing* callouts against the installed
/// device. Unlike [`drive_ops`], this issues no `Verdict`/`Update`/`Shutdown`
/// commands and never reads the event queue -- in the simulation those are the
/// user-space consumer's job, over the channel -- so it never blocks on the
/// (now blocking) event queue.
fn drive_producer(s: &mut Stream) {
    use driver::fuzz_api as api;

    while !s.done() {
        let op = s.u8() % N_PRODUCER_OPS;
        match op {
            // ---- ALE callouts: always set an action ----
            0 | 1 | 2 | 3 => {
                let conn = s.u8();
                let proto = s.u8();
                let flags = s.u8();
                let pid = s.u16() as u64;
                let plen = payload_len(s.u8());
                let payload = s.take(plen);
                let reauth = flags & 1 != 0;
                let raw = flags & 2 != 0;
                let r = match op {
                    0 => api::run_ale_connect_v4(conn, proto, reauth, pid, payload, raw),
                    1 => api::run_ale_accept_v4(conn, proto, reauth, pid, payload, raw),
                    2 => api::run_ale_connect_v6(conn, proto, reauth, pid, payload, raw),
                    _ => api::run_ale_accept_v6(conn, proto, reauth, pid, payload, raw),
                };
                assert!(r.action != 0, "ALE callout {op} left no action set");
            }
            // ---- Packet-layer callouts ----
            4 | 5 | 6 | 7 => {
                let conn = s.u8();
                let proto = s.u8();
                let flags = s.u8();
                let plen = payload_len(s.u8());
                let payload = s.take(plen);
                let raw = flags & 2 != 0;
                let r = match op {
                    4 => api::run_packet_in_v4(conn, proto, payload, raw),
                    5 => api::run_packet_out_v4(conn, proto, payload, raw),
                    6 => api::run_packet_in_v6(conn, proto, payload, raw),
                    _ => api::run_packet_out_v6(conn, proto, payload, raw),
                };
                if !raw && api::proto_is_connectable(proto) {
                    assert!(r.action != 0, "packet callout {op} left no action set");
                }
            }
            // ---- Endpoint closure (emits a connection-end event) ----
            8 => {
                let conn = s.u8();
                let proto = s.u8();
                let pid = s.u16() as u64;
                api::run_endpoint_close_v4(conn, proto, pid);
            }
            9 => {
                let conn = s.u8();
                let proto = s.u8();
                let pid = s.u16() as u64;
                api::run_endpoint_close_v6(conn, proto, pid);
            }
            // ---- Resource monitor (port assignment-discard / release) ----
            10 => {
                let kind = s.u8();
                let proto = s.u8();
                let port = s.u16();
                api::run_resource_v4(kind, proto, port);
            }
            _ => {
                let kind = s.u8();
                let proto = s.u8();
                let port = s.u16();
                api::run_resource_v6(kind, proto, port);
            }
        }
    }
}

/// Decode and execute the op stream against the (already installed) global
/// device. `concurrent` selects the oracle set: when other threads may be
/// mutating the same device, race-sensitive checks (Tier-3 verdict mapping and
/// the mid-stream shutdown-empties-cache assert) are skipped; everything else
/// (no panic, per-call "an action was set") still holds.
fn drive_ops(s: &mut Stream, concurrent: bool) {
    use driver::fuzz_api as api;

    while !s.done() {
        // Keep persistent state bounded (see thresholds above).
        if api::packet_cache_len() > PACKET_CACHE_LIMIT {
            api::device_shutdown();
        }
        if api::active_conn_count() > CONN_CACHE_LIMIT {
            api::device_clear_cache();
        }

        let op = s.u8() % N_OPS;
        match op {
            // ---- ALE callouts: always set an action ----
            0 | 1 | 2 | 3 => {
                let conn = s.u8();
                let proto = s.u8();
                let flags = s.u8();
                let pid = s.u16() as u64;
                let plen = payload_len(s.u8());
                let payload = s.take(plen);
                let reauth = flags & 1 != 0;
                let raw = flags & 2 != 0;
                let r = match op {
                    0 => api::run_ale_connect_v4(conn, proto, reauth, pid, payload, raw),
                    1 => api::run_ale_accept_v4(conn, proto, reauth, pid, payload, raw),
                    2 => api::run_ale_connect_v6(conn, proto, reauth, pid, payload, raw),
                    _ => api::run_ale_accept_v6(conn, proto, reauth, pid, payload, raw),
                };
                assert!(r.action != 0, "ALE callout {op} left no action set");
            }
            // ---- Packet-layer callouts ----
            4 | 5 | 6 | 7 => {
                let conn = s.u8();
                let proto = s.u8();
                let flags = s.u8();
                let plen = payload_len(s.u8());
                let payload = s.take(plen);
                let raw = flags & 2 != 0;
                let v4 = op == 4 || op == 5;
                // Verdict the packet layer is about to act on (read before the op;
                // a permanent verdict is not modified by the packet layer). Only
                // meaningful single-threaded -- under concurrency another thread
                // could change it, so we don't read or assert on it.
                let verdict = if concurrent {
                    None
                } else if v4 {
                    api::verdict_for_v4(conn, proto)
                } else {
                    api::verdict_for_v6(conn, proto)
                };
                let r = match op {
                    4 => api::run_packet_in_v4(conn, proto, payload, raw),
                    5 => api::run_packet_out_v4(conn, proto, payload, raw),
                    6 => api::run_packet_in_v6(conn, proto, payload, raw),
                    _ => api::run_packet_out_v6(conn, proto, payload, raw),
                };
                // A structured TCP/UDP packet always parses, so an action is set.
                if !raw && api::proto_is_connectable(proto) {
                    assert!(r.action != 0, "packet callout {op} left no action set");
                    if let Some(v) = verdict {
                        check_perm_verdict(op, v, r);
                    }
                }
            }
            // ---- Verdict command (resolve a pended packet) ----
            8 => {
                let id_sel = s.u8();
                let verdict = s.u8();
                let ids = api::live_ids();
                let id = if ids.is_empty() {
                    id_sel as u64
                } else {
                    ids[id_sel as usize % ids.len()]
                };
                api::device_write_verdict(id, verdict);
            }
            // ---- Update commands (set a verdict by key) ----
            9 => {
                let conn = s.u8();
                let proto = s.u8();
                let verdict = s.u8();
                api::device_write_update_v4(conn, proto, verdict);
            }
            10 => {
                let conn = s.u8();
                let proto = s.u8();
                let verdict = s.u8();
                api::device_write_update_v6(conn, proto, verdict);
            }
            // ---- Endpoint closure ----
            11 => {
                let conn = s.u8();
                let proto = s.u8();
                let pid = s.u16() as u64;
                api::run_endpoint_close_v4(conn, proto, pid);
            }
            12 => {
                let conn = s.u8();
                let proto = s.u8();
                let pid = s.u16() as u64;
                api::run_endpoint_close_v6(conn, proto, pid);
            }
            // ---- Resource monitor (port assignment-discard / release) ----
            13 => {
                let kind = s.u8();
                let proto = s.u8();
                let port = s.u16();
                api::run_resource_v4(kind, proto, port);
            }
            14 => {
                let kind = s.u8();
                let proto = s.u8();
                let port = s.u16();
                api::run_resource_v6(kind, proto, port);
            }
            // ---- Read / drain events ----
            15 => {
                let n = s.u8();
                api::drain_events(n);
            }
            // ---- Clear connection cache ----
            16 => {
                api::device_clear_cache();
            }
            // ---- Shutdown: must leave the packet cache empty ----
            _ => {
                api::device_shutdown();
                // Race-stable only when single-threaded: another worker may pend
                // a packet right after the shutdown drains the cache.
                if !concurrent {
                    assert_eq!(
                        api::packet_cache_len(),
                        0,
                        "packet cache not drained by shutdown"
                    );
                }
            }
        }
    }
}

// Tier-3 oracle: a permanent verdict fully determines the packet-layer action
// for a found TCP/UDP flow. `op` is only used to label assertion failures.
fn check_perm_verdict(op: u8, verdict: u8, r: driver::fuzz_api::CalloutResult) {
    use driver::fuzz_api::{FWP_ACTION_BLOCK, FWP_ACTION_PERMIT};
    match verdict {
        // PermanentAccept
        3 => assert_eq!(
            r.action, FWP_ACTION_PERMIT,
            "op {op}: PermanentAccept must permit"
        ),
        // PermanentBlock
        5 => {
            assert_eq!(
                r.action, FWP_ACTION_BLOCK,
                "op {op}: PermanentBlock must block"
            );
            assert!(!r.absorb, "op {op}: PermanentBlock must not absorb");
        }
        // PermanentDrop
        7 => {
            assert_eq!(
                r.action, FWP_ACTION_BLOCK,
                "op {op}: PermanentDrop must block"
            );
            assert!(r.absorb, "op {op}: PermanentDrop must absorb");
        }
        // RedirectNameServer / RedirectTunnel: the original packet is blocked+absorbed.
        8 | 9 => {
            assert_eq!(
                r.action, FWP_ACTION_BLOCK,
                "op {op}: Redirect must block original"
            );
            assert!(r.absorb, "op {op}: Redirect must absorb original");
        }
        _ => {} // temporary / invalid verdicts have no single-valued mapping
    }
}
