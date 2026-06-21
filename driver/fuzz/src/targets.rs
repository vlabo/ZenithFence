//! Fuzz-target bodies. Each takes a raw `&[u8]` (what libFuzzer / the replay
//! runner provide) and runs the code under test plus its oracles. A violated
//! oracle panics, which libFuzzer reports as a crash and the replay runner
//! surfaces as a process abort.

/// The set of valid target names (kept in sync with the functions below).
pub const NAMES: &[&str] = &["callouts"];

/// Dispatch by name. Returns `false` for an unknown target.
pub fn run(name: &str, data: &[u8]) -> bool {
    match name {
        "callouts" => callouts(data),
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
    use driver::fuzz_api as api;

    api::ensure_device();
    let mut s = Stream::new(data);

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
                let plen = (s.u8() % 64) as usize;
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
                let plen = (s.u8() % 64) as usize;
                let payload = s.take(plen);
                let raw = flags & 2 != 0;
                let v4 = op == 4 || op == 5;
                // Verdict the packet layer is about to act on (read before the op;
                // a permanent verdict is not modified by the packet layer).
                let verdict = if v4 {
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
                let tcp_udp = proto % 4 < 2;
                if !raw && tcp_udp {
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
                assert_eq!(
                    api::packet_cache_len(),
                    0,
                    "packet cache not drained by shutdown"
                );
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
