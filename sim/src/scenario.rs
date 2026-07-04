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
//! fields (`local`/`remote`/`payload`/`bytes`) are CBOR byte strings, and arrays
//! of byte values in JSON.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, ErrorKind, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crossbeam_channel::unbounded;
use serde::{Deserialize, Serialize};

use driver::fuzz_api::{
    self as api, CalloutResult, Direction, TupleSpecV4, TupleSpecV6, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT,
};

/// One scenario command ("line"). See the module docs for the field vocabulary.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
struct Record {
    /// Microseconds since scenario start (absolute point on the timeline).
    ts: u64,
    /// Command selector: `ale_connect` | `ale_accept` | `packet` |
    /// `packet_bytes` | `endpoint_close` | `resource_release`.
    op: String,
    /// Address family: `false` => IPv4, `true` => IPv6.
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
fn delta_micros(prev: Option<u64>, ts: u64) -> u64 {
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
        other => return sum.fail(format!("unknown op `{other}`")),
    };
    sum.tally(&rec.op, result);
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
    let threads = std::env::var("ZF_SIM_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(4);

    let summary = Arc::new(ScenarioSummary::default());

    // Open a streaming record iterator (codec chosen by extension). Records are
    // parsed and dispatched one at a time -- the whole file is never held in
    // memory, and a scenario can be arbitrarily long.
    let records = match open_records(path) {
        Ok(records) => records,
        Err(e) => {
            summary.fail(e);
            return summary;
        }
    };

    // Scheduler -> worker pool. One sender (this thread); each worker owns a
    // clone of the receiver, so whichever worker is free takes the next command.
    let (tx, rx) = unbounded::<Record>();
    let workers: Vec<_> = (0..threads)
        .map(|i| {
            let rx = rx.clone();
            let sum = Arc::clone(&summary);
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

    println!("[scenario] streaming `{path}` on {threads} worker(s) ...");
    let mut prev: Option<u64> = None;
    for item in records {
        let rec = match item {
            Ok(rec) => rec,
            Err(e) => {
                summary.fail(e);
                break;
            }
        };
        let delta = delta_micros(prev, rec.ts);
        if delta > 0 {
            thread::sleep(Duration::from_micros(delta));
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

    summary
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
        for records in [basic_v4(), mixed_v4v6_parallel(), icmp_burst()] {
            let back = decode(&encode(&records));
            assert_eq!(records, back);
        }
    }

    #[test]
    fn json_lines_roundtrips() {
        for records in [basic_v4(), mixed_v4v6_parallel(), icmp_burst()] {
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
        assert_eq!(delta_micros(None, 100), 0); // first record: no previous
        assert_eq!(delta_micros(Some(100), 250), 150); // forward delta
        assert_eq!(delta_micros(Some(250), 250), 0); // equal ts => parallel, no sleep
        assert_eq!(delta_micros(Some(250), 100), 0); // non-monotonic => clamped
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
}
