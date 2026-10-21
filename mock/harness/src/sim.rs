//! Full-driver simulation harness.
//!
//! Loads the *real* driver via its `DriverEntry` (over the mocked WDK), then lets
//! a user-space side talk to it through the same channel a real agent uses
//! ([`wdk::connection::DriverConnection`] = `ReadFile`/`WriteFile`/`DeviceIoControl`).
//! Callouts are driven on one thread (the "kernel" producer) while a separate
//! user-space consumer thread blocks on `read`, parses the event stream, and
//! replies with verdicts — exercising the asynchronous pend -> event -> verdict
//! -> inject pipeline, the blocking event queue, and the IRP dispatch, with real
//! OS threads (so ThreadSanitizer sees genuine concurrency).
//!
//! Teardown order is load-bearing: `shutdown` runs down the event queue so a
//! blocked reader wakes with end-of-file; join the consumer; only then drop the
//! `Simulation`, which unloads the driver through its registered `DriverUnload`.

use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use protocol::command::CommandType;
use wdk::connection::DriverConnection;
use wdk::kernel_types::{NTSTATUS, STATUS_END_OF_FILE, STATUS_SUCCESS};

use crate::loader::{self, Reads};

/// A loaded driver instance (loaded with blocking reads, so a consumer thread
/// blocks on `read` like a real user-space agent). Holds the harness driver lock
/// for its lifetime so concurrent tests don't fight over the one driver per
/// process, and unloads the driver when dropped.
pub struct Simulation {
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Simulation {
    /// Load the driver through its real `driver_entry`. A driver left loaded by
    /// an earlier harness user is unloaded first, so this run starts clean.
    pub fn start() -> Result<Self, NTSTATUS> {
        let guard = loader::lock();
        let status = loader::reload(Reads::Blocking);
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        Ok(Self { _guard: guard })
    }

    /// Open a fresh user-space connection to the driver. Each thread should use
    /// its own (the dispatch handlers take `&mut` device/IRP per call).
    pub fn connect(&self) -> DriverConnection {
        loader::with_driver_object(DriverConnection::open)
            .flatten()
            .expect("driver loaded")
    }

    /// Request shutdown: resolve pending packets and run down the event queue so
    /// any blocked reader wakes with end-of-file. Idempotent; safe to call from
    /// the producer once the op stream is done.
    pub fn shutdown(&self) {
        if let Some(device) = driver::entry::get_device() {
            device.shutdown();
        }
    }
}

impl Drop for Simulation {
    fn drop(&mut self) {
        // Unload through the DriverUnload registered by driver_entry (frees the
        // device and clears the driver's global).
        loader::unload();
    }
}

/// One decoded event frame from the driver's read stream
/// (`[InfoType:u8, size:u32 LE, payload]`).
pub struct Event {
    pub info_type: u8,
    pub payload: Vec<u8>,
}

impl Event {
    // ConnectionIpv4 (1) / ConnectionIpv6 (2) carry the pended packet id as the
    // first u64 of the payload; that's what a verdict command refers to.
    pub fn packet_id(&self) -> Option<u64> {
        const CONNECTION_IPV4: u8 = 1;
        const CONNECTION_IPV6: u8 = 2;
        if matches!(self.info_type, CONNECTION_IPV4 | CONNECTION_IPV6) && self.payload.len() >= 8 {
            let mut id = [0u8; 8];
            id.copy_from_slice(&self.payload[..8]);
            Some(u64::from_le_bytes(id))
        } else {
            None
        }
    }
}

/// Streaming parser for the driver's event byte stream. A single `read` may
/// return several whole frames, and the driver may split a frame across reads
/// (via its read-leftover buffer), so bytes are accumulated and whole frames are
/// pulled off the front.
pub struct EventParser {
    buf: Vec<u8>,
}

impl EventParser {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Pull the next complete frame, or `None` if a full frame isn't buffered yet.
    pub fn next_event(&mut self) -> Option<Event> {
        const HEADER: usize = 5; // info_type(1) + size(4)
        if self.buf.len() < HEADER {
            return None;
        }
        let size = u32::from_le_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]]) as usize;
        if self.buf.len() < HEADER + size {
            return None;
        }
        let info_type = self.buf[0];
        let payload = self.buf[HEADER..HEADER + size].to_vec();
        self.buf.drain(0..HEADER + size);
        Some(Event { info_type, payload })
    }
}

impl Default for EventParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialize a `Verdict` command (the wire form a user-space agent writes back
/// to resolve a pended packet).
pub fn verdict_command(id: u64, verdict: u8) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(10);
    cmd.push(CommandType::Verdict as u8);
    cmd.extend_from_slice(&id.to_le_bytes());
    cmd.push(verdict);
    cmd
}

/// What a finished consumer thread observed.
pub struct ConsumerStats {
    pub events: u64,
    pub replies: u64,
}

/// Handle to a running user-space consumer thread.
pub struct ConsumerHandle {
    join: JoinHandle<ConsumerStats>,
}

impl ConsumerHandle {
    /// Wait for the consumer to exit (it exits when the channel reaches
    /// end-of-file, i.e. after `Simulation::shutdown`). Re-raises a consumer panic.
    pub fn join(self) -> ConsumerStats {
        match self.join.join() {
            Ok(stats) => stats,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    /// Like [`join`](Self::join) but gives up after `dur`, returning `None` (used
    /// by the no-hang test to fail fast if shutdown didn't release the reader).
    pub fn join_timeout(self, dur: Duration) -> Option<ConsumerStats> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(self.join.join());
        });
        match rx.recv_timeout(dur) {
            Ok(Ok(stats)) => Some(stats),
            Ok(Err(payload)) => std::panic::resume_unwind(payload),
            Err(_) => None,
        }
    }
}

/// Spawn a user-space consumer thread: it blocks on `conn.read`, parses events,
/// and for each event asks `verdict_policy` for a verdict to write back. If
/// `processed` is set, the packet id of each replied-to event is sent on it (so a
/// test can synchronize on "the verdict has been applied"). The thread exits when
/// the channel reaches end-of-file (after shutdown).
pub fn spawn_consumer<F>(
    mut conn: DriverConnection,
    mut verdict_policy: F,
    processed: Option<mpsc::Sender<u64>>,
) -> ConsumerHandle
where
    F: FnMut(&Event) -> Option<u8> + Send + 'static,
{
    let join = thread::spawn(move || {
        let mut parser = EventParser::new();
        let mut buf = [0u8; 4096];
        let mut stats = ConsumerStats {
            events: 0,
            replies: 0,
        };
        loop {
            let (n, status) = conn.read(&mut buf);
            if status == STATUS_END_OF_FILE {
                break;
            }
            // Blocking reads only return SUCCESS (with data) or end-of-file; any
            // other status stops the loop rather than risk a spin.
            if status != STATUS_SUCCESS {
                break;
            }
            parser.feed(&buf[..n]);
            while let Some(event) = parser.next_event() {
                stats.events += 1;
                let Some(verdict) = verdict_policy(&event) else {
                    continue;
                };
                let Some(id) = event.packet_id() else {
                    continue;
                };
                conn.write(&verdict_command(id, verdict));
                stats.replies += 1;
                if let Some(tx) = &processed {
                    let _ = tx.send(id);
                }
            }
        }
        stats
    });
    ConsumerHandle { join }
}

#[cfg(test)]
mod tests {
    use super::*;
    use driver::connection::Verdict;

    // End-to-end async pipeline over the real channel: a new inbound TCP
    // connection pends and emits an event; a user-space consumer thread reads it
    // through `DriverConnection`, replies PermanentAccept, and that verdict is
    // observed in the connection cache.
    #[test]
    fn pipeline_event_to_verdict_over_channel() {
        let sim = Simulation::start().expect("driver loads");

        let (tx, rx) = mpsc::channel();
        let consumer = spawn_consumer(
            sim.connect(),
            |_event| Some(Verdict::PermanentAccept as u8),
            Some(tx),
        );

        // Producer ("kernel"): inbound TCP accept on a clean pool slot pends the
        // connection and pushes a ConnectionIpv4 event.
        let (conn_slot, proto_tcp) = (0u8, 0u8);
        assert!(crate::fuzz_api::proto_is_connectable(proto_tcp));
        let _ = crate::fuzz_api::run_ale_accept_v4(conn_slot, proto_tcp, false, 4321, &[], false);

        // Wait for the consumer to read the event and write the verdict back.
        rx.recv_timeout(Duration::from_secs(5))
            .expect("consumer read the event and replied within the deadline");

        assert_eq!(
            crate::fuzz_api::verdict_for_v4(conn_slot, proto_tcp),
            Some(Verdict::PermanentAccept as u8),
            "verdict sent over the channel is applied in the connection cache"
        );

        sim.shutdown();
        consumer
            .join_timeout(Duration::from_secs(5))
            .expect("consumer exits after shutdown");
    }

    // A consumer blocked in `read` with no events must unblock promptly when the
    // driver is shut down (event queue run down -> end-of-file). Guards against a
    // teardown hang.
    #[test]
    fn consumer_unblocks_on_shutdown() {
        let sim = Simulation::start().expect("driver loads");
        let consumer = spawn_consumer(sim.connect(), |_event| None, None);

        // Let the consumer park in the blocking read, then shut down.
        thread::sleep(Duration::from_millis(20));
        sim.shutdown();

        assert!(
            consumer.join_timeout(Duration::from_secs(5)).is_some(),
            "consumer thread did not exit after shutdown (hang)"
        );
    }
}
