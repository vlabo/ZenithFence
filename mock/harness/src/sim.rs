//! The loaded driver and its user-space channel.
//!
//! Loads the *real* driver via its `DriverEntry` (over the mocked WDK); the
//! agent side talks to it through the same channel a real agent uses
//! ([`wdk::connection::DriverConnection`] = `ReadFile`/`WriteFile`/`DeviceIoControl`).
//! [`EventParser`] / [`Event::decode`] read the event stream it produces.
//!
//! Teardown order is load-bearing: `shutdown` runs down the event queue so a
//! blocked reader wakes with end-of-file; join the readers; only then drop the
//! `Simulation`, which unloads the driver through its registered `DriverUnload`.

use std::net::IpAddr;

use protocol::command::CommandType;
use wdk::connection::DriverConnection;
use wdk::kernel_types::{NTSTATUS, STATUS_SUCCESS};

use crate::loader;

/// A loaded driver instance (reads block, like a real user-space agent's).
/// Holds the harness driver lock
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
        let status = loader::reload();
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
    /// any blocked reader wakes with end-of-file. Idempotent; safe to call
    /// from any thread.
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

    /// Decode the payload per its `info_type` (layouts: `protocol/src/info.rs`).
    /// `None` for an unknown type or a payload that doesn't match its layout.
    pub fn decode(&self) -> Option<Info> {
        let mut r = Reader(&self.payload);
        let v6 = matches!(self.info_type, 2 | 4 | 6);
        let info = match self.info_type {
            0 => Info::Log {
                severity: r.u8()?,
                line: String::from_utf8_lossy(r.rest()).into_owned(),
            },
            1 | 2 => {
                let id = r.u64()?;
                let process_id = r.u64()?;
                let direction = r.u8()?;
                let tuple = r.tuple(v6)?;
                let payload_layer = r.u8()?;
                let len = r.u32()? as usize;
                Info::Connection {
                    id,
                    process_id,
                    direction,
                    tuple,
                    payload_layer,
                    payload: r.take(len)?.to_vec(),
                }
            }
            3 | 4 => Info::ConnectionEnd {
                process_id: r.u64()?,
                direction: r.u8()?,
                tuple: r.tuple(v6)?,
                counters: r.counters()?,
            },
            5 | 6 => Info::ConnectionUpdate {
                tuple: r.tuple(v6)?,
                counters: r.counters()?,
            },
            7 => Info::ConnectionUpdateEnd { timestamp: r.u64()? },
            _ => return None,
        };
        r.rest().is_empty().then_some(info)
    }
}

/// A connection's 5-tuple as an event carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InfoTuple {
    pub protocol: u8,
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
}

/// Traffic counters of an end / update event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

/// A decoded event ([`Event::decode`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Info {
    Log { severity: u8, line: String },
    /// A pended packet awaiting a verdict for `id`.
    Connection {
        id: u64,
        process_id: u64,
        direction: u8,
        tuple: InfoTuple,
        payload_layer: u8,
        payload: Vec<u8>,
    },
    ConnectionEnd { process_id: u64, direction: u8, tuple: InfoTuple, counters: Counters },
    ConnectionUpdate { tuple: InfoTuple, counters: Counters },
    /// End of a connections update. `timestamp` is the driver's cursor: pass it
    /// unchanged with the next `GetConnectionsUpdate`.
    ConnectionUpdateEnd { timestamp: u64 },
}

/// Little-endian cursor over an event payload.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.0)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }
    fn ip(&mut self, v6: bool) -> Option<IpAddr> {
        Some(if v6 {
            IpAddr::from(<[u8; 16]>::try_from(self.take(16)?).ok()?)
        } else {
            IpAddr::from(<[u8; 4]>::try_from(self.take(4)?).ok()?)
        })
    }
    fn tuple(&mut self, v6: bool) -> Option<InfoTuple> {
        let protocol = self.u8()?;
        let (local, remote) = (self.ip(v6)?, self.ip(v6)?);
        let (local_port, remote_port) = (self.u16()?, self.u16()?);
        Some(InfoTuple { protocol, local, local_port, remote, remote_port })
    }
    fn counters(&mut self) -> Option<Counters> {
        Some(Counters {
            rx_bytes: self.u64()?,
            rx_packets: self.u64()?,
            tx_bytes: self.u64()?,
            tx_packets: self.u64()?,
        })
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
