use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{
    fmt::Display,
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
    time::Duration,
};

use crate::connection::{Connection, Direction, RedirectInfo, Verdict};
use smoltcp::wire::{IpAddress, IpProtocol};
use wdk::rw_spin_lock::Mutex;

#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
pub struct Key {
    pub(crate) protocol: IpProtocol,
    pub(crate) local_address: IpAddress,
    pub(crate) local_port: u16,
    pub(crate) remote_address: IpAddress,
    pub(crate) remote_port: u16,
}

impl Display for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "p: {} l: {}:{} r: {}:{}",
            self.protocol,
            self.local_address,
            self.local_port,
            self.remote_address,
            self.remote_port
        )
    }
}

impl Key {
    pub fn is_ipv6(&self) -> bool {
        match self.local_address {
            IpAddress::Ipv4(_) => false,
            IpAddress::Ipv6(_) => true,
        }
    }

    pub fn is_loopback(&self) -> bool {
        match self.local_address {
            IpAddress::Ipv4(ip) => ip.is_loopback(),
            IpAddress::Ipv6(ip) => ip.is_loopback(),
        }
    }

    #[allow(dead_code)]
    pub fn reverse(&self) -> Key {
        Key {
            protocol: self.protocol,
            local_address: self.remote_address,
            local_port: self.remote_port,
            remote_address: self.local_address,
            remote_port: self.local_port,
        }
    }
}

// -------------------------------------------------------------------------------------------------
// RCUPort — the core data structure
//
// Read path (lock-free, called per packet):
//   1. Atomic load of `current` pointer                   — ~1ns
//   2. Arc::increment_strong_count (atomic refcount bump) — ~2ns
//   3. Search the snapshot                                — the actual work, no lock held
//
// Write path (infrequent: new connection, verdict, cleanup):
//   1. Take write_state mutex                             — blocks other WRITERS only, not readers
//   2. Build new Vec<Arc<T>> before touching the pointer  — allocation happens outside any reader path
//   3. Atomic swap of `current`                           — ~2ns
//   4. Push old raw pointer to retire list               — deferred free
//   5. Release mutex
//
// Why writes never block reads:
//   Readers only touch `current` (AtomicPtr), never the mutex.
//   The mutex serializes concurrent writers only.
//
// Why the lock-free load is safe:
//   After a writer swaps `current`, the old raw pointer goes into the retire list.
//   The retire list holds one Arc reference to the old snapshot, keeping it alive.
//   Old snapshots are freed only after RETIRE_GRACE_MS (default: 30 seconds).
//   WFP classify callouts run at DISPATCH_LEVEL and complete in microseconds,
//   so every in-flight reader finishes Arc::increment_strong_count long before
//   any snapshot is freed. Therefore `current` (or a recently-retired snapshot)
//   always has refcount ≥ 1 when a reader loads and increments it.
// -------------------------------------------------------------------------------------------------

// How long (ms) a retired snapshot must sit before it can be freed.
// Must be >> the maximum time any reader can be in-flight between
// atomic_load(current) and Arc::increment_strong_count.
// At DISPATCH_LEVEL this is microseconds; 30 seconds is a very large margin.
const RETIRE_GRACE_MS: u64 = Duration::from_secs(30).as_millis() as u64;

struct RetiredEntry<T> {
    // Pointer originally created by Arc::into_raw. One Arc reference.
    ptr: *mut Vec<Arc<T>>,
    retired_at_ms: u64,
}

// SAFETY: we manage this pointer carefully and T: Send.
unsafe impl<T: Send> Send for RetiredEntry<T> {}

struct WriteState<T> {
    retired: Vec<RetiredEntry<T>>,
}

struct RCUPort<T: Connection> {
    // The current snapshot. Null means no connections on this port.
    // Non-null: raw pointer from Arc::into_raw(Arc::new(Vec<Arc<T>>)).
    // That is, the AtomicPtr "owns" one Arc reference.
    current: AtomicPtr<Vec<Arc<T>>>,

    // Taken exclusively by writers. Readers never acquire this.
    write_state: Mutex<WriteState<T>>,
}

impl<T: Connection + Send> RCUPort<T> {
    fn new() -> Self {
        Self {
            current: AtomicPtr::new(ptr::null_mut()),
            write_state: Mutex::new(WriteState {
                retired: Vec::new(),
            }),
        }
    }

    // Lock-free snapshot. Returns an owning Arc so the caller can search without any lock.
    #[inline(always)]
    fn snapshot(&self) -> Option<Arc<Vec<Arc<T>>>> {
        let p = self.current.load(Ordering::Acquire);
        if p.is_null() {
            return None;
        }
        // SAFETY: p was stored via Arc::into_raw and is kept alive by either:
        //   a) still being the `current` pointer (AtomicPtr owns one reference), or
        //   b) being in the retire list (which also owns one reference).
        // In both cases refcount ≥ 1, so increment_strong_count is safe.
        unsafe {
            Arc::increment_strong_count(p);
            Some(Arc::from_raw(p))
        }
    }

    // Swaps in a new snapshot. Caller must already hold write_state (i.e., be
    // the only writer). The old snapshot is retired, not freed immediately.
    fn publish(&self, new: Option<Vec<Arc<T>>>) {
        let new_raw: *mut Vec<Arc<T>> = match new {
            Some(v) => Arc::into_raw(Arc::new(v)) as *mut _,
            None => ptr::null_mut(),
        };

        let mut state = self.write_state.write_lock();
        let old_raw = self.current.swap(new_raw, Ordering::AcqRel);

        if !old_raw.is_null() {
            // Keep alive; freed in free_retired after the grace period.
            state.retired.push(RetiredEntry {
                ptr: old_raw,
                retired_at_ms: wdk::utils::get_system_timestamp_ms(),
            });
        }
    }

    // Drops retired snapshots older than RETIRE_GRACE_MS.
    // Called during periodic cleanup, never on the packet path.
    fn free_retired(&self, now_ms: u64) {
        let mut state = self.write_state.write_lock();
        state.retired.retain(|e| {
            if now_ms.saturating_sub(e.retired_at_ms) >= RETIRE_GRACE_MS {
                // All readers that could have loaded this pointer finished long ago.
                unsafe { drop(Arc::from_raw(e.ptr as *const Vec<Arc<T>>)) };
                false
            } else {
                true
            }
        });
    }
}

// 65536 slots: indices 0..=65535 cover all valid u16 port numbers.
const PORT_COUNT: usize = (u16::MAX as usize) + 1;

pub struct ConnectionMap<T: Connection + Send> {
    tcp: Box<[RCUPort<T>]>,
    udp: Box<[RCUPort<T>]>,
}

impl<T: Connection + Send> ConnectionMap<T> {
    pub fn new() -> Self {
        let make_ports = || {
            (0..PORT_COUNT)
                .map(|_| RCUPort::new())
                .collect::<Vec<_>>()
                .into_boxed_slice()
        };
        Self {
            tcp: make_ports(),
            udp: make_ports(),
        }
    }

    fn port(&self, protocol: IpProtocol, local_port: u16) -> Option<&RCUPort<T>> {
        match protocol {
            IpProtocol::Tcp => Some(&self.tcp[local_port as usize]),
            IpProtocol::Udp => Some(&self.udp[local_port as usize]),
            _ => None,
        }
    }

    // Adds a new connection. The new Vec is built before the mutex is taken,
    // so the critical section is just the pointer swap.
    pub fn add(&self, new: T) {
        let Some(port) = self.port(new.get_protocol(), new.get_local_port()) else {
            return;
        };

        // Box the connection on the heap before taking any lock.
        let new_arc: Arc<T> = Arc::new(new);

        // Read current snapshot lock-free to build the new one.
        let mut new_vec = match port.snapshot() {
            Some(snap) => {
                let mut v = Vec::with_capacity(snap.len() + 1);
                v.extend_from_slice(&snap); // clones Arc<T> pointers only, no connection data copied
                v
            }
            None => Vec::with_capacity(1),
        };
        new_vec.push(new_arc);

        // Critical section: just the pointer swap.
        port.publish(Some(new_vec));
    }

    // Finds the connection and updates its verdict. Lock-free after snapshot clone.
    pub fn update_verdict(&self, key: Key, verdict: Verdict) -> Option<RedirectInfo> {
        let snap = self.port(key.protocol, key.local_port)?.snapshot()?;
        for conn in snap.iter() {
            if conn.remote_equals(&key) {
                conn.set_verdict(verdict);
                return conn.redirect_info();
            }
        }
        None
    }

    // Reads a connection and updates bandwidth counters. Lock-free after snapshot clone.
    pub fn read_update_bw_usage<C>(
        &self,
        key: &Key,
        byte_size: u64,
        direction: Direction,
        read_connection: fn(&T) -> Option<C>,
    ) -> Option<C> {
        let snap = self.port(key.protocol, key.local_port)?.snapshot()?;
        for conn in snap.iter() {
            if conn.remote_equals(key) || conn.redirect_equals(key) {
                conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                conn.update_bandwidth_data(byte_size, direction);
                return read_connection(conn);
            }
        }
        None
    }

    // Reads a connection. Lock-free after snapshot clone.
    pub fn read<C>(&self, key: &Key, read_connection: fn(&T) -> Option<C>) -> Option<C> {
        let snap = self.port(key.protocol, key.local_port)?.snapshot()?;
        for conn in snap.iter() {
            if conn.remote_equals(key) || conn.redirect_equals(key) {
                conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                return read_connection(conn);
            }
        }
        None
    }

    // Marks the matching connection as ended. The connection stays in the snapshot
    // until clean_ended_connections removes it. Returns Arc so the caller can
    // read its fields (e.g. to emit a connection-end event).
    pub fn end(&self, key: Key) -> Option<Arc<T>> {
        let snap = self.port(key.protocol, key.local_port)?.snapshot()?;
        for conn in snap.iter() {
            if conn.remote_equals(&key) {
                conn.end(wdk::utils::get_system_timestamp_ms());
                return Some(Arc::clone(conn));
            }
        }
        None
    }

    // Marks all connections on a port as ended and returns them.
    pub fn end_all_on_port(&self, key: (IpProtocol, u16)) -> Option<Vec<Arc<T>>> {
        let snap = self.port(key.0, key.1)?.snapshot()?;
        let now = wdk::utils::get_system_timestamp_ms();
        let mut ended = Vec::new();
        for conn in snap.iter() {
            if !conn.has_ended() {
                conn.end(now);
                ended.push(Arc::clone(conn));
            }
        }
        Some(ended)
    }

    // Drops all connections from all ports.
    pub fn clear(&self) {
        for port in self.tcp.iter().chain(self.udp.iter()) {
            port.publish(None);
        }
    }

    // Removes stale/ended connections and frees retired snapshots.
    // Runs on a background timer, not the packet path.
    pub fn clean_ended_connections(&self, removed_connections: &mut Vec<Arc<T>>) {
        let now = wdk::utils::get_system_timestamp_ms();
        const TWO_MINUTES: u64 = Duration::from_secs(120).as_millis() as u64;
        const ONE_MINUTE: u64 = Duration::from_secs(60).as_millis() as u64;
        let before_two_minutes = now - TWO_MINUTES;
        let before_one_minute = now - ONE_MINUTE;

        for port in self.tcp.iter().chain(self.udp.iter()) {
            // First, free any retired snapshots that are past the grace period.
            port.free_retired(now);

            // Then rebuild the snapshot if any connections need to be removed.
            let snap = match port.snapshot() {
                Some(s) => s,
                None => continue,
            };

            let mut any_removed = false;
            let mut survivors: Vec<Arc<T>> = Vec::new();

            for conn in snap.iter() {
                if conn.has_ended() && conn.get_end_time() < before_one_minute {
                    // Ended more than 1 minute ago — drop silently.
                    any_removed = true;
                    continue;
                }
                if removed_connections.capacity() > removed_connections.len()
                    && conn.get_last_accessed_time() < before_two_minutes
                {
                    // Inactive for more than 2 minutes — report and remove.
                    removed_connections.push(Arc::clone(conn));
                    any_removed = true;
                    continue;
                }
                survivors.push(Arc::clone(conn));
            }

            if any_removed {
                port.publish(if survivors.is_empty() {
                    None
                } else {
                    Some(survivors)
                });
            }
        }
    }

    // Visits every connection without holding any lock during the callback.
    pub fn walk_over_connections<F: FnMut(&T)>(&self, mut iter: F) {
        for port in self.tcp.iter().chain(self.udp.iter()) {
            if let Some(snap) = port.snapshot() {
                for conn in snap.iter() {
                    iter(conn);
                }
            }
        }
    }
}
