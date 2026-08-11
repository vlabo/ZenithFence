use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use core::time::Duration;

use crate::connection::{Connection, ConnectionV4, ConnectionV6, Key, RedirectInfo, Verdict};
use crate::mpsc_queue::MpscQueue;
use crate::rcu_port::{ConnectionArray, RCUPort};
use smoltcp::wire::IpProtocol;

// 0-65535 must be valid ports. 0 is not a valid port number but its kept for future proofing for special cases.
const PORT_COUT: usize = u16::MAX as usize + 1;
type PortArray<T> = [RCUPort<T>; PORT_COUT];

// Selects the correct per-port slot from the tcp/udp arrays.
fn get_port<'a, T: Connection>(
    tcp: &'a PortArray<T>,
    udp: &'a PortArray<T>,
    protocol: IpProtocol,
    local_port: u16,
) -> Option<&'a RCUPort<T>> {
    match protocol {
        IpProtocol::Tcp => Some(&tcp[local_port as usize]),
        IpProtocol::Udp => Some(&udp[local_port as usize]),
        _ => None,
    }
}

fn alloc_port_array<T: Connection>() -> Box<PortArray<T>> {
    // RCUPort<T> is valid when zeroed:
    //   - AtomicPtr is valid as null
    //   - Mutex<()> / RwSpinLock uses i32 which is valid at 0
    // alloc_zeroed is used to allocate directly on the heap.
    let layout = core::alloc::Layout::new::<PortArray<T>>();
    unsafe {
        let ptr = alloc::alloc::alloc_zeroed(layout) as *mut PortArray<T>;
        Box::from_raw(ptr)
    }
}

fn ports_clear<T: Connection>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    queue: &MpscQueue<ConnectionArray<T>>,
) {
    // Free all tcp connections
    for port in tcp.iter() {
        if !port.is_empty() {
            port.lock().publish(None, queue);
        }
    }

    // Free all udp connections
    for port in udp.iter() {
        if !port.is_empty() {
            port.lock().publish(None, queue);
        }
    }
}

// get_connection generic function for getting a connection.
fn get_connection<T: Connection>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    key: &Key,
) -> Option<Arc<T>> {
    // Get the connection array port.
    let port = get_port(tcp, udp, key.protocol, key.local_port)?.read();
    let snap = port.get()?;
    // Iterate over all connection and find the connection.
    for conn in snap.iter() {
        if conn.equals(key) || conn.redirect_equals(key) {
            // Update last accessed.
            conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
            return Some(conn.clone());
        }
    }
    None
}

// Adds a connection to its port. If an equal one is already present, its
// last-accessed time and bandwidth are updated instead of inserting a duplicate.
//
// The duplicate check and the publish both run under the port write lock, so
// concurrent adds of the same connection collapse to a single entry. This
// matters because `get_connection` + add is not atomic and the packet layer
// runs on multiple CPUs, so two callers can miss the same connection and race
// to insert it.
fn add_connection<T: Connection>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    queue: &MpscQueue<ConnectionArray<T>>,
    new: T,
) {
    let Some(port) = get_port(tcp, udp, new.get_protocol(), new.get_local_port()) else {
        return;
    };

    // Identity key, taken before `new` is moved into the Arc.
    let key = new.get_key();
    let new_arc = Arc::new(new);

    // Lock for writing.
    let port_lock = port.lock();

    // Copy the current port connection array. If the connection is already
    // present, fold the new observation into it instead of inserting a duplicate.
    let mut new_vec = match port_lock.snapshot() {
        Some(snap) => {
            // Check if connection is already in.
            for conn in snap.iter() {
                if conn.equals(&key) {
                    // Refresh last-accessed and accumulate bandwidth so no traffic
                    // accounting is lost. Identity, verdict and process id are left
                    // untouched — the existing connection stays authoritative.
                    conn.set_last_accessed_time(new_arc.get_last_accessed_time());
                    conn.get_bandwidth_usage()
                        .add_from(new_arc.get_bandwidth_usage());
                    return;
                }
            }

            let mut v = Vec::with_capacity(snap.len() + 1);
            v.extend(snap.iter().cloned());
            v
        }
        None => Vec::with_capacity(1),
    };

    // Add the new connection and publish.
    new_vec.push(new_arc);
    port_lock.publish(Some(new_vec.into_boxed_slice()), queue);
}

// Marks the connection matching `key` as ended and returns it. Read-only guard.
fn end_connection<T: Connection>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    key: &Key,
) -> Option<Arc<T>> {
    let port = get_port(tcp, udp, key.protocol, key.local_port)?.read();
    let snap = port.get()?;
    for conn in snap.iter() {
        if conn.equals(key) {
            conn.end(wdk::utils::get_system_timestamp_ms());
            return Some(conn.clone());
        }
    }
    None
}

// Marks every active connection on the given (protocol, port) as ended and
// returns them. Read-only guard.
fn end_all_on_port<T: Connection>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    protocol: IpProtocol,
    local_port: u16,
) -> Option<Vec<Arc<T>>> {
    let port = get_port(tcp, udp, protocol, local_port)?.read();
    let snap = port.get()?;
    let now = wdk::utils::get_system_timestamp_ms();
    let mut ended = Vec::new();
    for conn in snap.iter() {
        if !conn.has_ended() {
            conn.end(now);
            ended.push(conn.clone());
        }
    }
    Some(ended)
}

// Sets the verdict on the connection matching `key`, returning any redirect
// info. Read-only guard.
fn set_connection_verdict<T: Connection>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    key: &Key,
    verdict: Verdict,
) -> Option<RedirectInfo> {
    let port = get_port(tcp, udp, key.protocol, key.local_port)?.read();
    let snap = port.get()?;
    for conn in snap.iter() {
        if conn.equals(key) {
            conn.set_verdict(verdict);
            return conn.redirect_info();
        }
    }
    None
}

// Returns the verdict of the connection matching `key`, including redirect
// matches. Refreshes the last-accessed time. Read-only guard.
fn find_verdict<T: Connection>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    key: &Key,
) -> Option<Verdict> {
    let port = get_port(tcp, udp, key.protocol, key.local_port)?.read();
    let snap = port.get()?;
    for conn in snap.iter() {
        if conn.equals(key) || conn.redirect_equals(key) {
            conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
            return Some(conn.get_verdict());
        }
    }
    None
}

// ports_walk generic function for waling over all connections.
fn ports_walk<T: Connection, F: FnMut(&T)>(tcp: &PortArray<T>, udp: &PortArray<T>, mut iter: F) {
    for port in tcp.iter().chain(udp.iter()) {
        let guard = port.read();
        if let Some(snap) = guard.get() {
            for conn in snap.iter() {
                iter(conn.as_ref());
            }
        }
    }
}

fn ports_clean_ended<T: Connection>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    removed_connections: &mut Vec<Arc<T>>,
    queue: &MpscQueue<ConnectionArray<T>>,
) {
    // Durations
    const TWO_MINUTES: u64 = Duration::from_secs(120).as_millis() as u64;
    const ONE_MINUTE: u64 = Duration::from_secs(60).as_millis() as u64;
    const SECOND: u64 = Duration::from_secs(1).as_millis() as u64;

    let now = wdk::utils::get_system_timestamp_ms();
    let before_two_minutes = now - TWO_MINUTES;
    let before_one_minute = now - ONE_MINUTE;

    // Remove all ended or stale connections.
    for port in tcp.iter().chain(udp.iter()) {
        let mut any_removed = false;
        let mut survivors: Vec<Arc<T>> = Vec::new();

        // Port is still readable while the lock is acquired; it just stops concurrent writes.
        let port_guard = port.lock();
        let snap = match port_guard.snapshot() {
            Some(s) => s,
            None => continue,
        };

        // Check for ended connections and build a new list.
        for conn in snap.iter() {
            if conn.has_ended() && conn.get_end_time() < before_one_minute {
                any_removed = true;
                continue;
            }
            if removed_connections.capacity() > removed_connections.len()
                && conn.get_last_accessed_time() < before_two_minutes
            {
                removed_connections.push(conn.clone());
                any_removed = true;
                continue;
            }
            survivors.push(conn.clone());
        }

        // Publish if there are any changes.
        if any_removed {
            port_guard.publish(
                if survivors.is_empty() {
                    None
                } else {
                    Some(survivors.into_boxed_slice())
                },
                queue,
            );
        }
    }

    // Clean unused and unlinked connection arrays.
    let now = wdk::utils::get_system_timestamp_ms();
    loop {
        let mut continue_loop = false;
        match queue.peek() {
            Some(conn_array) => 'conn_match: {
                // Check for active readers
                let readers = conn_array.readers.load(Ordering::SeqCst);
                if readers != 0 {
                    break 'conn_match;
                }

                let time = conn_array.unlinked_timestamp.load(Ordering::SeqCst);
                // Prevent overflow
                if time > now {
                    break 'conn_match;
                }

                // Check if enough time has passed since the un-linking.
                if now - time < SECOND {
                    break 'conn_match;
                }

                // Array is safe to free.
                let array = queue.pop();
                unsafe {
                    drop(Box::from_raw(array));
                }

                // Continue to next.
                continue_loop = true;
            }
            None => (),
        }

        if !continue_loop {
            // No more arrays to free.
            break;
        }
    }
}

// ConnectionCache holds the state of all active connections.
pub struct ConnectionCache {
    // Connection states
    tcp_v4: Box<PortArray<ConnectionV4>>,
    udp_v4: Box<PortArray<ConnectionV4>>,
    tcp_v6: Box<PortArray<ConnectionV6>>,
    udp_v6: Box<PortArray<ConnectionV6>>,

    // Holds ended connection that need to be send as an event to user space.
    tmp_ended_connections_buffer_v4: Vec<Arc<ConnectionV4>>,
    tmp_ended_connections_buffer_v6: Vec<Arc<ConnectionV6>>,

    // Holds unlinked connections arrays.
    unlinked_ports_v4: MpscQueue<ConnectionArray<ConnectionV4>>,
    unlinked_ports_v6: MpscQueue<ConnectionArray<ConnectionV6>>,
}

impl ConnectionCache {
    pub fn new() -> Self {
        // Initialize all the arrays.
        Self {
            tcp_v4: alloc_port_array(),
            udp_v4: alloc_port_array(),
            tcp_v6: alloc_port_array(),
            udp_v6: alloc_port_array(),
            tmp_ended_connections_buffer_v4: Vec::with_capacity(100),
            tmp_ended_connections_buffer_v6: Vec::with_capacity(100),
            unlinked_ports_v4: MpscQueue::new(),
            unlinked_ports_v6: MpscQueue::new(),
        }
    }

    pub fn add_v4(&self, new: ConnectionV4) {
        add_connection(&self.tcp_v4, &self.udp_v4, &self.unlinked_ports_v4, new);
    }

    pub fn add_v6(&self, new: ConnectionV6) {
        add_connection(&self.tcp_v6, &self.udp_v6, &self.unlinked_ports_v6, new);
    }

    pub fn end_v4(&self, key: Key) -> Option<Arc<ConnectionV4>> {
        end_connection(&self.tcp_v4, &self.udp_v4, &key)
    }

    pub fn end_v6(&self, key: Key) -> Option<Arc<ConnectionV6>> {
        end_connection(&self.tcp_v6, &self.udp_v6, &key)
    }

    pub fn end_all_on_port_v4(&self, key: (IpProtocol, u16)) -> Option<Vec<Arc<ConnectionV4>>> {
        end_all_on_port(&self.tcp_v4, &self.udp_v4, key.0, key.1)
    }

    pub fn end_all_on_port_v6(&self, key: (IpProtocol, u16)) -> Option<Vec<Arc<ConnectionV6>>> {
        end_all_on_port(&self.tcp_v6, &self.udp_v6, key.0, key.1)
    }

    pub fn update_connection(&self, key: Key, verdict: Verdict) -> Option<RedirectInfo> {
        if key.is_ipv6() {
            set_connection_verdict(&self.tcp_v6, &self.udp_v6, &key, verdict)
        } else {
            set_connection_verdict(&self.tcp_v4, &self.udp_v4, &key, verdict)
        }
    }

    // clean_ended_connections is not thread safe and should be called from one place only.
    pub fn clean_ended_connections<'a>(
        &'a mut self,
    ) -> (
        &'a mut Vec<Arc<ConnectionV4>>,
        &'a mut Vec<Arc<ConnectionV6>>,
    ) {
        self.tmp_ended_connections_buffer_v4.clear();
        self.tmp_ended_connections_buffer_v6.clear();
        ports_clean_ended(
            &self.tcp_v4,
            &self.udp_v4,
            &mut self.tmp_ended_connections_buffer_v4,
            &self.unlinked_ports_v4,
        );
        ports_clean_ended(
            &self.tcp_v6,
            &self.udp_v6,
            &mut self.tmp_ended_connections_buffer_v6,
            &self.unlinked_ports_v6,
        );
        return (
            &mut self.tmp_ended_connections_buffer_v4,
            &mut self.tmp_ended_connections_buffer_v6,
        );
    }

    pub fn get_verdict(&self, key: &Key) -> Option<Verdict> {
        if key.is_ipv6() {
            find_verdict(&self.tcp_v6, &self.udp_v6, key)
        } else {
            find_verdict(&self.tcp_v4, &self.udp_v4, key)
        }
    }
    // walk_over_connections_v4 walks over all IPv4 connections. Lock free.
    pub fn walk_over_connections_v4<F: FnMut(&ConnectionV4)>(&self, iter: F) {
        ports_walk(&self.tcp_v4, &self.udp_v4, iter);
    }

    // walk_over_connections_v6 walks over all IPv6 connections. Lock free.
    pub fn walk_over_connections_v6<F: FnMut(&ConnectionV6)>(&self, iter: F) {
        ports_walk(&self.tcp_v6, &self.udp_v6, iter);
    }

    // get_unlinked_queue_counts returns stats of all the unlinked connection arrays. Lock free.
    pub fn get_unlinked_queue_counts(&self) -> (usize, usize) {
        (
            self.unlinked_ports_v4.count(),
            self.unlinked_ports_v6.count(),
        )
    }

    // get_entries_count returns stats for all the connections count. Lock free.
    pub fn get_entries_count(&self) -> (usize, usize) {
        let mut active = 0usize;
        let mut ended = 0usize;
        ports_walk(&self.tcp_v4, &self.udp_v4, |conn: &ConnectionV4| {
            if conn.has_ended() {
                ended += 1;
            } else {
                active += 1;
            }
        });
        ports_walk(&self.tcp_v6, &self.udp_v6, |conn: &ConnectionV6| {
            if conn.has_ended() {
                ended += 1;
            } else {
                active += 1;
            }
        });
        (active, ended)
    }

    // get_connection_v4 returns a connection by key. Lock free.
    pub fn get_connection_v4(&self, key: &Key) -> Option<Arc<ConnectionV4>> {
        get_connection(&self.tcp_v4, &self.udp_v4, key)
    }

    // get_connection_v6 returns a connection by key. Lock free.
    pub fn get_connection_v6(&self, key: &Key) -> Option<Arc<ConnectionV6>> {
        get_connection(&self.tcp_v6, &self.udp_v6, key)
    }

    // Clears the connection cache.
    pub fn clear(&self) {
        ports_clear(&self.tcp_v4, &self.udp_v4, &self.unlinked_ports_v4);
        ports_clear(&self.tcp_v6, &self.udp_v6, &self.unlinked_ports_v6);
    }
}

impl Drop for ConnectionCache {
    fn drop(&mut self) {
        // Clear the cache
        self.clear();
        // Free all unlinked connection arrays
        loop {
            let array = self.unlinked_ports_v4.pop();
            if array.is_null() {
                break;
            }
            unsafe {
                drop(Box::from_raw(array));
            }
        }
        loop {
            let array = self.unlinked_ports_v6.pop();
            if array.is_null() {
                break;
            }
            unsafe {
                drop(Box::from_raw(array));
            }
        }
    }
}
