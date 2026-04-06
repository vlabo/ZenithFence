use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use crate::connection::{
    Connection, ConnectionInfo, ConnectionV4, ConnectionV6, Direction, Key, RedirectInfo, Verdict,
};
use crate::rcu_port::RCUPort;
use smoltcp::wire::IpProtocol;

// Selects the correct per-port slot from the tcp/udp arrays.
fn get_port<'a, T: Connection>(
    tcp: &'a [RCUPort<T>; u16::MAX as usize],
    udp: &'a [RCUPort<T>; u16::MAX as usize],
    protocol: IpProtocol,
    local_port: u16,
) -> Option<&'a RCUPort<T>> {
    match protocol {
        IpProtocol::Tcp => Some(&tcp[local_port as usize]),
        IpProtocol::Udp => Some(&udp[local_port as usize]),
        _ => None,
    }
}

fn alloc_port_array<T: Connection>() -> Box<[RCUPort<T>; u16::MAX as usize]> {
    // SAFETY: RCUPort<T> is valid when zeroed:
    //   - AtomicPtr is valid as null
    //   - Mutex<()> / RwSpinLock uses i32 which is valid at 0
    // alloc_zeroed is used to allocate directly on the heap.
    let layout = core::alloc::Layout::new::<[RCUPort<T>; u16::MAX as usize]>();
    unsafe {
        let ptr = alloc::alloc::alloc_zeroed(layout) as *mut [RCUPort<T>; u16::MAX as usize];
        Box::from_raw(ptr)
    }
}

fn ports_clear<T: Connection>(
    tcp: &[RCUPort<T>; u16::MAX as usize],
    udp: &[RCUPort<T>; u16::MAX as usize],
) {
    for port in tcp.iter() {
        port.lock().publish(None);
    }
    for port in udp.iter() {
        port.lock().publish(None);
    }
}

fn ports_walk<T: Connection, F: FnMut(&T)>(
    tcp: &[RCUPort<T>; u16::MAX as usize],
    udp: &[RCUPort<T>; u16::MAX as usize],
    mut iter: F,
) {
    for port in tcp.iter() {
        if let Some(snap) = port.snapshot() {
            for conn in snap.iter() {
                iter(conn);
            }
        }
    }

    for port in udp.iter() {
        if let Some(snap) = port.snapshot() {
            for conn in snap.iter() {
                iter(conn);
            }
        }
    }
}

fn ports_clean_ended<T: Connection>(
    tcp: &[RCUPort<T>; u16::MAX as usize],
    udp: &[RCUPort<T>; u16::MAX as usize],
    removed_connections: &mut Vec<Arc<T>>,
) {
    let now = wdk::utils::get_system_timestamp_ms();
    const TWO_MINUTES: u64 = Duration::from_secs(120).as_millis() as u64;
    const ONE_MINUTE: u64 = Duration::from_secs(60).as_millis() as u64;
    let before_two_minutes = now - TWO_MINUTES;
    let before_one_minute = now - ONE_MINUTE;

    for port in tcp.iter().chain(udp.iter()) {
        let mut any_removed = false;
        let mut survivors: Vec<Arc<T>> = Vec::new();

        // Port is still readable while the lock is acquired it just stops concurrent writes.
        let port_guard = port.lock();
        let snap = match port.snapshot() {
            Some(s) => s,
            None => continue,
        };

        // Check for and connections and build a new list.
        for conn in snap.iter() {
            if conn.has_ended() && conn.get_end_time() < before_one_minute {
                any_removed = true;
                continue;
            }
            if removed_connections.capacity() > removed_connections.len()
                && conn.get_last_accessed_time() < before_two_minutes
            {
                removed_connections.push(Arc::clone(conn));
                any_removed = true;
                continue;
            }
            survivors.push(Arc::clone(conn));
        }

        // publish if there are any changes.
        if any_removed {
            port_guard.publish(if survivors.is_empty() {
                None
            } else {
                Some(survivors)
            });
        }
    }
}

pub struct ConnectionCache {
    tcp_v4: Box<[RCUPort<ConnectionV4>; u16::MAX as usize]>,
    udp_v4: Box<[RCUPort<ConnectionV4>; u16::MAX as usize]>,
    tcp_v6: Box<[RCUPort<ConnectionV6>; u16::MAX as usize]>,
    udp_v6: Box<[RCUPort<ConnectionV6>; u16::MAX as usize]>,

    tmp_ended_connections_buffer_v4: Vec<Arc<ConnectionV4>>,
    tmp_ended_connections_buffer_v6: Vec<Arc<ConnectionV6>>,
}

impl ConnectionCache {
    pub fn new() -> Self {
        Self {
            tcp_v4: alloc_port_array(),
            udp_v4: alloc_port_array(),
            tcp_v6: alloc_port_array(),
            udp_v6: alloc_port_array(),
            tmp_ended_connections_buffer_v4: Vec::with_capacity(100),
            tmp_ended_connections_buffer_v6: Vec::with_capacity(100),
        }
    }

    pub fn add_v4(&self, new: ConnectionV4) {
        let Some(port) = get_port(
            &self.tcp_v4,
            &self.udp_v4,
            new.get_protocol(),
            new.get_local_port(),
        ) else {
            return;
        };
        let new_conn = Arc::new(new);

        // Lock for writing.
        let port_lock = port.lock();

        // Copy current port connection array.
        let mut new_vec = match port.snapshot() {
            Some(snap) => {
                let mut v = Vec::with_capacity(snap.len() + 1);
                v.extend(snap.iter().cloned());
                v
            }
            None => Vec::with_capacity(1),
        };
        // Add the new connection.
        new_vec.push(new_conn);

        // Publish the change.
        port_lock.publish(Some(new_vec));
    }

    pub fn add_v6(&self, new: ConnectionV6) {
        let Some(port) = get_port(
            &self.tcp_v6,
            &self.udp_v6,
            new.get_protocol(),
            new.get_local_port(),
        ) else {
            return;
        };
        let new_conn = Arc::new(new);

        // Lock for writing.
        let port_lock = port.lock();

        // Copy current port connection array.
        let mut new_vec = match port.snapshot() {
            Some(snap) => {
                let mut v = Vec::with_capacity(snap.len() + 1);
                v.extend(snap.iter().cloned());
                v
            }
            None => Vec::with_capacity(1),
        };

        // Add the new connection.
        new_vec.push(new_conn);

        // Publish the change.
        port_lock.publish(Some(new_vec));
    }

    pub fn end_v4(&self, key: Key) -> Option<Arc<ConnectionV4>> {
        let snap =
            get_port(&self.tcp_v4, &self.udp_v4, key.protocol, key.local_port)?.snapshot()?;
        for conn in snap.iter() {
            if conn.equals(&key) {
                conn.end(wdk::utils::get_system_timestamp_ms());
                return Some(Arc::clone(conn));
            }
        }
        None
    }

    pub fn end_v6(&self, key: Key) -> Option<Arc<ConnectionV6>> {
        let snap =
            get_port(&self.tcp_v6, &self.udp_v6, key.protocol, key.local_port)?.snapshot()?;
        for conn in snap.iter() {
            if conn.equals(&key) {
                conn.end(wdk::utils::get_system_timestamp_ms());
                return Some(Arc::clone(conn));
            }
        }
        None
    }

    pub fn end_all_on_port_v4(&self, key: (IpProtocol, u16)) -> Option<Vec<Arc<ConnectionV4>>> {
        let snap = get_port(&self.tcp_v4, &self.udp_v4, key.0, key.1)?.snapshot()?;
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

    pub fn end_all_on_port_v6(&self, key: (IpProtocol, u16)) -> Option<Vec<Arc<ConnectionV6>>> {
        let snap = get_port(&self.tcp_v6, &self.udp_v6, key.0, key.1)?.snapshot()?;
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

    pub fn update_connection(&self, key: Key, verdict: Verdict) -> Option<RedirectInfo> {
        if key.is_ipv6() {
            let snap =
                get_port(&self.tcp_v6, &self.udp_v6, key.protocol, key.local_port)?.snapshot()?;
            for conn in snap.iter() {
                if conn.equals(&key) {
                    conn.set_verdict(verdict);
                    return conn.redirect_info();
                }
            }
        } else {
            let snap =
                get_port(&self.tcp_v4, &self.udp_v4, key.protocol, key.local_port)?.snapshot()?;
            for conn in snap.iter() {
                if conn.equals(&key) {
                    conn.set_verdict(verdict);
                    return conn.redirect_info();
                }
            }
        }
        None
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
        );
        ports_clean_ended(
            &self.tcp_v6,
            &self.udp_v6,
            &mut self.tmp_ended_connections_buffer_v6,
        );
        return (
            &mut self.tmp_ended_connections_buffer_v4,
            &mut self.tmp_ended_connections_buffer_v6,
        );
    }

    pub fn get_verdict(&self, key: &Key) -> Option<Verdict> {
        if key.is_ipv6() {
            let snap =
                get_port(&self.tcp_v6, &self.udp_v6, key.protocol, key.local_port)?.snapshot()?;
            for conn in snap.iter() {
                if conn.equals(key) || conn.redirect_equals(key) {
                    conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                    return Some(conn.get_verdict());
                }
            }
        } else {
            let snap =
                get_port(&self.tcp_v4, &self.udp_v4, key.protocol, key.local_port)?.snapshot()?;
            for conn in snap.iter() {
                if conn.equals(key) || conn.redirect_equals(key) {
                    conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                    return Some(conn.get_verdict());
                }
            }
        }
        None
    }

    pub fn walk_over_connections_v4<F: FnMut(&ConnectionV4)>(&self, iter: F) {
        ports_walk(&self.tcp_v4, &self.udp_v4, iter);
    }

    pub fn walk_over_connections_v6<F: FnMut(&ConnectionV6)>(&self, iter: F) {
        ports_walk(&self.tcp_v6, &self.udp_v6, iter);
    }

    /// Returns the count of (active, ended) connections across all protocols and IP versions.
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

    pub fn get_connection_and_update_bw_usage(
        &self,
        key: &Key,
        packet_size: u64,
        direction: Direction,
    ) -> Option<ConnectionInfo> {
        if key.is_ipv6() {
            let snap =
                get_port(&self.tcp_v6, &self.udp_v6, key.protocol, key.local_port)?.snapshot()?;
            for conn in snap.iter() {
                if conn.equals(key) || conn.redirect_equals(key) {
                    conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                    conn.update_bandwidth_data(packet_size, direction);
                    return Some(ConnectionInfo::from_connection(conn.as_ref()));
                }
            }
        } else {
            let snap =
                get_port(&self.tcp_v4, &self.udp_v4, key.protocol, key.local_port)?.snapshot()?;
            for conn in snap.iter() {
                if conn.equals(key) || conn.redirect_equals(key) {
                    conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                    conn.update_bandwidth_data(packet_size, direction);
                    return Some(ConnectionInfo::from_connection(conn.as_ref()));
                }
            }
        }
        None
    }

    pub fn clear(&self) {
        ports_clear(&self.tcp_v4, &self.udp_v4);
        ports_clear(&self.tcp_v6, &self.udp_v6);
    }
}
