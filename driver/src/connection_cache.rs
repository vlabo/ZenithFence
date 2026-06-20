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
        // Get the specific port connection array for the connection.
        let Some(port) = get_port(
            &self.tcp_v4,
            &self.udp_v4,
            new.get_protocol(),
            new.get_local_port(),
        ) else {
            return;
        };
        // Make it into a pointer.
        let new_arc = Arc::new(new);

        // Lock for writing.
        let port_lock = port.lock();

        // Copy current port connection array.
        let mut new_vec = match port_lock.snapshot() {
            Some(snap) => {
                let mut v = Vec::with_capacity(snap.len() + 1);
                v.extend(snap.iter().cloned());
                v
            }
            None => Vec::with_capacity(1),
        };
        // Add the new connection.
        new_vec.push(new_arc);

        // Publish the change.
        port_lock.publish(Some(new_vec.into_boxed_slice()), &self.unlinked_ports_v4);
    }

    pub fn add_v6(&self, new: ConnectionV6) {
        // Get the specific port connection array for the connection.
        let Some(port) = get_port(
            &self.tcp_v6,
            &self.udp_v6,
            new.get_protocol(),
            new.get_local_port(),
        ) else {
            return;
        };
        // Make it into a pointer.
        let new_arc = Arc::new(new);

        // Lock for writing.
        let port_lock = port.lock();

        // Copy current port connection array.
        let mut new_vec = match port_lock.snapshot() {
            Some(snap) => {
                let mut v = Vec::with_capacity(snap.len() + 1);
                v.extend(snap.iter().cloned());
                v
            }
            None => Vec::with_capacity(1),
        };

        // Add the new connection.
        new_vec.push(new_arc);

        // Publish the change.
        port_lock.publish(Some(new_vec.into_boxed_slice()), &self.unlinked_ports_v6);
    }

    pub fn end_v4(&self, key: Key) -> Option<Arc<ConnectionV4>> {
        // Get the specific port connection array for the connection.
        // Read only guard.
        let port = get_port(&self.tcp_v4, &self.udp_v4, key.protocol, key.local_port)?.read();
        let snap = port.get()?;
        // Iterate over all connection on the port.
        for conn in snap.iter() {
            if conn.equals(&key) {
                conn.end(wdk::utils::get_system_timestamp_ms());
                return Some(conn.clone());
            }
        }
        None
    }

    pub fn end_v6(&self, key: Key) -> Option<Arc<ConnectionV6>> {
        // Get the specific port connection array for the connection.
        // Read only guard.
        let port = get_port(&self.tcp_v6, &self.udp_v6, key.protocol, key.local_port)?.read();
        let snap = port.get()?;
        // Iterate over all connection on the port.
        for conn in snap.iter() {
            if conn.equals(&key) {
                // Mark it as ended.
                conn.end(wdk::utils::get_system_timestamp_ms());
                return Some(conn.clone());
            }
        }
        None
    }

    pub fn end_all_on_port_v4(&self, key: (IpProtocol, u16)) -> Option<Vec<Arc<ConnectionV4>>> {
        // Get the port, read only
        let port = get_port(&self.tcp_v4, &self.udp_v4, key.0, key.1)?.read();
        let snap = port.get()?;
        let now = wdk::utils::get_system_timestamp_ms();
        let mut ended = Vec::new();
        // Mark all as ended
        for conn in snap.iter() {
            if !conn.has_ended() {
                conn.end(now);
                ended.push(conn.clone());
            }
        }
        Some(ended)
    }

    pub fn end_all_on_port_v6(&self, key: (IpProtocol, u16)) -> Option<Vec<Arc<ConnectionV6>>> {
        // Get the port, read only
        let port = get_port(&self.tcp_v6, &self.udp_v6, key.0, key.1)?.read();
        let snap = port.get()?;
        let now = wdk::utils::get_system_timestamp_ms();
        let mut ended = Vec::new();
        // Mark all as ended
        for conn in snap.iter() {
            if !conn.has_ended() {
                conn.end(now);
                ended.push(conn.clone());
            }
        }
        Some(ended)
    }

    pub fn update_connection(&self, key: Key, verdict: Verdict) -> Option<RedirectInfo> {
        if key.is_ipv6() {
            // Get read only port.
            let port = get_port(&self.tcp_v6, &self.udp_v6, key.protocol, key.local_port)?.read();
            let snap = port.get()?;
            // Iterate over all connections.
            for conn in snap.iter() {
                if conn.equals(&key) {
                    // Update verdict.
                    conn.set_verdict(verdict);
                    return conn.redirect_info();
                }
            }
        } else {
            // Get read only port.
            let port = get_port(&self.tcp_v4, &self.udp_v4, key.protocol, key.local_port)?.read();
            let snap = port.get()?;
            // Iterate over all connections.
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
            let port = get_port(&self.tcp_v6, &self.udp_v6, key.protocol, key.local_port)?;
            let guard = port.read();
            let snap = guard.get()?;
            for conn in snap.iter() {
                if conn.equals(key) || conn.redirect_equals(key) {
                    conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                    return Some(conn.get_verdict());
                }
            }
        } else {
            let port = get_port(&self.tcp_v4, &self.udp_v4, key.protocol, key.local_port)?;
            let guard = port.read();
            let snap = guard.get()?;
            for conn in snap.iter() {
                if conn.equals(key) || conn.redirect_equals(key) {
                    conn.set_last_accessed_time(wdk::utils::get_system_timestamp_ms());
                    return Some(conn.get_verdict());
                }
            }
        }
        None
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

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use crate::connection::{Direction, Verdict};
    use proptest::prelude::*;
    use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Address, Ipv6Address};

    // A non-loopback 2001:: address whose last byte is `last`.
    fn v6(last: u8) -> Ipv6Address {
        Ipv6Address::from_octets([
            0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last,
        ])
    }

    // Fixed pool of 6 distinct keys. None use the DNS (53) / SPN (717) remote
    // port or a loopback/equal remote, so `redirect_equals` never matches and
    // `get_verdict` resolves a key to at most its own connection. Key 5 shares
    // the TCP/1000 bucket with key 0 (tests multiple connections per port).
    fn key(i: usize) -> Key {
        match i {
            0 => Key {
                protocol: IpProtocol::Tcp,
                local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
                local_port: 1000,
                remote_address: IpAddress::Ipv4(Ipv4Address::new(1, 1, 1, 1)),
                remote_port: 80,
            },
            1 => Key {
                protocol: IpProtocol::Udp,
                local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
                local_port: 1000,
                remote_address: IpAddress::Ipv4(Ipv4Address::new(8, 8, 8, 8)),
                remote_port: 5353,
            },
            2 => Key {
                protocol: IpProtocol::Tcp,
                local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)),
                local_port: 2000,
                remote_address: IpAddress::Ipv4(Ipv4Address::new(1, 1, 1, 1)),
                remote_port: 443,
            },
            3 => Key {
                protocol: IpProtocol::Tcp,
                local_address: IpAddress::Ipv6(v6(1)),
                local_port: 3000,
                remote_address: IpAddress::Ipv6(v6(0x80)),
                remote_port: 80,
            },
            4 => Key {
                protocol: IpProtocol::Udp,
                local_address: IpAddress::Ipv6(v6(2)),
                local_port: 4000,
                remote_address: IpAddress::Ipv6(v6(0x88)),
                remote_port: 5353,
            },
            _ => Key {
                protocol: IpProtocol::Tcp,
                local_address: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
                local_port: 1000,
                remote_address: IpAddress::Ipv4(Ipv4Address::new(2, 2, 2, 2)),
                remote_port: 80,
            },
        }
    }

    const POOL: usize = 6;

    fn verdict_from(v: u8) -> Verdict {
        num_traits::FromPrimitive::from_u8(v).unwrap()
    }

    #[derive(Clone, Copy, Debug)]
    struct ConnModel {
        verdict: u8,
        ended: bool,
        end_time: u64,
        last_access: u64,
    }

    #[derive(Clone, Debug)]
    enum Op {
        Add(usize),
        Update(usize, u8),
        End(usize),
        EndAllOnPort(usize),
        Clean,
        Clear,
        Advance(u64),
        CheckVerdict(usize),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0..POOL).prop_map(Op::Add),
            (0..POOL, prop::sample::select(vec![0u8, 1, 2, 3, 4, 5, 6, 7, 10]))
                .prop_map(|(i, v)| Op::Update(i, v)),
            (0..POOL).prop_map(Op::End),
            (0..POOL).prop_map(Op::EndAllOnPort),
            Just(Op::Clean),
            Just(Op::Clear),
            prop::sample::select(vec![0u64, 30_000, 70_000, 130_000]).prop_map(Op::Advance),
            (0..POOL).prop_map(Op::CheckVerdict),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        // Model-based test of the connection cache against a simple reference
        // model. Exercises the real RCU / unlinked-queue reclamation
        // (alloc_zeroed + Box::from_raw) under randomized op sequences, asserting
        // verdict lookups and active/ended counts stay consistent with the model.
        #[test]
        fn cache_state_machine(ops in proptest::collection::vec(op_strategy(), 0..32)) {
            let mut now: u64 = 1_000_000;
            wdk::utils::set_mock_time_ms(now);

            let mut cache = ConnectionCache::new();
            let mut model: [Option<ConnModel>; POOL] = [None; POOL];

            for op in ops {
                match op {
                    Op::Add(i) => {
                        if model[i].is_none() {
                            let k = key(i);
                            if k.is_ipv6() {
                                let c = ConnectionV6::from_key(&k, 1, Direction::Outbound).unwrap();
                                cache.add_v6(c);
                            } else {
                                let c = ConnectionV4::from_key(&k, 1, Direction::Outbound).unwrap();
                                cache.add_v4(c);
                            }
                            model[i] = Some(ConnModel {
                                verdict: 0,
                                ended: false,
                                end_time: 0,
                                last_access: now,
                            });
                        }
                    }
                    Op::Update(i, v) => {
                        cache.update_connection(key(i), verdict_from(v));
                        if let Some(cm) = &mut model[i] {
                            cm.verdict = v;
                        }
                    }
                    Op::End(i) => {
                        let k = key(i);
                        if k.is_ipv6() {
                            cache.end_v6(k);
                        } else {
                            cache.end_v4(k);
                        }
                        if let Some(cm) = &mut model[i] {
                            cm.ended = true;
                            cm.end_time = now;
                        }
                    }
                    Op::EndAllOnPort(i) => {
                        let k = key(i);
                        if k.is_ipv6() {
                            cache.end_all_on_port_v6((k.protocol, k.local_port));
                        } else {
                            cache.end_all_on_port_v4((k.protocol, k.local_port));
                        }
                        for j in 0..POOL {
                            let kj = key(j);
                            if kj.is_ipv6() == k.is_ipv6()
                                && kj.protocol == k.protocol
                                && kj.local_port == k.local_port
                            {
                                if let Some(cm) = &mut model[j] {
                                    if !cm.ended {
                                        cm.ended = true;
                                        cm.end_time = now;
                                    }
                                }
                            }
                        }
                    }
                    Op::Clean => {
                        cache.clean_ended_connections();
                        for slot in model.iter_mut() {
                            if let Some(cm) = *slot {
                                let remove = (cm.ended && cm.end_time < now.saturating_sub(60_000))
                                    || (cm.last_access < now.saturating_sub(120_000));
                                if remove {
                                    *slot = None;
                                }
                            }
                        }
                    }
                    Op::Clear => {
                        cache.clear();
                        for slot in model.iter_mut() {
                            *slot = None;
                        }
                    }
                    Op::Advance(d) => {
                        now += d;
                        wdk::utils::set_mock_time_ms(now);
                    }
                    Op::CheckVerdict(i) => {
                        let got = cache.get_verdict(&key(i)).map(|v| v as u8);
                        let expected = model[i].map(|cm| cm.verdict);
                        prop_assert_eq!(got, expected);
                        if let Some(cm) = &mut model[i] {
                            cm.last_access = now;
                        }
                    }
                }
            }

            // Final invariants: verdict lookups and active/ended counts match.
            for i in 0..POOL {
                let got = cache.get_verdict(&key(i)).map(|v| v as u8);
                let expected = model[i].map(|cm| cm.verdict);
                prop_assert_eq!(got, expected, "verdict mismatch for key {}", i);
            }
            let (active, ended) = cache.get_entries_count();
            let exp_active = model.iter().filter(|m| matches!(m, Some(c) if !c.ended)).count();
            let exp_ended = model.iter().filter(|m| matches!(m, Some(c) if c.ended)).count();
            prop_assert_eq!(active, exp_active, "active count mismatch");
            prop_assert_eq!(ended, exp_ended, "ended count mismatch");
        }
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
