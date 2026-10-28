use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::time::Duration;

use crate::connection::{
    Connection, ConnectionV4, ConnectionV6, Key, RedirectInfo, Verdict, PM_DNS_PORT, PM_SPN_PORT,
};
use crate::port_connections::{Entry, PortConnections};
use smoltcp::wire::IpProtocol;

// 0-65535 must be valid ports. 0 is not a valid port number but its kept for future proofing for special cases.
const PORT_COUT: usize = u16::MAX as usize + 1;
type PortArray<T> = [PortConnections<T>; PORT_COUT];

/// The most stale connections one `clean_ended_connections` call evicts per IP version, which
/// bounds the end events it sends at once.
const MAX_STALE_EVICTIONS: usize = 100;

// Selects the correct per-port slot from the tcp/udp arrays.
fn get_port<'a, T: Connection>(
    tcp: &'a PortArray<T>,
    udp: &'a PortArray<T>,
    protocol: IpProtocol,
    local_port: u16,
) -> Option<&'a PortConnections<T>> {
    match protocol {
        IpProtocol::Tcp => Some(&tcp[local_port as usize]),
        IpProtocol::Udp => Some(&udp[local_port as usize]),
        _ => None,
    }
}

fn alloc_port_array<T: Connection>() -> Result<Box<PortArray<T>>, String> {
    // PortConnections<T> is valid when zeroed:
    //   - AtomicPtr is valid as null
    //   - Mutex<()> / RwSpinLock uses i32 which is valid at 0
    // alloc_zeroed is used to allocate directly on the heap.
    let layout = core::alloc::Layout::new::<PortArray<T>>();
    unsafe {
        let ptr = alloc::alloc::alloc_zeroed(layout) as *mut PortArray<T>;
        if ptr.is_null() {
            return Err("failed to allocate the connection cache".to_string());
        }
        Ok(Box::from_raw(ptr))
    }
}

/// The connection `key` names exactly.
fn find_exact<'a, T: Connection>(entries: &'a [Entry<T>], key: &Key) -> Option<&'a T> {
    let compact = T::compact_key_of(key)?;
    entries
        .iter()
        .find(|entry| entry.key == compact)
        .map(|entry| &*entry.conn)
}

/// The connection `key` names, or the redirected connection a packet with `key` belongs to.
fn find_exact_or_redirect<'a, T: Connection>(
    entries: &'a [Entry<T>],
    key: &Key,
) -> Option<&'a T> {
    if let Some(conn) = find_exact(entries, key) {
        return Some(conn);
    }
    // A redirected packet carries the address it was redirected to, not the connection's, so it
    // needs a slower check against each connection. Redirects only go to the DNS and the tunnel
    // port, so no other packet pays for it.
    if key.remote_port != PM_DNS_PORT && key.remote_port != PM_SPN_PORT {
        return None;
    }
    entries
        .iter()
        .map(|entry| &*entry.conn)
        .find(|conn| conn.redirect_equals(key))
}

// Runs `f` on the connection `key` names, holding its port's lock shared.
fn with_exact<T: Connection, R>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    key: &Key,
    f: impl FnOnce(&T) -> R,
) -> Option<R> {
    let port = get_port(tcp, udp, key.protocol, key.local_port)?;
    port.read(|entries| find_exact(entries, key).map(f))
}

// Runs `f` on the connection `key` names, or the redirected connection it belongs to, holding its
// port's lock shared. Refreshes the last-accessed time.
fn with_exact_or_redirect<T: Connection, R>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    key: &Key,
    f: impl FnOnce(&T) -> R,
) -> Option<R> {
    let port = get_port(tcp, udp, key.protocol, key.local_port)?;
    port.read(|entries| {
        let conn = find_exact_or_redirect(entries, key)?;
        conn.set_last_accessed_time(wdk::utils::get_monotonic_ms());
        Some(f(conn))
    })
}

fn ports_clear<T: Connection>(tcp: &PortArray<T>, udp: &PortArray<T>) {
    for port in tcp.iter().chain(udp.iter()) {
        if !port.is_empty() {
            port.write(|entries| entries.clear());
        }
    }
}

// Adds a connection to its port. If an equal one is already present, its
// last-accessed time and bandwidth are updated instead of inserting a duplicate.
//
// The duplicate check and the publish both run under the port write lock, so
// concurrent adds of the same connection collapse to a single entry. This
// matters because a lookup + add is not atomic and the packet layer
// runs on multiple CPUs, so two callers can miss the same connection and race
// to insert it.
fn add_connection<T: Connection>(tcp: &PortArray<T>, udp: &PortArray<T>, new: T) {
    let Some(port) = get_port(tcp, udp, new.get_protocol(), new.get_local_port()) else {
        return;
    };

    // Allocated before the lock is taken.
    let new = Entry::new(Box::new(new));

    port.write(|entries| {
        // If the connection is already present, fold the new observation into it instead of
        // inserting a duplicate.
        if let Some(entry) = entries.iter().find(|entry| entry.key == new.key) {
            // Refresh last-accessed and accumulate bandwidth so no traffic
            // accounting is lost. Identity, verdict and process id are left
            // untouched — the existing connection stays authoritative.
            entry
                .conn
                .set_last_accessed_time(new.conn.get_last_accessed_time());
            entry
                .conn
                .get_bandwidth_usage()
                .add_from(new.conn.get_bandwidth_usage());
            return;
        }

        entries.push(new);
    });
}

// Marks the connection matching `key` as ended and runs `f` on it.
fn end_connection<T: Connection, R>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    key: &Key,
    f: impl FnOnce(&T) -> R,
) -> Option<R> {
    with_exact(tcp, udp, key, |conn| {
        conn.end(wdk::utils::get_monotonic_ms());
        f(conn)
    })
}

// Marks every active connection on the given (protocol, port) as ended and
// runs `f` on each, holding the port's lock shared.
fn end_all_on_port<T: Connection>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    protocol: IpProtocol,
    local_port: u16,
    mut f: impl FnMut(&T),
) {
    let Some(port) = get_port(tcp, udp, protocol, local_port) else {
        return;
    };
    let now = wdk::utils::get_monotonic_ms();
    port.read(|entries| {
        for conn in entries.iter().map(|entry| &*entry.conn) {
            if !conn.has_ended() {
                conn.end(now);
                f(conn);
            }
        }
    })
}

// ports_walk generic function for waling over all connections.
fn ports_walk<T: Connection, F: FnMut(&T)>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    mut iter: F,
) {
    for port in tcp.iter().chain(udp.iter()) {
        // One lock at a time, held only for its own port.
        if !port.is_empty() {
            port.read(|entries| entries.iter().for_each(|entry| iter(&entry.conn)));
        }
    }
}

// Removes the connections that ended over a minute ago, and evicts up to MAX_STALE_EVICTIONS
// that saw no traffic for two minutes, running `on_stale` on each of those before it is freed,
// holding its port's lock exclusive.
fn ports_clean_ended<T: Connection>(
    tcp: &PortArray<T>,
    udp: &PortArray<T>,
    mut on_stale: impl FnMut(&T),
) {
    // Durations
    const TWO_MINUTES: u64 = Duration::from_secs(120).as_millis() as u64;
    const ONE_MINUTE: u64 = Duration::from_secs(60).as_millis() as u64;

    let now = wdk::utils::get_monotonic_ms();
    // The clock counts from boot, so it can be below these windows when the driver loads early.
    // Saturating makes the cutoff 0, which no timestamp is below: nothing is old enough yet.
    let before_two_minutes = now.saturating_sub(TWO_MINUTES);
    let before_one_minute = now.saturating_sub(ONE_MINUTE);

    let mut evicted = 0;
    for port in tcp.iter().chain(udp.iter()) {
        if port.is_empty() {
            continue;
        }
        port.write(|entries| {
            entries.retain(|entry| {
                let conn = &*entry.conn;
                if conn.has_ended() && conn.get_end_time() < before_one_minute {
                    return false;
                }
                if evicted < MAX_STALE_EVICTIONS
                    && conn.get_last_accessed_time() < before_two_minutes
                {
                    on_stale(conn);
                    evicted += 1;
                    return false;
                }
                true
            })
        });
    }
}

// ConnectionCache holds the state of all active connections.
pub struct ConnectionCache {
    // Connection states
    tcp_v4: Box<PortArray<ConnectionV4>>,
    udp_v4: Box<PortArray<ConnectionV4>>,
    tcp_v6: Box<PortArray<ConnectionV6>>,
    udp_v6: Box<PortArray<ConnectionV6>>,
}

impl ConnectionCache {
    pub fn new() -> Result<Self, String> {
        // Initialize all the arrays.
        Ok(Self {
            tcp_v4: alloc_port_array()?,
            udp_v4: alloc_port_array()?,
            tcp_v6: alloc_port_array()?,
            udp_v6: alloc_port_array()?,
        })
    }

    pub fn add_v4(&self, new: ConnectionV4) {
        add_connection(&self.tcp_v4, &self.udp_v4, new);
    }

    pub fn add_v6(&self, new: ConnectionV6) {
        add_connection(&self.tcp_v6, &self.udp_v6, new);
    }

    /// Marks the connection matching `key` as ended and runs `f` on it.
    pub fn end_v4<R>(&self, key: Key, f: impl FnOnce(&ConnectionV4) -> R) -> Option<R> {
        end_connection(&self.tcp_v4, &self.udp_v4, &key, f)
    }

    /// Marks the connection matching `key` as ended and runs `f` on it.
    pub fn end_v6<R>(&self, key: Key, f: impl FnOnce(&ConnectionV6) -> R) -> Option<R> {
        end_connection(&self.tcp_v6, &self.udp_v6, &key, f)
    }

    /// Marks every active connection on the port as ended and runs `f` on each, holding the
    /// port's lock shared.
    pub fn end_all_on_port_v4(&self, key: (IpProtocol, u16), f: impl FnMut(&ConnectionV4)) {
        end_all_on_port(&self.tcp_v4, &self.udp_v4, key.0, key.1, f)
    }

    /// Marks every active connection on the port as ended and runs `f` on each, holding the
    /// port's lock shared.
    pub fn end_all_on_port_v6(&self, key: (IpProtocol, u16), f: impl FnMut(&ConnectionV6)) {
        end_all_on_port(&self.tcp_v6, &self.udp_v6, key.0, key.1, f)
    }

    /// Sets the verdict of the connection matching `key`, returning any redirect info.
    pub fn update_connection(&self, key: Key, verdict: Verdict) -> Option<RedirectInfo> {
        fn set<T: Connection>(conn: &T, verdict: Verdict) -> Option<RedirectInfo> {
            conn.set_verdict(verdict);
            conn.redirect_info()
        }
        if key.is_ipv6() {
            with_exact(&self.tcp_v6, &self.udp_v6, &key, |conn| set(conn, verdict))?
        } else {
            with_exact(&self.tcp_v4, &self.udp_v4, &key, |conn| set(conn, verdict))?
        }
    }

    // clean_ended_connections should be called from one place only.
    // Removes ended connections and evicts stale ones, running `on_stale_v4` / `on_stale_v6` on
    // each evicted connection before it is freed, so its end can be reported to user space. They
    // run under the port's lock: they must not use the connection cache again.
    pub fn clean_ended_connections(
        &self,
        on_stale_v4: impl FnMut(&ConnectionV4),
        on_stale_v6: impl FnMut(&ConnectionV6),
    ) {
        ports_clean_ended(&self.tcp_v4, &self.udp_v4, on_stale_v4);
        ports_clean_ended(&self.tcp_v6, &self.udp_v6, on_stale_v6);
    }

    /// Fails the connection matching `key` if it is still undecided, so a verdict that arrived in
    /// the meantime is kept.
    pub fn fail_if_undecided(&self, key: &Key) {
        fn fail<T: Connection>(conn: &T) {
            conn.replace_verdict(Verdict::Undecided, Verdict::Failed);
        }
        if key.is_ipv6() {
            with_exact(&self.tcp_v6, &self.udp_v6, key, fail);
        } else {
            with_exact(&self.tcp_v4, &self.udp_v4, key, fail);
        }
    }

    /// The verdict of the connection matching `key`, including redirect matches. Refreshes the
    /// last-accessed time.
    pub fn get_verdict(&self, key: &Key) -> Option<Verdict> {
        if key.is_ipv6() {
            with_exact_or_redirect(&self.tcp_v6, &self.udp_v6, key, Connection::get_verdict)
        } else {
            with_exact_or_redirect(&self.tcp_v4, &self.udp_v4, key, Connection::get_verdict)
        }
    }

    // walk_over_connections_v4 walks over all IPv4 connections. Takes the port's lock shared.
    pub fn walk_over_connections_v4<F: FnMut(&ConnectionV4)>(&self, iter: F) {
        ports_walk(&self.tcp_v4, &self.udp_v4, iter);
    }

    // walk_over_connections_v6 walks over all IPv6 connections. Takes the port's lock shared.
    pub fn walk_over_connections_v6<F: FnMut(&ConnectionV6)>(&self, iter: F) {
        ports_walk(&self.tcp_v6, &self.udp_v6, iter);
    }

    // get_entries_count returns stats for all the connections count. Takes the port's lock shared.
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

    /// Runs `f` on the connection matching `key`, including redirect matches. Refreshes the
    /// last-accessed time. Takes the port's lock shared.
    pub fn with_connection_v4<R>(
        &self,
        key: &Key,
        f: impl FnOnce(&ConnectionV4) -> R,
    ) -> Option<R> {
        with_exact_or_redirect(&self.tcp_v4, &self.udp_v4, key, f)
    }

    /// Runs `f` on the connection matching `key`, including redirect matches. Refreshes the
    /// last-accessed time. Takes the port's lock shared.
    pub fn with_connection_v6<R>(
        &self,
        key: &Key,
        f: impl FnOnce(&ConnectionV6) -> R,
    ) -> Option<R> {
        with_exact_or_redirect(&self.tcp_v6, &self.udp_v6, key, f)
    }

    // Clears the connection cache.
    pub fn clear(&self) {
        ports_clear(&self.tcp_v4, &self.udp_v4);
        ports_clear(&self.tcp_v6, &self.udp_v6);
    }
}
