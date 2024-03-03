use crate::{
    connection::{ConnectionV4, ConnectionV6, Verdict},
    driver_hashmap::DeviceHashMap,
};
use alloc::{format, string::String, vec::Vec};
use core::fmt::Display;

use smoltcp::wire::{IpAddress, IpProtocol};
use wdk::{
    filter_engine::{callout_data::ClassifyDefer, net_buffer::NetBufferList},
    rw_spin_lock::RwSpinLock,
};

#[derive(PartialEq, PartialOrd, Eq, Ord)]
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
    fn small(&self) -> (IpProtocol, u16) {
        (self.protocol, self.local_port)
    }

    fn is_ipv6(&self) -> bool {
        match self.local_address {
            IpAddress::Ipv4(_) => false,
            IpAddress::Ipv6(_) => true,
        }
    }
}

struct Entry<T> {
    has_redirect: bool,
    connections: Vec<T>,
}

type EntryV4 = Entry<ConnectionV4>;
type EntryV6 = Entry<ConnectionV6>;

pub struct ConnectionCache {
    connections_v4: DeviceHashMap<(IpProtocol, u16), EntryV4>,
    connections_v6: DeviceHashMap<(IpProtocol, u16), EntryV6>,
    lock_v4: RwSpinLock,
    lock_v6: RwSpinLock,
}

impl ConnectionCache {
    pub fn new() -> Self {
        Self {
            connections_v4: DeviceHashMap::new(),
            connections_v6: DeviceHashMap::new(),
            lock_v4: RwSpinLock::default(),
            lock_v6: RwSpinLock::default(),
        }
    }

    pub fn add_connection_v4(&mut self, connection: ConnectionV4) {
        let key = connection.get_key();
        let _guard = self.lock_v4.write_lock();
        if let Some(entry) = self.connections_v4.get_mut(&key.small()) {
            if connection.verdict.is_redirect() {
                entry.has_redirect = true;
            }
            entry.connections.push(connection);
        } else {
            let entry = EntryV4 {
                has_redirect: connection.verdict.is_redirect(),
                connections: alloc::vec![connection],
            };
            self.connections_v4.insert(key.small(), entry);
        }
    }

    pub fn add_connection_v6(&mut self, connection: ConnectionV6) {
        let key = connection.get_key();
        let _guard = self.lock_v6.write_lock();
        if let Some(entry) = self.connections_v6.get_mut(&key.small()) {
            if connection.verdict.is_redirect() {
                entry.has_redirect = true;
            }
            entry.connections.push(connection);
        } else {
            let entry = EntryV6 {
                has_redirect: connection.verdict.is_redirect(),
                connections: alloc::vec![connection],
            };
            self.connections_v6.insert(key.small(), entry);
        }
    }

    pub fn push_packet_to_connection(&mut self, key: Key, packet: NetBufferList) {
        if key.is_ipv6() {
            let _guard = self.lock_v6.write_lock();
            if let Some(entry) = self.connections_v6.get_mut(&key.small()) {
                for conn in &mut entry.connections {
                    if conn.remote_equals(&key) {
                        if let Some(classify_defer) = &mut conn.extra.packet_queue {
                            classify_defer.add_net_buffer(packet);
                            return;
                        }
                    }
                }
            }
        } else {
            let _guard = self.lock_v4.write_lock();
            if let Some(entry) = self.connections_v4.get_mut(&key.small()) {
                for conn in &mut entry.connections {
                    if conn.remote_equals(&key) {
                        if let Some(classify_defer) = &mut conn.extra.packet_queue {
                            classify_defer.add_net_buffer(packet);
                            return;
                        }
                    }
                }
            }
        }
    }

    pub fn update_connection(&mut self, key: Key, verdict: Verdict) -> Option<ClassifyDefer> {
        if key.is_ipv6() {
            let _guard = self.lock_v6.write_lock();
            if let Some(entry) = self.connections_v6.get_mut(&key.small()) {
                if verdict.is_redirect() {
                    entry.has_redirect = true;
                }
                for conn in &mut entry.connections {
                    if conn.remote_equals(&key) {
                        conn.verdict = verdict;
                        let classify_defer = conn.extra.packet_queue.take();
                        if classify_defer.is_some() {
                            return classify_defer;
                        }
                        return Some(ClassifyDefer::Reauthorization(conn.extra.callout_id, None));
                    }
                }
            }
        } else {
            let _guard = self.lock_v4.write_lock();
            if let Some(entry) = self.connections_v4.get_mut(&key.small()) {
                if verdict.is_redirect() {
                    entry.has_redirect = true;
                }
                for conn in &mut entry.connections {
                    if conn.remote_equals(&key) {
                        conn.verdict = verdict;
                        let classify_defer = conn.extra.packet_queue.take();
                        if classify_defer.is_some() {
                            return classify_defer;
                        } else {
                            return Some(ClassifyDefer::Reauthorization(
                                conn.extra.callout_id,
                                None,
                            ));
                        }
                    }
                }
            }
        }
        None
    }

    pub fn get_connection_action_v4<T>(
        &mut self,
        key: &Key,
        process_connection: fn(&ConnectionV4) -> Option<T>,
    ) -> Option<T> {
        let _guard = self.lock_v4.read_lock();

        if let Some(entry) = self.connections_v4.get(&key.small()) {
            for conn in &entry.connections {
                if conn.remote_equals(key) {
                    return process_connection(conn);
                }
                if conn.redirect_equals(key) {
                    return process_connection(conn);
                }
            }
        }

        None
    }

    pub fn get_connection_action_v6<T>(
        &mut self,
        key: &Key,
        process_connection: fn(&ConnectionV6) -> Option<T>,
    ) -> Option<T> {
        let _guard = self.lock_v6.read_lock();

        if let Some(entry) = self.connections_v6.get(&key.small()) {
            for conn in &entry.connections {
                if conn.remote_equals(key) {
                    return process_connection(conn);
                }
                if conn.redirect_equals(key) {
                    return process_connection(conn);
                }
            }
        }

        None
    }

    pub fn get_connection_redirect_v4<T>(
        &mut self,
        key: &Key,
        process_connection: fn(&ConnectionV4) -> Option<T>,
    ) -> Option<T> {
        let _guard = self.lock_v4.read_lock();

        if let Some(entry) = self.connections_v4.get(&key.small()) {
            if !entry.has_redirect {
                return None;
            }
            for conn in &entry.connections {
                if !conn.verdict.is_redirect() {
                    continue;
                }
                if conn.remote_equals(key) {
                    return process_connection(conn);
                }
                if conn.redirect_equals(key) {
                    return process_connection(conn);
                }
            }
        }

        None
    }

    pub fn get_connection_redirect_v6<T>(
        &mut self,
        key: &Key,
        process_connection: fn(&ConnectionV6) -> Option<T>,
    ) -> Option<T> {
        let _guard = self.lock_v6.read_lock();

        if let Some(entry) = self.connections_v6.get(&key.small()) {
            if !entry.has_redirect {
                return None;
            }
            for conn in &entry.connections {
                if !conn.verdict.is_redirect() {
                    continue;
                }
                if conn.remote_equals(key) {
                    return process_connection(conn);
                }
                if conn.redirect_equals(key) {
                    return process_connection(conn);
                }
            }
        }

        None
    }

    pub fn remove_connection_v4(&mut self, key: Key) -> Option<ConnectionV4> {
        let _guard = self.lock_v4.write_lock();
        let mut index = None;
        let mut conn = None;
        let mut delete = false;
        if let Some(entry) = self.connections_v4.get_mut(&key.small()) {
            for (i, conn) in entry.connections.iter().enumerate() {
                if conn.remote_equals(&key) {
                    index = Some(i);
                    break;
                }
            }
            if let Some(index) = index {
                conn = Some(entry.connections.remove(index));
            }

            if entry.connections.is_empty() {
                delete = true;
            }
        }
        if delete {
            self.connections_v4.remove(&key.small());
        }

        return conn;
    }

    pub fn remove_connection_v6(&mut self, key: Key) -> Option<ConnectionV6> {
        let _guard = self.lock_v6.write_lock();
        let mut index = None;
        let mut conn = None;
        let mut delete = false;
        if let Some(entry) = self.connections_v6.get_mut(&key.small()) {
            for (i, conn) in entry.connections.iter().enumerate() {
                if conn.remote_equals(&key) {
                    index = Some(i);
                    break;
                }
            }
            if let Some(index) = index {
                conn = Some(entry.connections.remove(index));
            }

            if entry.connections.is_empty() {
                delete = true;
            }
        }
        if delete {
            self.connections_v6.remove(&key.small());
        }

        return conn;
    }

    pub fn unregister_port_v4(&mut self, key: (IpProtocol, u16)) -> Option<Vec<ConnectionV4>> {
        let _guard = self.lock_v4.write_lock();
        if let Some(entry) = self.connections_v4.remove(&key) {
            return Some(entry.connections);
        }
        return None;
    }

    pub fn unregister_port_v6(&mut self, key: (IpProtocol, u16)) -> Option<Vec<ConnectionV6>> {
        let _guard = self.lock_v6.write_lock();
        if let Some(entry) = self.connections_v6.remove(&key) {
            return Some(entry.connections);
        }
        return None;
    }

    pub fn clear(&mut self) {
        let _guard = self.lock_v4.write_lock();
        self.connections_v4.clear();
        self.connections_v6.clear();
    }

    pub fn get_entries_count(&self) -> usize {
        let mut size = 0;
        {
            let values = self.connections_v4.values();
            let _guard = self.lock_v4.read_lock();
            for entry in values {
                size += entry.connections.len();
            }
        }

        {
            let values = self.connections_v6.values();
            let _guard = self.lock_v6.read_lock();
            for entry in values {
                size += entry.connections.len();
            }
        }

        return size;
    }

    pub fn get_full_cache_info(&self) -> String {
        let mut info = String::new();
        {
            let _guard = self.lock_v4.read_lock();
            for ((protocol, port), entry) in self.connections_v4.iter() {
                info.push_str(&format!(
                    "{} -> {} has_redirect: {}\n",
                    protocol, port, entry.has_redirect
                ));
                for conn in &entry.connections {
                    info.push_str(&format!(
                        "\t{}:{} -> {}:{} {}\n",
                        conn.local_address,
                        conn.local_port,
                        conn.remote_address,
                        conn.remote_port,
                        conn.verdict
                    ))
                }
            }
        }

        {
            let _guard = self.lock_v6.read_lock();
            for ((protocol, port), entry) in self.connections_v6.iter() {
                info.push_str(&format!(
                    "{} -> {} has_redirect: {}\n",
                    protocol, port, entry.has_redirect
                ));
                for conn in &entry.connections {
                    info.push_str(&format!(
                        "\t{}:{} -> {}:{} {}\n",
                        conn.local_address,
                        conn.local_port,
                        conn.remote_address,
                        conn.remote_port,
                        conn.verdict
                    ))
                }
            }
        }

        return info;
    }
}
