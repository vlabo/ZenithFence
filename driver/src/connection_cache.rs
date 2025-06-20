use core::time::Duration;

use crate::{
    connection::{Connection, ConnectionV4, ConnectionV6, RedirectInfo, Verdict},
    connection_map::{ConnectionMap, Key},
};
use alloc::{format, string::String, vec::Vec};

use smoltcp::wire::IpProtocol;
use wdk::rw_spin_lock::RwSpinLock;

pub struct ConnectionCache {
    connections_v4: ConnectionMap<ConnectionV4>,
    connections_v6: ConnectionMap<ConnectionV6>,
    lock_v4: RwSpinLock,
    lock_v6: RwSpinLock,

    tmp_ended_connections_buffer_v4: Vec<ConnectionV4>,
    tmp_ended_connections_buffer_v6: Vec<ConnectionV6>,
}

impl ConnectionCache {
    pub fn new() -> Self {
        Self {
            connections_v4: ConnectionMap::new(),
            connections_v6: ConnectionMap::new(),
            lock_v4: RwSpinLock::default(),
            lock_v6: RwSpinLock::default(),
            tmp_ended_connections_buffer_v4: Vec::with_capacity(100),
            tmp_ended_connections_buffer_v6: Vec::with_capacity(100),
        }
    }

    pub fn add_connection_v4(&mut self, connection: ConnectionV4) {
        let _guard = self.lock_v4.write_lock();
        self.connections_v4.add(connection);
    }

    pub fn add_connection_v6(&mut self, connection: ConnectionV6) {
        let _guard = self.lock_v6.write_lock();
        self.connections_v6.add(connection);
    }

    pub fn update_connection(&mut self, key: Key, verdict: Verdict) -> Option<RedirectInfo> {
        if key.is_ipv6() {
            let _guard = self.lock_v6.write_lock();
            if let Some(conn) = self.connections_v6.get_mut(&key) {
                conn.verdict = verdict;
                return conn.redirect_info();
            }
        } else {
            let _guard = self.lock_v4.write_lock();
            if let Some(conn) = self.connections_v4.get_mut(&key) {
                conn.verdict = verdict;
                return conn.redirect_info();
            }
        }
        None
    }

    pub fn read_connection_v4<T>(
        &self,
        key: &Key,
        process_connection: fn(&ConnectionV4) -> Option<T>,
    ) -> Option<T> {
        let _guard = self.lock_v4.read_lock();
        self.connections_v4.read(&key, process_connection)
    }

    pub fn read_connection_v6<T>(
        &self,
        key: &Key,
        process_connection: fn(&ConnectionV6) -> Option<T>,
    ) -> Option<T> {
        let _guard = self.lock_v6.read_lock();
        self.connections_v6.read(&key, process_connection)
    }

    pub fn end_connection_v4(&mut self, key: Key) -> Option<ConnectionV4> {
        let _guard = self.lock_v4.write_lock();
        self.connections_v4.end(key)
    }

    pub fn end_connection_v6(&mut self, key: Key) -> Option<ConnectionV6> {
        let _guard = self.lock_v6.write_lock();
        self.connections_v6.end(key)
    }

    pub fn end_all_on_port_v4(&mut self, key: (IpProtocol, u16)) -> Option<Vec<ConnectionV4>> {
        let _guard = self.lock_v4.write_lock();
        self.connections_v4.end_all_on_port(key)
    }

    pub fn end_all_on_port_v6(&mut self, key: (IpProtocol, u16)) -> Option<Vec<ConnectionV6>> {
        let _guard = self.lock_v6.write_lock();
        self.connections_v6.end_all_on_port(key)
    }

    pub fn clean_ended_connections<'a>(
        &'a mut self,
    ) -> (&'a mut Vec<ConnectionV4>, &'a mut Vec<ConnectionV6>) {
        {
            let _guard = self.lock_v4.write_lock();
            self.connections_v4
                .clean_ended_connections(&mut self.tmp_ended_connections_buffer_v4);
        }

        {
            let _guard = self.lock_v6.write_lock();
            self.connections_v6
                .clean_ended_connections(&mut self.tmp_ended_connections_buffer_v6);
        }
        return (
            &mut self.tmp_ended_connections_buffer_v4,
            &mut self.tmp_ended_connections_buffer_v6,
        );
    }

    pub fn clear(&mut self) {
        {
            let _guard = self.lock_v4.write_lock();
            self.connections_v4.clear();
        }
        {
            let _guard = self.lock_v6.write_lock();
            self.connections_v6.clear();
        }
    }

    #[allow(dead_code)]
    pub fn get_entries_count(&self) -> usize {
        let mut size = 0;
        {
            let _guard = self.lock_v4.read_lock();
            size += self.connections_v4.get_count();
        }

        {
            let _guard = self.lock_v6.read_lock();
            size += self.connections_v6.get_count();
        }

        return size;
    }

    #[allow(dead_code)]
    pub fn get_full_cache_info(&self) -> String {
        let mut info = String::new();
        let now = wdk::utils::get_system_timestamp_ms();
        {
            let _guard = self.lock_v4.read_lock();
            for ((protocol, port), connections) in self.connections_v4.iter() {
                info.push_str(&format!("{} -> {}\n", protocol, port,));
                for conn in connections {
                    let active_time_seconds =
                        Duration::from_millis(now - conn.get_last_accessed_time()).as_secs();
                    info.push_str(&format!(
                        "\t{}:{} -> {}:{} {} last active {}m {}s ago",
                        conn.local_address,
                        conn.local_port,
                        conn.remote_address,
                        conn.remote_port,
                        conn.verdict,
                        active_time_seconds / 60,
                        active_time_seconds % 60
                    ));
                    if conn.has_ended() {
                        let end_time_seconds =
                            Duration::from_millis(now - conn.get_end_time()).as_secs();
                        info.push_str(&format!(
                            "\t ended {}m {}s ago",
                            end_time_seconds / 60,
                            end_time_seconds % 60
                        ));
                    }
                    info.push('\n');
                }
            }
        }

        {
            let _guard = self.lock_v6.read_lock();
            for ((protocol, port), connections) in self.connections_v6.iter() {
                info.push_str(&format!("{} -> {} \n", protocol, port));
                for conn in connections {
                    let active_time_seconds =
                        Duration::from_millis(now - conn.get_last_accessed_time()).as_secs();
                    info.push_str(&format!(
                        "\t{}:{} -> {}:{} {} last active {}m {}s ago",
                        conn.local_address,
                        conn.local_port,
                        conn.remote_address,
                        conn.remote_port,
                        conn.verdict,
                        active_time_seconds / 60,
                        active_time_seconds % 60
                    ));
                    if conn.has_ended() {
                        let end_time_seconds =
                            Duration::from_millis(now - conn.get_end_time()).as_secs();
                        info.push_str(&format!(
                            "\t ended {}m {}s ago",
                            end_time_seconds / 60,
                            end_time_seconds % 60
                        ));
                    }
                    info.push('\n');
                }
            }
        }

        return info;
    }
}
