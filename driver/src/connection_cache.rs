use crate::{
    connection::{ConnectionV4, ConnectionV6, RedirectInfo, Verdict},
    connection_map::{ConnectionMap, Key},
};
use alloc::vec::Vec;

use smoltcp::wire::IpProtocol;

pub struct ConnectionCache {
    connections_v4: ConnectionMap<ConnectionV4>,
    connections_v6: ConnectionMap<ConnectionV6>,
    tmp_ended_connections_buffer_v4: Vec<ConnectionV4>,
    tmp_ended_connections_buffer_v6: Vec<ConnectionV6>,
}

impl ConnectionCache {
    pub fn new() -> Self {
        Self {
            connections_v4: ConnectionMap::new(),
            connections_v6: ConnectionMap::new(),
            tmp_ended_connections_buffer_v4: Vec::with_capacity(100),
            tmp_ended_connections_buffer_v6: Vec::with_capacity(100),
        }
    }

    pub fn add_connection_v4(&mut self, connection: ConnectionV4) {
        self.connections_v4.add(connection);
    }

    pub fn add_connection_v6(&mut self, connection: ConnectionV6) {
        self.connections_v6.add(connection);
    }

    pub fn update_connection(&mut self, key: Key, verdict: Verdict) -> Option<RedirectInfo> {
        if key.is_ipv6() {
            return self.connections_v6.update_verdict(key, verdict);
        } else {
            return self.connections_v4.update_verdict(key, verdict);
        }
    }

    pub fn read_connection_v4<T>(
        &self,
        key: &Key,
        process_connection: fn(&ConnectionV4) -> Option<T>,
    ) -> Option<T> {
        self.connections_v4.read(&key, process_connection)
    }

    pub fn read_connection_v6<T>(
        &self,
        key: &Key,
        process_connection: fn(&ConnectionV6) -> Option<T>,
    ) -> Option<T> {
        self.connections_v6.read(&key, process_connection)
    }

    pub fn end_connection_v4(&mut self, key: Key) -> Option<ConnectionV4> {
        self.connections_v4.end(key)
    }

    pub fn end_connection_v6(&mut self, key: Key) -> Option<ConnectionV6> {
        self.connections_v6.end(key)
    }

    pub fn end_all_on_port_v4(&mut self, key: (IpProtocol, u16)) -> Option<Vec<ConnectionV4>> {
        self.connections_v4.end_all_on_port(key)
    }

    pub fn end_all_on_port_v6(&mut self, key: (IpProtocol, u16)) -> Option<Vec<ConnectionV6>> {
        self.connections_v6.end_all_on_port(key)
    }

    pub fn clean_ended_connections<'a>(
        &'a mut self,
    ) -> (&'a mut Vec<ConnectionV4>, &'a mut Vec<ConnectionV6>) {
        self.connections_v4
            .clean_ended_connections(&mut self.tmp_ended_connections_buffer_v4);

        self.connections_v6
            .clean_ended_connections(&mut self.tmp_ended_connections_buffer_v6);
        return (
            &mut self.tmp_ended_connections_buffer_v4,
            &mut self.tmp_ended_connections_buffer_v6,
        );
    }

    pub fn clear(&mut self) {
        self.connections_v4.clear();
        self.connections_v6.clear();
    }
}
