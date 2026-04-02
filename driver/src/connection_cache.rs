use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{
    connection::{ConnectionInfo, ConnectionV4, ConnectionV6, Direction},
    connection_map::{ConnectionMap, Key},
};

pub struct ConnectionCache {
    pub v4: ConnectionMap<ConnectionV4>,
    pub v6: ConnectionMap<ConnectionV6>,

    tmp_ended_connections_buffer_v4: Vec<Arc<ConnectionV4>>,
    tmp_ended_connections_buffer_v6: Vec<Arc<ConnectionV6>>,
}

impl ConnectionCache {
    pub fn new() -> Self {
        Self {
            v4: ConnectionMap::new(),
            v6: ConnectionMap::new(),
            tmp_ended_connections_buffer_v4: Vec::with_capacity(100),
            tmp_ended_connections_buffer_v6: Vec::with_capacity(100),
        }
    }

    pub fn update_connection(
        &self,
        key: Key,
        verdict: crate::connection::Verdict,
    ) -> Option<crate::connection::RedirectInfo> {
        if key.is_ipv6() {
            self.v6.update_verdict(key, verdict)
        } else {
            self.v4.update_verdict(key, verdict)
        }
    }

    // clean_ended_connections is not thread safe and should be called from one place only.
    pub fn clean_ended_connections<'a>(
        &'a mut self,
    ) -> (&'a mut Vec<Arc<ConnectionV4>>, &'a mut Vec<Arc<ConnectionV6>>) {
        self.tmp_ended_connections_buffer_v4.clear();
        self.tmp_ended_connections_buffer_v6.clear();
        self.v4
            .clean_ended_connections(&mut self.tmp_ended_connections_buffer_v4);
        self.v6
            .clean_ended_connections(&mut self.tmp_ended_connections_buffer_v6);

        return (
            &mut self.tmp_ended_connections_buffer_v4,
            &mut self.tmp_ended_connections_buffer_v6,
        );
    }

    pub fn walk_over_connections_v4<F: FnMut(&ConnectionV4)>(&self, iter: F) {
        self.v4.walk_over_connections(iter)
    }

    pub fn walk_over_connections_v6<F: FnMut(&ConnectionV6)>(&self, iter: F) {
        self.v6.walk_over_connections(iter)
    }

    pub fn get_connection_and_update_bw_usage(
        &self,
        key: &Key,
        packet_size: u64,
        direction: Direction,
    ) -> Option<ConnectionInfo> {
        if key.is_ipv6() {
            self.v6.read_update_bw_usage(
                key,
                packet_size,
                direction,
                |conn: &ConnectionV6| Some(ConnectionInfo::from_connection(conn)),
            )
        } else {
            self.v4.read_update_bw_usage(
                key,
                packet_size,
                direction,
                |conn: &ConnectionV4| Some(ConnectionInfo::from_connection(conn)),
            )
        }
    }

    pub fn clear(&self) {
        self.v4.clear();
        self.v6.clear();
    }
}
