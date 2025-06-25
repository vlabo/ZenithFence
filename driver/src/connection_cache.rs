use crate::{
    connection::{ConnectionInfo, ConnectionV4, ConnectionV6},
    connection_map::{ConnectionMap, Key},
};
use alloc::vec::Vec;

pub struct ConnectionCache {
    pub v4: ConnectionMap<ConnectionV4>,
    pub v6: ConnectionMap<ConnectionV6>,

    tmp_ended_connections_buffer_v4: Vec<ConnectionV4>,
    tmp_ended_connections_buffer_v6: Vec<ConnectionV6>,
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
        &mut self,
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
    ) -> (&'a mut Vec<ConnectionV4>, &'a mut Vec<ConnectionV6>) {
        self.v4
            .clean_ended_connections(&mut self.tmp_ended_connections_buffer_v4);
        self.v6
            .clean_ended_connections(&mut self.tmp_ended_connections_buffer_v6);

        return (
            &mut self.tmp_ended_connections_buffer_v4,
            &mut self.tmp_ended_connections_buffer_v6,
        );
    }

    pub fn get_connection_info(&self, key: &Key) -> Option<ConnectionInfo> {
        if key.is_ipv6() {
            let conn_info = self
                .v6
                .read(&key, |conn: &ConnectionV6| -> Option<ConnectionInfo> {
                    // Function is is behind spin lock. Just copy and return.
                    Some(ConnectionInfo::from_connection(conn))
                });
            return conn_info;
        } else {
            let conn_info = self
                .v4
                .read(&key, |conn: &ConnectionV4| -> Option<ConnectionInfo> {
                    // Function is is behind spin lock. Just copy and return.
                    Some(ConnectionInfo::from_connection(conn))
                });
            return conn_info;
        }
    }

    pub fn clear(&mut self) {
        self.v4.clear();
        self.v6.clear();
    }
}
