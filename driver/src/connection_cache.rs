use crate::connection::{ConnectionAction, ConnectionV4, ConnectionV6};
use alloc::{collections::BTreeMap, vec::Vec};
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

pub struct ConnectionCache {
    connections_v4: BTreeMap<(IpProtocol, u16), Vec<ConnectionV4>>,
    connections_v6: BTreeMap<(IpProtocol, u16), Vec<ConnectionV6>>,
    lock: RwSpinLock,
}

impl ConnectionCache {
    pub fn init(&mut self) {
        self.connections_v4 = BTreeMap::new();
        self.connections_v6 = BTreeMap::new();
        self.lock = RwSpinLock::default();
    }

    pub fn add_connection_v4(&mut self, connection: ConnectionV4) {
        let key = connection.get_key();
        let _guard = self.lock.write_lock();
        if let Some(conns) = self.connections_v4.get_mut(&key.small()) {
            conns.push(connection);
        } else {
            let conns = alloc::vec![connection];
            self.connections_v4.insert(key.small(), conns);
        }
    }

    pub fn add_connection_v6(&mut self, connection: ConnectionV6) {
        let key = connection.get_key();
        let _guard = self.lock.write_lock(); // TODO: replace with ipv6 lock
        if let Some(conns) = self.connections_v6.get_mut(&key.small()) {
            conns.push(connection);
        } else {
            let conns = alloc::vec![connection];
            self.connections_v6.insert(key.small(), conns);
        }
    }

    pub fn push_packet_to_connection(&mut self, key: Key, packet: NetBufferList) {
        if key.is_ipv6() {
            let _guard = self.lock.write_lock(); // TODO: replace with ipv6 lock
            if let Some(conns) = self.connections_v6.get_mut(&key.small()) {
                for conn in conns {
                    if conn.remote_equals(&key) {
                        if let Some(classify_defer) = &mut conn.extra.packet_queue {
                            classify_defer.add_net_buffer(packet);
                            return;
                        }
                    }
                }
            }
        } else {
            let _guard = self.lock.write_lock();
            if let Some(conns) = self.connections_v4.get_mut(&key.small()) {
                for conn in conns {
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

    pub fn update_connection(
        &mut self,
        key: Key,
        action: ConnectionAction,
    ) -> Option<ClassifyDefer> {
        if key.is_ipv6() {
            let _guard = self.lock.write_lock(); // TODO: replace with ipv6 lock
            if let Some(conns) = self.connections_v6.get_mut(&key.small()) {
                for conn in conns {
                    if conn.remote_equals(&key) {
                        conn.action = action;
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
        } else {
            let _guard = self.lock.write_lock();
            if let Some(conns) = self.connections_v4.get_mut(&key.small()) {
                for conn in conns {
                    if conn.remote_equals(&key) {
                        conn.action = action;
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
        let _guard = self.lock.read_lock();

        if let Some(conns) = self.connections_v4.get(&key.small()) {
            for conn in conns {
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
        let _guard = self.lock.read_lock(); // TODO: replace with ipv6 lock

        if let Some(conns) = self.connections_v6.get(&key.small()) {
            for conn in conns {
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

    pub fn remove_connection_v4(
        &mut self,
        key: (IpProtocol, u16),
        endpoint_handle: u64,
    ) -> Option<ConnectionV4> {
        let _guard = self.lock.write_lock();
        let mut index = None;
        let mut conn = None;
        let mut delete = false;
        if let Some(conns) = self.connections_v4.get_mut(&key) {
            for (i, conn) in conns.iter().enumerate() {
                if conn.extra.endpoint_handle == endpoint_handle {
                    index = Some(i);
                    break;
                }
            }
            if let Some(index) = index {
                conn = Some(conns.remove(index));
            }

            if conns.is_empty() {
                delete = true;
            }
        }
        if delete {
            self.connections_v4.remove(&key);
        }

        return conn;
    }

    pub fn remove_connection_v6(
        &mut self,
        key: (IpProtocol, u16),
        endpoint_handle: u64,
    ) -> Option<ConnectionV6> {
        let _guard = self.lock.write_lock();
        let mut index = None;
        let mut conn = None;
        let mut delete = false;
        if let Some(conns) = self.connections_v6.get_mut(&key) {
            for (i, conn) in conns.iter().enumerate() {
                if conn.extra.endpoint_handle == endpoint_handle {
                    index = Some(i);
                    break;
                }
            }
            if let Some(index) = index {
                conn = Some(conns.remove(index));
            }

            if conns.is_empty() {
                delete = true;
            }
        }
        if delete {
            self.connections_v4.remove(&key);
        }

        return conn;
    }

    pub fn unregister_port_v4(&mut self, key: (IpProtocol, u16)) -> Option<Vec<ConnectionV4>> {
        let _guard = self.lock.write_lock();
        self.connections_v4.remove(&key)
    }

    pub fn unregister_port_v6(&mut self, key: (IpProtocol, u16)) -> Option<Vec<ConnectionV6>> {
        let _guard = self.lock.write_lock();
        self.connections_v6.remove(&key)
    }

    pub fn clear(&mut self) {
        let _guard = self.lock.write_lock();
        self.connections_v4.clear();
        self.connections_v6.clear();
    }
}
