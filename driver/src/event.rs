use protocol::info::{
    ConnectionEndV4, ConnectionEndV6, ConnectionInfoV4, ConnectionInfoV6, ConnectionUpdateEnd,
    ConnectionUpdateV4, ConnectionUpdateV6, Info, Writer,
};

use crate::id_cache::IdCache;

/// An event waiting for user space to read it.
///
/// Every kind but the log line is a plain fixed-size value, so the event queue can hold them
/// without allocating. They are serialized when they are read, straight into the read buffer. A
/// packet event does not carry the packet: its payload is copied from the packet cache then.
pub enum Event {
    ConnectionV4(ConnectionInfoV4),
    ConnectionV6(ConnectionInfoV6),
    EndV4(ConnectionEndV4),
    EndV6(ConnectionEndV6),
    UpdateV4(ConnectionUpdateV4),
    UpdateV6(ConnectionUpdateV6),
    UpdateEnd(ConnectionUpdateEnd),
    /// Log lines stay dynamic: they are rare and their length varies.
    Log(Info),
}

impl Event {
    /// The size of the serialized event.
    pub fn serialized_size(&self) -> usize {
        match self {
            Event::ConnectionV4(info) => info.serialized_size(),
            Event::ConnectionV6(info) => info.serialized_size(),
            Event::EndV4(info) => info.serialized_size(),
            Event::EndV6(info) => info.serialized_size(),
            Event::UpdateV4(info) => info.serialized_size(),
            Event::UpdateV6(info) => info.serialized_size(),
            Event::UpdateEnd(info) => info.serialized_size(),
            Event::Log(info) => info.serialized_size(),
        }
    }

    /// Serializes the event into `writer`. A packet event takes its payload from `packet_cache`;
    /// if the packet is no longer there (it expired), the payload is sent as zeros.
    pub fn write(&self, writer: &mut Writer, packet_cache: &IdCache) {
        match self {
            Event::ConnectionV4(info) => {
                packet_cache.with_payload(info.id, |payload| info.write(writer, payload))
            }
            Event::ConnectionV6(info) => {
                packet_cache.with_payload(info.id, |payload| info.write(writer, payload))
            }
            Event::EndV4(info) => info.write(writer),
            Event::EndV6(info) => info.write(writer),
            Event::UpdateV4(info) => info.write(writer),
            Event::UpdateV6(info) => info.write(writer),
            Event::UpdateEnd(info) => info.write(writer),
            Event::Log(info) => info.write(writer),
        }
    }
}
