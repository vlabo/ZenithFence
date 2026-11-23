use alloc::vec::Vec;

#[repr(u8)]
#[derive(Clone, Copy)]
enum InfoType {
    LogLine = 0,
    ConnectionIpv4 = 1,
    ConnectionIpv6 = 2,
    ConnectionEndEventV4 = 3,
    ConnectionEndEventV6 = 4,
    ConnectionUpdateEventV4 = 5,
    ConnectionUpdateEventV6 = 6,
    ConnectionUpdateEnd = 7,
}

// Fallow this pattern when adding new packets: [InfoType: u8, data_size_in_bytes: u32, data: ...]

/// The bytes in front of every event's data: the InfoType (u8) and the data size (u32).
pub const HEADER_SIZE: usize = 5;

/// Where an event is serialized to: a `Vec` that grows to fit it, or a `Writer` over a fixed
/// buffer.
pub trait Sink {
    fn put(&mut self, bytes: &[u8]);
    fn put_zeros(&mut self, count: usize);
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    fn put_zeros(&mut self, count: usize) {
        self.resize(self.len() + count, 0);
    }
}

/// Serializes an event into a fixed buffer, without allocating. The first `skip` bytes of the
/// event are left out (an earlier read sent them), and so is whatever does not fit in the buffer,
/// so an event too big for one read is sent across several.
pub struct Writer<'a> {
    buffer: &'a mut [u8],
    /// Bytes written into `buffer`. Never more than its length.
    written: usize,
    /// Bytes of the event still to leave out before writing starts.
    skip: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buffer: &'a mut [u8], skip: usize) -> Self {
        Self {
            buffer,
            written: 0,
            skip,
        }
    }

    /// The bytes written into the buffer.
    pub fn written(&self) -> usize {
        self.written
    }

    /// Leaves out what is still to skip of the next `count` bytes. Returns how many are left to
    /// write.
    fn skip(&mut self, count: usize) -> usize {
        let skipped = count.min(self.skip);
        self.skip -= skipped;
        count - skipped
    }

    /// Takes room for up to `count` more bytes, as much as the buffer has left.
    fn take(&mut self, count: usize) -> &mut [u8] {
        let start = self.written;
        self.written += count.min(self.buffer.len() - start);
        &mut self.buffer[start..self.written]
    }
}

impl Sink for Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        let left = self.skip(bytes.len());
        let bytes = &bytes[bytes.len() - left..];
        let room = self.take(left);
        let count = room.len();
        room.copy_from_slice(&bytes[..count]);
    }

    fn put_zeros(&mut self, count: usize) {
        let left = self.skip(count);
        self.take(left).fill(0);
    }
}

trait PushBytes {
    fn push(self, sink: &mut impl Sink);
}

impl PushBytes for u8 {
    fn push(self, sink: &mut impl Sink) {
        sink.put(&[self]);
    }
}

impl PushBytes for InfoType {
    fn push(self, sink: &mut impl Sink) {
        sink.put(&[self as u8]);
    }
}

impl PushBytes for u16 {
    fn push(self, sink: &mut impl Sink) {
        sink.put(&u16::to_le_bytes(self));
    }
}

impl PushBytes for u32 {
    fn push(self, sink: &mut impl Sink) {
        sink.put(&u32::to_le_bytes(self));
    }
}

impl PushBytes for u64 {
    fn push(self, sink: &mut impl Sink) {
        sink.put(&u64::to_le_bytes(self));
    }
}

impl PushBytes for [u8; 4] {
    fn push(self, sink: &mut impl Sink) {
        sink.put(&self);
    }
}

impl PushBytes for [u8; 16] {
    fn push(self, sink: &mut impl Sink) {
        sink.put(&self);
    }
}

impl PushBytes for &[u8] {
    fn push(self, sink: &mut impl Sink) {
        sink.put(self);
    }
}

macro_rules! push_bytes {
    ($sink:expr,$value:expr) => {
        PushBytes::push($value, $sink);
    };
}

/// A serialized event in a buffer of its own. Log lines are built this way; the other events are
/// plain structs that are serialized when they are read (see `Sink`).
pub struct Info(Vec<u8>);

impl Info {
    fn with_capacity(info_type: InfoType, capacity: usize) -> Self {
        let mut vec = Vec::with_capacity(capacity + HEADER_SIZE);
        push_bytes!(&mut vec, info_type);
        push_bytes!(&mut vec, 0 as u32);
        Self(vec)
    }

    #[cfg(test)]
    fn assert_size(&self) {
        let size = u32::from_le_bytes([self.0[1], self.0[2], self.0[3], self.0[4]]) as usize;
        assert_eq!(size, self.0.len() - HEADER_SIZE);
    }

    fn update_size(&mut self) {
        let size = (self.0.len() - HEADER_SIZE) as u32;
        self.0[1..5].copy_from_slice(&size.to_le_bytes());
    }

    pub fn as_bytes(&self) -> &[u8] {
        return self.0.as_slice();
    }

    /// The size of the serialized event, header included.
    pub fn serialized_size(&self) -> usize {
        self.0.len()
    }

    pub fn write(&self, sink: &mut impl Sink) {
        sink.put(&self.0);
    }
}

impl core::fmt::Write for Info {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        const MAX_CAPACITY: usize = 500;

        let space_left = self.0.capacity() - self.0.len();
        if s.len() > space_left {
            if self.0.capacity() < MAX_CAPACITY {
                self.0.reserve(MAX_CAPACITY);
            } else {
                return Ok(());
            }
        }

        self.0.extend_from_slice(s.as_bytes());
        self.update_size();
        Ok(())
    }
}

/// Declares the event for a new connection (or a packet of one), followed by the packet payload.
/// Only the payload length is stored: the payload itself is handed to `write`.
macro_rules! connection_info_event {
    ($(#[$attr:meta])* $name:ident = $info_type:expr, $ip:ty) => {
        $(#[$attr])*
        #[derive(Clone, Copy)]
        pub struct $name {
            pub id: u64,
            pub process_id: u64,
            pub direction: u8,
            pub protocol: u8,
            pub local_ip: $ip,
            pub remote_ip: $ip,
            pub local_port: u16,
            pub remote_port: u16,
            pub payload_layer: u8,
            pub payload_len: u32,
        }

        impl $name {
            /// The data size without the payload: every field, in the order `write` puts them.
            const FIXED_SIZE: usize = size_of::<u64>() // id
                + size_of::<u64>() // process_id
                + size_of::<u8>() // direction
                + size_of::<u8>() // protocol
                + size_of::<$ip>() // local_ip
                + size_of::<$ip>() // remote_ip
                + size_of::<u16>() // local_port
                + size_of::<u16>() // remote_port
                + size_of::<u8>() // payload_layer
                + size_of::<u32>(); // payload_len

            /// The size of the serialized event, header and payload included.
            pub const fn serialized_size(&self) -> usize {
                HEADER_SIZE + Self::FIXED_SIZE + self.payload_len as usize
            }

            /// Writes the event followed by `payload`. A `payload` that is not `payload_len` bytes
            /// long (the packet is gone) is written as zeros, so the stream keeps its framing.
            pub fn write(&self, sink: &mut impl Sink, payload: &[u8]) {
                let payload_len = self.payload_len as usize;
                push_bytes!(sink, $info_type);
                push_bytes!(sink, (Self::FIXED_SIZE + payload_len) as u32);
                push_bytes!(sink, self.id);
                push_bytes!(sink, self.process_id);
                push_bytes!(sink, self.direction);
                push_bytes!(sink, self.protocol);
                push_bytes!(sink, self.local_ip);
                push_bytes!(sink, self.remote_ip);
                push_bytes!(sink, self.local_port);
                push_bytes!(sink, self.remote_port);
                push_bytes!(sink, self.payload_layer);
                push_bytes!(sink, self.payload_len);
                if payload.len() == payload_len {
                    push_bytes!(sink, payload);
                } else {
                    sink.put_zeros(payload_len);
                }
            }

            /// The serialized event, in a buffer of its own.
            pub fn to_info(&self, payload: &[u8]) -> Info {
                let mut vec = Vec::with_capacity(self.serialized_size());
                self.write(&mut vec, payload);
                Info(vec)
            }
        }
    };
}

/// Declares an event with fixed-size data: a plain struct whose fields are serialized in
/// declaration order.
macro_rules! fixed_size_event {
    ($(#[$attr:meta])* $name:ident = $info_type:expr, { $($field:ident: $type:ty),* $(,)? }) => {
        $(#[$attr])*
        #[derive(Clone, Copy)]
        pub struct $name {
            $(pub $field: $type),*
        }

        impl $name {
            const DATA_SIZE: usize = 0 $(+ core::mem::size_of::<$type>())*;

            /// The size of the serialized event, header included.
            pub const fn serialized_size(&self) -> usize {
                HEADER_SIZE + Self::DATA_SIZE
            }

            pub fn write(&self, sink: &mut impl Sink) {
                push_bytes!(sink, $info_type);
                push_bytes!(sink, Self::DATA_SIZE as u32);
                $(push_bytes!(sink, self.$field);)*
            }

            /// The serialized event, in a buffer of its own.
            pub fn to_info(&self) -> Info {
                let mut vec = Vec::with_capacity(self.serialized_size());
                self.write(&mut vec);
                Info(vec)
            }
        }
    };
}

connection_info_event!(
    /// A new connection (IPv4), or a packet of one that waits for a verdict.
    ConnectionInfoV4 = InfoType::ConnectionIpv4, [u8; 4]
);

connection_info_event!(
    /// A new connection (IPv6), or a packet of one that waits for a verdict.
    ConnectionInfoV6 = InfoType::ConnectionIpv6, [u8; 16]
);

fixed_size_event!(
    /// A connection ended (IPv4), with its final counters.
    ConnectionEndV4 = InfoType::ConnectionEndEventV4, {
        process_id: u64,
        direction: u8,
        protocol: u8,
        local_ip: [u8; 4],
        remote_ip: [u8; 4],
        local_port: u16,
        remote_port: u16,
        rx_bytes: u64,
        rx_packets: u64,
        tx_bytes: u64,
        tx_packets: u64,
    }
);

fixed_size_event!(
    /// A connection ended (IPv6), with its final counters.
    ConnectionEndV6 = InfoType::ConnectionEndEventV6, {
        process_id: u64,
        direction: u8,
        protocol: u8,
        local_ip: [u8; 16],
        remote_ip: [u8; 16],
        local_port: u16,
        remote_port: u16,
        rx_bytes: u64,
        rx_packets: u64,
        tx_bytes: u64,
        tx_packets: u64,
    }
);

fixed_size_event!(
    /// The counters of a connection (IPv4), for GetConnectionsUpdate.
    ConnectionUpdateV4 = InfoType::ConnectionUpdateEventV4, {
        protocol: u8,
        local_ip: [u8; 4],
        remote_ip: [u8; 4],
        local_port: u16,
        remote_port: u16,
        rx_bytes: u64,
        rx_packets: u64,
        tx_bytes: u64,
        tx_packets: u64,
    }
);

fixed_size_event!(
    /// The counters of a connection (IPv6), for GetConnectionsUpdate.
    ConnectionUpdateV6 = InfoType::ConnectionUpdateEventV6, {
        protocol: u8,
        local_ip: [u8; 16],
        remote_ip: [u8; 16],
        local_port: u16,
        remote_port: u16,
        rx_bytes: u64,
        rx_packets: u64,
        tx_bytes: u64,
        tx_packets: u64,
    }
);

fixed_size_event!(
    /// Signals the end of connection updates. `timestamp` is the driver's clock when the update
    /// was taken; user space passes it back unchanged with the next GetConnectionsUpdate request.
    ConnectionUpdateEnd = InfoType::ConnectionUpdateEnd, {
        timestamp: u64,
    }
);

// connection_info_v4 creates an Info packet for a connection (IPv4).
pub fn connection_info_v4(
    id: u64,
    process_id: u64,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
    local_port: u16,
    remote_port: u16,
    payload_layer: u8,
    payload: &[u8],
) -> Info {
    ConnectionInfoV4 {
        id,
        process_id,
        direction,
        protocol,
        local_ip,
        remote_ip,
        local_port,
        remote_port,
        payload_layer,
        payload_len: payload.len() as u32,
    }
    .to_info(payload)
}

// connection_info_v6 creates an Info packet for a connection (IPv6).
pub fn connection_info_v6(
    id: u64,
    process_id: u64,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 16],
    remote_ip: [u8; 16],
    local_port: u16,
    remote_port: u16,
    payload_layer: u8,
    payload: &[u8],
) -> Info {
    ConnectionInfoV6 {
        id,
        process_id,
        direction,
        protocol,
        local_ip,
        remote_ip,
        local_port,
        remote_port,
        payload_layer,
        payload_len: payload.len() as u32,
    }
    .to_info(payload)
}

// connection_end_event_v4_info creates an Info packet for a connection end event (IPv4).
pub fn connection_end_event_v4_info(
    process_id: u64,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
    local_port: u16,
    remote_port: u16,
    rx_bytes: u64,
    rx_packets: u64,
    tx_bytes: u64,
    tx_packets: u64,
) -> Info {
    ConnectionEndV4 {
        process_id,
        direction,
        protocol,
        local_ip,
        remote_ip,
        local_port,
        remote_port,
        rx_bytes,
        rx_packets,
        tx_bytes,
        tx_packets,
    }
    .to_info()
}

// connection_end_event_v6_info creates an Info packet for a connection end event (IPv6).
pub fn connection_end_event_v6_info(
    process_id: u64,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 16],
    remote_ip: [u8; 16],
    local_port: u16,
    remote_port: u16,
    rx_bytes: u64,
    rx_packets: u64,
    tx_bytes: u64,
    tx_packets: u64,
) -> Info {
    ConnectionEndV6 {
        process_id,
        direction,
        protocol,
        local_ip,
        remote_ip,
        local_port,
        remote_port,
        rx_bytes,
        rx_packets,
        tx_bytes,
        tx_packets,
    }
    .to_info()
}

// connection_update_event_v4_info creates an Info packet for a connection update event (IPv4).
pub fn connection_update_event_v4_info(
    protocol: u8,
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
    local_port: u16,
    remote_port: u16,
    rx_bytes: u64,
    rx_packets: u64,
    tx_bytes: u64,
    tx_packets: u64,
) -> Info {
    ConnectionUpdateV4 {
        protocol,
        local_ip,
        remote_ip,
        local_port,
        remote_port,
        rx_bytes,
        rx_packets,
        tx_bytes,
        tx_packets,
    }
    .to_info()
}

// connection_update_event_v6_info creates an Info packet for a connection update event (IPv6).
pub fn connection_update_event_v6_info(
    protocol: u8,
    local_ip: [u8; 16],
    remote_ip: [u8; 16],
    local_port: u16,
    remote_port: u16,
    rx_bytes: u64,
    rx_packets: u64,
    tx_bytes: u64,
    tx_packets: u64,
) -> Info {
    ConnectionUpdateV6 {
        protocol,
        local_ip,
        remote_ip,
        local_port,
        remote_port,
        rx_bytes,
        rx_packets,
        tx_bytes,
        tx_packets,
    }
    .to_info()
}

// connection_update_end_info signals the end of connection updates. `timestamp` is the
// driver's clock when the update was taken; user space passes it back unchanged with the
// next GetConnectionsUpdate request.
pub fn connection_update_end_info(timestamp: u64) -> Info {
    ConnectionUpdateEnd { timestamp }.to_info()
}

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Severity {
    Trace = 1,
    Debug = 2,
    Info = 3,
    Warning = 4,
    Error = 5,
    Critical = 6,
    Disabled = 7,
}

// log_line creates an Info packet for a log line.
pub fn log_line(severity: Severity, capacity: usize) -> Info {
    let mut info = Info::with_capacity(InfoType::LogLine, capacity);
    let vec = &mut info.0;
    push_bytes!(vec, severity as u8);
    info
}

/// A `Writer` that serializes an event in pieces, skipping what earlier pieces sent, produces the
/// same bytes as serializing it into a `Vec` in one go.
#[test]
fn writer_resumes_events() {
    let payload: Vec<u8> = (0..37).collect();
    let conn = ConnectionInfoV6 {
        id: 1,
        process_id: 2,
        direction: 1,
        protocol: 6,
        local_ip: [7; 16],
        remote_ip: [9; 16],
        local_port: 80,
        remote_port: 443,
        payload_layer: 3,
        payload_len: payload.len() as u32,
    };
    let end = ConnectionEndV4 {
        process_id: 2,
        direction: 0,
        protocol: 17,
        local_ip: [1, 2, 3, 4],
        remote_ip: [5, 6, 7, 8],
        local_port: 53,
        remote_port: 5353,
        rx_bytes: 10,
        rx_packets: 11,
        tx_bytes: 12,
        tx_packets: 13,
    };

    let cases: [(Vec<u8>, usize, &dyn Fn(&mut Writer)); 2] = [
        (conn.to_info(&payload).0, conn.serialized_size(), &|w| {
            conn.write(w, &payload)
        }),
        (end.to_info().0, end.serialized_size(), &|w| end.write(w)),
    ];
    for (expected, size, write) in cases {
        assert_eq!(expected.len(), size);
        for chunk in 1..=size + 1 {
            let mut out = Vec::new();
            while out.len() < size {
                let mut buffer = vec![0xAA; chunk];
                let mut writer = Writer::new(&mut buffer, out.len());
                write(&mut writer);
                let written = writer.written();
                assert!(written > 0);
                out.extend_from_slice(&buffer[..written]);
            }
            assert_eq!(out, expected, "chunk size {}", chunk);
        }
    }

    // A payload that is gone is sent as zeros of the announced length.
    let mut zeroed = Vec::new();
    conn.write(&mut zeroed, &[]);
    assert_eq!(zeroed.len(), conn.serialized_size());
    assert!(zeroed[conn.serialized_size() - payload.len()..]
        .iter()
        .all(|b| *b == 0));
}

#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::Write;

#[cfg(test)]
use rand::seq::SliceRandom;

#[test]
fn generate_test_info_file() -> Result<(), std::io::Error> {
    let mut file = File::create("rust_info_test.bin")?;
    let enums = [
        InfoType::LogLine,
        InfoType::ConnectionIpv4,
        InfoType::ConnectionIpv6,
        InfoType::ConnectionEndEventV4,
        InfoType::ConnectionEndEventV6,
        InfoType::ConnectionUpdateEventV4,
        InfoType::ConnectionUpdateEventV6,
        InfoType::ConnectionUpdateEnd,
    ];

    let mut selected: Vec<InfoType> = Vec::with_capacity(1000);
    let mut rng = rand::thread_rng();
    for _ in 0..selected.capacity() {
        selected.push(enums.choose(&mut rng).unwrap().clone());
    }

    for value in selected {
        file.write_all(&match value {
            InfoType::LogLine => {
                let mut info = log_line(Severity::Trace, 5);
                use std::fmt::Write;
                _ = write!(info, "prefix: test log");
                info.assert_size();
                info.0
            }
            InfoType::ConnectionIpv4 => {
                let info = connection_info_v4(
                    1,
                    2,
                    3,
                    4,
                    [1, 2, 3, 4],
                    [2, 3, 4, 5],
                    5,
                    6,
                    7,
                    &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                );
                info.assert_size();
                info.0
            }
            InfoType::ConnectionIpv6 => {
                let info = connection_info_v6(
                    1,
                    2,
                    3,
                    4,
                    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    5,
                    6,
                    7,
                    &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                );
                info.assert_size();
                info.0
            }
            InfoType::ConnectionEndEventV4 => {
                let info = connection_end_event_v4_info(
                    1,
                    2,
                    3,
                    [1, 2, 3, 4],
                    [2, 3, 4, 5],
                    4,
                    5,
                    6,
                    7,
                    8,
                    9,
                );
                info.assert_size();
                info.0
            }
            InfoType::ConnectionEndEventV6 => {
                let info = connection_end_event_v6_info(
                    1,
                    2,
                    3,
                    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    4,
                    5,
                    6,
                    7,
                    8,
                    9,
                );
                info.assert_size();
                info.0
            }
            InfoType::ConnectionUpdateEventV4 => {
                let info = connection_update_event_v4_info(
                    1,
                    [1, 2, 3, 4],
                    [2, 3, 4, 5],
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                );
                info.assert_size();
                info.0
            }
            InfoType::ConnectionUpdateEventV6 => {
                let info = connection_update_event_v6_info(
                    1,
                    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                );
                info.assert_size();
                info.0
            }
            InfoType::ConnectionUpdateEnd => {
                let info = connection_update_end_info(1);
                info.assert_size();
                info.0
            }
        })?;
    }
    return Ok(());
}
