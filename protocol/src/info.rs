use alloc::vec::Vec;
use zerocopy::{Immutable, IntoBytes};

// Every message is sent on the wire as a frame:
//
//     [kind: u8][len: u32 LE][body ...]
//
// `body` is the packed bytes of one of the structs below. The two new-connection
// variants append `[payload_len: u32 LE][payload ...]` after their fixed header.
//
// The structs are `#[repr(C, packed)]` and serialized via zerocopy's `as_bytes`,
// which copies their in-memory representation verbatim. This is only equivalent to
// the little-endian wire format because the driver is amd64-only (little-endian);
// see the project README.

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

/// Fixed header of a new-connection event (IPv4). The captured packet payload is
/// appended after this struct on the wire.
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy)]
pub struct ConnectionV4 {
    pub id: u64,
    pub process_id: u64,
    pub direction: u8,
    pub protocol: u8,
    pub local_ip: [u8; 4],
    pub remote_ip: [u8; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub payload_layer: u8,
}

/// Fixed header of a new-connection event (IPv6). The captured packet payload is
/// appended after this struct on the wire.
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy)]
pub struct ConnectionV6 {
    pub id: u64,
    pub process_id: u64,
    pub direction: u8,
    pub protocol: u8,
    pub local_ip: [u8; 16],
    pub remote_ip: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
    pub payload_layer: u8,
}

/// Connection-ended event (IPv4) carrying final byte/packet counters.
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy)]
pub struct ConnectionEndV4 {
    pub process_id: u64,
    pub direction: u8,
    pub protocol: u8,
    pub local_ip: [u8; 4],
    pub remote_ip: [u8; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

/// Connection-ended event (IPv6) carrying final byte/packet counters.
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy)]
pub struct ConnectionEndV6 {
    pub process_id: u64,
    pub direction: u8,
    pub protocol: u8,
    pub local_ip: [u8; 16],
    pub remote_ip: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

/// Periodic bandwidth update for a tracked connection (IPv4).
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy)]
pub struct ConnectionUpdateV4 {
    pub protocol: u8,
    pub local_ip: [u8; 4],
    pub remote_ip: [u8; 4],
    pub local_port: u16,
    pub remote_port: u16,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

/// Periodic bandwidth update for a tracked connection (IPv6).
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy)]
pub struct ConnectionUpdateV6 {
    pub protocol: u8,
    pub local_ip: [u8; 16],
    pub remote_ip: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
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

/// A framed, ready-to-send message: the `[kind][len][body]` bytes.
pub struct Info(Vec<u8>);

impl Info {
    /// Writes the `[kind][len]` frame header followed by `body`.
    fn framed(info_type: InfoType, body: &[u8]) -> Self {
        let mut vec = Vec::with_capacity(5 + body.len());
        vec.push(info_type as u8);
        vec.extend_from_slice(&(body.len() as u32).to_le_bytes());
        vec.extend_from_slice(body);
        Self(vec)
    }

    /// Recomputes the `len` field from the current body length. Used while a log
    /// line's text is streamed in via [`core::fmt::Write`].
    fn update_size(&mut self) {
        let size = (self.0.len() - 5) as u32;
        self.0[1..5].copy_from_slice(&size.to_le_bytes());
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[cfg(test)]
    fn assert_size(&self) {
        let size = u32::from_le_bytes([self.0[1], self.0[2], self.0[3], self.0[4]]) as usize;
        assert_eq!(size, self.0.len() - 5);
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

/// Frames a fixed-size event struct.
fn frame<T: IntoBytes + Immutable>(info_type: InfoType, event: &T) -> Info {
    Info::framed(info_type, event.as_bytes())
}

/// Frames a connection event whose fixed `header` is followed by a variable
/// `payload`. Body layout: `[header][payload_len: u32 LE][payload]`.
fn frame_connection<T: IntoBytes + Immutable>(
    info_type: InfoType,
    header: &T,
    payload: &[u8],
) -> Info {
    let header = header.as_bytes();
    let body_len = header.len() + 4 + payload.len();
    let mut vec = Vec::with_capacity(5 + body_len);
    vec.push(info_type as u8);
    vec.extend_from_slice(&(body_len as u32).to_le_bytes());
    vec.extend_from_slice(header);
    vec.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    vec.extend_from_slice(payload);
    Info(vec)
}

pub fn connection_v4(conn: ConnectionV4, payload: &[u8]) -> Info {
    frame_connection(InfoType::ConnectionIpv4, &conn, payload)
}

pub fn connection_v6(conn: ConnectionV6, payload: &[u8]) -> Info {
    frame_connection(InfoType::ConnectionIpv6, &conn, payload)
}

pub fn connection_end_v4(event: ConnectionEndV4) -> Info {
    frame(InfoType::ConnectionEndEventV4, &event)
}

pub fn connection_end_v6(event: ConnectionEndV6) -> Info {
    frame(InfoType::ConnectionEndEventV6, &event)
}

pub fn connection_update_v4(event: ConnectionUpdateV4) -> Info {
    frame(InfoType::ConnectionUpdateEventV4, &event)
}

pub fn connection_update_v6(event: ConnectionUpdateV6) -> Info {
    frame(InfoType::ConnectionUpdateEventV6, &event)
}

/// Signals the end of a batch of connection updates.
pub fn connection_update_end() -> Info {
    Info::framed(InfoType::ConnectionUpdateEnd, &[])
}

/// Starts a log-line message. The text is appended via [`core::fmt::Write`].
pub fn log_line(severity: Severity, capacity: usize) -> Info {
    // Body is `[severity: u8][text ...]`; the text is streamed in afterwards.
    let mut vec = Vec::with_capacity(5 + 1 + capacity);
    vec.push(InfoType::LogLine as u8);
    vec.extend_from_slice(&0u32.to_le_bytes()); // len, patched as text is written
    vec.push(severity as u8);
    let mut info = Info(vec);
    info.update_size();
    info
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
                let info = connection_v4(
                    ConnectionV4 {
                        id: 1,
                        process_id: 2,
                        direction: 3,
                        protocol: 4,
                        local_ip: [1, 2, 3, 4],
                        remote_ip: [2, 3, 4, 5],
                        local_port: 5,
                        remote_port: 6,
                        payload_layer: 7,
                    },
                    &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                );
                info.assert_size();
                info.0
            }
            InfoType::ConnectionIpv6 => {
                let info = connection_v6(
                    ConnectionV6 {
                        id: 1,
                        process_id: 2,
                        direction: 3,
                        protocol: 4,
                        local_ip: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                        remote_ip: [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                        local_port: 5,
                        remote_port: 6,
                        payload_layer: 7,
                    },
                    &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                );
                info.assert_size();
                info.0
            }
            InfoType::ConnectionEndEventV4 => {
                let info = connection_end_v4(ConnectionEndV4 {
                    process_id: 1,
                    direction: 2,
                    protocol: 3,
                    local_ip: [1, 2, 3, 4],
                    remote_ip: [2, 3, 4, 5],
                    local_port: 4,
                    remote_port: 5,
                    rx_bytes: 6,
                    rx_packets: 7,
                    tx_bytes: 8,
                    tx_packets: 9,
                });
                info.assert_size();
                info.0
            }
            InfoType::ConnectionEndEventV6 => {
                let info = connection_end_v6(ConnectionEndV6 {
                    process_id: 1,
                    direction: 2,
                    protocol: 3,
                    local_ip: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    remote_ip: [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    local_port: 4,
                    remote_port: 5,
                    rx_bytes: 6,
                    rx_packets: 7,
                    tx_bytes: 8,
                    tx_packets: 9,
                });
                info.assert_size();
                info.0
            }
            InfoType::ConnectionUpdateEventV4 => {
                let info = connection_update_v4(ConnectionUpdateV4 {
                    protocol: 1,
                    local_ip: [1, 2, 3, 4],
                    remote_ip: [2, 3, 4, 5],
                    local_port: 2,
                    remote_port: 3,
                    rx_bytes: 4,
                    rx_packets: 5,
                    tx_bytes: 6,
                    tx_packets: 7,
                });
                info.assert_size();
                info.0
            }
            InfoType::ConnectionUpdateEventV6 => {
                let info = connection_update_v6(ConnectionUpdateV6 {
                    protocol: 1,
                    local_ip: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    remote_ip: [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    local_port: 2,
                    remote_port: 3,
                    rx_bytes: 4,
                    rx_packets: 5,
                    tx_bytes: 6,
                    tx_packets: 7,
                });
                info.assert_size();
                info.0
            }
            InfoType::ConnectionUpdateEnd => {
                let info = connection_update_end();
                info.assert_size();
                info.0
            }
        })?;
    }
    return Ok(());
}
