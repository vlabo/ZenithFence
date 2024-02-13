use core::mem::size_of;

use alloc::string::String;
use alloc::vec::Vec;

#[repr(u8)]
#[derive(Clone, Copy)]
enum InfoType {
    LogLine = 0,
    ConnectionIpv4 = 1,
    ConnectionIpv6 = 2,
    ConnectionEndEventV4 = 3,
    ConnectionEndEventV6 = 4,
    BandwidthStatsV4 = 5,
    BandwidthStatsV6 = 6,
}

pub trait Info {
    fn as_bytes(&mut self) -> &[u8];
}
// Fallow this pattern when adding new structs
#[repr(C, packed)]
pub struct ConnectionInfoV4 {
    info_type: InfoType,
    id: u64,
    process_id: u64,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
    local_port: u16,
    remote_port: u16,
}

impl ConnectionInfoV4 {
    pub fn new(
        id: u64,
        process_id: u64,
        direction: u8,
        protocol: u8,
        local_ip: [u8; 4],
        remote_ip: [u8; 4],
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        Self {
            info_type: InfoType::ConnectionIpv4,
            id,
            process_id,
            direction,
            protocol,
            local_ip,
            remote_ip,
            local_port,
            remote_port,
        }
    }
}

impl Info for ConnectionInfoV4 {
    fn as_bytes(&mut self) -> &[u8] {
        as_bytes(self)
    }
}

#[repr(C, packed)]
pub struct ConnectionInfoV6 {
    info_type: InfoType,
    id: u64,
    process_id: u64,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 16],
    remote_ip: [u8; 16],
    local_port: u16,
    remote_port: u16,
}

impl ConnectionInfoV6 {
    pub fn new(
        id: u64,
        process_id: u64,
        direction: u8,
        protocol: u8,
        local_ip: [u8; 16],
        remote_ip: [u8; 16],
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        Self {
            info_type: InfoType::ConnectionIpv6,
            id,
            process_id,
            direction,
            protocol,
            local_ip,
            remote_ip,
            local_port,
            remote_port,
        }
    }
}

impl Info for ConnectionInfoV6 {
    fn as_bytes(&mut self) -> &[u8] {
        as_bytes(self)
    }
}

#[repr(C, packed)]
pub struct ConnectionEndEventV4Info {
    info_type: InfoType,
    process_id: u64,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 4],
    remote_ip: [u8; 4],
    local_port: u16,
    remote_port: u16,
}

impl ConnectionEndEventV4Info {
    pub fn new(
        process_id: u64,
        direction: u8,
        protocol: u8,
        local_ip: [u8; 4],
        remote_ip: [u8; 4],
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        Self {
            info_type: InfoType::ConnectionEndEventV4,
            process_id,
            direction,
            protocol,
            local_ip,
            remote_ip,
            local_port,
            remote_port,
        }
    }
}

impl Info for ConnectionEndEventV4Info {
    fn as_bytes(&mut self) -> &[u8] {
        as_bytes(self)
    }
}
#[repr(C, packed)]
pub struct ConnectionEndEventV6Info {
    info_type: InfoType,
    process_id: u64,
    direction: u8,
    protocol: u8,
    local_ip: [u8; 16],
    remote_ip: [u8; 16],
    local_port: u16,
    remote_port: u16,
}

impl ConnectionEndEventV6Info {
    pub fn new(
        process_id: u64,
        direction: u8,
        protocol: u8,
        local_ip: [u8; 16],
        remote_ip: [u8; 16],
        local_port: u16,
        remote_port: u16,
    ) -> Self {
        Self {
            info_type: InfoType::ConnectionEndEventV6,
            process_id,
            direction,
            protocol,
            local_ip,
            remote_ip,
            local_port,
            remote_port,
        }
    }
}

impl Info for ConnectionEndEventV6Info {
    fn as_bytes(&mut self) -> &[u8] {
        as_bytes(self)
    }
}

fn as_bytes<T>(value: &T) -> &[u8] {
    let info_ptr: *const T = value as _;
    let ptr: *const u8 = info_ptr as _;
    unsafe { core::slice::from_raw_parts(ptr, core::mem::size_of::<T>()) }
}

// Special struct for logging
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Severity {
    Trace = 1,
    Debug = 2,
    Info = 3,
    Warning = 4,
    Error = 5,
    Critical = 6,
}

pub struct LogLine {
    severity: Severity,
    prefix: String,
    line: String,
    combined: Vec<u8>,
}

impl LogLine {
    pub fn new(severity: Severity, prefix: String, line: String) -> Self {
        Self {
            severity,
            prefix,
            line,
            combined: Vec::new(),
        }
    }
}

impl Info for LogLine {
    fn as_bytes(&mut self) -> &[u8] {
        // Write [InfoType: u8, Severity: u8, size: u32, prefix+line: [u8; size]]
        let size: u32 = (self.prefix.len() + self.line.len()) as u32;
        self.combined = Vec::with_capacity(1 + 1 + size_of::<u32>() + size as usize);
        self.combined.push(InfoType::LogLine as u8);
        self.combined.push(self.severity as u8);
        self.combined.extend_from_slice(&u32::to_le_bytes(size));
        self.combined.extend_from_slice(self.prefix.as_bytes());
        self.combined.extend_from_slice(self.line.as_bytes());

        return &self.combined;
    }
}

// Special struct for Bandwidth stats
#[repr(C, packed)]
pub struct BandwidthValueV4 {
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub remote_ip: [u8; 4],
    pub remote_port: u16,
    pub transmitted_bytes: u64,
    pub received_bytes: u64,
}

#[repr(C, packed)]
pub struct BandwidthValueV6 {
    pub local_ip: [u8; 16],
    pub local_port: u16,
    pub remote_ip: [u8; 16],
    pub remote_port: u16,
    pub transmitted_bytes: u64,
    pub received_bytes: u64,
}

pub struct BandwidthStatArray<Value> {
    info_type: InfoType,
    protocol: u8,
    array: Vec<Value>,
    bytes: Vec<u8>,
}

impl BandwidthStatArray<BandwidthValueV4> {
    pub fn new_v4(size: usize, protocol: u8) -> Self {
        Self {
            info_type: InfoType::BandwidthStatsV4,
            protocol,
            array: Vec::with_capacity(size),
            bytes: Vec::new(),
        }
    }
}
impl BandwidthStatArray<BandwidthValueV6> {
    pub fn new_v6(size: usize, protocol: u8) -> Self {
        Self {
            info_type: InfoType::BandwidthStatsV6,
            protocol,
            array: Vec::with_capacity(size),
            bytes: Vec::new(),
        }
    }
}
impl<Value> BandwidthStatArray<Value> {
    pub fn push_value(&mut self, value: Value) {
        self.array.push(value);
    }
}

impl<Value> Info for BandwidthStatArray<Value> {
    fn as_bytes(&mut self) -> &[u8] {
        // Write [InfoType: u8, protocol: u8, ArraySize: u64, stats_array: [BandwidthValueTcpV4; ArraySize]]
        self.bytes
            .reserve(1 + 1 + size_of::<u64>() + self.array.len() * size_of::<Value>());

        self.bytes.push(self.info_type as u8);
        self.bytes.push(self.protocol as u8);

        let size: u64 = self.array.len() as _;
        self.bytes.extend_from_slice(&size.to_ne_bytes());

        for value in &self.array {
            self.bytes.extend_from_slice(as_bytes(value));
        }
        return &self.bytes;
    }
}

#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::Write;

#[test]
fn generate_test_info_file() -> Result<(), std::io::Error> {
    let mut file = File::create("rust_info_test.bin")?;
    let enums = [
        InfoType::LogLine,
        InfoType::ConnectionIpv4,
        InfoType::ConnectionIpv6,
        InfoType::ConnectionEndEventV4,
        InfoType::ConnectionEndEventV6,
        InfoType::BandwidthStatsV4,
        InfoType::BandwidthStatsV6,
    ];
    for value in enums {
        file.write_all(&match value {
            InfoType::LogLine => LogLine::new(
                Severity::Trace,
                "prefix: ".to_string(),
                "test log".to_string(),
            )
            .as_bytes()
            .to_vec(),
            InfoType::ConnectionIpv4 => {
                ConnectionInfoV4::new(1, 2, 3, 4, [1, 2, 3, 4], [2, 3, 4, 5], 5, 6)
                    .as_bytes()
                    .to_vec()
            }

            InfoType::ConnectionIpv6 => ConnectionInfoV6::new(
                1,
                2,
                3,
                4,
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                5,
                6,
            )
            .as_bytes()
            .to_vec(),
            InfoType::ConnectionEndEventV4 => {
                ConnectionEndEventV4Info::new(1, 2, 3, [1, 2, 3, 4], [2, 3, 4, 5], 4, 5)
                    .as_bytes()
                    .to_vec()
            }
            InfoType::ConnectionEndEventV6 => ConnectionEndEventV6Info::new(
                1,
                2,
                3,
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                4,
                5,
            )
            .as_bytes()
            .to_vec(),
            InfoType::BandwidthStatsV4 => {
                let mut info = BandwidthStatArray::new_v4(2, 1);
                info.push_value(BandwidthValueV4 {
                    local_ip: [1, 2, 3, 4],
                    local_port: 1,
                    remote_ip: [2, 3, 4, 5],
                    remote_port: 2,
                    transmitted_bytes: 3,
                    received_bytes: 4,
                });
                info.push_value(BandwidthValueV4 {
                    local_ip: [1, 2, 3, 4],
                    local_port: 5,
                    remote_ip: [2, 3, 4, 5],
                    remote_port: 6,
                    transmitted_bytes: 7,
                    received_bytes: 8,
                });
                info.as_bytes().to_vec()
            }
            InfoType::BandwidthStatsV6 => {
                let mut info = BandwidthStatArray::new_v6(2, 1);
                info.push_value(BandwidthValueV6 {
                    local_ip: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    local_port: 1,
                    remote_ip: [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    remote_port: 2,
                    transmitted_bytes: 3,
                    received_bytes: 4,
                });
                info.push_value(BandwidthValueV6 {
                    local_ip: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                    local_port: 5,
                    remote_ip: [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                    remote_port: 6,
                    transmitted_bytes: 7,
                    received_bytes: 8,
                });
                info.as_bytes().to_vec()
            }
        })?;
    }
    return Ok(());
}
