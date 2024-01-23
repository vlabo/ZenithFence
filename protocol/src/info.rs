use core::mem::size_of;

use alloc::string::String;
use alloc::vec::Vec;
#[repr(u8)]
#[derive(Clone, Copy)]
enum InfoType {
    ConnectionIpv4 = 0,
    LogLine = 1,
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
