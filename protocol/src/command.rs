// Commands from user space

use num::FromPrimitive;
use num_derive::FromPrimitive;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

#[repr(u8)]
#[derive(Clone, Copy, FromPrimitive)]
#[rustfmt::skip]
pub enum CommandType {
    Shutdown              = 0,
    Verdict               = 1,
    UpdateV4              = 2,
    UpdateV6              = 3,
    ClearCache            = 4,
    GetConnectionsUpdate  = 5,
    GetLogs               = 6,
    PrintMemoryStats      = 7,
    CleanEndedConnections = 8,
}

#[repr(C, packed)]
pub struct Command {
    pub command_type: CommandType,
    value: [u8; 0],
}

#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct Verdict {
    pub id: u64,
    pub verdict: u8,
}

#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct UpdateV4 {
    pub protocol: u8,
    pub local_address: [u8; 4],
    pub local_port: u16,
    pub remote_address: [u8; 4],
    pub remote_port: u16,
    pub verdict: u8,
}

#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct UpdateV6 {
    pub protocol: u8,
    pub local_address: [u8; 16],
    pub local_port: u16,
    pub remote_address: [u8; 16],
    pub remote_port: u16,
    pub verdict: u8,
}

#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct ConnectionsUpdate {
    pub timestamp: u64,
}

pub fn parse_type(bytes: &[u8]) -> Option<CommandType> {
    FromPrimitive::from_u8(bytes[0])
}

pub fn parse_verdict(bytes: &[u8]) -> Option<&Verdict> {
    Verdict::ref_from_prefix(bytes).ok().map(|(value, _)| value)
}

pub fn parse_update_v4(bytes: &[u8]) -> Option<&UpdateV4> {
    UpdateV4::ref_from_prefix(bytes).ok().map(|(value, _)| value)
}

pub fn parse_update_v6(bytes: &[u8]) -> Option<&UpdateV6> {
    UpdateV6::ref_from_prefix(bytes).ok().map(|(value, _)| value)
}

pub fn parse_update_info(bytes: &[u8]) -> Option<&ConnectionsUpdate> {
    ConnectionsUpdate::ref_from_prefix(bytes)
        .ok()
        .map(|(value, _)| value)
}

#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::Read;
#[cfg(test)]
use std::mem::size_of;
#[cfg(test)]
use std::panic;

#[test]
fn test_go_command_file() {
    let mut file = File::open("../kext_interface/go_command_test.bin").unwrap();
    loop {
        let mut command: [u8; 1] = [0];
        let bytes_count = file.read(&mut command).unwrap();
        if bytes_count == 0 {
            return;
        }
        if let Some(command) = parse_type(&command) {
            match command {
                CommandType::Shutdown => {}
                CommandType::Verdict => {
                    let mut buf = [0; size_of::<Verdict>()];
                    let bytes_count = file.read(&mut buf).unwrap();
                    if bytes_count != size_of::<Verdict>() {
                        panic!("unexpected bytes count")
                    }

                    assert_eq!(parse_verdict(&buf).unwrap(), &Verdict { id: 1, verdict: 2 })
                }
                CommandType::UpdateV4 => {
                    let mut buf = [0; size_of::<UpdateV4>()];
                    let bytes_count = file.read(&mut buf).unwrap();
                    if bytes_count != size_of::<UpdateV4>() {
                        panic!("unexpected bytes count")
                    }

                    assert_eq!(
                        parse_update_v4(&buf).unwrap(),
                        &UpdateV4 {
                            protocol: 1,
                            local_address: [1, 2, 3, 4],
                            local_port: 2,
                            remote_address: [2, 3, 4, 5],
                            remote_port: 3,
                            verdict: 4
                        }
                    )
                }
                CommandType::UpdateV6 => {
                    let mut buf = [0; size_of::<UpdateV6>()];
                    let bytes_count = file.read(&mut buf).unwrap();
                    if bytes_count != size_of::<UpdateV6>() {
                        panic!("unexpected bytes count")
                    }

                    assert_eq!(
                        parse_update_v6(&buf).unwrap(),
                        &UpdateV6 {
                            protocol: 1,
                            local_address: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                            local_port: 2,
                            remote_address: [
                                2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
                            ],
                            remote_port: 3,
                            verdict: 4
                        }
                    )
                }
                CommandType::ClearCache => {}
                CommandType::GetLogs => {}
                CommandType::PrintMemoryStats => {}
                CommandType::CleanEndedConnections => {}
                CommandType::GetConnectionsUpdate => {
                    let mut buf = [0; size_of::<ConnectionsUpdate>()];
                    let bytes_count = file.read(&mut buf).unwrap();
                    if bytes_count != size_of::<ConnectionsUpdate>() {
                        panic!("unexpected bytes count")
                    }

                    assert_eq!(
                        parse_update_info(&buf).unwrap(),
                        &ConnectionsUpdate {
                            timestamp: 1234567890
                        }
                    )
                }
            }
        } else {
            panic!("Unknown command: {}", command[0]);
        }
    }
}
