// Commands from user space

use num::FromPrimitive;
use num_derive::FromPrimitive;

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
#[derive(Debug, PartialEq, Eq)]
pub struct Verdict {
    pub id: u64,
    pub verdict: u8,
}

#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq)]
pub struct UpdateV4 {
    pub protocol: u8,
    pub local_address: [u8; 4],
    pub local_port: u16,
    pub remote_address: [u8; 4],
    pub remote_port: u16,
    pub verdict: u8,
}

#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq)]
pub struct UpdateV6 {
    pub protocol: u8,
    pub local_address: [u8; 16],
    pub local_port: u16,
    pub remote_address: [u8; 16],
    pub remote_port: u16,
    pub verdict: u8,
}

#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq)]
pub struct ConnectionsUpdate {
    pub timestamp: u64,
}

pub fn parse_type(bytes: &[u8]) -> Option<CommandType> {
    // Bounds-checked: an empty command buffer yields `None` instead of panicking
    // on `bytes[0]`.
    FromPrimitive::from_u8(*bytes.first()?)
}

pub fn parse_verdict(bytes: &[u8]) -> Option<&Verdict> {
    as_type(bytes)
}

pub fn parse_update_v4(bytes: &[u8]) -> Option<&UpdateV4> {
    as_type(bytes)
}

pub fn parse_update_v6(bytes: &[u8]) -> Option<&UpdateV6> {
    as_type(bytes)
}

pub fn parse_update_info(bytes: &[u8]) -> Option<&ConnectionsUpdate> {
    as_type(bytes)
}

/// Reinterpret the start of `bytes` as a `T`.
///
/// Returns `None` unless the buffer holds at least `size_of::<T>()` bytes, so a
/// short/truncated command from user space can never cause an out-of-bounds
/// read. The command structs are `#[repr(C, packed)]` (alignment 1), so the
/// cast is always correctly aligned.
fn as_type<T>(bytes: &[u8]) -> Option<&T> {
    if bytes.len() < core::mem::size_of::<T>() {
        return None;
    }
    let t_ptr: *const T = bytes.as_ptr() as *const T;
    unsafe { t_ptr.as_ref() }
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

                    assert_eq!(parse_verdict(&buf), Some(&Verdict { id: 1, verdict: 2 }))
                }
                CommandType::UpdateV4 => {
                    let mut buf = [0; size_of::<UpdateV4>()];
                    let bytes_count = file.read(&mut buf).unwrap();
                    if bytes_count != size_of::<UpdateV4>() {
                        panic!("unexpected bytes count")
                    }

                    assert_eq!(
                        parse_update_v4(&buf),
                        Some(&UpdateV4 {
                            protocol: 1,
                            local_address: [1, 2, 3, 4],
                            local_port: 2,
                            remote_address: [2, 3, 4, 5],
                            remote_port: 3,
                            verdict: 4
                        })
                    )
                }
                CommandType::UpdateV6 => {
                    let mut buf = [0; size_of::<UpdateV6>()];
                    let bytes_count = file.read(&mut buf).unwrap();
                    if bytes_count != size_of::<UpdateV6>() {
                        panic!("unexpected bytes count")
                    }

                    assert_eq!(
                        parse_update_v6(&buf),
                        Some(&UpdateV6 {
                            protocol: 1,
                            local_address: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                            local_port: 2,
                            remote_address: [
                                2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
                            ],
                            remote_port: 3,
                            verdict: 4
                        })
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
                        parse_update_info(&buf),
                        Some(&ConnectionsUpdate {
                            timestamp: 1234567890
                        })
                    )
                }
            }
        } else {
            panic!("Unknown command: {}", command[0]);
        }
    }
}

// Regression tests for the bounds-checking fixes. Before the fix, `parse_type`
// panicked on an empty buffer (`bytes[0]`) and `as_type` read `size_of::<T>()`
// bytes out of bounds for a short buffer (UB). These lock the fixes in place.
#[cfg(test)]
mod bounds_tests {
    use super::*;

    #[test]
    fn parse_type_empty_is_none() {
        assert!(parse_type(&[]).is_none());
    }

    #[test]
    fn parse_type_valid_and_unknown() {
        assert!(matches!(parse_type(&[1]), Some(CommandType::Verdict)));
        assert!(parse_type(&[200]).is_none());
    }

    #[test]
    fn parse_verdict_short_is_none() {
        for n in 0..core::mem::size_of::<Verdict>() {
            assert!(parse_verdict(&vec![0u8; n]).is_none(), "len {n} must be None");
        }
        assert!(parse_verdict(&vec![0u8; core::mem::size_of::<Verdict>()]).is_some());
    }

    #[test]
    fn parse_update_v4_short_is_none() {
        for n in 0..core::mem::size_of::<UpdateV4>() {
            assert!(parse_update_v4(&vec![0u8; n]).is_none(), "len {n} must be None");
        }
        assert!(parse_update_v4(&vec![0u8; core::mem::size_of::<UpdateV4>()]).is_some());
    }

    #[test]
    fn parse_update_v6_short_is_none() {
        for n in 0..core::mem::size_of::<UpdateV6>() {
            assert!(parse_update_v6(&vec![0u8; n]).is_none(), "len {n} must be None");
        }
        assert!(parse_update_v6(&vec![0u8; core::mem::size_of::<UpdateV6>()]).is_some());
    }

    #[test]
    fn parse_update_info_short_is_none() {
        for n in 0..core::mem::size_of::<ConnectionsUpdate>() {
            assert!(parse_update_info(&vec![0u8; n]).is_none(), "len {n} must be None");
        }
        assert!(parse_update_info(&vec![0u8; core::mem::size_of::<ConnectionsUpdate>()]).is_some());
    }
}
