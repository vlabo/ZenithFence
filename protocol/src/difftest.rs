//! Deterministic Rust <-> Go differential tests of the user/kernel wire format.
//!
//! Every record's field values are derived from its index by [`diff_mix`] (a
//! splitmix64-style hash implemented identically here and in
//! `kext_interface/diff_test.go`). No shared RNG is needed: both languages
//! compute the same expected values from the record position, so any divergence
//! in encoding/decoding (endianness, field order, type width, struct size)
//! surfaces immediately as a mismatch.
//!
//! Two files cross the language boundary:
//!   * commands  Go writes `go_command_diff.bin` -> Rust reads (`test_go_command_diff`)
//!   * info      Rust writes `info_diff.bin`      -> Go reads (`TestInfoDiffFile`)
//!
//! KEEP THE FORMULAS BELOW IN SYNC WITH kext_interface/diff_test.go.

use std::fs::File;
use std::io::{Read, Write};

use crate::command::{
    parse_type, parse_update_info, parse_update_v4, parse_update_v6, parse_verdict, CommandType,
    ConnectionsUpdate, UpdateV4, UpdateV6, Verdict,
};
use crate::info::{
    connection_end_event_v4_info, connection_end_event_v6_info, connection_info_v4,
    connection_info_v6, connection_update_event_v4_info, connection_update_event_v6_info,
};

const COMMAND_DIFF_FILE: &str = "../kext_interface/go_command_diff.bin";
const INFO_DIFF_FILE: &str = "info_diff.bin";
const INFO_RECORDS: u32 = 6000;

/// splitmix64-style per-(record, field) value. MUST match `diffMix` in
/// kext_interface/diff_test.go. All arithmetic wraps (matches Go's uint64).
pub(crate) fn diff_mix(i: u32, f: u32) -> u64 {
    let mut x = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ (f as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    x ^= x >> 29;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 32;
    x
}

fn b4(i: u32, f: u32) -> [u8; 4] {
    let m = diff_mix(i, f).to_le_bytes();
    [m[0], m[1], m[2], m[3]]
}

fn b16(i: u32, f: u32) -> [u8; 16] {
    let a = diff_mix(i, f).to_le_bytes();
    let b = diff_mix(i, f + 0x1000).to_le_bytes();
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&a);
    out[8..].copy_from_slice(&b);
    out
}

fn verdict_val(i: u32, f: u32) -> u8 {
    (diff_mix(i, f) % 11) as u8
}

fn diff_payload(i: u32) -> Vec<u8> {
    let len = (diff_mix(i, 9) % 17) as usize;
    (0..len).map(|j| diff_mix(i, 100 + j as u32) as u8).collect()
}

/// Rust writes random-valued Info packets; the Go side reads them back and
/// verifies every field against the same `diff_mix` formula (`TestInfoDiffFile`).
#[test]
fn generate_info_diff_file() {
    let mut file = File::create(INFO_DIFF_FILE).expect("create info_diff.bin");
    for i in 0..INFO_RECORDS {
        let info = match i % 6 {
            0 => connection_end_event_v4_info(
                diff_mix(i, 0),
                diff_mix(i, 1) as u8,
                diff_mix(i, 2) as u8,
                b4(i, 3),
                b4(i, 4),
                diff_mix(i, 5) as u16,
                diff_mix(i, 6) as u16,
                diff_mix(i, 7),
                diff_mix(i, 8),
                diff_mix(i, 9),
                diff_mix(i, 10),
            ),
            1 => connection_end_event_v6_info(
                diff_mix(i, 0),
                diff_mix(i, 1) as u8,
                diff_mix(i, 2) as u8,
                b16(i, 3),
                b16(i, 4),
                diff_mix(i, 5) as u16,
                diff_mix(i, 6) as u16,
                diff_mix(i, 7),
                diff_mix(i, 8),
                diff_mix(i, 9),
                diff_mix(i, 10),
            ),
            2 => connection_update_event_v4_info(
                diff_mix(i, 0) as u8,
                b4(i, 1),
                b4(i, 2),
                diff_mix(i, 3) as u16,
                diff_mix(i, 4) as u16,
                diff_mix(i, 5),
                diff_mix(i, 6),
                diff_mix(i, 7),
                diff_mix(i, 8),
            ),
            3 => connection_update_event_v6_info(
                diff_mix(i, 0) as u8,
                b16(i, 1),
                b16(i, 2),
                diff_mix(i, 3) as u16,
                diff_mix(i, 4) as u16,
                diff_mix(i, 5),
                diff_mix(i, 6),
                diff_mix(i, 7),
                diff_mix(i, 8),
            ),
            4 => {
                let payload = diff_payload(i);
                connection_info_v4(
                    diff_mix(i, 0),
                    diff_mix(i, 1),
                    diff_mix(i, 2) as u8,
                    diff_mix(i, 3) as u8,
                    b4(i, 4),
                    b4(i, 5),
                    diff_mix(i, 6) as u16,
                    diff_mix(i, 7) as u16,
                    diff_mix(i, 8) as u8,
                    &payload,
                )
            }
            _ => {
                let payload = diff_payload(i);
                connection_info_v6(
                    diff_mix(i, 0),
                    diff_mix(i, 1),
                    diff_mix(i, 2) as u8,
                    diff_mix(i, 3) as u8,
                    b16(i, 4),
                    b16(i, 5),
                    diff_mix(i, 6) as u16,
                    diff_mix(i, 7) as u16,
                    diff_mix(i, 8) as u8,
                    &payload,
                )
            }
        };
        file.write_all(info.as_bytes()).expect("write info record");
    }
}

/// Go writes random-valued commands; Rust parses each and verifies every field
/// against the same `diff_mix` formula. Run the Go generator first
/// (`go test -run TestGenerateCommandDiff`).
#[test]
fn test_go_command_diff() {
    let mut file = File::open(COMMAND_DIFF_FILE).unwrap_or_else(|e| {
        panic!("open {COMMAND_DIFF_FILE}: {e} (run `go test -run TestGenerateCommandDiff` first)")
    });

    let field_cmds = [
        CommandType::Verdict as u8,
        CommandType::UpdateV4 as u8,
        CommandType::UpdateV6 as u8,
        CommandType::GetConnectionsUpdate as u8,
    ];

    let mut i: u32 = 0;
    loop {
        let mut cmd = [0u8; 1];
        match file.read(&mut cmd) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => panic!("record {i}: read command byte: {e}"),
        }
        let expected_type = field_cmds[(i as usize) % field_cmds.len()];
        assert_eq!(cmd[0], expected_type, "record {i}: command byte");

        match parse_type(&cmd).expect("valid command type") {
            CommandType::Verdict => {
                let mut buf = [0u8; core::mem::size_of::<Verdict>()];
                file.read_exact(&mut buf).unwrap();
                let v = parse_verdict(&buf).unwrap();
                let (id, verdict) = (v.id, v.verdict);
                assert_eq!(id, diff_mix(i, 0), "record {i}: verdict.id");
                assert_eq!(verdict, verdict_val(i, 1), "record {i}: verdict.verdict");
            }
            CommandType::UpdateV4 => {
                let mut buf = [0u8; core::mem::size_of::<UpdateV4>()];
                file.read_exact(&mut buf).unwrap();
                let u = parse_update_v4(&buf).unwrap();
                let (protocol, local, local_port, remote, remote_port, verdict) = (
                    u.protocol,
                    u.local_address,
                    u.local_port,
                    u.remote_address,
                    u.remote_port,
                    u.verdict,
                );
                assert_eq!(protocol, diff_mix(i, 0) as u8, "record {i}: v4 protocol");
                assert_eq!(local, b4(i, 1), "record {i}: v4 local_address");
                assert_eq!(local_port, diff_mix(i, 2) as u16, "record {i}: v4 local_port");
                assert_eq!(remote, b4(i, 3), "record {i}: v4 remote_address");
                assert_eq!(remote_port, diff_mix(i, 4) as u16, "record {i}: v4 remote_port");
                assert_eq!(verdict, verdict_val(i, 5), "record {i}: v4 verdict");
            }
            CommandType::UpdateV6 => {
                let mut buf = [0u8; core::mem::size_of::<UpdateV6>()];
                file.read_exact(&mut buf).unwrap();
                let u = parse_update_v6(&buf).unwrap();
                let (protocol, local, local_port, remote, remote_port, verdict) = (
                    u.protocol,
                    u.local_address,
                    u.local_port,
                    u.remote_address,
                    u.remote_port,
                    u.verdict,
                );
                assert_eq!(protocol, diff_mix(i, 0) as u8, "record {i}: v6 protocol");
                assert_eq!(local, b16(i, 1), "record {i}: v6 local_address");
                assert_eq!(local_port, diff_mix(i, 2) as u16, "record {i}: v6 local_port");
                assert_eq!(remote, b16(i, 3), "record {i}: v6 remote_address");
                assert_eq!(remote_port, diff_mix(i, 4) as u16, "record {i}: v6 remote_port");
                assert_eq!(verdict, verdict_val(i, 5), "record {i}: v6 verdict");
            }
            CommandType::GetConnectionsUpdate => {
                let mut buf = [0u8; core::mem::size_of::<ConnectionsUpdate>()];
                file.read_exact(&mut buf).unwrap();
                let c = parse_update_info(&buf).unwrap();
                let ts = c.timestamp;
                assert_eq!(ts, diff_mix(i, 0), "record {i}: timestamp");
            }
            other => panic!("record {i}: unexpected command type {}", other as u8),
        }
        i += 1;
    }
    assert!(i > 0, "no command records read from {COMMAND_DIFF_FILE}");
}
