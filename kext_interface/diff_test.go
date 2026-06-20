package kext_interface

// Deterministic Rust <-> Go differential tests of the user/kernel wire format.
//
// Each record's field values are derived from its index by diffMix (a
// splitmix64-style hash implemented identically here and in
// protocol/src/difftest.rs). Both languages compute the same expected values
// from the record position, so any encoding/decoding divergence (endianness,
// field order, type width, struct size) surfaces as a mismatch.
//
//   commands  TestGenerateCommandDiff writes go_command_diff.bin -> Rust reads
//   info      Rust writes info_diff.bin -> TestInfoDiffFile reads
//
// KEEP THE FORMULAS BELOW IN SYNC WITH protocol/src/difftest.rs.

import (
	"encoding/binary"
	"io"
	"os"
	"testing"
)

const commandDiffFile = "go_command_diff.bin"
const infoDiffFile = "../protocol/info_diff.bin"
const commandDiffRecords = 4000

// MUST match diff_mix in protocol/src/difftest.rs. Go uint64 arithmetic wraps,
// matching Rust's wrapping_mul.
func diffMix(i uint32, f uint32) uint64 {
	x := uint64(i)*0x9E3779B97F4A7C15 ^ uint64(f)*0xC2B2AE3D27D4EB4F
	x ^= x >> 29
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 32
	return x
}

func diffB4(i uint32, f uint32) [4]byte {
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], uint32(diffMix(i, f)))
	return out
}

func diffB16(i uint32, f uint32) [16]byte {
	var out [16]byte
	binary.LittleEndian.PutUint64(out[:8], diffMix(i, f))
	binary.LittleEndian.PutUint64(out[8:], diffMix(i, f+0x1000))
	return out
}

func diffVerdict(i uint32, f uint32) uint8 {
	return uint8(diffMix(i, f) % 11)
}

// Go writes random-valued commands; the Rust side parses and verifies them
// (protocol::difftest::test_go_command_diff).
func TestGenerateCommandDiff(t *testing.T) {
	file, err := os.Create(commandDiffFile)
	if err != nil {
		t.Fatalf("failed to create file: %s", err)
	}
	defer file.Close() //nolint:errcheck

	for i := uint32(0); i < commandDiffRecords; i++ {
		switch i % 4 {
		case 0:
			_ = SendVerdictCommand(file, Verdict{
				Id:      diffMix(i, 0),
				Verdict: diffVerdict(i, 1),
			})
		case 1:
			_ = SendUpdateV4Command(file, UpdateV4{
				Protocol:      uint8(diffMix(i, 0)),
				LocalAddress:  diffB4(i, 1),
				LocalPort:     uint16(diffMix(i, 2)),
				RemoteAddress: diffB4(i, 3),
				RemotePort:    uint16(diffMix(i, 4)),
				Verdict:       diffVerdict(i, 5),
			})
		case 2:
			_ = SendUpdateV6Command(file, UpdateV6{
				Protocol:      uint8(diffMix(i, 0)),
				LocalAddress:  diffB16(i, 1),
				LocalPort:     uint16(diffMix(i, 2)),
				RemoteAddress: diffB16(i, 3),
				RemotePort:    uint16(diffMix(i, 4)),
				Verdict:       diffVerdict(i, 5),
			})
		case 3:
			_ = SendGetConnectionsUpdateCommand(file, diffMix(i, 0))
		}
	}
}

// Go reads the Info packets Rust wrote and verifies every field against the same
// diffMix formula.
func TestInfoDiffFile(t *testing.T) {
	file, err := os.Open(infoDiffFile)
	if err != nil {
		t.Fatalf("open %s: %s (run `cargo test` in protocol/ first)", infoDiffFile, err)
	}
	defer file.Close() //nolint:errcheck

	var i uint32 = 0
	for {
		info, err := RecvInfo(file)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("record %d: %s", i, err)
		}

		switch i % 6 {
		case 0:
			v, ok := info.(*ConnectionEndV4)
			if !ok {
				t.Fatalf("record %d: expected *ConnectionEndV4, got %T", i, info)
			}
			expected := ConnectionEndV4{
				ProcessId:  diffMix(i, 0),
				Direction:  uint8(diffMix(i, 1)),
				Protocol:   uint8(diffMix(i, 2)),
				LocalIp:    diffB4(i, 3),
				RemoteIp:   diffB4(i, 4),
				LocalPort:  uint16(diffMix(i, 5)),
				RemotePort: uint16(diffMix(i, 6)),
				RxBytes:    diffMix(i, 7),
				RxPackets:  diffMix(i, 8),
				TxBytes:    diffMix(i, 9),
				TxPackets:  diffMix(i, 10),
			}
			if *v != expected {
				t.Fatalf("record %d ConnectionEndV4:\n got %+v\nwant %+v", i, *v, expected)
			}
		case 1:
			v, ok := info.(*ConnectionEndV6)
			if !ok {
				t.Fatalf("record %d: expected *ConnectionEndV6, got %T", i, info)
			}
			expected := ConnectionEndV6{
				ProcessId:  diffMix(i, 0),
				Direction:  uint8(diffMix(i, 1)),
				Protocol:   uint8(diffMix(i, 2)),
				LocalIp:    diffB16(i, 3),
				RemoteIp:   diffB16(i, 4),
				LocalPort:  uint16(diffMix(i, 5)),
				RemotePort: uint16(diffMix(i, 6)),
				RxBytes:    diffMix(i, 7),
				RxPackets:  diffMix(i, 8),
				TxBytes:    diffMix(i, 9),
				TxPackets:  diffMix(i, 10),
			}
			if *v != expected {
				t.Fatalf("record %d ConnectionEndV6:\n got %+v\nwant %+v", i, *v, expected)
			}
		case 2:
			v, ok := info.(*ConnectionUpdateV4)
			if !ok {
				t.Fatalf("record %d: expected *ConnectionUpdateV4, got %T", i, info)
			}
			expected := ConnectionUpdateV4{
				Protocol:   uint8(diffMix(i, 0)),
				LocalIp:    diffB4(i, 1),
				RemoteIp:   diffB4(i, 2),
				LocalPort:  uint16(diffMix(i, 3)),
				RemotePort: uint16(diffMix(i, 4)),
				RxBytes:    diffMix(i, 5),
				RxPackets:  diffMix(i, 6),
				TxBytes:    diffMix(i, 7),
				TxPackets:  diffMix(i, 8),
			}
			if *v != expected {
				t.Fatalf("record %d ConnectionUpdateV4:\n got %+v\nwant %+v", i, *v, expected)
			}
		case 3:
			v, ok := info.(*ConnectionUpdateV6)
			if !ok {
				t.Fatalf("record %d: expected *ConnectionUpdateV6, got %T", i, info)
			}
			expected := ConnectionUpdateV6{
				Protocol:   uint8(diffMix(i, 0)),
				LocalIp:    diffB16(i, 1),
				RemoteIp:   diffB16(i, 2),
				LocalPort:  uint16(diffMix(i, 3)),
				RemotePort: uint16(diffMix(i, 4)),
				RxBytes:    diffMix(i, 5),
				RxPackets:  diffMix(i, 6),
				TxBytes:    diffMix(i, 7),
				TxPackets:  diffMix(i, 8),
			}
			if *v != expected {
				t.Fatalf("record %d ConnectionUpdateV6:\n got %+v\nwant %+v", i, *v, expected)
			}
		case 4:
			v, ok := info.(*ConnectionV4)
			if !ok {
				t.Fatalf("record %d: expected *ConnectionV4, got %T", i, info)
			}
			if v.Id != diffMix(i, 0) || v.ProcessId != diffMix(i, 1) ||
				v.Direction != uint8(diffMix(i, 2)) || v.Protocol != uint8(diffMix(i, 3)) ||
				v.LocalIp != diffB4(i, 4) || v.RemoteIp != diffB4(i, 5) ||
				v.LocalPort != uint16(diffMix(i, 6)) || v.RemotePort != uint16(diffMix(i, 7)) ||
				v.PayloadLayer != uint8(diffMix(i, 8)) {
				t.Fatalf("record %d ConnectionV4 header mismatch: %+v", i, v)
			}
			checkPayload(t, i, v.Payload)
		case 5:
			v, ok := info.(*ConnectionV6)
			if !ok {
				t.Fatalf("record %d: expected *ConnectionV6, got %T", i, info)
			}
			if v.Id != diffMix(i, 0) || v.ProcessId != diffMix(i, 1) ||
				v.Direction != uint8(diffMix(i, 2)) || v.Protocol != uint8(diffMix(i, 3)) ||
				v.LocalIp != diffB16(i, 4) || v.RemoteIp != diffB16(i, 5) ||
				v.LocalPort != uint16(diffMix(i, 6)) || v.RemotePort != uint16(diffMix(i, 7)) ||
				v.PayloadLayer != uint8(diffMix(i, 8)) {
				t.Fatalf("record %d ConnectionV6 header mismatch: %+v", i, v)
			}
			checkPayload(t, i, v.Payload)
		}
		i++
	}

	if i == 0 {
		t.Fatalf("no records read from %s", infoDiffFile)
	}
}

func checkPayload(t *testing.T, i uint32, payload []byte) {
	expLen := int(diffMix(i, 9) % 17)
	if len(payload) != expLen {
		t.Fatalf("record %d: payload len got %d want %d", i, len(payload), expLen)
	}
	for j := 0; j < expLen; j++ {
		if payload[j] != byte(diffMix(i, uint32(100+j))) {
			t.Fatalf("record %d: payload[%d] mismatch", i, j)
		}
	}
}
