package kext_interface_test

import (
	"io"
	"math/rand"
	"os"
	"testing"

	"github.com/vlabo/portmaster_windows_rust_kext/kext_interface"
)

func TestRustInfoFile(t *testing.T) {
	file, err := os.Open("../protocol/rust_info_test.bin")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	for {
		info, err := kext_interface.RecvInfo(file)
		if err != nil {
			if err != io.EOF {
				t.Errorf("unexpected error: %s\n", err)
			}
			return
		}
		if info.LogLine != nil {
			if info.LogLine.Severity != 1 {
				t.Errorf("unexpected Log severity: %d\n", info.LogLine.Severity)
			}

			if info.LogLine.Line != "prefix: test log" {
				t.Errorf("unexpected Log line: %s\n", info.LogLine.Line)
			}
		} else if info.ConnectionV4 != nil {
			conn := info.ConnectionV4
			expected := kext_interface.ConnectionV4{
				Id:         1,
				ProcessId:  2,
				Direction:  3,
				Protocol:   4,
				LocalIp:    [4]byte{1, 2, 3, 4},
				RemoteIp:   [4]byte{2, 3, 4, 5},
				LocalPort:  5,
				RemotePort: 6,
			}
			if *conn != expected {
				t.Errorf("unexpected ConnectionV4: %+v\n", conn)
			}
		} else if info.ConnectionV6 != nil {
			conn := info.ConnectionV6
			expected := kext_interface.ConnectionV6{
				Id:         1,
				ProcessId:  2,
				Direction:  3,
				Protocol:   4,
				LocalIp:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				RemoteIp:   [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
				LocalPort:  5,
				RemotePort: 6,
			}
			if *conn != expected {
				t.Errorf("unexpected ConnectionV6: %+v\n", conn)
			}
		} else if info.ConnectionEndV4 != nil {
			endEvent := info.ConnectionEndV4
			expected := kext_interface.ConnectionEndV4{
				ProcessId:  1,
				Direction:  2,
				Protocol:   3,
				LocalIp:    [4]byte{1, 2, 3, 4},
				RemoteIp:   [4]byte{2, 3, 4, 5},
				LocalPort:  4,
				RemotePort: 5,
			}
			if *endEvent != expected {
				t.Errorf("unexpected ConnectionEndV4: %+v\n", endEvent)
			}
		} else if info.ConnectionEndV6 != nil {
			endEvent := info.ConnectionEndV6
			expected := kext_interface.ConnectionEndV6{
				ProcessId:  1,
				Direction:  2,
				Protocol:   3,
				LocalIp:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				RemoteIp:   [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
				LocalPort:  4,
				RemotePort: 5,
			}
			if *endEvent != expected {
				t.Errorf("unexpected ConnectionEndV6: %+v\n", endEvent)
			}
		} else if info.BandwidthStats != nil {
			stats := info.BandwidthStats
			if stats.Protocol != 1 {
				t.Errorf("unexpected Bandwidth stats protocol: %d\n", stats.Protocol)
			}

			if stats.ValuesV4 != nil {
				if len(stats.ValuesV4) != 2 {
					t.Errorf("unexpected Bandwidth stats value length: %d\n", len(stats.ValuesV4))
				}
				expected1 := kext_interface.BandwidthValueV4{
					LocalIP:          [4]byte{1, 2, 3, 4},
					LocalPort:        1,
					RemoteIP:         [4]byte{2, 3, 4, 5},
					RemotePort:       2,
					TransmittedBytes: 3,
					ReceivedBytes:    4,
				}
				if stats.ValuesV4[0] != expected1 {
					t.Errorf("unexpected Bandwidth stats value: %+v expected: %+v\n", stats.ValuesV4[0], expected1)
				}
				expected2 := kext_interface.BandwidthValueV4{
					LocalIP:          [4]byte{1, 2, 3, 4},
					LocalPort:        5,
					RemoteIP:         [4]byte{2, 3, 4, 5},
					RemotePort:       6,
					TransmittedBytes: 7,
					ReceivedBytes:    8,
				}
				if stats.ValuesV4[1] != expected2 {
					t.Errorf("unexpected Bandwidth stats value: %+v expected: %+v\n", stats.ValuesV4[1], expected2)
				}

			} else if stats.ValuesV6 != nil {
				if len(stats.ValuesV6) != 2 {
					t.Errorf("unexpected Bandwidth stats value length: %d\n", len(stats.ValuesV6))
				}

				expected1 := kext_interface.BandwidthValueV6{
					LocalIP:          [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					LocalPort:        1,
					RemoteIP:         [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
					RemotePort:       2,
					TransmittedBytes: 3,
					ReceivedBytes:    4,
				}
				if stats.ValuesV6[0] != expected1 {
					t.Errorf("unexpected Bandwidth stats value: %+v expected: %+v\n", stats.ValuesV6[0], expected1)
				}
				expected2 := kext_interface.BandwidthValueV6{
					LocalIP:          [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					LocalPort:        5,
					RemoteIP:         [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
					RemotePort:       6,
					TransmittedBytes: 7,
					ReceivedBytes:    8,
				}
				if stats.ValuesV6[1] != expected2 {
					t.Errorf("unexpected Bandwidth stats value: %+v expected: %+v\n", stats.ValuesV6[1], expected2)
				}

			}
		}
	}
}

func TestGenerateCommandFile(t *testing.T) {
	file, err := os.Create("go_command_test.bin")
	if err != nil {
		t.Errorf("failed to create file: %s", err)
	}
	defer file.Close()
	enums := []byte{
		kext_interface.CommandShutdown,
		kext_interface.CommandVerdict,
		kext_interface.CommandUpdateV4,
		kext_interface.CommandUpdateV6,
		kext_interface.CommandClearCache,
		kext_interface.CommandGetLogs,
		kext_interface.CommandBandwidthStats,
	}

	selected := make([]byte, 5000)
	for i := range selected {
		selected[i] = enums[rand.Intn(len(enums))]
	}

	for _, value := range selected {
		switch value {
		case kext_interface.CommandShutdown:
			{
				kext_interface.SendShutdownCommand(file)
			}
		case kext_interface.CommandVerdict:
			{
				kext_interface.SendVerdictCommand(file, kext_interface.Verdict{
					Id:      1,
					Verdict: 2,
				})
			}
		case kext_interface.CommandUpdateV4:
			{
				kext_interface.SendUpdateV4Command(file, kext_interface.UpdateV4{
					Protocol:      1,
					LocalAddress:  [4]byte{1, 2, 3, 4},
					LocalPort:     2,
					RemoteAddress: [4]byte{2, 3, 4, 5},
					RemotePort:    3,
					Verdict:       4,
				})
			}
		case kext_interface.CommandUpdateV6:
			{

				kext_interface.SendUpdateV6Command(file, kext_interface.UpdateV6{
					Protocol:      1,
					LocalAddress:  [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					LocalPort:     2,
					RemoteAddress: [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
					RemotePort:    3,
					Verdict:       4,
				})
			}
		case kext_interface.CommandClearCache:
			{
				kext_interface.SendClearCacheCommand(file)
			}
		case kext_interface.CommandGetLogs:
			{
				kext_interface.SendGetLogsCommand(file)
			}
		case kext_interface.CommandBandwidthStats:
			{
				kext_interface.SendGetBandwidthStatsCommand(file)
			}
		}
	}

}
