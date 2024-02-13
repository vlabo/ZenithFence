package kext_interface_test

import (
	"io"
	"os"
	"testing"

	"github.com/vlabo/portmaster_windows_rust_kext/kext_interface"
)

func TestInfo(t *testing.T) {
	file, err := os.Open("../protocol/rust_info_test.bin")
	if err != nil {
		panic(err)
	}
	for {
		info, err := kext_interface.ReadInfo(file)
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
