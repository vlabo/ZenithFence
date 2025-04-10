package kext_interface

import (
	"io"
	"math/rand"
	"os"
	"testing"
)

func TestRustInfoFile(t *testing.T) {
	file, err := os.Open("../protocol/rust_info_test.bin")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	for {
		info, err := RecvInfo(file)
		if err != nil {
			if err != io.EOF {
				t.Errorf("unexpected error: %s\n", err)
			}
			return
		}
		switch v := info.(type) {
		case *LogLine:
			if v.Severity != 1 {
				t.Errorf("unexpected Log severity: %d\n", v.Severity)
			}
			if v.Line != "prefix: test log" {
				t.Errorf("unexpected Log line: %s\n", v.Line)
			}

		case *ConnectionV4:
			expected := ConnectionV4{
				connectionV4Internal: connectionV4Internal{
					Id:           1,
					ProcessId:    2,
					Direction:    3,
					Protocol:     4,
					LocalIp:      [4]byte{1, 2, 3, 4},
					RemoteIp:     [4]byte{2, 3, 4, 5},
					LocalPort:    5,
					RemotePort:   6,
					PayloadLayer: 7,
				},
				Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			}
			if !v.Compare(&expected) {
				t.Errorf("unexpected ConnectionV4: %+v\n", v)
			}

		case *ConnectionV6:
			expected := ConnectionV6{
				connectionV6Internal: connectionV6Internal{
					Id:           1,
					ProcessId:    2,
					Direction:    3,
					Protocol:     4,
					LocalIp:      [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					RemoteIp:     [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
					LocalPort:    5,
					RemotePort:   6,
					PayloadLayer: 7,
				},
				Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			}
			if !v.Compare(&expected) {
				t.Errorf("unexpected ConnectionV6: %+v\n", v)
			}

		case *ConnectionEndV4:
			expected := ConnectionEndV4{
				ProcessId:  1,
				Direction:  2,
				Protocol:   3,
				LocalIp:    [4]byte{1, 2, 3, 4},
				RemoteIp:   [4]byte{2, 3, 4, 5},
				LocalPort:  4,
				RemotePort: 5,
			}
			if *v != expected {
				t.Errorf("unexpected ConnectionEndV4: %+v\n", v)
			}
		case *ConnectionEndV6:
			expected := ConnectionEndV6{
				ProcessId:  1,
				Direction:  2,
				Protocol:   3,
				LocalIp:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				RemoteIp:   [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
				LocalPort:  4,
				RemotePort: 5,
			}
			if *v != expected {
				t.Errorf("unexpected ConnectionEndV6: %+v\n", v)
			}
		case *BandwidthStatsV4:
			if v.Protocol != 1 {
				t.Errorf("unexpected Bandwidth stats protocol: %d\n", v.Protocol)
			}
			if len(v.Values) != 2 {
				t.Errorf("unexpected Bandwidth stats value length: %d\n", len(v.Values))
			}
			expected1 := BandwidthValueV4{
				LocalIP:          [4]byte{1, 2, 3, 4},
				LocalPort:        1,
				RemoteIP:         [4]byte{2, 3, 4, 5},
				RemotePort:       2,
				TransmittedBytes: 3,
				ReceivedBytes:    4,
			}
			if v.Values[0] != expected1 {
				t.Errorf("unexpected Bandwidth stats value: %+v expected: %+v\n", v.Values[0], expected1)
			}
			expected2 := BandwidthValueV4{
				LocalIP:          [4]byte{1, 2, 3, 4},
				LocalPort:        5,
				RemoteIP:         [4]byte{2, 3, 4, 5},
				RemotePort:       6,
				TransmittedBytes: 7,
				ReceivedBytes:    8,
			}
			if v.Values[1] != expected2 {
				t.Errorf("unexpected Bandwidth stats value: %+v expected: %+v\n", v.Values[1], expected2)
			}
		case *BandwidthStatsV6:
			if v.Protocol != 1 {
				t.Errorf("unexpected Bandwidth stats protocol: %d\n", v.Protocol)
			}
			if len(v.Values) != 2 {
				t.Errorf("unexpected Bandwidth stats value length: %d\n", len(v.Values))
			}
			expected1 := BandwidthValueV6{
				LocalIP:          [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				LocalPort:        1,
				RemoteIP:         [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
				RemotePort:       2,
				TransmittedBytes: 3,
				ReceivedBytes:    4,
			}
			if v.Values[0] != expected1 {
				t.Errorf("unexpected Bandwidth stats value: %+v expected: %+v\n", v.Values[0], expected1)
			}
			expected2 := BandwidthValueV6{
				LocalIP:          [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				LocalPort:        5,
				RemoteIP:         [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
				RemotePort:       6,
				TransmittedBytes: 7,
				ReceivedBytes:    8,
			}
			if v.Values[1] != expected2 {
				t.Errorf("unexpected Bandwidth stats value: %+v expected: %+v\n", v.Values[1], expected2)
			}
		default:
			t.Errorf("unexpected info type: %T\n", v)
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
		CommandShutdown,
		CommandVerdict,
		CommandUpdateV4,
		CommandUpdateV6,
		CommandClearCache,
		CommandGetLogs,
		CommandBandwidthStats,
		CommandCleanEndedConnections,
	}

	selected := make([]byte, 5000)
	for i := range selected {
		selected[i] = enums[rand.Intn(len(enums))]
	}

	for _, value := range selected {
		switch value {
		case CommandShutdown:
			{
				SendShutdownCommand(file)
			}
		case CommandVerdict:
			{
				SendVerdictCommand(file, Verdict{
					Id:      1,
					Verdict: 2,
				})
			}
		case CommandUpdateV4:
			{
				SendUpdateV4Command(file, UpdateV4{
					Protocol:      1,
					LocalAddress:  [4]byte{1, 2, 3, 4},
					LocalPort:     2,
					RemoteAddress: [4]byte{2, 3, 4, 5},
					RemotePort:    3,
					Verdict:       4,
				})
			}
		case CommandUpdateV6:
			{
				SendUpdateV6Command(file, UpdateV6{
					Protocol:      1,
					LocalAddress:  [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					LocalPort:     2,
					RemoteAddress: [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
					RemotePort:    3,
					Verdict:       4,
				})
			}
		case CommandClearCache:
			{
				SendClearCacheCommand(file)
			}
		case CommandGetLogs:
			{
				SendGetLogsCommand(file)
			}
		case CommandBandwidthStats:
			{
				SendGetBandwidthStatsCommand(file)
			}
		case CommandPrintMemoryStats:
			{
				SendPrintMemoryStatsCommand(file)
			}
		case CommandCleanEndedConnections:
			{
				SendCleanEndedConnectionsCommand(file)
			}
		}
	}
}
