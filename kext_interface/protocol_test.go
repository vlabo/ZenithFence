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
	defer file.Close() //nolint:errcheck
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
			t.Logf("LogLine: Severity=%d, Line=%s\n", v.Severity, v.Line)
			if v.Severity != 1 {
				t.Errorf("unexpected Log severity: %d\n", v.Severity)
			}
			if v.Line != "prefix: test log" {
				t.Errorf("unexpected Log line: %s\n", v.Line)
			}

		case *ConnectionV4:
			t.Logf("ConnectionV4: %+v\n", v)
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
			t.Logf("ConnectionV6: %+v\n", v)
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
			t.Logf("ConnectionEndV4: %+v\n", v)
			expected := ConnectionEndV4{
				ProcessId:  1,
				Direction:  2,
				Protocol:   3,
				LocalIp:    [4]byte{1, 2, 3, 4},
				RemoteIp:   [4]byte{2, 3, 4, 5},
				LocalPort:  4,
				RemotePort: 5,
				RxBytes:    6,
				RxPackets:  7,
				TxBytes:    8,
				TxPackets:  9,
			}
			if *v != expected {
				t.Errorf("unexpected ConnectionEndV4: %+v\n", v)
			}
		case *ConnectionEndV6:
			t.Logf("ConnectionEndV6: %+v\n", v)
			expected := ConnectionEndV6{
				ProcessId:  1,
				Direction:  2,
				Protocol:   3,
				LocalIp:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				RemoteIp:   [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
				LocalPort:  4,
				RemotePort: 5,
				RxBytes:    6,
				RxPackets:  7,
				TxBytes:    8,
				TxPackets:  9,
			}
			if *v != expected {
				t.Errorf("unexpected ConnectionEndV6: %+v\n", v)
			}
		case *ConnectionUpdateV4:
			t.Logf("ConnectionUpdateV4: %+v\n", v)
			expected := ConnectionUpdateV4{
				Protocol:   1,
				LocalIp:    [4]byte{1, 2, 3, 4},
				RemoteIp:   [4]byte{2, 3, 4, 5},
				LocalPort:  2,
				RemotePort: 3,
				RxBytes:    4,
				RxPackets:  5,
				TxBytes:    6,
				TxPackets:  7,
			}
			if *v != expected {
				t.Errorf("unexpected ConnectionUpdateV4: %+v\n", v)
			}
		case *ConnectionUpdateV6:
			t.Logf("ConnectionUpdateV6: %+v\n", v)
			expected := ConnectionUpdateV6{
				Protocol:   1,
				LocalIp:    [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				RemoteIp:   [16]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
				LocalPort:  2,
				RemotePort: 3,
				RxBytes:    4,
				RxPackets:  5,
				TxBytes:    6,
				TxPackets:  7,
			}
			if *v != expected {
				t.Errorf("unexpected ConnectionUpdateV6: %+v\n", v)
			}
		case *ConnectionUpdateEnd:
			t.Logf("ConnectionUpdateEnd: %+v\n", v)
			// Empty struct
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
	defer file.Close() //nolint:errcheck
	enums := []byte{
		CommandShutdown,
		CommandVerdict,
		CommandUpdateV4,
		CommandUpdateV6,
		CommandClearCache,
		CommandGetConnetionsUpdate,
		CommandGetLogs,
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
				_ = SendShutdownCommand(file)
			}
		case CommandVerdict:
			{
				_ = SendVerdictCommand(file, Verdict{
					Id:      1,
					Verdict: 2,
				})
			}
		case CommandUpdateV4:
			{
				_ = SendUpdateV4Command(file, UpdateV4{
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
				_ = SendUpdateV6Command(file, UpdateV6{
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
				_ = SendClearCacheCommand(file)
			}
		case CommandGetLogs:
			{
				_ = SendGetLogsCommand(file)
			}
		case CommandGetConnetionsUpdate:
			{
				_ = SendGetConnectionsUpdateCommand(file, 1234567890)
			}
		case CommandPrintMemoryStats:
			{
				_ = SendPrintMemoryStatsCommand(file)
			}
		case CommandCleanEndedConnections:
			{
				_ = SendCleanEndedConnectionsCommand(file)
			}
		}
	}
}
