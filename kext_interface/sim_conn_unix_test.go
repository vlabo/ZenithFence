//go:build unix

package kext_interface

import (
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"
)

// Two back-to-back commands must reach the server as two separate frames, since
// the driver parses exactly one command per write.
func TestFramedConnKeepsCommandBoundaries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zf.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	conn, err := openSimConn(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	if err := SendVerdictCommand(conn, Verdict{Id: 42, Verdict: uint8(VerdictPermanentAccept)}); err != nil {
		t.Fatal(err)
	}
	if err := SendGetLogsCommand(conn); err != nil {
		t.Fatal(err)
	}

	readFrame := func() []byte {
		var size uint32
		if err := binary.Read(server, binary.LittleEndian, &size); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(server, payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}

	verdict := readFrame()
	if want := binary.Size(Verdict{}); len(verdict) != want || verdict[0] != CommandVerdict {
		t.Fatalf("verdict frame = %v, want %d bytes starting with %d", verdict, want, CommandVerdict)
	}
	logs := readFrame()
	if len(logs) != 1 || logs[0] != CommandGetLogs {
		t.Fatalf("get-logs frame = %v, want [%d]", logs, CommandGetLogs)
	}
}

// Read must fill the caller's buffer even when the bytes arrive in pieces.
func TestFramedConnReadFillsBuffer(t *testing.T) {
	client, server := net.Pipe()
	conn := &framedConn{conn: client}
	defer conn.Close()

	go func() {
		server.Write([]byte{1, 2})
		server.Write([]byte{3, 4, 5})
		server.Close()
	}()

	buffer := make([]byte, 5)
	n, err := conn.Read(buffer)
	if err != nil || n != 5 || buffer[4] != 5 {
		t.Fatalf("Read = %d, %v, %v", n, err, buffer)
	}
}
