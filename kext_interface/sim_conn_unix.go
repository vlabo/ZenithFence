//go:build unix

package kext_interface

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SimEndpoint returns the Unix socket path for the logical endpoint name.
func SimEndpoint(name string) string {
	if strings.Contains(name, "/") {
		return name
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return strings.TrimRight(dir, "/") + "/" + name + ".sock"
	}
	return "/tmp/" + name + ".sock"
}

// openSimConn dials the daemon's Unix socket, retrying while the daemon has not
// created it yet (ENOENT) or is not accepting yet (ECONNREFUSED). The read
// buffer size is unused: the socket buffers in the kernel.
func openSimConn(name string, _ int) (SimConn, error) {
	path := SimEndpoint(name)
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.Dial("unix", path)
		if err == nil {
			return &framedConn{conn: conn}, nil
		}
		retryable := errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
		if retryable && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return nil, fmt.Errorf("failed to open socket %s: %w", path, err)
	}
}

// framedConn restores the kernel device's "one write = one command" semantics
// over a stream socket, which has no message boundaries: each Write goes out as
// a u32 little-endian length followed by the payload, and the daemon hands
// each frame to the driver as one write. Events come back as an unframed byte
// stream, as from the device.
type framedConn struct {
	conn net.Conn
	// Serializes frames from concurrent Send*Command callers.
	writeMutex sync.Mutex
}

// Read fills the whole buffer, as *KextFile.Read does; RecvInfo relies on it.
func (c *framedConn) Read(buffer []byte) (int, error) {
	return io.ReadFull(c.conn, buffer)
}

func (c *framedConn) Write(buffer []byte) (int, error) {
	frame := make([]byte, 4+len(buffer))
	binary.LittleEndian.PutUint32(frame, uint32(len(buffer)))
	copy(frame[4:], buffer)

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if _, err := c.conn.Write(frame); err != nil {
		return 0, err
	}
	return len(buffer), nil
}

func (c *framedConn) Close() error {
	return c.conn.Close()
}
