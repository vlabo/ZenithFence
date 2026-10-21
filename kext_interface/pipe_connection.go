//go:build windows
// +build windows

package kext_interface

import (
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// OpenPipe connects to a userspace fake-driver named pipe and returns a
// *KextFile that is interchangeable with the one KextService.OpenFile returns
// for the kernel device. pipeName is either a full pipe path (\\.\pipe\...) or a
// bare name, which maps to \\.\pipe\<pipeName> (see SimEndpoint). This is the
// "different loading" path for the simulation harness; production uses
// KextService.OpenFile instead.
//
// The handle is opened with FILE_FLAG_OVERLAPPED, exactly like the device, so a
// pending Read on one goroutine does not block Writes from others and Close can
// cancel the pending Read. The client's default read mode is byte-stream, which
// is what the event parser (RecvInfo) expects, so message boundaries on the
// command direction don't affect event reassembly. CreateFile is retried while
// the server is still coming up, so daemon-first ordering is not required.
func OpenPipe(pipeName string, readBufferSize int) (*KextFile, error) {
	path := SimEndpoint(pipeName)
	pathU16, err := syscall.UTF16FromString(path)
	if err != nil {
		return nil, fmt.Errorf("failed to convert pipe name to UTF16 string: %w", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		handle, err := windows.CreateFile(
			&pathU16[0],
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0, nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED,
			0)
		if err == nil {
			return &KextFile{handle: handle, buffer: make([]byte, readBufferSize), pipe: true}, nil
		}

		// The daemon may not have created the pipe yet, or it may be momentarily
		// busy between instances; retry until the deadline.
		if (err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PIPE_BUSY) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return nil, fmt.Errorf("failed to open pipe %s: %w", path, err)
	}
}
