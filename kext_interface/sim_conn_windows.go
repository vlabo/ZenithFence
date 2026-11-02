//go:build windows
// +build windows

package kext_interface

// The named pipe is message-mode, so each Write already reaches the driver as
// one command; the pipe handle needs no extra framing.
var _ SimConn = (*KextFile)(nil)

func openSimConn(path string, readBufferSize int) (SimConn, error) {
	return OpenPipe(path, readBufferSize)
}
