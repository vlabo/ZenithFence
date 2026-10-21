//go:build windows
// +build windows

package kext_interface

// The named pipe is message-mode, so each Write already reaches the driver as
// one command; the pipe handle needs no extra framing.
var _ SimConn = (*KextFile)(nil)

// SimEndpoint returns the named-pipe path for the logical endpoint name.
func SimEndpoint(name string) string {
	return `\\.\pipe\` + name
}

func openSimConn(name string, readBufferSize int) (SimConn, error) {
	return OpenPipe(name, readBufferSize)
}
