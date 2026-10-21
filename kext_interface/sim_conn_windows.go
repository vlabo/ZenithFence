//go:build windows
// +build windows

package kext_interface

import "strings"

// The named pipe is message-mode, so each Write already reaches the driver as
// one command; the pipe handle needs no extra framing.
var _ SimConn = (*KextFile)(nil)

// pipePrefix is the namespace every named-pipe path lives under.
const pipePrefix = `\\.\pipe\`

// SimEndpoint returns the named-pipe path for the logical endpoint name. A name
// that is already a full pipe path (\\.\pipe\...) is returned unchanged.
func SimEndpoint(name string) string {
	if strings.HasPrefix(strings.ToLower(name), pipePrefix) {
		return name
	}
	return pipePrefix + name
}

func openSimConn(name string, readBufferSize int) (SimConn, error) {
	return OpenPipe(name, readBufferSize)
}
