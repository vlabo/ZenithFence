package kext_interface

import "io"

// SimConn is a connection to the userspace fake-driver daemon (`zf-sim`, see
// sim/). Read/Write behave like a *KextFile against the kernel device: Read
// fills the whole buffer from the event stream, and each Write delivers exactly
// one command to the driver.
//
// The daemon's endpoint is addressed by a logical name (ZF_SIM_PIPE), mapped
// per OS by SimEndpoint. The rule must match `endpoint` in sim/src/pipe/mod.rs:
//   - Windows: the named pipe \\.\pipe\<name>
//   - Unix:    <name> itself if it contains '/', else $XDG_RUNTIME_DIR/<name>.sock,
//     falling back to /tmp/<name>.sock
type SimConn = io.ReadWriteCloser

// OpenSimConn connects to the daemon endpoint for name, retrying while the
// daemon is still coming up, so daemon-first ordering is not required.
func OpenSimConn(name string, readBufferSize int) (SimConn, error) {
	return openSimConn(name, readBufferSize)
}
