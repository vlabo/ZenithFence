package kext_interface

import "io"

// SimConn is a connection to the userspace mock driver, served by a Python
// script through the `zfsim` module (`Sim.serve`, see sim/). Read/Write behave like a *KextFile against the kernel device: Read
// fills the whole buffer from the event stream, and each Write delivers exactly
// one command to the driver.
//
// The endpoint is addressed by a logical name (ZF_SIM_PIPE), mapped
// per OS by SimEndpoint. The rule must match `endpoint` in sim/src/pipe/mod.rs:
//   - Windows: <name> itself if it is a full \\.\pipe\ path, else the named
//     pipe \\.\pipe\<name>
//   - Unix:    <name> itself if it contains '/', else $XDG_RUNTIME_DIR/<name>.sock,
//     falling back to /tmp/<name>.sock
type SimConn = io.ReadWriteCloser

// OpenSimConn connects to the mock driver endpoint for name, retrying while the
// script is still coming up, so script-first ordering is not required.
func OpenSimConn(name string, readBufferSize int) (SimConn, error) {
	return openSimConn(name, readBufferSize)
}
