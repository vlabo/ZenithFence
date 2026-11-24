package kext_interface

import "io"

// SimConn is a connection to the userspace mock driver, served by a Python
// script through the `zfsim` module (`Sim.serve`, see mock/sim/). Read/Write behave like a *KextFile against the kernel device: Read
// fills the whole buffer from the event stream, and each Write delivers exactly
// one command to the driver.
//
// The endpoint is a full path (ZF_SIM_PIPE), used verbatim and set to the same
// value as the script's `Sim.serve(path)`: \\.\pipe\<name> on Windows, a socket
// file path on Unix.
type SimConn = io.ReadWriteCloser

// OpenSimConn connects to the mock driver endpoint at path, retrying while the
// script is still coming up, so script-first ordering is not required.
func OpenSimConn(path string, readBufferSize int) (SimConn, error) {
	return openSimConn(path, readBufferSize)
}
