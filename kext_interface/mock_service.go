//go:build windows
// +build windows

package kext_interface

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

// startupGrace is how long Start waits after spawning the daemon to catch an
// immediate death (driver_entry / registration / pipe creation failing). If the
// daemon is still alive after this, the real "is the pipe up yet" wait is left to
// OpenFile, whose OpenPipe retries while the server comes up.
const startupGrace = 300 * time.Millisecond

// MockKextService is a drop-in stand-in for KextService that is backed by the
// userspace `zf-sim` daemon instead of a kernel driver service. The daemon loads
// the *real* driver over the host WDK mock (mock_wdk) and runs its actual
// driver_entry, then exposes it on a named pipe.
//
// It mirrors the KextService lifecycle so the agent drives the mock exactly as it
// drives a kernel driver:
//
//   - CreateMockKextService -> CreateKextService (register the driver image)
//   - Start                 -> StartService      (kernel loads driver.sys, DriverEntry runs)
//   - OpenFile              -> OpenFile          (open the device / pipe)
//   - Stop / Delete         -> Stop / Delete     (unload / deregister the driver)
//
// The mock "load and start" is spawning the daemon process; the OS reclaims the
// driver, its I/O pumps and the pipe when that process exits, so Stop/Delete are
// a hard process termination rather than a graceful service stop.
type MockKextService struct {
	pipeName   string
	daemonPath string
	args       []string

	cmd  *exec.Cmd
	done chan struct{} // closed once the reaper goroutine has Wait()ed on cmd

	mu       sync.Mutex
	finished bool
	killed   bool
	exitCode int
	waitErr  error
}

// CreateMockKextService prepares (but does not start) a simulated kext service
// backed by the `zf-sim` daemon at daemonPath, reachable on \\.\pipe\<pipeName>.
// Any extra args are passed to the daemon; the daemon also inherits this
// process's environment (ZF_SIM_SCENARIO, ZF_SIM_SEED, ...). Mirrors
// CreateKextService: it validates the daemon image exists, analogous to the SCM
// checking the driver path, but starts nothing until Start is called.
func CreateMockKextService(pipeName string, daemonPath string, args ...string) (*MockKextService, error) {
	if pipeName == "" {
		return nil, fmt.Errorf("mock kext service requires a pipe name")
	}
	if daemonPath == "" {
		return nil, fmt.Errorf("mock kext service requires a daemon path")
	}
	if _, err := os.Stat(daemonPath); err != nil {
		return nil, fmt.Errorf("mock driver daemon not found at %q: %w", daemonPath, err)
	}
	return &MockKextService{pipeName: pipeName, daemonPath: daemonPath, args: args}, nil
}

// Start spawns the daemon, which loads the driver over mock_wdk and runs its
// driver_entry -- the mock analog of StartService loading the kernel driver. The
// daemon's stdout/stderr are inherited so its logs interleave with the agent's.
// When wait is set, Start fails fast if the daemon dies during startup; otherwise
// it returns as soon as the process is launched.
func (s *MockKextService) Start(wait bool) error {
	if s.cmd != nil {
		return fmt.Errorf("mock kext service already started")
	}

	cmd := exec.Command(s.daemonPath, s.args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// No stdin: the daemon is non-interactive when driven by the agent.

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start mock driver daemon %q: %w", s.daemonPath, err)
	}
	s.cmd = cmd
	s.done = make(chan struct{})

	// One reaper owns cmd.Wait(); everyone else observes completion via `done`,
	// so Wait/Stop/Delete can be called (and deferred) freely without racing on a
	// second cmd.Wait().
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		s.finished = true
		s.waitErr = err
		if cmd.ProcessState != nil {
			s.exitCode = cmd.ProcessState.ExitCode()
		}
		s.mu.Unlock()
		close(s.done)
	}()

	if wait {
		select {
		case <-s.done:
			return fmt.Errorf("mock driver daemon exited during startup (code %d)", s.exitCode)
		case <-time.After(startupGrace):
			// Still alive; OpenFile handles the pipe-available wait.
		}
	}
	return nil
}

// OpenFile connects to the daemon's named pipe and returns a *KextFile whose
// Read/Write behave as they do against the kernel device. OpenPipe retries while
// the daemon finishes coming up, so Start need not block until the pipe is ready.
func (s *MockKextService) OpenFile(readBufferSize int) (*KextFile, error) {
	return OpenPipe(s.pipeName, readBufferSize)
}

// Wait blocks until the daemon exits on its own (e.g. a scenario finished
// replaying) and returns its process exit code, so a caller can propagate the
// mock driver's pass/fail result. Safe to call after Stop/Delete (returns the
// recorded code).
func (s *MockKextService) Wait() (int, error) {
	if s.cmd == nil {
		return 0, fmt.Errorf("mock kext service not started")
	}
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exitCode, s.waitErr
}

// Stop terminates the daemon if it is still running -- the mock analog of
// stopping the service. The producer runs forever, so a hard TerminateProcess is
// how the agent stops it; the OS reclaims the driver, pumps and pipe with the
// process. Idempotent, and a no-op once the daemon has already exited. With wait
// set it blocks until the process is fully reaped.
func (s *MockKextService) Stop(wait bool) error {
	if s.cmd == nil {
		return nil
	}

	s.mu.Lock()
	needKill := !s.finished && !s.killed
	if needKill {
		s.killed = true
	}
	s.mu.Unlock()

	if needKill {
		// Ignore the error: a race where the daemon exits between the check and
		// the kill reports "process already finished", which is fine.
		_ = s.cmd.Process.Kill()
	}
	if wait {
		<-s.done
	}
	return nil
}

// Delete ensures the daemon is gone -- the mock analog of deleting the service.
// It is idempotent (delegates to Stop), so deferring both Stop and Delete is safe.
func (s *MockKextService) Delete() error {
	return s.Stop(true)
}
