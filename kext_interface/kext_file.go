//go:build windows

package kext_interface

import (
	"errors"
	"sync"

	"golang.org/x/sys/windows"
)

// errFileClosed is returned when an I/O operation is attempted after the file
// has been (or is being) closed.
var errFileClosed = errors.New("kext file is closed")

type KextFile struct {
	// mutex guards handle/closed and serializes the transition to the closed
	// state against operations trying to start.
	mutex  sync.Mutex
	handle windows.Handle
	closed bool
	// inflight counts operations that currently own an OVERLAPPED/buffer the
	// kernel may still be writing to. Close waits for it to drain (after
	// cancelling) so the driver is guaranteed to be done with our buffers
	// before the handle is closed and the driver unloads.
	inflight sync.WaitGroup

	buffer     []byte
	read_slice []byte
}

// Read reads the next chunk of data from the kext.
// IMPORTANT: method is not thread safe.
func (f *KextFile) Read(buffer []byte) (int, error) {
	if len(f.read_slice) == 0 {
		err := f.refill_read_buffer()
		if err != nil {
			return 0, err
		}
	}

	if len(f.read_slice) >= len(buffer) {
		// Write all requested bytes.
		copy(buffer, f.read_slice[0:len(buffer)])
		f.read_slice = f.read_slice[len(buffer):]
	} else {
		// Write all available bytes and read again.
		copy(buffer[0:len(f.read_slice)], f.read_slice)
		copiedBytes := len(f.read_slice)
		f.read_slice = nil
		_, err := f.Read(buffer[copiedBytes:])
		if err != nil {
			return 0, err
		}
	}

	return len(buffer), nil
}

func (f *KextFile) refill_read_buffer() error {
	count, err := f.runOverlapped(func(handle windows.Handle, overlapped *windows.Overlapped, done *uint32) error {
		return windows.ReadFile(handle, f.buffer[:], done, overlapped)
	})
	if err != nil {
		return err
	}
	f.read_slice = f.buffer[0:count]

	return nil
}

func (f *KextFile) Write(buffer []byte) (int, error) {
	count, err := f.runOverlapped(func(handle windows.Handle, overlapped *windows.Overlapped, done *uint32) error {
		return windows.WriteFile(handle, buffer, done, overlapped)
	})
	return int(count), err
}

func (f *KextFile) deviceIOControl(code uint32, inData []byte, outData []byte) error {
	var inDataPtr *byte = nil
	var inDataSize uint32 = 0
	if inData != nil {
		inDataPtr = &inData[0]
		inDataSize = uint32(len(inData))
	}

	var outDataPtr *byte = nil
	var outDataSize uint32 = 0
	if outData != nil {
		outDataPtr = &outData[0]
		outDataSize = uint32(len(outData))
	}

	_, err := f.runOverlapped(func(handle windows.Handle, overlapped *windows.Overlapped, done *uint32) error {
		return windows.DeviceIoControl(handle,
			code,
			inDataPtr, inDataSize,
			outDataPtr, outDataSize,
			done, overlapped)
	})
	return err
}

// beginIO registers the start of an overlapped operation. It returns the handle
// to use, or a false ok if the file has been closed and no new I/O may start.
// Every successful beginIO must be paired with an endIO.
func (f *KextFile) beginIO() (windows.Handle, bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.closed || f.handle == winInvalidHandleValue {
		return winInvalidHandleValue, false
	}
	f.inflight.Add(1)
	return f.handle, true
}

func (f *KextFile) endIO() {
	f.inflight.Done()
}

// runOverlapped issues a single overlapped operation and waits for it to
// complete. Each operation gets its own event so that concurrent reads, writes
// and IOCTLs on the same handle do not observe each other's completion. If the
// operation is cancelled (via Cancel or Close) it returns once the kernel has
// released the buffer, with err == ERROR_OPERATION_ABORTED.
func (f *KextFile) runOverlapped(issue func(handle windows.Handle, overlapped *windows.Overlapped, done *uint32) error) (uint32, error) {
	handle, ok := f.beginIO()
	if !ok {
		return 0, errFileClosed
	}
	defer f.endIO()

	// Manual-reset event, dedicated to this single operation.
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)

	overlapped := &windows.Overlapped{HEvent: event}
	var done uint32
	err = issue(handle, overlapped, &done)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		// The driver kept the request pending. Block until it finishes, which
		// also happens when the request is cancelled. Waiting here guarantees
		// the kernel is done with the buffer/overlapped before we return.
		err = windows.GetOverlappedResult(handle, overlapped, &done, true)
	}
	if err != nil {
		return done, err
	}

	return done, nil
}

// Cancel aborts any overlapped operations currently in flight on the file
// without closing it. It is safe to call from a different goroutine than the
// one that issued the I/O: CancelIoEx cancels requests issued by any thread.
func (f *KextFile) Cancel() error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.closed || f.handle == winInvalidHandleValue {
		return nil
	}
	// A nil overlapped cancels every outstanding request on the handle.
	err := windows.CancelIoEx(f.handle, nil)
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		// Nothing was in flight; not an error.
		return nil
	}
	return err
}

func (f *KextFile) getAndMarkHandleAsClosed() windows.Handle {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if f.closed {
		return winInvalidHandleValue
	}
	f.closed = true
	handle := f.handle
	f.handle = winInvalidHandleValue

	return handle
}

func (f *KextFile) Close() error {
	handle := f.getAndMarkHandleAsClosed()
	if handle == winInvalidHandleValue {
		return nil
	}

	// Cancel anything still pending so the kernel releases our buffers and the
	// associated IRPs, then wait for those operations to unwind before closing
	// the handle. This keeps a request that raced into the shutdown window from
	// lingering and blocking driver unload.
	_ = windows.CancelIoEx(handle, nil)
	f.inflight.Wait()

	err := windows.CloseHandle(handle)

	return err
}

func (f *KextFile) GetHandle() windows.Handle {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.handle
}
