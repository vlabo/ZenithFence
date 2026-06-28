//! Minimal Windows named-pipe server with overlapped (asynchronous) I/O.
//!
//! Raw `kernel32` FFI (no `windows-sys`/`windows` dependency, so it is immune to
//! the version churn in those crates and pulls nothing extra into the build).
//!
//! The handle **must** be overlapped: the daemon reads commands on one thread and
//! writes events on another, and on a *synchronous* pipe handle Windows
//! serializes all I/O — a blocked `ReadFile` (waiting for a command) would block
//! every concurrent `WriteFile` (sending an event), which deadlocks the pipeline
//! (no events out -> no verdicts in -> read never unblocks). With overlapped I/O
//! each operation carries its own OVERLAPPED + event and completes independently,
//! so reads and writes run concurrently.
//!
//! The pipe is **message** type so each agent `WriteFile` (one per command)
//! arrives as a single message on our read side — one message maps to one
//! `Device::write`, exactly like one IRP per `WriteFile` in the kernel. The agent
//! reads events in byte mode (its default), so the byte-oriented event parser is
//! unaffected by message boundaries.

use std::ffi::c_void;
use std::io;
use std::ptr;

type Handle = *mut c_void;
type Bool = i32;
type Dword = u32;

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    h_event: Handle,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateNamedPipeW(
        name: *const u16,
        open_mode: Dword,
        pipe_mode: Dword,
        max_instances: Dword,
        out_buffer_size: Dword,
        in_buffer_size: Dword,
        default_timeout: Dword,
        security_attributes: *mut c_void,
    ) -> Handle;
    fn ConnectNamedPipe(pipe: Handle, overlapped: *mut Overlapped) -> Bool;
    fn DisconnectNamedPipe(pipe: Handle) -> Bool;
    fn ReadFile(
        file: Handle,
        buffer: *mut u8,
        to_read: Dword,
        read: *mut Dword,
        overlapped: *mut Overlapped,
    ) -> Bool;
    fn WriteFile(
        file: Handle,
        buffer: *const u8,
        to_write: Dword,
        written: *mut Dword,
        overlapped: *mut Overlapped,
    ) -> Bool;
    fn GetOverlappedResult(
        file: Handle,
        overlapped: *mut Overlapped,
        transferred: *mut Dword,
        wait: Bool,
    ) -> Bool;
    fn CreateEventW(
        attributes: *mut c_void,
        manual_reset: Bool,
        initial_state: Bool,
        name: *const u16,
    ) -> Handle;
    fn CloseHandle(handle: Handle) -> Bool;
    fn GetLastError() -> Dword;
}

const FILE_FLAG_OVERLAPPED: Dword = 0x4000_0000;
const PIPE_ACCESS_DUPLEX: Dword = 0x0000_0003;
const PIPE_TYPE_MESSAGE: Dword = 0x0000_0004;
const PIPE_READMODE_MESSAGE: Dword = 0x0000_0002;
const PIPE_WAIT: Dword = 0x0000_0000;
const PIPE_UNLIMITED_INSTANCES: Dword = 255;
const INVALID_HANDLE_VALUE: isize = -1;
const ERROR_IO_PENDING: Dword = 997;
// A client connected between CreateNamedPipe and ConnectNamedPipe; not an error.
const ERROR_PIPE_CONNECTED: Dword = 535;

pub struct PipeServer {
    handle: Handle,
}

// The handle is read on the command-pump thread and written on the event-pump
// thread concurrently. With overlapped I/O (each op carries its own OVERLAPPED)
// this is sound; the main thread calls `disconnect`.
unsafe impl Send for PipeServer {}
unsafe impl Sync for PipeServer {}

impl PipeServer {
    /// Create the overlapped, message-mode pipe server (e.g. `\\.\pipe\ZenithFence`).
    pub fn create(name: &str) -> io::Result<Self> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                ptr::null_mut(),
            )
        };
        if handle as isize == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle })
    }

    /// Block until a client (the Go agent) connects.
    pub fn wait_for_client(&self) -> io::Result<()> {
        let event = new_event()?;
        let mut ov = zeroed_overlapped(event);
        let ok = unsafe { ConnectNamedPipe(self.handle, &mut ov) };
        let result = if ok != 0 {
            Ok(())
        } else {
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => Ok(()),
                ERROR_IO_PENDING => self.wait(&mut ov).map(|_| ()),
                err => Err(io::Error::from_raw_os_error(err as i32)),
            }
        };
        unsafe { CloseHandle(event) };
        result
    }

    /// Write all `bytes` to the pipe (event stream → agent).
    pub fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            let n = self.overlapped(|ov| unsafe {
                WriteFile(
                    self.handle,
                    bytes[offset..].as_ptr(),
                    (bytes.len() - offset) as Dword,
                    ptr::null_mut(),
                    ov,
                )
            })?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "pipe wrote 0 bytes"));
            }
            offset += n;
        }
        Ok(())
    }

    /// Read one command message (agent → command channel). Returns the byte
    /// count, or `Err` once the client disconnects.
    pub fn read_message(&self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len() as Dword;
        let ptr = buf.as_mut_ptr();
        self.overlapped(|ov| unsafe { ReadFile(self.handle, ptr, len, ptr::null_mut(), ov) })
    }

    /// Force the connection closed: completes both a pending server `ReadFile`
    /// and the agent's `ReadFile` with an error, so each side's loop ends.
    pub fn disconnect(&self) {
        unsafe {
            DisconnectNamedPipe(self.handle);
        }
    }

    /// Run an overlapped op (started by `start`) to completion and return the
    /// number of bytes transferred.
    fn overlapped(&self, start: impl FnOnce(*mut Overlapped) -> Bool) -> io::Result<usize> {
        let event = new_event()?;
        let mut ov = zeroed_overlapped(event);
        let ok = start(&mut ov);
        let result = if ok != 0 {
            self.wait(&mut ov)
        } else {
            match unsafe { GetLastError() } {
                ERROR_IO_PENDING => self.wait(&mut ov),
                err => Err(io::Error::from_raw_os_error(err as i32)),
            }
        };
        unsafe { CloseHandle(event) };
        result
    }

    /// Block on an overlapped op's completion; returns bytes transferred.
    fn wait(&self, ov: &mut Overlapped) -> io::Result<usize> {
        let mut transferred: Dword = 0;
        let ok = unsafe { GetOverlappedResult(self.handle, ov, &mut transferred, 1) };
        if ok != 0 {
            Ok(transferred as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

fn new_event() -> io::Result<Handle> {
    let event = unsafe { CreateEventW(ptr::null_mut(), 1, 0, ptr::null()) };
    if event.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(event)
    }
}

fn zeroed_overlapped(event: Handle) -> Overlapped {
    Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        h_event: event,
    }
}
