//! Unix domain socket server: the Unix counterpart of the Windows named pipe.
//!
//! A `SOCK_STREAM` socket from `std` (no extra dependencies). Reads and writes
//! run on separate threads over separate fds (`try_clone`), the same concurrency
//! the overlapped pipe provides on Windows.
//!
//! Stream sockets don't keep message boundaries, but the driver needs one command
//! per `Device::write` (one IRP per `WriteFile` in the kernel). So on this
//! transport each agent command arrives as a frame: a `u32` little-endian length,
//! then that many bytes. `SOCK_SEQPACKET` would keep the boundaries without
//! framing, but it truncates any message larger than the reader's buffer, and the
//! agent deliberately reads events through a small (1 KiB) buffer. Events are
//! therefore sent as a plain byte stream, exactly like the pipe's byte-mode reads.

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::OnceLock;

pub struct PipeServer {
    path: String,
    listener: UnixListener,
    // Set once by `wait_for_client`; the reader and writer are separate fds so
    // the command and event pumps never contend on one handle.
    reader: OnceLock<UnixStream>,
    writer: OnceLock<UnixStream>,
}

impl PipeServer {
    /// Bind the socket at `path`, replacing a stale socket file left by a
    /// daemon that was killed before it could clean up.
    pub fn create(path: &str) -> io::Result<Self> {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let listener = UnixListener::bind(path)?;
        Ok(Self {
            path: path.to_string(),
            listener,
            reader: OnceLock::new(),
            writer: OnceLock::new(),
        })
    }

    /// Block until a client (the Go agent) connects.
    pub fn wait_for_client(&self) -> io::Result<()> {
        let (stream, _) = self.listener.accept()?;
        let writer = stream.try_clone()?;
        let _ = self.reader.set(stream);
        let _ = self.writer.set(writer);
        Ok(())
    }

    /// Write all `bytes` to the socket (event stream → agent).
    pub fn write_all(&self, bytes: &[u8]) -> io::Result<()> {
        let mut writer = self.writer.get().ok_or_else(not_connected)?;
        writer.write_all(bytes)
    }

    /// Read one length-prefixed command frame into `buf` (agent → command
    /// channel). Returns the byte count, or `Err` once the client disconnects or
    /// sends a frame that doesn't fit `buf`.
    pub fn read_message(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut reader = self.reader.get().ok_or_else(not_connected)?;
        let mut len = [0u8; 4];
        reader.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        if len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("command frame of {len} bytes exceeds {}-byte buffer", buf.len()),
            ));
        }
        reader.read_exact(&mut buf[..len])?;
        Ok(len)
    }

    /// Force the connection closed, ending both pumps. Unused while the
    /// producer runs forever; kept for parity with the Windows pipe.
    #[allow(dead_code)]
    pub fn disconnect(&self) {
        if let Some(stream) = self.reader.get() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn not_connected() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "no agent connected")
}
