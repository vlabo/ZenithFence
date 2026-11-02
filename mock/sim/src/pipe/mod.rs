//! The agent-facing endpoint, one implementation per OS behind the same
//! `PipeServer` API (`create`, `wait_for_client`, `write_all`, `read_message`,
//! `disconnect`). One client is served at a time; after `disconnect` the server
//! can `wait_for_client` again for the next one:
//!
//! * Windows: an overlapped, message-mode named pipe (`\\.\pipe\<name>`).
//! * Unix: a stream Unix domain socket. Stream sockets don't preserve message
//!   boundaries, so on this transport the agent prefixes each command with a
//!   `u32` little-endian length, which restores "one command message = one
//!   `Device::write`". The event direction stays an unframed byte stream on both.
//!
//! The endpoint is always a full path (`\\.\pipe\<name>` on Windows, a socket
//! file path on Unix), used verbatim; the script and the agent (`ZF_SIM_PIPE` on
//! the Go side) each set it themselves.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::PipeServer;
#[cfg(windows)]
pub use windows::PipeServer;

/// Connect to `endpoint` and hang up at once. Wakes a server of ours blocked in
/// `wait_for_client` when nobody else is going to connect (shutting down).
pub fn poke(endpoint: &str) {
    #[cfg(windows)]
    let _ = std::fs::OpenOptions::new().read(true).write(true).open(endpoint);
    #[cfg(unix)]
    let _ = std::os::unix::net::UnixStream::connect(endpoint);
}
