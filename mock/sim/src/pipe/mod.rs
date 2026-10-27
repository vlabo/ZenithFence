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
//! [`endpoint`] maps the logical name (`ZF_SIM_PIPE` on the Go side) to the OS
//! address. The Go side (`kext_interface/sim_conn*.go`) applies the same rule.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::PipeServer;
#[cfg(windows)]
pub use windows::PipeServer;

/// The OS address for the logical endpoint `name`: `name` itself if it is a
/// full pipe path (`\\.\pipe\...`), else `\\.\pipe\<name>`.
#[cfg(windows)]
pub fn endpoint(name: &str) -> String {
    const PREFIX: &str = r"\\.\pipe\";
    if name.get(..PREFIX.len()).is_some_and(|p| p.eq_ignore_ascii_case(PREFIX)) {
        return name.to_string();
    }
    format!("{PREFIX}{name}")
}

/// The OS address for the logical endpoint `name`: `name` itself if it is a
/// path (contains `/`), else `$XDG_RUNTIME_DIR/<name>.sock`, falling back to
/// `/tmp/<name>.sock`.
#[cfg(unix)]
pub fn endpoint(name: &str) -> String {
    if name.contains('/') {
        return name.to_string();
    }
    match std::env::var("XDG_RUNTIME_DIR") {
        Ok(dir) if !dir.is_empty() => format!("{}/{name}.sock", dir.trim_end_matches('/')),
        _ => format!("/tmp/{name}.sock"),
    }
}

/// Connect to `endpoint` and hang up at once. Wakes a server of ours blocked in
/// `wait_for_client` when nobody else is going to connect (shutting down).
pub fn poke(endpoint: &str) {
    #[cfg(windows)]
    let _ = std::fs::OpenOptions::new().read(true).write(true).open(endpoint);
    #[cfg(unix)]
    let _ = std::os::unix::net::UnixStream::connect(endpoint);
}
