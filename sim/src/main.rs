//! Real-world userspace simulation: a *fake driver* the real Go agent connects
//! to over a Windows named pipe.
//!
//! Loads the real driver over `mock_wdk` ([`driver::sim::Simulation`]), exposes
//! it on `\\.\pipe\ZenithFence`, and bridges the pipe to the driver's user-space
//! channel ([`DriverConnection`] read/write). A producer injects fake OS network
//! events through the driver's callout entry points; the agent reads the
//! resulting events and writes verdicts back, exactly as it does against the
//! kernel device.
//!
//! Threads (genuine concurrency, all funnelling to the one global `Device`):
//!   - producer ("kernel"): runs callouts that pend packets and emit events
//!   - event pump: blocks on `DriverConnection::read`, ships bytes to the pipe
//!   - command pump: reads command messages from the pipe, applies them
//!
//! Teardown order is load-bearing: drain → `shutdown` (runs down the event queue
//! so the blocked event pump wakes with end-of-file) → join event pump →
//! `disconnect` (so the agent exits and the command pump's blocked read errors)
//! → join command pump.

mod pipe;
mod producer;

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use driver::fuzz_api::packet_cache_len;
use driver::sim::Simulation;
use mock_wdk::kernel_types::{STATUS_END_OF_FILE, STATUS_SUCCESS};

use pipe::PipeServer;

const PIPE_NAME: &str = r"\\.\pipe\ZenithFence";
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> std::process::ExitCode {
    println!("[sim] loading driver over mock_wdk ...");
    let sim = match Simulation::start() {
        Ok(sim) => sim,
        Err(status) => {
            eprintln!("[sim] driver_entry failed: {status:#x}");
            return std::process::ExitCode::FAILURE;
        }
    };

    println!("[sim] creating pipe {PIPE_NAME}");
    let server = match PipeServer::create(PIPE_NAME) {
        Ok(server) => Arc::new(server),
        Err(err) => {
            eprintln!("[sim] CreateNamedPipe failed: {err}");
            return std::process::ExitCode::FAILURE;
        }
    };

    println!("[sim] waiting for agent to connect ...");
    if let Err(err) = server.wait_for_client() {
        eprintln!("[sim] ConnectNamedPipe failed: {err}");
        return std::process::ExitCode::FAILURE;
    }
    println!("[sim] agent connected");

    // Event pump: driver events -> pipe. Its own connection, blocking reads.
    let mut evt_conn = sim.connect();
    let evt_pipe = Arc::clone(&server);
    let evt_thread = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut reads = 0u64;
        loop {
            let (n, status) = evt_conn.read(&mut buf);
            if status == STATUS_END_OF_FILE || status != STATUS_SUCCESS {
                break;
            }
            if n == 0 {
                continue;
            }
            if evt_pipe.write_all(&buf[..n]).is_err() {
                break;
            }
            reads += 1;
        }
        reads
    });

    // Command pump: pipe -> driver. One command message per read.
    let mut cmd_conn = sim.connect();
    let cmd_pipe = Arc::clone(&server);
    let cmd_thread = thread::spawn(move || {
        let mut buf = [0u8; 512];
        let mut commands = 0u64;
        loop {
            match cmd_pipe.read_message(&mut buf) {
                Ok(0) => continue,
                Ok(n) => {
                    cmd_conn.write(&buf[..n]);
                    commands += 1;
                }
                Err(_) => break,
            }
        }
        commands
    });

    // Producer: fake OS network events.
    println!("[sim] producing fake network events ...");
    let produced = producer::drive();
    println!("[sim] pended {produced} flows; waiting for verdicts ...");

    // Wait for the agent's verdicts to drain the pended packets.
    let drained = wait_until(DRAIN_TIMEOUT, || packet_cache_len() == 0);
    println!(
        "[sim] verdicts drained={drained} (packet cache len={})",
        packet_cache_len()
    );

    // The outcome is already known (the agent's verdicts drained every pended
    // packet), so decide pass/fail now and let a watchdog enforce it even if the
    // best-effort clean teardown below stalls on a blocked pipe read.
    let pass = drained && packet_cache_len() == 0;
    let exit_code = if pass { 0 } else { 1 };
    spawn_exit_watchdog(Duration::from_secs(10), exit_code);

    // Teardown (best effort): run down the event queue so the event pump wakes
    // with EOF; join it; force the connection closed so the agent exits and the
    // command pump's blocked read returns an error; join it.
    sim.shutdown();
    let reads = evt_thread.join().unwrap_or(0);
    server.disconnect();
    let commands = cmd_thread.join().unwrap_or(0);
    println!(
        "[sim] done: {reads} event reads, {commands} commands applied, cache={}",
        packet_cache_len()
    );

    // `sim` drops here, unloading the driver. Threads are already joined.
    drop(sim);

    if pass {
        println!("[sim] PASS");
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("[sim] FAIL: verdicts did not drain / packet cache not empty after shutdown");
        std::process::ExitCode::FAILURE
    }
}

/// Backstop so the harness can never hang: if clean teardown does not finish
/// within `after`, terminate the process with the already-decided exit code.
fn spawn_exit_watchdog(after: Duration, code: i32) {
    thread::spawn(move || {
        thread::sleep(after);
        eprintln!("[sim] watchdog: teardown stalled after {after:?}; forcing exit {code}");
        std::process::exit(code);
    });
}

/// Poll `cond` until it is true or `timeout` elapses.
fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if cond() {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}
