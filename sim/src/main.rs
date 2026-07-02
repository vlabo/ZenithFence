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
mod rng;
mod scenarios;

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use driver::fuzz_api::{filter_engine_snapshot, packet_cache_len, Layer};
use driver::sim::Simulation;
use mock_wdk::kernel_types::{STATUS_END_OF_FILE, STATUS_SUCCESS};

use pipe::PipeServer;

const PIPE_NAME: &str = r"\\.\pipe\ZenithFence";

fn main() -> std::process::ExitCode {
    let cfg = producer::Config::from_env();
    println!(
        "[sim] seed=0x{:016x} flows={} threads={} (ZF_SIM_SEED / ZF_SIM_FLOWS / ZF_SIM_THREADS)",
        cfg.seed, cfg.random_flows, cfg.threads
    );

    println!("[sim] loading driver over mock_wdk ...");
    let sim = match Simulation::start() {
        Ok(sim) => sim,
        Err(status) => {
            eprintln!("[sim] driver_entry failed: {status:#x}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Loading-fidelity oracle: the driver must have committed the filter engine
    // with the production callout set, like a real kernel load would.
    if let Err(err) = check_registration() {
        eprintln!("[sim] FAIL: {err}");
        return std::process::ExitCode::FAILURE;
    }
    println!("[sim] filter engine committed; all callouts registered");

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

    // Producer: fake OS network traffic (scenarios + seeded random flows).
    // `drive` returns once every flow ran, the agent's verdicts resolved every
    // pended packet, and the reinjector replayed every injected packet.
    println!("[sim] producing fake network traffic ...");
    let summary = producer::drive(&cfg);
    summary.print();

    // The outcome is already known, so decide pass/fail now and let a watchdog
    // enforce it even if the best-effort clean teardown below stalls on a
    // blocked pipe read.
    let pass = summary.is_ok() && packet_cache_len() == 0;
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
        eprintln!("[sim] FAIL: traffic invariants violated (see failures above)");
        std::process::ExitCode::FAILURE
    }
}

/// Assert the driver's load registered exactly the production callout set, on
/// the expected layers, inside a committed filter-engine transaction.
fn check_registration() -> Result<(), String> {
    let snapshot = filter_engine_snapshot().ok_or("no device installed after driver_entry")?;
    if !snapshot.committed {
        return Err("filter engine transaction not committed".into());
    }
    let expected = [
        Layer::AleAuthConnectV4,
        Layer::AleAuthRecvAcceptV4,
        Layer::AleAuthConnectV6,
        Layer::AleAuthRecvAcceptV6,
        Layer::AleEndpointClosureV4,
        Layer::AleEndpointClosureV6,
        Layer::AleResourceReleaseV4,
        Layer::AleResourceReleaseV6,
        Layer::OutboundIppacketV4,
        Layer::InboundIppacketV4,
        Layer::OutboundIppacketV6,
        Layer::InboundIppacketV6,
    ];
    let layers: Vec<Layer> = snapshot.callouts.iter().map(|(_, layer, _)| *layer).collect();
    if layers != expected {
        return Err(format!("registered callout layers mismatch: {layers:?}"));
    }
    if snapshot.callouts.iter().any(|(_, _, filter_id)| *filter_id == 0) {
        return Err("a callout has no registered filter".into());
    }
    Ok(())
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

