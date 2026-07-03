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
//! The producer runs forever, so there is no clean-teardown phase: a healthy run
//! ends when the user stops it (Ctrl+C), and a broken invariant ends it via the
//! monitor thread's non-zero `process::exit`. Either way the OS reclaims the
//! driver, the pumps, and the pipe.

mod pipe;
mod producer;
mod rng;
mod scenarios;

use std::sync::Arc;
use std::thread;

use driver::fuzz_api::{filter_engine_snapshot, Layer};
use driver::sim::Simulation;
use mock_wdk::kernel_types::{STATUS_END_OF_FILE, STATUS_SUCCESS};

use pipe::PipeServer;

const PIPE_NAME: &str = r"\\.\pipe\ZenithFence";

fn main() -> std::process::ExitCode {
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
    let _evt_pump = thread::spawn(move || {
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
    let _cmd_pump = thread::spawn(move || {
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

    // Producer: fake OS network traffic (seeded random flows), forever. `drive`
    // never returns -- the monitor thread exits the process non-zero the moment
    // an invariant breaks, and Ctrl+C stops a healthy run. `sim` and the pumps
    // stay alive for the whole run because `main` never returns past this call.
    println!("[sim] producing fake network traffic ...");
    producer::drive();

    // Unreachable in practice (`drive` loops forever); kept so `main` returns an
    // `ExitCode` on every path.
    std::process::ExitCode::SUCCESS
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

