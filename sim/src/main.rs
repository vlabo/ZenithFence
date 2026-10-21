//! Real-world userspace simulation: a *fake driver* the real Go agent connects
//! to over a Windows named pipe or, on Unix, a Unix domain socket (see [`pipe`]).
//!
//! Loads the real driver over `mock_wdk` ([`driver::sim::Simulation`]), exposes
//! it on the endpoint named by `ZF_SIM_PIPE` (default `ZenithFence`, i.e.
//! `\\.\pipe\ZenithFence` on Windows; a full `\\.\pipe\...` path is used as is),
//! waits for an agent to connect, and bridges the pipe to the driver's
//! user-space channel ([`DriverConnection`] read/write). A producer injects fake
//! OS network events through the driver's callout entry points; the agent reads
//! the resulting events and writes verdicts back, exactly as it does against the
//! kernel device.
//!
//! Threads (genuine concurrency, all funnelling to the one global `Device`):
//!   - producer ("kernel"): runs callouts that pend packets and emit events
//!   - event pump: blocks on `DriverConnection::read`, ships bytes to the pipe
//!   - command pump: reads command messages from the pipe, applies them
//!
//! With no scenario file the daemon serves agents one after another until the
//! user stops it (Ctrl+C): each agent session gets a freshly loaded driver and
//! seeded-random traffic, and when the agent disconnects the driver is unloaded
//! and the daemon waits for the next agent -- the way the agent's Start/Stop load
//! and unload the kernel driver. A broken invariant ends the process via the
//! monitor thread's non-zero `process::exit`. `--any-verdict` /
//! `ZF_SIM_ANY_VERDICT` lets a real agent decide verdicts by its own policy (see
//! [`producer::VerdictPolicy`]). Given a scenario file (positional arg or
//! `ZF_SIM_SCENARIO`, see [`scenario`]) the daemon instead serves one agent,
//! replays that file on a worker pool and exits when it finishes. Either way the
//! OS reclaims the driver, the pumps, and the pipe.

mod dns;
mod pipe;
mod producer;
mod rng;
mod scenario;
mod scenarios;

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use driver::fuzz_api::{filter_engine_snapshot, Layer};
use driver::sim::Simulation;
use mock_wdk::kernel_types::{STATUS_END_OF_FILE, STATUS_SUCCESS};

use pipe::PipeServer;
use producer::VerdictPolicy;

/// Logical endpoint name when `ZF_SIM_PIPE` is unset; mapped per OS by [`pipe::endpoint`].
const DEFAULT_PIPE_NAME: &str = "ZenithFence";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    // `zf-sim --emit-samples [dir]` writes the reference scenario files and exits
    // without loading the driver -- handy for authoring / regenerating fixtures.
    if args.get(1).map(String::as_str) == Some("--emit-samples") {
        let dir = args.get(2).map(String::as_str).unwrap_or("./sim/scenarios");
        return match scenario::emit_samples(dir) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("[sim] --emit-samples failed: {err}");
                ExitCode::FAILURE
            }
        };
    }

    // A scenario file (first non-flag arg or ZF_SIM_SCENARIO) switches the traffic
    // source from seeded-random to deterministic file replay. Verdicts still come
    // from the Go agent over the pipe -- only the injection source changes. Finding
    // the first non-flag arg lets the path sit before or after flags like --loop.
    let scenario_path = std::env::var("ZF_SIM_SCENARIO")
        .ok()
        .or_else(|| args.iter().skip(1).find(|a| !a.starts_with("--")).cloned());

    // --loop / ZF_SIM_LOOP replays the scenario on repeat, restarting from the top
    // each time it finishes, until the process is stopped (Ctrl+C). The env var is
    // how the agent-spawned daemon receives it (like ZF_SIM_SCENARIO); the flag is
    // for running the daemon directly.
    let looping = args.iter().any(|a| a == "--loop") || std::env::var_os("ZF_SIM_LOOP").is_some();

    // --any-verdict / ZF_SIM_ANY_VERDICT: the random producer accepts whatever
    // verdict the agent decides (a real agent with its own policy) instead of
    // kext_tester's fixed rules.
    let policy = if args.iter().any(|a| a == "--any-verdict")
        || std::env::var_os("ZF_SIM_ANY_VERDICT").is_some()
    {
        VerdictPolicy::Any
    } else {
        VerdictPolicy::Expected
    };

    let sim = match load_driver() {
        Ok(sim) => sim,
        Err(code) => return code,
    };

    // The agent-spawned daemon inherits ZF_SIM_PIPE from the agent, so both
    // sides agree on the endpoint.
    let pipe_name = std::env::var("ZF_SIM_PIPE").unwrap_or_else(|_| DEFAULT_PIPE_NAME.into());
    let endpoint = pipe::endpoint(&pipe_name);
    println!("[sim] creating endpoint {endpoint}");
    let server = match PipeServer::create(&endpoint) {
        Ok(server) => Arc::new(server),
        Err(err) => {
            eprintln!("[sim] creating endpoint {endpoint} failed: {err}");
            return ExitCode::FAILURE;
        }
    };

    let Some(path) = scenario_path else {
        return serve_agents(sim, &server, policy);
    };

    if let Err(code) = wait_for_agent(&server) {
        return code;
    }
    // The scenario modes serve one agent; the pumps run until the process exits.
    let _pumps = Pumps::spawn(&sim, &server, Arc::new(AtomicBool::new(false)));

    // A scenario file replays deterministically on a worker pool (verdicts still
    // come from the agent over the pipe), once or -- with --loop / ZF_SIM_LOOP --
    // restarting from the top until stopped. `sim` and the pumps stay alive across
    // the call because `main` does not return until it finishes.
    if looping {
        // Loop until the user stops the process, resetting the driver between
        // passes so each is an independent scenario. Diverges: `run_loop` prints
        // the accumulated totals on Ctrl+C and exits; the OS reclaims `sim` and
        // the pumps.
        println!("[sim] looping scenario `{path}` until stopped (Ctrl+C) ...");
        scenario::run_loop(&path);
    }
    println!("[sim] replaying scenario `{path}` ...");
    let summary = scenario::run(&path);
    summary.print();
    sim.shutdown();
    if summary.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Random-traffic mode: serve agents one after another until the process is
/// stopped. Each session mirrors the agent's Start/Stop of the kernel driver: the
/// producer runs while the agent is connected; once it disconnects the driver is
/// shut down and unloaded, and a fresh one is loaded for the next agent.
fn serve_agents(mut sim: Simulation, server: &Arc<PipeServer>, policy: VerdictPolicy) -> ExitCode {
    loop {
        if let Err(code) = wait_for_agent(server) {
            return code;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let pumps = Pumps::spawn(&sim, server, Arc::clone(&stop));
        println!("[sim] producing fake network traffic ...");
        producer::drive(policy, stop);

        // Teardown order is load-bearing (see driver::sim): run down the event
        // queue so the event pump wakes, join the pumps, only then unload.
        sim.shutdown();
        pumps.join();
        drop(sim);
        server.disconnect();
        println!("[sim] agent disconnected; driver unloaded");

        sim = match load_driver() {
            Ok(sim) => sim,
            Err(code) => return code,
        };
    }
}

/// Load the real driver over mock_wdk and check it registered like a kernel
/// load would.
fn load_driver() -> Result<Simulation, ExitCode> {
    println!("[sim] loading driver over mock_wdk ...");
    let sim = Simulation::start().map_err(|status| {
        eprintln!("[sim] driver_entry failed: {status:#x}");
        ExitCode::FAILURE
    })?;

    // Loading-fidelity oracle: the driver must have committed the filter engine
    // with the production callout set, like a real kernel load would.
    if let Err(err) = check_registration() {
        eprintln!("[sim] FAIL: {err}");
        return Err(ExitCode::FAILURE);
    }
    println!("[sim] filter engine committed; all callouts registered");
    Ok(sim)
}

fn wait_for_agent(server: &PipeServer) -> Result<(), ExitCode> {
    println!("[sim] waiting for agent to connect ...");
    if let Err(err) = server.wait_for_client() {
        eprintln!("[sim] waiting for agent failed: {err}");
        return Err(ExitCode::FAILURE);
    }
    println!("[sim] agent connected");
    Ok(())
}

/// The two threads bridging the pipe and the driver's user-space channel. Both
/// set `stop` once the agent is gone.
struct Pumps {
    events: JoinHandle<()>,
    commands: JoinHandle<()>,
}

impl Pumps {
    fn spawn(sim: &Simulation, server: &Arc<PipeServer>, stop: Arc<AtomicBool>) -> Self {
        // Event pump: driver events -> pipe. Its own connection, blocking reads;
        // ends when the driver's event queue is run down or the agent is gone.
        let mut evt_conn = sim.connect();
        let evt_pipe = Arc::clone(server);
        let evt_stop = Arc::clone(&stop);
        let events = thread::spawn(move || loop {
            let mut buf = [0u8; 4096];
            let (n, status) = evt_conn.read(&mut buf);
            if status == STATUS_END_OF_FILE || status != STATUS_SUCCESS {
                break;
            }
            if n == 0 {
                continue;
            }
            if evt_pipe.write_all(&buf[..n]).is_err() {
                evt_stop.store(true, Ordering::Relaxed);
                break;
            }
        });

        // Command pump: pipe -> driver. One command message per read; ends when
        // the agent disconnects.
        let mut cmd_conn = sim.connect();
        let cmd_pipe = Arc::clone(server);
        let commands = thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                match cmd_pipe.read_message(&mut buf) {
                    Ok(0) => continue,
                    Ok(n) => {
                        cmd_conn.write(&buf[..n]);
                    }
                    Err(_) => break,
                }
            }
            stop.store(true, Ordering::Relaxed);
        });

        Self { events, commands }
    }

    fn join(self) {
        let _ = self.commands.join();
        let _ = self.events.join();
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
