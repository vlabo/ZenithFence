//! Loading the driver and bridging it to an agent on the pipe.
//!
//! [`Pumps`] are the two threads between the pipe and the driver's user-space
//! channel (events out, commands in). They can *tee* what flows through them
//! ([`Tap`]), which is how a script sees the events a real agent receives and
//! the commands (verdicts) it sends back.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use driver_harness::api::{filter_engine_snapshot, Layer};
use driver_harness::loader;
use driver_harness::sim::{Event, EventParser, Simulation};
use mock_wdk::connection::DriverConnection;
use mock_wdk::kernel_types::{STATUS_END_OF_FILE, STATUS_SUCCESS};

use crate::pipe::PipeServer;

/// Default logical endpoint name; mapped per OS by [`crate::pipe::endpoint`].
pub const DEFAULT_PIPE_NAME: &str = "ZenithFence";

/// One observation made by a pump.
pub enum TapMessage {
    /// A whole event frame the driver sent towards the agent.
    Event(Event),
    /// One command message the agent wrote towards the driver (raw bytes,
    /// `[CommandType, ...]`).
    Command(Vec<u8>),
}

/// Callback receiving everything that passes through the pumps. Called on the
/// pump threads, so it must not block for long.
pub type Tap = Arc<dyn Fn(TapMessage) + Send + Sync>;

/// Load the real driver over mock_wdk and check it registered like a kernel
/// load would.
pub fn load_driver() -> Result<Simulation, String> {
    let sim = Simulation::start().map_err(|status| format!("driver_entry failed: {status:#x}"))?;

    // Loading-fidelity oracle: the driver must have committed the filter engine
    // with the production callout set, like a real kernel load would.
    check_registration()?;
    Ok(sim)
}

/// Open a fresh user-space connection to the loaded driver, from any thread
/// (the same as `Simulation::connect`, which needs the `Simulation` handle).
/// `None` if no driver is loaded.
pub fn connect() -> Option<DriverConnection> {
    loader::with_driver_object(DriverConnection::open).flatten()
}

/// The two threads bridging the pipe and the driver's user-space channel. Both
/// set `stop` once the agent is gone.
pub struct Pumps {
    events: JoinHandle<()>,
    commands: JoinHandle<()>,
}

impl Pumps {
    /// `evt_conn` / `cmd_conn` are two fresh connections to the loaded driver
    /// ([`connect`], or `Simulation::connect`); each pump owns one.
    pub fn spawn(
        mut evt_conn: DriverConnection,
        mut cmd_conn: DriverConnection,
        server: &Arc<PipeServer>,
        stop: Arc<AtomicBool>,
        tap: Option<Tap>,
    ) -> Self {
        // Event pump: driver events -> pipe. Its own connection, blocking reads;
        // ends when the driver's event queue is run down or the agent is gone.
        let evt_pipe = Arc::clone(server);
        let evt_stop = Arc::clone(&stop);
        let evt_tap = tap.clone();
        let events = thread::spawn(move || {
            let mut parser = EventParser::new();
            loop {
                let mut buf = [0u8; 4096];
                let (n, status) = evt_conn.read(&mut buf);
                if status == STATUS_END_OF_FILE || status != STATUS_SUCCESS {
                    break;
                }
                if n == 0 {
                    continue;
                }
                // Parse for the tap only; the agent gets the raw bytes untouched.
                if let Some(tap) = &evt_tap {
                    parser.feed(&buf[..n]);
                    while let Some(event) = parser.next_event() {
                        tap(TapMessage::Event(event));
                    }
                }
                if evt_pipe.write_all(&buf[..n]).is_err() {
                    evt_stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
        });

        // Command pump: pipe -> driver. One command message per read; ends when
        // the agent disconnects.
        let cmd_pipe = Arc::clone(server);
        let commands = thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                match cmd_pipe.read_message(&mut buf) {
                    Ok(0) => continue,
                    Ok(n) => {
                        // Tee before applying, so a script that waits on the
                        // command sees it no later than its effect.
                        if let Some(tap) = &tap {
                            tap(TapMessage::Command(buf[..n].to_vec()));
                        }
                        cmd_conn.write(&buf[..n]);
                    }
                    Err(_) => break,
                }
            }
            stop.store(true, Ordering::Relaxed);
        });

        Self { events, commands }
    }

    pub fn join(self) {
        let _ = self.commands.join();
        let _ = self.events.join();
    }
}

/// Assert the driver's load registered exactly the production callout set, on
/// the expected layers, inside a committed filter-engine transaction.
pub fn check_registration() -> Result<(), String> {
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
