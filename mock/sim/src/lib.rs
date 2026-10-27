//! `zfsim._native`: the real ZenithFence driver (over the mock WDK) loaded
//! in-process and driven from Python through plain function calls.
//!
//! This crate is only the interface: scenarios, traffic, seeds and assertions
//! live in Python scripts. A [`Sim`] owns the one global driver and serves it on
//! the agent's named pipe / Unix socket (`serve()`); the agent is always a real
//! one connected there. The pumps tee the events the agent receives and the
//! commands it sends into queues the script reads.
//!
//! Traffic is injected through the driver's callout entry points (`ale_connect`,
//! `packet`, ...), exactly like the OS would. The wire protocol never reaches
//! Python: events are decoded by `driver_harness::sim`.

mod pipe;
mod pumps;

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use driver_harness::api::{self, CalloutResult, Direction, TupleSpecV4, TupleSpecV6};
use driver_harness::sim::{self as hsim, verdict_command, EventParser, Info, InfoTuple};
use mock_wdk::connection::DriverConnection;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use pipe::PipeServer;
use pumps::{Pumps, Tap, TapMessage};

/// Whether a [`Sim`] currently holds the driver (it is a process-wide global).
static OPEN: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Blocking queue with timeouts (events / commands handed to Python)
// ---------------------------------------------------------------------------

struct Queue<T> {
    state: Mutex<(VecDeque<T>, bool)>, // (items, closed)
    ready: Condvar,
}

impl<T> Queue<T> {
    fn new() -> Self {
        Self {
            state: Mutex::new((VecDeque::new(), false)),
            ready: Condvar::new(),
        }
    }

    fn push(&self, item: T) {
        self.state.lock().unwrap().0.push_back(item);
        self.ready.notify_all();
    }

    fn close(&self) {
        self.state.lock().unwrap().1 = true;
        self.ready.notify_all();
    }

    /// Next item, waiting up to `timeout` (`None`: until closed). `None` on
    /// timeout, or when closed and drained.
    fn pop(&self, timeout: Option<Duration>) -> Option<T> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut state = self.state.lock().unwrap();
        loop {
            if let Some(item) = state.0.pop_front() {
                return Some(item);
            }
            if state.1 {
                return None;
            }
            state = match deadline {
                None => self.ready.wait(state).unwrap(),
                Some(deadline) => {
                    let left = deadline.checked_duration_since(Instant::now())?;
                    self.ready.wait_timeout(state, left).unwrap().0
                }
            };
        }
    }

    fn len(&self) -> usize {
        self.state.lock().unwrap().0.len()
    }
}

fn timeout_of(secs: Option<f64>) -> PyResult<Option<Duration>> {
    match secs {
        None => Ok(None),
        Some(s) if s.is_finite() && s >= 0.0 => Ok(Some(Duration::from_secs_f64(s))),
        Some(s) => Err(PyValueError::new_err(format!("bad timeout {s}"))),
    }
}

// ---------------------------------------------------------------------------
// Flow: a 5-tuple
// ---------------------------------------------------------------------------

fn parse_proto(obj: &Bound<'_, PyAny>) -> PyResult<u8> {
    if let Ok(n) = obj.extract::<u8>() {
        return Ok(n);
    }
    let name: String = obj.extract()?;
    match name.to_ascii_lowercase().as_str() {
        "icmp" => Ok(1),
        "igmp" => Ok(2),
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmpv6" | "icmp6" => Ok(58),
        other => Err(PyValueError::new_err(format!("unknown protocol {other:?}"))),
    }
}

fn parse_ip(text: &str) -> PyResult<IpAddr> {
    text.parse()
        .map_err(|_| PyValueError::new_err(format!("bad IP address {text:?}")))
}

/// An IPv4 or IPv6 5-tuple. `protocol` is an IP protocol number or one of
/// `"tcp"`, `"udp"`, `"icmp"`; both addresses must be the same family.
#[pyclass(frozen, module = "zfsim")]
#[derive(Clone)]
struct Flow(InfoTuple);

impl Flow {
    fn v4(&self) -> Option<TupleSpecV4> {
        let t = &self.0;
        match (t.local, t.remote) {
            (IpAddr::V4(l), IpAddr::V4(r)) => Some(TupleSpecV4 {
                protocol: t.protocol,
                local: l.octets(),
                local_port: t.local_port,
                remote: r.octets(),
                remote_port: t.remote_port,
            }),
            _ => None,
        }
    }

    fn v6(&self) -> Option<TupleSpecV6> {
        let t = &self.0;
        match (t.local, t.remote) {
            (IpAddr::V6(l), IpAddr::V6(r)) => Some(TupleSpecV6 {
                protocol: t.protocol,
                local: l.octets(),
                local_port: t.local_port,
                remote: r.octets(),
                remote_port: t.remote_port,
            }),
            _ => None,
        }
    }
}

#[pymethods]
impl Flow {
    #[new]
    fn new(
        protocol: &Bound<'_, PyAny>,
        local: &str,
        local_port: u16,
        remote: &str,
        remote_port: u16,
    ) -> PyResult<Self> {
        let (local, remote) = (parse_ip(local)?, parse_ip(remote)?);
        if local.is_ipv4() != remote.is_ipv4() {
            return Err(PyValueError::new_err("local and remote must be the same IP family"));
        }
        Ok(Self(InfoTuple {
            protocol: parse_proto(protocol)?,
            local,
            local_port,
            remote,
            remote_port,
        }))
    }

    #[getter]
    fn protocol(&self) -> u8 {
        self.0.protocol
    }
    #[getter]
    fn local(&self) -> String {
        self.0.local.to_string()
    }
    #[getter]
    fn local_port(&self) -> u16 {
        self.0.local_port
    }
    #[getter]
    fn remote(&self) -> String {
        self.0.remote.to_string()
    }
    #[getter]
    fn remote_port(&self) -> u16 {
        self.0.remote_port
    }
    #[getter]
    fn is_v6(&self) -> bool {
        self.0.local.is_ipv6()
    }

    /// Constructor syntax, as Python convention has it: `Flow('tcp', '10.0.0.5', 50000, ...)`.
    fn __repr__(&self) -> String {
        let t = &self.0;
        let protocol = match t.protocol {
            1 => "'icmp'".to_string(),
            2 => "'igmp'".to_string(),
            6 => "'tcp'".to_string(),
            17 => "'udp'".to_string(),
            58 => "'icmpv6'".to_string(),
            n => n.to_string(),
        };
        format!(
            "Flow({protocol}, '{}', {}, '{}', {})",
            t.local, t.local_port, t.remote, t.remote_port
        )
    }
    fn __eq__(&self, other: &Self) -> bool {
        self.0 == other.0
    }
    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.0.hash(&mut h);
        h.finish()
    }
}

// ---------------------------------------------------------------------------
// Events and commands
// ---------------------------------------------------------------------------

fn direction_name(d: u8) -> &'static str {
    match d {
        0 => "outbound",
        1 => "inbound",
        _ => "unknown",
    }
}

fn parse_direction(obj: &Bound<'_, PyAny>) -> PyResult<Direction> {
    if let Ok(n) = obj.extract::<u8>() {
        return match n {
            0 => Ok(Direction::Outbound),
            1 => Ok(Direction::Inbound),
            _ => Err(PyValueError::new_err("direction must be 0 or 1")),
        };
    }
    match obj.extract::<String>()?.to_ascii_lowercase().as_str() {
        "outbound" | "out" => Ok(Direction::Outbound),
        "inbound" | "in" => Ok(Direction::Inbound),
        other => Err(PyValueError::new_err(format!("unknown direction {other:?}"))),
    }
}

/// One event the driver sent towards the agent. `kind` is `"connection"` (a
/// pended packet awaiting a verdict), `"connection_end"`, `"connection_update"`,
/// `"update_end"` or `"log"`; the attributes that don't apply to a kind are
/// `None`. A frame that doesn't decode is kept as `"unknown"` with its raw
/// bytes rather than dropped, so a script can see a driver bug.
#[pyclass(frozen, module = "zfsim")]
#[derive(Clone)]
struct Event {
    info_type: u8,
    info: Option<Info>,
    raw: Vec<u8>,
}

impl From<hsim::Event> for Event {
    fn from(event: hsim::Event) -> Self {
        Self {
            info_type: event.info_type,
            info: event.decode(),
            raw: event.payload,
        }
    }
}

impl Event {
    fn tuple(&self) -> Option<&InfoTuple> {
        match &self.info {
            Some(Info::Connection { tuple, .. })
            | Some(Info::ConnectionEnd { tuple, .. })
            | Some(Info::ConnectionUpdate { tuple, .. }) => Some(tuple),
            _ => None,
        }
    }

    fn counters(&self) -> Option<&hsim::Counters> {
        match &self.info {
            Some(Info::ConnectionEnd { counters, .. }) | Some(Info::ConnectionUpdate { counters, .. }) => {
                Some(counters)
            }
            _ => None,
        }
    }
}

#[pymethods]
impl Event {
    #[getter]
    fn kind(&self) -> &'static str {
        match &self.info {
            Some(Info::Log { .. }) => "log",
            Some(Info::Connection { .. }) => "connection",
            Some(Info::ConnectionEnd { .. }) => "connection_end",
            Some(Info::ConnectionUpdate { .. }) => "connection_update",
            Some(Info::ConnectionUpdateEnd { .. }) => "update_end",
            None => "unknown",
        }
    }
    #[getter]
    fn info_type(&self) -> u8 {
        self.info_type
    }
    /// Packet id a `Verdict` command refers to (`"connection"` events).
    #[getter]
    fn id(&self) -> Option<u64> {
        match &self.info {
            Some(Info::Connection { id, .. }) => Some(*id),
            _ => None,
        }
    }
    #[getter]
    fn pid(&self) -> Option<u64> {
        match &self.info {
            Some(Info::Connection { process_id, .. }) | Some(Info::ConnectionEnd { process_id, .. }) => {
                Some(*process_id)
            }
            _ => None,
        }
    }
    /// `"outbound"` / `"inbound"`.
    #[getter]
    fn direction(&self) -> Option<&'static str> {
        match &self.info {
            Some(Info::Connection { direction, .. }) | Some(Info::ConnectionEnd { direction, .. }) => {
                Some(direction_name(*direction))
            }
            _ => None,
        }
    }
    #[getter]
    fn flow(&self) -> Option<Flow> {
        self.tuple().map(|t| Flow(*t))
    }
    #[getter]
    fn payload_layer(&self) -> Option<u8> {
        match &self.info {
            Some(Info::Connection { payload_layer, .. }) => Some(*payload_layer),
            _ => None,
        }
    }
    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        match &self.info {
            Some(Info::Connection { payload, .. }) => Some(PyBytes::new(py, payload)),
            _ => None,
        }
    }
    #[getter]
    fn rx_bytes(&self) -> Option<u64> {
        self.counters().map(|c| c.rx_bytes)
    }
    #[getter]
    fn rx_packets(&self) -> Option<u64> {
        self.counters().map(|c| c.rx_packets)
    }
    #[getter]
    fn tx_bytes(&self) -> Option<u64> {
        self.counters().map(|c| c.tx_bytes)
    }
    #[getter]
    fn tx_packets(&self) -> Option<u64> {
        self.counters().map(|c| c.tx_packets)
    }
    #[getter]
    fn severity(&self) -> Option<u8> {
        match &self.info {
            Some(Info::Log { severity, .. }) => Some(*severity),
            _ => None,
        }
    }
    #[getter]
    fn message(&self) -> Option<String> {
        match &self.info {
            Some(Info::Log { line, .. }) => Some(line.clone()),
            _ => None,
        }
    }
    /// The driver's cursor (`"update_end"` events): send it unchanged with the
    /// next `GetConnectionsUpdate` to get the connections active since.
    #[getter]
    fn timestamp(&self) -> Option<u64> {
        match &self.info {
            Some(Info::ConnectionUpdateEnd { timestamp }) => Some(*timestamp),
            _ => None,
        }
    }
    /// The frame's payload bytes as the driver wrote them.
    #[getter]
    fn raw<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.raw)
    }

    fn __repr__(&self) -> String {
        match (self.flow(), self.id()) {
            (Some(flow), Some(id)) => format!(
                "Event(connection id={id} {} {})",
                self.direction().unwrap_or("unknown"),
                flow.__repr__()
            ),
            (Some(flow), None) => format!("Event({} {})", self.kind(), flow.__repr__()),
            _ => format!("Event({})", self.kind()),
        }
    }
}

/// Splits the driver's event byte stream into [`Event`]s, for a script that
/// reads the pipe itself (a hand-written agent): `feed(bytes)` returns every
/// event completed so far; a frame may span several reads.
#[pyclass(module = "zfsim")]
#[derive(Default)]
struct EventStream(EventParser);

#[pymethods]
impl EventStream {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn feed(&mut self, data: &[u8]) -> Vec<Event> {
        self.0.feed(data);
        std::iter::from_fn(|| self.0.next_event()).map(Event::from).collect()
    }
}

const COMMAND_NAMES: [&str; 9] = [
    "shutdown",
    "verdict",
    "update_v4",
    "update_v6",
    "clear_cache",
    "get_connections_update",
    "get_logs",
    "print_memory_stats",
    "clean_ended_connections",
];

/// One command written towards the driver (`name` e.g. `"verdict"`; for a
/// verdict, `id` and `verdict` are set).
#[pyclass(frozen, module = "zfsim")]
#[derive(Clone)]
struct Command {
    raw: Vec<u8>,
}

#[pymethods]
impl Command {
    #[getter]
    fn name(&self) -> &'static str {
        self.raw
            .first()
            .and_then(|t| COMMAND_NAMES.get(*t as usize))
            .copied()
            .unwrap_or("unknown")
    }
    #[getter]
    fn id(&self) -> Option<u64> {
        (self.name() == "verdict" && self.raw.len() >= 9)
            .then(|| u64::from_le_bytes(self.raw[1..9].try_into().unwrap()))
    }
    #[getter]
    fn verdict(&self) -> Option<u8> {
        (self.name() == "verdict" && self.raw.len() >= 10).then(|| self.raw[9])
    }
    #[getter]
    fn raw<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.raw)
    }
    fn __repr__(&self) -> String {
        match (self.id(), self.verdict()) {
            (Some(id), Some(v)) => format!("Command(verdict id={id} verdict={v})"),
            _ => format!("Command({})", self.name()),
        }
    }
}

/// The wire form of a `Verdict` command, for a script writing to the pipe itself.
#[pyfunction(name = "verdict_command")]
fn py_verdict_command<'py>(py: Python<'py>, packet_id: u64, verdict: u8) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &verdict_command(packet_id, verdict))
}

/// `value` as a `zfsim.Verdict` (the Python enum, so scripts get names, not
/// numbers).
fn to_verdict<'py>(py: Python<'py>, value: u8) -> PyResult<Bound<'py, PyAny>> {
    py.import("zfsim.verdict")?.getattr("Verdict")?.call1((value,))
}

// ---------------------------------------------------------------------------
// Small result types
// ---------------------------------------------------------------------------

/// What a callout decided: `action` is `FWP_ACTION_PERMIT` / `FWP_ACTION_BLOCK`
/// (0 if it set none) and `absorb` says it took ownership of the packet (pended,
/// awaiting a verdict, or dropped).
#[pyclass(frozen, module = "zfsim", get_all)]
#[derive(Clone)]
struct CalloutOutcome {
    action: u32,
    absorb: bool,
}

#[pymethods]
impl CalloutOutcome {
    /// Let through (permitted and not absorbed).
    #[getter]
    fn permit(&self) -> bool {
        self.action == api::FWP_ACTION_PERMIT && !self.absorb
    }
    #[getter]
    fn block(&self) -> bool {
        self.action == api::FWP_ACTION_BLOCK
    }
    fn __repr__(&self) -> String {
        let action = match self.action {
            api::FWP_ACTION_PERMIT => "FWP_ACTION_PERMIT".to_string(),
            api::FWP_ACTION_BLOCK => "FWP_ACTION_BLOCK".to_string(),
            other => format!("{other:#x}"),
        };
        let absorb = if self.absorb { "True" } else { "False" };
        format!("CalloutOutcome(action={action}, absorb={absorb})")
    }
}

impl From<CalloutResult> for CalloutOutcome {
    fn from(r: CalloutResult) -> Self {
        Self { action: r.action, absorb: r.absorb }
    }
}

/// A packet the driver re-injected (the mock records instead of injecting).
/// `transport` injects carry no IP header on inbound; `data` is what the driver
/// handed to the inject call.
#[pyclass(frozen, module = "zfsim", get_all)]
struct Injected {
    inbound: bool,
    ipv6: bool,
    transport: bool,
    loopback: bool,
    data: Vec<u8>,
}

#[pymethods]
impl Injected {
    fn __repr__(&self) -> String {
        format!(
            "Injected({} {} {}{}, {} bytes)",
            if self.inbound { "inbound" } else { "outbound" },
            if self.transport { "transport" } else { "network" },
            if self.ipv6 { "v6" } else { "v4" },
            if self.loopback { " loopback" } else { "" },
            self.data.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Sim
// ---------------------------------------------------------------------------

enum OwnerMsg {
    /// Run down the event queue (readers see end-of-file) and ack.
    Shutdown(mpsc::Sender<()>),
    /// Unload the driver and exit.
    Close,
}

/// The thread that holds the harness' driver lock for the sim's lifetime. The
/// lock guard isn't `Send`, so load and unload happen on one dedicated thread
/// and the Python object (usable from any thread) just messages it.
struct Owner {
    tx: mpsc::Sender<OwnerMsg>,
    join: JoinHandle<()>,
}

struct Serving {
    server: Arc<PipeServer>,
    endpoint: String,
    state: Arc<(Mutex<ServeState>, Condvar)>,
    acceptor: JoinHandle<()>,
}

#[derive(Default)]
struct ServeState {
    /// Set by `close()`: the acceptor must not start pumps any more.
    closed: bool,
    connected: bool,
    /// Set by the pumps once the agent is gone.
    stop: Option<Arc<AtomicBool>>,
    pumps: Option<Pumps>,
}

struct Inner {
    owner: Option<Owner>,
    cmd_conn: Option<DriverConnection>,
    serving: Option<Serving>,
}

fn not_open() -> PyErr {
    PyRuntimeError::new_err("Sim is closed")
}

fn connect() -> PyResult<DriverConnection> {
    pumps::connect().ok_or_else(not_open)
}

/// The real driver, loaded in-process. Use as a context manager; only one `Sim`
/// can be open per process at a time (the driver is a process-wide global).
#[pyclass(module = "zfsim")]
struct Sim {
    inner: Mutex<Inner>,
    events: Arc<Queue<Event>>,
    commands: Arc<Queue<Command>>,
}

impl Sim {
    fn tap(&self) -> Tap {
        let events = Arc::clone(&self.events);
        let commands = Arc::clone(&self.commands);
        Arc::new(move |msg| match msg {
            TapMessage::Event(event) => events.push(event.into()),
            TapMessage::Command(raw) => commands.push(Command { raw }),
        })
    }

    /// Run `f` on the command connection (created on first use).
    fn with_cmd<R>(&self, f: impl FnOnce(&mut DriverConnection) -> R) -> PyResult<R> {
        let mut inner = self.inner.lock().unwrap();
        if inner.owner.is_none() {
            return Err(not_open());
        }
        let conn = match &mut inner.cmd_conn {
            Some(conn) => conn,
            slot => slot.insert(connect()?),
        };
        Ok(f(conn))
    }

    fn require_open(&self) -> PyResult<()> {
        if self.inner.lock().unwrap().owner.is_none() {
            return Err(not_open());
        }
        Ok(())
    }
}

impl Drop for Sim {
    fn drop(&mut self) {
        // A Sim garbage-collected without close() still unloads the driver, so
        // the next Sim can load it.
        Python::attach(|py| {
            let _ = self.close(py);
        });
    }
}

#[pymethods]
impl Sim {
    /// Load the real driver (its `driver_entry`) and verify it registered the
    /// production callout set.
    #[new]
    fn new(py: Python<'_>) -> PyResult<Self> {
        if OPEN.swap(true, Ordering::SeqCst) {
            return Err(PyRuntimeError::new_err(
                "a Sim is already open in this process (the driver is a global); close it first",
            ));
        }
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let (tx, rx) = mpsc::channel::<OwnerMsg>();
        let join = thread::spawn(move || {
            let sim = match pumps::load_driver() {
                Ok(sim) => {
                    let _ = ready_tx.send(Ok(()));
                    sim
                }
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                    return;
                }
            };
            while let Ok(msg) = rx.recv() {
                match msg {
                    OwnerMsg::Shutdown(ack) => {
                        sim.shutdown();
                        let _ = ack.send(());
                    }
                    OwnerMsg::Close => break,
                }
            }
            // `sim` drops here: DriverUnload + release the driver lock.
        });
        let loaded = py.detach(move || ready_rx.recv());
        let err = match loaded {
            Ok(Ok(())) => None,
            Ok(Err(err)) => Some(err),
            Err(_) => Some("driver loader thread died".to_string()),
        };
        if let Some(err) = err {
            let _ = py.detach(|| join.join());
            OPEN.store(false, Ordering::SeqCst);
            return Err(PyRuntimeError::new_err(err));
        }
        Ok(Self {
            inner: Mutex::new(Inner {
                owner: Some(Owner { tx, join }),
                cmd_conn: None,
                serving: None,
            }),
            events: Arc::new(Queue::new()),
            commands: Arc::new(Queue::new()),
        })
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_args))]
    fn __exit__(&self, py: Python<'_>, _args: &Bound<'_, pyo3::types::PyTuple>) -> PyResult<bool> {
        self.close(py)?;
        Ok(false)
    }

    /// Run down the driver, stop the pumps (the agent sees the endpoint close)
    /// and unload the driver. Idempotent. Pending packets are resolved by the
    /// driver's shutdown.
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let (owner, serving) = {
            let mut inner = self.inner.lock().unwrap();
            let Some(owner) = inner.owner.take() else {
                return Ok(());
            };
            inner.cmd_conn = None;
            (owner, inner.serving.take())
        };
        // Joins can wait on pump threads that need the GIL (the tap), so
        // release it while tearing down.
        py.detach(|| {
            // No new agent from here on. If none connected yet, wake the
            // acceptor by connecting to ourselves; it sees `closed` and exits.
            if let Some(serving) = &serving {
                let connected = {
                    let mut st = serving.state.0.lock().unwrap();
                    st.closed = true;
                    st.connected
                };
                if !connected {
                    pipe::poke(&serving.endpoint);
                }
            }
            let serving = serving.map(|s| {
                let _ = s.acceptor.join();
                (s.server, s.state)
            });

            // Driver shutdown runs the event queue down: the event pump sees
            // end-of-file.
            let (ack_tx, ack_rx) = mpsc::channel();
            if owner.tx.send(OwnerMsg::Shutdown(ack_tx)).is_ok() {
                let _ = ack_rx.recv();
            }
            if let Some((server, state)) = serving {
                let pumps = state.0.lock().unwrap().pumps.take();
                // Ends the command pump (agent gone).
                server.disconnect();
                if let Some(pumps) = pumps {
                    pumps.join();
                }
            }
            let _ = owner.tx.send(OwnerMsg::Close);
            let _ = owner.join.join();
        });
        OPEN.store(false, Ordering::SeqCst);
        self.events.close();
        self.commands.close();
        Ok(())
    }

    // ---- Commands ------------------------------------------------------------

    /// Write a raw command message (`[CommandType, ...]`) to the driver, like
    /// the agent would (e.g. `ClearCache`). Replies go to the agent; the tee
    /// shows them in `next_event()`.
    fn send(&self, py: Python<'_>, command: &[u8]) -> PyResult<()> {
        let command = command.to_vec();
        self.with_cmd(|conn| {
            py.detach(|| conn.write(&command));
        })
    }

    // ---- Real agent attached ---------------------------------------------

    /// Expose the driver on an agent endpoint: a logical name (default
    /// `ZenithFence`, the agent's `ZF_SIM_PIPE`) or a full path. Returns the OS
    /// endpoint. Returns immediately; the agent may connect later (see
    /// `wait_agent`). Events the agent receives and commands it sends land in
    /// `next_event()` / `next_command()`. One agent per `serve()`.
    #[pyo3(signature = (name=None))]
    fn serve(&self, name: Option<String>) -> PyResult<String> {
        let mut inner = self.inner.lock().unwrap();
        if inner.owner.is_none() {
            return Err(not_open());
        }
        if inner.serving.is_some() {
            return Err(PyRuntimeError::new_err("serve() was already called"));
        }
        let name = name.unwrap_or_else(|| pumps::DEFAULT_PIPE_NAME.into());
        let endpoint = pipe::endpoint(&name);
        let server = Arc::new(
            PipeServer::create(&endpoint)
                .map_err(|e| PyRuntimeError::new_err(format!("creating {endpoint}: {e}")))?,
        );
        let state = Arc::new((Mutex::new(ServeState::default()), Condvar::new()));
        let (acceptor_server, acceptor_state, tap) = (Arc::clone(&server), Arc::clone(&state), self.tap());
        let acceptor = thread::spawn(move || {
            if acceptor_server.wait_for_client().is_err() {
                return;
            }
            let (lock, cv) = &*acceptor_state;
            let mut st = lock.lock().unwrap();
            if st.closed {
                return;
            }
            let (Some(evt_conn), Some(cmd_conn)) = (pumps::connect(), pumps::connect()) else {
                return;
            };
            let stop = Arc::new(AtomicBool::new(false));
            st.pumps = Some(Pumps::spawn(evt_conn, cmd_conn, &acceptor_server, Arc::clone(&stop), Some(tap)));
            st.stop = Some(stop);
            st.connected = true;
            cv.notify_all();
        });
        inner.serving = Some(Serving { server, endpoint: endpoint.clone(), state, acceptor });
        Ok(endpoint)
    }

    /// Wait until an agent connects to the endpoint opened by `serve()`.
    /// Returns whether it did within `timeout` seconds (`None`: wait forever).
    #[pyo3(signature = (timeout=None))]
    fn wait_agent(&self, py: Python<'_>, timeout: Option<f64>) -> PyResult<bool> {
        let timeout = timeout_of(timeout)?;
        let state = {
            let inner = self.inner.lock().unwrap();
            let Some(serving) = &inner.serving else {
                return Err(PyRuntimeError::new_err("serve() was not called"));
            };
            Arc::clone(&serving.state)
        };
        Ok(py.detach(|| {
            let (lock, cv) = &*state;
            let deadline = timeout.map(|t| Instant::now() + t);
            let mut st = lock.lock().unwrap();
            while !st.connected {
                st = match deadline {
                    None => cv.wait(st).unwrap(),
                    Some(d) => match d.checked_duration_since(Instant::now()) {
                        None => return false,
                        Some(left) => cv.wait_timeout(st, left).unwrap().0,
                    },
                };
            }
            true
        }))
    }

    /// Whether the agent attached by `serve()` is connected right now (false
    /// before it connects and once it hung up).
    #[getter]
    fn agent_connected(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        let Some(serving) = &inner.serving else {
            return false;
        };
        let st = serving.state.0.lock().unwrap();
        st.connected && st.stop.as_ref().is_some_and(|stop| !stop.load(Ordering::Relaxed))
    }

    /// The OS endpoint opened by `serve()`, if any.
    #[getter]
    fn endpoint(&self) -> Option<String> {
        self.inner.lock().unwrap().serving.as_ref().map(|s| s.endpoint.clone())
    }

    // ---- Observing ---------------------------------------------------------

    /// Next event the driver sent the agent (the `serve()` tee),
    /// waiting up to `timeout` seconds (`None`: forever). `None` on timeout or
    /// after `close()`.
    #[pyo3(signature = (timeout=None))]
    fn next_event(&self, py: Python<'_>, timeout: Option<f64>) -> PyResult<Option<Event>> {
        let timeout = timeout_of(timeout)?;
        let events = Arc::clone(&self.events);
        let event = py.detach(move || events.pop(timeout));
        Ok(event)
    }

    /// Next command the attached agent sent (`serve()` mode), see `next_event`.
    #[pyo3(signature = (timeout=None))]
    fn next_command(&self, py: Python<'_>, timeout: Option<f64>) -> PyResult<Option<Command>> {
        let timeout = timeout_of(timeout)?;
        let commands = Arc::clone(&self.commands);
        Ok(py.detach(move || commands.pop(timeout)))
    }

    /// Number of queued, not yet consumed events.
    #[getter]
    fn pending_events(&self) -> usize {
        self.events.len()
    }

    // ---- Injecting traffic (the "OS" side) ---------------------------------

    /// ALE outbound-connect classify (the first packet of a new outbound flow).
    #[pyo3(signature = (flow, *, pid=0, reauth=false, payload=None))]
    fn ale_connect(
        &self,
        py: Python<'_>,
        flow: &Flow,
        pid: u64,
        reauth: bool,
        payload: Option<&[u8]>,
    ) -> PyResult<CalloutOutcome> {
        self.require_open()?;
        let payload = payload.unwrap_or_default().to_vec();
        Ok(py
            .detach(|| match (flow.v4(), flow.v6()) {
                (Some(spec), _) => api::ale_connect_v4(spec, reauth, pid, &payload),
                (_, Some(spec)) => api::ale_connect_v6(spec, reauth, pid, &payload),
                _ => unreachable!("Flow families are checked at construction"),
            })
            .into())
    }

    /// ALE inbound-accept classify.
    #[pyo3(signature = (flow, *, pid=0, reauth=false, payload=None))]
    fn ale_accept(
        &self,
        py: Python<'_>,
        flow: &Flow,
        pid: u64,
        reauth: bool,
        payload: Option<&[u8]>,
    ) -> PyResult<CalloutOutcome> {
        self.require_open()?;
        let payload = payload.unwrap_or_default().to_vec();
        Ok(py
            .detach(|| match (flow.v4(), flow.v6()) {
                (Some(spec), _) => api::ale_accept_v4(spec, reauth, pid, &payload),
                (_, Some(spec)) => api::ale_accept_v6(spec, reauth, pid, &payload),
                _ => unreachable!("Flow families are checked at construction"),
            })
            .into())
    }

    /// IP-packet-layer classify for a structured packet around `payload`.
    /// `direction` is `"outbound"` / `"inbound"`.
    #[pyo3(signature = (flow, direction, payload=None))]
    fn packet(
        &self,
        py: Python<'_>,
        flow: &Flow,
        direction: &Bound<'_, PyAny>,
        payload: Option<&[u8]>,
    ) -> PyResult<CalloutOutcome> {
        self.require_open()?;
        let direction = parse_direction(direction)?;
        let payload = payload.unwrap_or_default().to_vec();
        Ok(py
            .detach(|| match (flow.v4(), flow.v6()) {
                (Some(spec), _) => api::packet_v4(spec, direction, &payload),
                (_, Some(spec)) => api::packet_v6(spec, direction, &payload),
                _ => unreachable!("Flow families are checked at construction"),
            })
            .into())
    }

    /// IP-packet-layer classify for raw IP bytes (starting at the IP header),
    /// verbatim -- including malformed ones. The family comes from the version
    /// nibble. `injected_by_self` marks it as a packet the driver injected.
    #[pyo3(signature = (data, direction, *, injected_by_self=false))]
    fn packet_bytes(
        &self,
        py: Python<'_>,
        data: &[u8],
        direction: &Bound<'_, PyAny>,
        injected_by_self: bool,
    ) -> PyResult<CalloutOutcome> {
        self.require_open()?;
        let direction = parse_direction(direction)?;
        let data = data.to_vec();
        let v6 = data.first().is_some_and(|b| b >> 4 == 6);
        Ok(py
            .detach(|| {
                if v6 {
                    api::packet_bytes_v6(&data, direction, injected_by_self)
                } else {
                    api::packet_bytes_v4(&data, direction, injected_by_self)
                }
            })
            .into())
    }

    /// ALE endpoint-closure for `flow` (the connection ended).
    #[pyo3(signature = (flow, *, pid=0))]
    fn endpoint_close(&self, py: Python<'_>, flow: &Flow, pid: u64) -> PyResult<()> {
        self.require_open()?;
        py.detach(|| match (flow.v4(), flow.v6()) {
            (Some(spec), _) => api::endpoint_close_v4(spec, pid),
            (_, Some(spec)) => api::endpoint_close_v6(spec, pid),
            _ => unreachable!("Flow families are checked at construction"),
        });
        Ok(())
    }

    /// ALE resource-release (a local port was released).
    #[pyo3(signature = (protocol, port, *, v6=false))]
    fn resource_release(&self, protocol: &Bound<'_, PyAny>, port: u16, v6: bool) -> PyResult<()> {
        self.require_open()?;
        let protocol = parse_proto(protocol)?;
        if v6 {
            api::resource_release_v6(protocol, port);
        } else {
            api::resource_release_v4(protocol, port);
        }
        Ok(())
    }

    // ---- Inspecting the driver ---------------------------------------------

    /// The verdict the connection cache holds for `flow` (the agent's decision
    /// once applied) as a `zfsim.Verdict`, or `None`.
    fn verdict_for<'py>(&self, py: Python<'py>, flow: &Flow) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.require_open()?;
        let value = match (flow.v4(), flow.v6()) {
            (Some(spec), _) => api::verdict_for_v4(spec),
            (_, Some(spec)) => api::verdict_for_v6(spec),
            _ => None,
        };
        value.map(|v| to_verdict(py, v)).transpose()
    }

    /// Take every packet the driver injected since the last call.
    fn drain_injected(&self) -> PyResult<Vec<Injected>> {
        self.require_open()?;
        Ok(api::drain_injected()
            .into_iter()
            .map(|p| Injected {
                inbound: p.inbound,
                ipv6: p.ipv6,
                transport: p.transport,
                loopback: p.loopback,
                data: p.data,
            })
            .collect())
    }

    /// Packets currently pended in the packet cache (awaiting a verdict).
    #[getter]
    fn packet_cache_len(&self) -> usize {
        api::packet_cache_len()
    }

    /// Active (not yet ended) connections in the connection cache.
    #[getter]
    fn active_conn_count(&self) -> usize {
        api::active_conn_count()
    }

    /// Ids of the packets currently pended.
    fn live_ids(&self) -> Vec<u64> {
        api::live_ids()
    }

    /// Drop every tracked connection and pended packet and discard recorded
    /// injects, keeping the driver loaded.
    fn reset(&self) -> PyResult<()> {
        self.require_open()?;
        api::reset_device_state();
        Ok(())
    }

    /// Filter-engine registration: `{"committed": bool, "callouts": [(name,
    /// layer, filter_id), ...]}`.
    fn filter_engine<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let snapshot = api::filter_engine_snapshot().ok_or_else(not_open)?;
        let out = PyDict::new(py);
        out.set_item("committed", snapshot.committed)?;
        let callouts: Vec<(String, String, u64)> = snapshot
            .callouts
            .into_iter()
            .map(|(name, layer, id)| (name, format!("{layer:?}"), id))
            .collect();
        out.set_item("callouts", callouts)?;
        Ok(out)
    }
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Sim>()?;
    m.add_class::<Flow>()?;
    m.add_class::<Event>()?;
    m.add_class::<EventStream>()?;
    m.add_class::<Command>()?;
    m.add_class::<CalloutOutcome>()?;
    m.add_class::<Injected>()?;
    m.add_function(wrap_pyfunction!(py_verdict_command, m)?)?;
    m.add("FWP_ACTION_PERMIT", api::FWP_ACTION_PERMIT)?;
    m.add("FWP_ACTION_BLOCK", api::FWP_ACTION_BLOCK)?;
    Ok(())
}
