"""Type stubs for `zfsim._native`, the Rust extension (sim/src/lib.rs).

The extension carries no type information of its own; IDEs and type checkers
read this file instead. Keep it in sync with the `#[pymethods]` in lib.rs.
"""
from typing import Literal, TypedDict, final

from .verdict import Verdict

__all__ = [
    "FWP_ACTION_BLOCK",
    "FWP_ACTION_PERMIT",
    "CalloutOutcome",
    "Command",
    "Event",
    "EventStream",
    "Flow",
    "Injected",
    "Sim",
    "verdict_command",
]

_Protocol = int | Literal["tcp", "udp", "icmp", "igmp", "icmpv6", "icmp6"]
"""An IP protocol number, or one of the names (case-insensitive)."""

_Direction = Literal["outbound", "out", "inbound", "in", 0, 1]
"""Packet direction: `"outbound"` / `"out"` / `0`, or `"inbound"` / `"in"` / `1`."""

_EventKind = Literal["connection", "connection_end", "connection_update", "update_end", "log", "unknown"]

_CommandName = Literal[
    "shutdown",
    "verdict",
    "update_v4",
    "update_v6",
    "clear_cache",
    "get_connections_update",
    "get_logs",
    "print_memory_stats",
    "clean_ended_connections",
    "unknown",
]

class _FilterEngine(TypedDict):
    """`Sim.filter_engine()`: the WFP registration the driver made."""

    committed: bool
    callouts: list[tuple[str, str, int]]
    """(name, layer, filter_id) per callout."""

FWP_ACTION_PERMIT: int
"""WFP action: the packet is permitted."""
FWP_ACTION_BLOCK: int
"""WFP action: the packet is blocked (also set while a packet is pended)."""

@final
class Flow:
    """An IPv4 or IPv6 5-tuple. Immutable, hashable and comparable, so it can
    be a dict key or a set member.

    `protocol` is an IP protocol number or `"tcp"`, `"udp"`, `"icmp"`, `"igmp"`,
    `"icmpv6"`. Both addresses must be the same family.

        Flow("tcp", "10.0.0.5", 50000, "93.184.216.34", 443)
        Flow("udp", "2001:db8::1", 53000, "2606:4700::1111", 53)
    """

    def __new__(cls, protocol: _Protocol, local: str, local_port: int, remote: str, remote_port: int) -> Flow:
        """Raises `ValueError` on a bad address, unknown protocol or mixed families."""
    @property
    def protocol(self) -> int:
        """IP protocol number (6 = TCP, 17 = UDP, 1 = ICMP, ...)."""
    @property
    def local(self) -> str:
        """Local address, as text."""
    @property
    def local_port(self) -> int: ...
    @property
    def remote(self) -> str:
        """Remote address, as text."""
    @property
    def remote_port(self) -> int: ...
    @property
    def is_v6(self) -> bool: ...
    def __eq__(self, other: object, /) -> bool: ...
    def __hash__(self) -> int: ...

@final
class Event:
    """One event the driver sent towards the agent.

    `kind` says which attributes are set; the others are `None`:

    - `"connection"`: a pended packet awaiting a verdict. `id`, `pid`,
      `direction`, `flow`, `payload`, `payload_layer`. The agent answers with
      a `Verdict` command for `id`.
    - `"connection_end"`: `pid`, `direction`, `flow`, byte/packet counters.
    - `"connection_update"`: `flow`, byte/packet counters.
    - `"update_end"`: end of a connections-update batch. `timestamp`.
    - `"log"`: `severity`, `message`.
    - `"unknown"`: a frame that didn't decode (kept so a driver bug is
      visible); see `raw`.
    """

    @property
    def kind(self) -> _EventKind: ...
    @property
    def info_type(self) -> int:
        """The frame's raw type byte."""
    @property
    def id(self) -> int | None:
        """Packet id a `Verdict` command refers to (`"connection"` events)."""
    @property
    def pid(self) -> int | None:
        """Process id (`"connection"`, `"connection_end"`)."""
    @property
    def direction(self) -> Literal["outbound", "inbound", "unknown"] | None: ...
    @property
    def flow(self) -> Flow | None: ...
    @property
    def payload_layer(self) -> int | None: ...
    @property
    def payload(self) -> bytes | None:
        """The pended packet, from its IP header on (`"connection"` events)."""
    @property
    def rx_bytes(self) -> int | None: ...
    @property
    def rx_packets(self) -> int | None: ...
    @property
    def tx_bytes(self) -> int | None: ...
    @property
    def tx_packets(self) -> int | None: ...
    @property
    def severity(self) -> int | None:
        """Log severity (`"log"` events)."""
    @property
    def message(self) -> str | None:
        """Log line (`"log"` events)."""
    @property
    def timestamp(self) -> int | None:
        """The driver's cursor (`"update_end"` events): send it unchanged with
        the next `GetConnectionsUpdate` to get the connections active since."""
    @property
    def raw(self) -> bytes:
        """The frame's payload bytes as the driver wrote them."""

@final
class EventStream:
    """Splits the driver's event byte stream into `Event`s, for a script that
    reads the pipe itself (a hand-written agent). A frame may span several
    reads."""

    def __init__(self) -> None: ...
    def feed(self, data: bytes) -> list[Event]:
        """Add bytes read from the pipe; return every event completed so far."""

@final
class Command:
    """One command the agent wrote towards the driver."""

    @property
    def name(self) -> _CommandName: ...
    @property
    def id(self) -> int | None:
        """Packet id (`"verdict"` commands)."""
    @property
    def verdict(self) -> int | None:
        """The verdict byte as the agent sent it (`"verdict"` commands). Kept
        raw, so a bad value from a buggy agent is visible: `Verdict(cmd.verdict)`
        names a valid one."""
    @property
    def raw(self) -> bytes:
        """The command bytes, `[CommandType, ...]`."""

@final
class CalloutOutcome:
    """What a callout decided for one packet."""

    @property
    def action(self) -> int:
        """`FWP_ACTION_PERMIT`, `FWP_ACTION_BLOCK`, or 0 if the callout set none."""
    @property
    def absorb(self) -> bool:
        """The driver took ownership of the packet: pended awaiting a verdict,
        or dropped."""
    @property
    def permit(self) -> bool:
        """Let through: permitted and not absorbed."""
    @property
    def block(self) -> bool:
        """Action is `FWP_ACTION_BLOCK` (absorbed or not)."""

@final
class Injected:
    """A packet the driver re-injected (the mock records it instead)."""

    @property
    def inbound(self) -> bool: ...
    @property
    def ipv6(self) -> bool: ...
    @property
    def transport(self) -> bool:
        """Transport-layer inject (a released ALE connect / accept); inbound ones
        carry no IP header."""
    @property
    def loopback(self) -> bool: ...
    @property
    def data(self) -> bytes:
        """What the driver handed to the inject call."""

@final
class Sim:
    """The real driver, loaded in-process over the mock WDK.

    Use as a context manager; only one `Sim` can be open per process (the
    driver is a global). The agent is a real one: `serve()` opens the agent's
    named pipe / Unix socket and `wait_agent()` waits for it to connect.

        with Sim() as sim:
            sim.serve("ZenithFence")
            assert sim.wait_agent(timeout=60)
            flow = Flow("tcp", "10.0.0.5", 50000, "93.184.216.34", 443)
            assert sim.ale_connect(flow, pid=1234).absorb
            verdict = wait_verdict(sim, flow)
    """

    def __init__(self) -> None:
        """Load the driver (`driver_entry`) and check it registered the
        production callout set. Raises `RuntimeError` if a `Sim` is already
        open or the load fails."""
    def __enter__(self) -> Sim: ...
    def __exit__(self, *args: object) -> bool: ...
    def close(self) -> None:
        """Run down the driver, stop the pumps (the agent sees the endpoint
        close) and unload the driver. Idempotent. Pending packets are resolved by
        the driver's shutdown."""

    # ---- Commands ------------------------------------------------------------

    def send(self, command: bytes) -> None:
        """Write a raw command message (`[CommandType, ...]`) to the driver, like
        the agent would (e.g. `ClearCache`). Replies go to the agent; the tee
        shows them in `next_event()`."""

    # ---- The agent -----------------------------------------------------------

    def serve(self, name: str | None = None) -> str:
        """Expose the driver on an agent endpoint: a logical name (default
        `"ZenithFence"`, the agent's `ZF_SIM_PIPE`) or a full path. Returns the
        OS endpoint at once; the agent may connect later (see `wait_agent`).
        One agent per `serve()`."""
    def wait_agent(self, timeout: float | None = None) -> bool:
        """Wait until an agent connects to the `serve()` endpoint. Returns
        whether it did within `timeout` seconds (`None`: wait forever)."""
    @property
    def agent_connected(self) -> bool:
        """Whether the `serve()` agent is connected right now (false before it
        connects and once it hung up)."""
    @property
    def endpoint(self) -> str | None:
        """The OS endpoint opened by `serve()`, if any."""

    # ---- Observing -----------------------------------------------------------

    def next_event(self, timeout: float | None = None) -> Event | None:
        """Next event the driver sent the agent (the `serve()` tee), waiting up to `timeout` seconds (`None`: forever). `None` on
        timeout or after `close()`."""
    def next_command(self, timeout: float | None = None) -> Command | None:
        """Next command the `serve()` agent sent, see `next_event`."""
    @property
    def pending_events(self) -> int:
        """Number of queued, not yet consumed events."""

    # ---- Injecting traffic (the "OS" side) -----------------------------------

    def ale_connect(
        self, flow: Flow, *, pid: int = 0, reauth: bool = False, payload: bytes | None = None
    ) -> CalloutOutcome:
        """ALE outbound-connect classify: the first packet of a new outbound
        flow. A new flow pends (`absorb`) until the agent decides. `payload`
        rides the pended packet to the agent."""
    def ale_accept(
        self, flow: Flow, *, pid: int = 0, reauth: bool = False, payload: bytes | None = None
    ) -> CalloutOutcome:
        """ALE inbound-accept classify."""
    def packet(self, flow: Flow, direction: _Direction, payload: bytes | None = None) -> CalloutOutcome:
        """IP-packet-layer classify for a packet built around `payload` (IP and
        TCP/UDP headers are generated)."""
    def packet_bytes(self, data: bytes, direction: _Direction, *, injected_by_self: bool = False) -> CalloutOutcome:
        """IP-packet-layer classify for raw IP bytes (from the IP header),
        verbatim, malformed ones included. The family comes from the version
        nibble. `injected_by_self` marks it as a packet the driver injected."""
    def endpoint_close(self, flow: Flow, *, pid: int = 0) -> None:
        """ALE endpoint-closure for `flow`: the connection ended."""
    def resource_release(self, protocol: _Protocol, port: int, *, v6: bool = False) -> None:
        """ALE resource-release: local `port` was released."""

    # ---- Inspecting the driver -----------------------------------------------

    def verdict_for(self, flow: Flow) -> Verdict | None:
        """The verdict the connection cache holds for `flow`, or `None`."""
    def drain_injected(self) -> list[Injected]:
        """Take every packet the driver injected since the last call."""
    @property
    def packet_cache_len(self) -> int:
        """Packets currently pended, awaiting a verdict."""
    @property
    def active_conn_count(self) -> int:
        """Active (not yet ended) connections in the connection cache."""
    def live_ids(self) -> list[int]:
        """Ids of the packets currently pended."""
    def reset(self) -> None:
        """Drop every tracked connection and pended packet and discard recorded
        injects, keeping the driver loaded."""
    def filter_engine(self) -> _FilterEngine:
        """Filter-engine registration: `{"committed": bool, "callouts":
        [(name, layer, filter_id), ...]}`."""

def verdict_command(packet_id: int, verdict: int) -> bytes:
    """The wire form of a `Verdict` command, for a script writing to the pipe
    itself."""
