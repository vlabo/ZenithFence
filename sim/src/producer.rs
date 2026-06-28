//! Fake OS-side network data.
//!
//! Deliberately tiny ("simplest possible thing"): a few hardcoded connections
//! driven through the real ALE callout entry points. Each first-seen flow pends
//! a packet and pushes a `Connection*` event the agent must answer with a
//! verdict — that is the whole point of the harness. A richer or randomised
//! generator can replace this without touching the pipe bridge.

use driver::fuzz_api::{run_ale_accept_v4, run_ale_connect_v4, run_ale_connect_v6};

/// Inject the hardcoded connections. Returns the number of pended flows (and so
/// the number of events the agent is expected to answer).
///
/// Distinct pool slots / address families are used so the keys differ and each
/// call pends its own packet (the same key would coalesce into one pend).
pub fn drive() -> u32 {
    // args: (conn slot, proto_sel=0 → TCP, reauthorize, process_id, payload, raw)
    let _ = run_ale_accept_v4(0, 0, false, 4321, &[], false); // inbound TCP
    let _ = run_ale_connect_v4(1, 0, false, 1234, &[], false); // outbound TCP
    let _ = run_ale_connect_v6(0, 0, false, 1234, &[], false); // outbound TCP (v6)
    3
}
