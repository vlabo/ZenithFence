//! Host harness for the ZenithFence driver, used by the Python module `zfsim`
//! (sim/).
//!
//! Everything here drives the REAL driver: `driver` is the `driver-mock`
//! package, which compiles the production sources in driver/src against the
//! host mock of the Windows kernel API (mock/wdk). The harness only uses the
//! driver's public API -- it loads it through `driver_entry`, calls its callout
//! entry points, talks to it through the user-space channel, and observes its
//! state -- so no test code lives in the driver itself.

pub mod api;
pub mod loader;
pub mod sim;
