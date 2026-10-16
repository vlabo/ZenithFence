# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZenithFence is a Windows kernel network filtering driver (`.sys`) written in Rust, with Go bindings for user-space communication. It hooks into the Windows Filtering Platform (WFP) to intercept, inspect, and make allow/block decisions on network traffic at the kernel level. Target architecture: **amd64 only**.

## Common Commands

All top-level tasks are in the `Justfile` (run `just` to list them).

```bash
# Build the Rust driver static lib
just build              # debug
just build --release    # release

# Link + sign into driver.sys (Windows only, requires link.exe + signtool in PATH)
just link
just link --release

# Run all tests (generates fixtures, then runs Rust + Go tests)
just test

# Individual test targets
just test-protocol          # Rust serialization tests (protocol/)
just test-kext-interface    # Go parsing tests (kext_interface/)
just kext-interface-gen     # Regenerate binary test fixtures

# One-time: generate test signing certificate
just generate-cert
```

To run a single Rust test:
```bash
cd protocol && cargo test <test_name>
cd driver   && cargo test <test_name>
```

To run a single Go test:
```bash
cd kext_interface && go test -run <TestName>
```

## Architecture

### Component Map

| Directory | Language | Role |
|-----------|----------|------|
| `driver/` | Rust (`no_std`) | Kernel driver — WFP callouts, packet decisions, I/O with user space |
| `protocol/` | Rust | Shared serialization of commands (user→kernel) and info events (kernel→user) |
| `wdk/` | Rust (unsafe) | Thin wrappers over Windows kernel APIs (NDIS, WFP, IRP, etc.) |
| `kext_interface/` | Go | User-space library: open the driver device, send commands, receive events |
| `kext_tester/` | Go | Manual test app that loads and exercises the driver |
| `release/` | Rust | Packages the signed `.sys` into a `.zip`/`.cab` for Microsoft submission |
| `c_helper/` | C | Small ASM/C helpers needed by the linker |
| `libs/` | — | Pre-compiled Windows import libraries |

### Data Flow

```
User Space (Go/kext_interface)
        │  Write: Command (Verdict, UpdateV4/V6, ClearCache, GetLogs …)
        │  Read:  Info event (new connection, bandwidth, connection end, log)
        ▼
  Device file handle  (entry.rs → device.rs)
        │
        ├── IOQueue  — events queued for user-space reads (blocks until data)
        ├── ConnectionCache — per-port RCU-protected table of TCP/UDP state
        ├── PacketCache — pending absorbed packets awaiting verdict
        ├── FilterEngine — WFP session + callout registration
        └── Injector — re-injects packets after a verdict is applied
```

### Packet Path (see PacketDoc.md for full detail)

**Outbound TCP/UDP (first packet):**
ALE Auth Connect layer → absorb + send event to user space → await verdict → update cache → inject

**Outbound reauthorized connection** (special case — `reauthorize == true`):
ALE layer **cannot** pend (no completion handle); instead it records the PID, emits an info-only event, and permits. The real packet then passes through the packet layer, which sends it to user space and reinjects after the verdict. This avoids `STATUS_FWP_TXN_IN_PROGRESS` from `reset_all_filters`.

**Inbound TCP/UDP (all packets — ALE inbound callouts are disabled):**
IP Packet Inbound layer → if no cache entry: create entry (PID unset, resolved by user space), absorb, send event, await verdict → if cached: apply verdict directly

**Non-TCP/UDP (ICMP, IGMP …):**
Treated as temporary verdict — no cache entry, every packet sent to user space individually.

### Key Source Files

| File | Purpose |
|------|---------|
| `driver/src/entry.rs` | `DriverEntry`, IRP dispatch table, I/O routing |
| `driver/src/device.rs` | `DeviceContext` — global state, `read()`, `write()`, command processing |
| `driver/src/connection.rs` | `Connection`, `Verdict` enum, bandwidth tracking |
| `driver/src/connection_cache.rs` | Per-port arrays, RCU-style concurrent access, 1-min/10-min eviction |
| `driver/src/ale_callouts.rs` | ALE Auth + Endpoint/Resource-release callout logic |
| `driver/src/packet_callouts.rs` | Packet-layer callout logic (inbound + outbound) |
| `driver/src/callouts.rs` | Callout registration list |
| `protocol/src/command.rs` | `CommandType` enum + binary parse (user→kernel) |
| `protocol/src/info.rs` | Info event structs + binary serialization (kernel→user) |
| `kext_interface/kext.go` | Windows service management, driver loading |
| `kext_interface/kext_file.go` | Device file handle, overlapped I/O |
| `kext_interface/command.go` | Command serialization (Go side) |
| `kext_interface/info.go` | Event deserialization (Go side) |

### Protocol

Binary, little-endian, no framing library.

- **Commands (user→kernel write):** `CommandType` byte prefix — `Shutdown(0)`, `Verdict(1)`, `UpdateV4(2)`, `UpdateV6(3)`, `ClearCache(4)`, `GetConnectionsUpdate(5)`, `GetLogs(6)`, `PrintMemoryStats(7)`, `CleanEndedConnections(8)`
- **Info events (kernel→user read):** tagged structs per event type
- **Cross-language contract tested by:** `protocol/tests/` (Rust) and `kext_interface/` Go tests reading `rust_info_test.bin` / `go_command_test.bin`

Whenever the protocol changes, regenerate test fixtures with `just kext-interface-gen` and run `just test`.

## Important Constraints

- **`wdk/` is unsafe Rust — exercise extra care when modifying it.**
- **Do NOT update the `windows-sys` dependency** in `driver/Cargo.toml` or `wdk/Cargo.toml`. The pinned commit (`41ad38d8c42c92fd23fe25ba4dca76c2d861ca06`) contains workarounds for known upstream bugs; updating without reviewing the new version can break the build or cause undefined behavior (see `wdk/README.md`).
- **`kext_interface/version.txt`** must stay in sync with the version embedded in the Rust driver.
- The driver is `#![no_std]` with a custom kernel allocator — no standard library available.
- Building and linking the `.sys` requires Windows + Visual Studio 2022 (with C++ and Windows 11 SDK 22H2) and `link.exe`/`signtool` in `PATH`. The Rust `cargo build` step alone can run on Linux.
- Loading the driver on Windows 10+ requires test-signing mode (`Bcdedit.exe -set TESTSIGNING ON`) and an installed test certificate.
