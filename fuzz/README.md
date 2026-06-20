# Fuzzing the ZenithFence driver

Coverage-guided (libFuzzer) fuzz targets for the driver's packet-handling and
user-space command paths. They link the driver against the host **mock_wdk**
(via the driver's `mock` feature), so no kernel is involved.

## Requirements

- A nightly Rust toolchain
- `cargo install cargo-fuzz`
- Linux or WSL recommended (libFuzzer + AddressSanitizer are most reliable there)

## Targets

| Target             | Under test                                                        |
|--------------------|-------------------------------------------------------------------|
| `packet_key_v4`    | `get_key_from_nbl_v4` + `get_ports` on arbitrary bytes            |
| `packet_key_v6`    | `get_key_from_nbl_v6` + `get_ports` on arbitrary bytes            |
| `packet_redirect`  | `redirect_outbound/inbound_packet`, `recalc_header_checksums`     |
| `device_write`     | `Device::write` command channel (where the OOB bug lived)         |
| `protocol_command` | `protocol::command` wire-format parsers                           |

## Run (coverage-guided, Linux)

```sh
# from repo root
just fuzz packet_redirect 120      # run target for 120s
just fuzz-build                    # build all targets (CI smoke check)

# or directly
cd fuzz && cargo +nightly fuzz run device_write -- -max_total_time=60
```

## Run on Windows (replay / smoke -- NOT coverage-guided)

The `fuzz_targets/` binaries are `#![no_main]`; their entry point is supplied by
the libFuzzer runtime, which is only linked by `cargo fuzz` (Linux). So
`cargo run --bin <target>` on Windows fails with `LNK1561: entry point must be
defined` -- that is expected, not a misconfiguration.

For Windows, use the ordinary `replay` binary, which shares the same target
logic (`src/targets.rs`):

```sh
# from repo root
just fuzz-replay device_write                 # random-input smoke loop
just fuzz-replay protocol_command crash-abc   # replay a specific input file

# or directly
cd fuzz
cargo run --bin replay -- packet_redirect           # random smoke (env: ITERS, SEED)
cargo run --bin replay -- device_write artifacts/x  # reproduce a Linux crash on Windows
```

`replay` is random/replay testing, not coverage-guided -- it complements the
`proptest` suite (`just test-driver`) for everyday Windows checks, and lets you
reproduce a Linux fuzzer crash locally. Coverage-guided runs happen on Linux.

## Corpus & regressions

`corpus/<target>/` is seeded already: minimal valid IPv4/IPv6 TCP/UDP packets
for the packet targets, and command-stream seeds (incl. the committed
`go_command_test.bin`) for the command targets. Add more by dropping real `.pcap`
captures reduced to raw L3 bytes into `corpus/packet_key_*`.

On a crash: `cargo +nightly fuzz tmin <target> <crash-file>`, then commit the
minimized input under `corpus/<target>/` and add a deterministic `#[test]` in the
driver/protocol crate so it also runs in the fast (non-fuzz) test job. You can
reproduce any crash file on Windows with `just fuzz-replay <target> <file>`.
