# Fuzzing the ZenithFence driver

A coverage-guided (libFuzzer) fuzz target for the driver's stateful callout
pipeline. It links the driver against the host **mock_wdk** (via the driver's
`mock` feature), so no kernel is involved.

## Requirements

- A nightly Rust toolchain
- `cargo install cargo-fuzz`
- Linux or WSL recommended (libFuzzer + AddressSanitizer are most reliable there)

## Target

| Target     | Under test                                                                 |
|------------|----------------------------------------------------------------------------|
| `callouts` | The full ALE + packet-layer callout pipeline against one persistent device |

The input is decoded into a sequence of operations replayed against a single
persistent mock `Device`: ALE callouts pend flows, `Verdict`/`Update` commands
resolve them, and packet-layer callouts then read the resulting verdict. Oracles
range from "never panic / no OOB / no UB" up to "a permanent verdict fully
determines the packet-layer action for a found TCP/UDP flow" (see the doc comment
on `targets::callouts` in `src/targets.rs`).

## Run (coverage-guided, Linux)

```sh
# from repo root
just fuzz callouts 120      # run target for 120s
just fuzz-build            # build all targets (CI smoke check)

# or directly
cd driver/fuzz && cargo +nightly fuzz run callouts -- -max_total_time=60
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
just fuzz-replay callouts                 # random-input smoke loop
just fuzz-replay callouts crash-abc       # replay a specific input file

# or directly
cd driver/fuzz
cargo run --bin replay -- callouts            # random smoke (env: ITERS, SEED)
cargo run --bin replay -- callouts artifacts/x  # reproduce a Linux crash on Windows
```

`replay` is random/replay testing, not coverage-guided -- it complements the
`proptest` suite (`just test-driver`) for everyday Windows checks, and lets you
reproduce a Linux fuzzer crash locally. Coverage-guided runs happen on Linux.

## Corpus & regressions

`corpus/callouts/` is seeded with operation-stream inputs that drive the pipeline
through its main states.

On a crash: `cargo +nightly fuzz tmin callouts <crash-file>`, then commit the
minimized input under `corpus/callouts/` and add a deterministic `#[test]` in the
driver crate so it also runs in the fast (non-fuzz) test job. You can reproduce
any crash file on Windows with `just fuzz-replay callouts <file>`.
