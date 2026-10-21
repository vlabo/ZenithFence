set windows-shell := ["powershell.exe", "-NoProfile", "-NoLogo", "-Command"]

default:
	@just --list

# Builds the production build root (driver/kernel), which links the driver core
# against the real kernel wdk. Output: driver_kernel.lib (`link` copies it to driver.lib).
[working-directory: './driver/kernel']
build arg="":
	cargo build {{arg}}

link arg="":
	#!powershell.exe -File
	just build {{arg}}

	$DriverVarient="{{ if arg == "--release" { "release" } else { "debug" } }}"
	cp ./driver/kernel/target/x86_64-pc-windows-msvc/$DriverVarient/driver_kernel.lib ./driver.lib
	link.exe /OUT:driver.sys /RELEASE /DEBUG /NOLOGO /NXCOMPAT /NODEFAULTLIB /SUBSYSTEM:NATIVE /DRIVER /DYNAMICBASE /MANIFEST:NO /PDBALTPATH:driver.pdb /MACHINE:X64 /OPT:REF,ICF /SUBSYSTEM:NATIVE,6.01 /ENTRY:FxDriverEntry "/MERGE:.edata=.rdata;_TEXT=.text;_PAGE=PAGE" /MERGE:.rustc=.data /INTEGRITYCHECK driver.lib
	signtool sign /a /s PrivateCertStore /n DriverCertificate /fd SHA256 /t http://timestamp.digicert.com driver.sys

rebrand name: link
	./scripts/rebrand-driver.ps1 -Name {{name}} -Sign

generate-cert:
	MakeCert -r -pe -ss PrivateCertStore -n "CN=DriverCertificate" DriverCertificate.cer

[working-directory: './protocol']
test-protocol:
	cargo test

[working-directory: './kext_interface']
test-kext-interface:
	go test -run 'TestRustInfoFile|TestInfoDiffFile'

[working-directory: './kext_interface']
kext-interface-gen:
	go test -run 'TestGenerateCommandFile|TestGenerateCommandDiff'

# The real driver sources over the host mock of the Windows kernel API (see
# mock/): the driver's own unit tests (mock/driver) plus the property tests and
# the harness tests (mock/harness). Runs natively on the MSVC toolchain -- no kernel.
[working-directory: './mock']
test-mock:
	cargo test --workspace

# Coverage-guided fuzzing. Requires a nightly toolchain + `cargo install cargo-fuzz`,
# and is most reliable on Linux/WSL (libFuzzer + AddressSanitizer). `target` is one
# of the names under mock/fuzz/fuzz_targets/. Example: `just fuzz callouts 120`.
[working-directory: './mock/fuzz']
fuzz target time="60":
	cargo +nightly fuzz run {{target}} -- -max_total_time={{time}}

# Coverage-guided fuzzing under ThreadSanitizer -- the deep data-race detector
# for the multithreaded `callouts_mt` target (stresses one shared device from
# many threads). Linux/WSL + nightly only. Example: `just fuzz-tsan callouts_mt 120`.
[working-directory: './mock/fuzz']
fuzz-tsan target="callouts_mt" time="60":
	cargo +nightly fuzz run {{target}} --sanitizer thread -- -max_total_time={{time}}

# Smoke-build every fuzz target so the harnesses don't bit-rot.
[working-directory: './mock/fuzz']
fuzz-build:
	cargo +nightly fuzz build

# Windows-runnable: random-input smoke loop, or replay specific input files.
# Coverage-guided fuzzing needs Linux (`just fuzz`); this runs anywhere.
#   just fuzz-replay callouts                       # random smoke loop (env ITERS, SEED)
#   just fuzz-replay callouts crash-abc             # replay a crash/corpus file
[working-directory: './mock/fuzz']
fuzz-replay target *files:
	cargo run --bin replay -- {{target}} {{files}}

test: kext-interface-gen test-protocol test-kext-interface test-mock

# Regenerate the LLM reference files under docs/LLMs/ (see docs/LLMs/README.md).
gen-llm-docs:
	go run ./tools/godoc-gen .
	cargo run -q --manifest-path tools/rustdoc-gen/Cargo.toml -- .

# ---------------------------------------------------------------------------
# Real-world userspace simulation (see sim/).
#
# The fake-driver daemon (Rust, runs the real driver over mock_wdk) exposes the
# driver on a Windows named pipe (a Unix domain socket on Linux/macOS); the
# *real* Go agent (kext_tester) drives it
# exactly as it would the kernel device. By default the agent *loads and starts
# the mock driver itself* -- it spawns the daemon (ZF_SIM_DAEMON), mirroring how
# production loads and starts the kernel driver -- so a single command runs the
# whole thing. Fake OS network events are injected by the daemon. In random-
# traffic mode the daemon serves agents one after another: each disconnect
# unloads the driver and the daemon waits for the next agent. Each recipe
# below that differs by OS has a [windows] (pwsh) and a [unix] (bash) variant.
# ---------------------------------------------------------------------------

# Build the fake-driver daemon and the Go agent. The repo-root go.work makes the
# agent build against the local kext_interface (incl. the sim transports).
[windows]
sim-build:
	cargo build --manifest-path ./sim/Cargo.toml
	go build -C ./kext_tester -o ../kext_tester.exe

# (Unix: the agent can't sit at ./kext_tester, which is its source directory.)
[unix]
sim-build:
	cargo build --manifest-path ./sim/Cargo.toml
	go build -C ./kext_tester -o kext_tester

# Run the fake driver daemon STANDALONE (no agent): generate random network
# traffic forever, exiting non-zero the moment a driver invariant breaks. Rarely
# needed now that `just sim-run` starts the daemon itself; use it to run the
# daemon under a debugger, then attach the agent with `just sim-attach`.
[windows]
mock-run: sim-build
	#!pwsh.exe -File
	./sim/target/debug/zf-sim.exe

[unix]
mock-run: sim-build
	./sim/target/debug/zf-sim

# Serve the mock driver to the REAL agent (nexufend, built with
# `just agent build-mock-kext`): random traffic, any verdict the agent decides is
# accepted (--any-verdict), and after the agent disconnects the driver is
# reloaded and the daemon waits for the next agent. Start this before the agent;
# `pipe` must match the path the agent was built with. Ctrl+C to stop.
[windows]
mock-serve pipe='\\.\pipe\ZenithFence': sim-build
	#!pwsh.exe -File
	$env:ZF_SIM_PIPE = '{{pipe}}'
	./sim/target/debug/zf-sim.exe --any-verdict

[unix]
mock-serve pipe='ZenithFence': sim-build
	ZF_SIM_PIPE='{{pipe}}' ./sim/target/debug/zf-sim --any-verdict

# Run the whole simulation with ONE command: the agent loads and starts the mock
# driver (spawns the daemon), then reads events and answers verdicts. The daemon
# generates random traffic forever, exiting non-zero the moment a driver
# invariant breaks; the seed is fixed, so any failure reproduces. Ctrl+C stops
# both.
[windows]
sim-run: sim-build
	#!pwsh.exe -File
	$env:ZF_SIM_PIPE = "ZenithFence"
	$env:ZF_SIM_DAEMON = (Resolve-Path ./sim/target/debug/zf-sim.exe).Path
	& "./kext_tester.exe"

[unix]
sim-run: sim-build
	#!/usr/bin/env bash
	set -euo pipefail
	export ZF_SIM_PIPE=ZenithFence
	export ZF_SIM_DAEMON="$(realpath ./sim/target/debug/zf-sim)"
	exec ./kext_tester/kext_tester

# Attach the agent to a daemon started separately (`just mock-run`), leaving
# ZF_SIM_DAEMON unset so the agent does NOT start one. For debugging the daemon.
[windows]
sim-attach: sim-build
	#!pwsh.exe -File
	$env:ZF_SIM_PIPE = "ZenithFence"
	& "./kext_tester.exe"

[unix]
sim-attach: sim-build
	ZF_SIM_PIPE=ZenithFence ./kext_tester/kext_tester

# Regenerate the reference CBOR scenario files under sim/scenarios/. Writes the
# fixtures only -- no driver load. Run after changing the sample builders.
[windows]
sim-emit-samples: sim-build
	#!pwsh.exe -File
	./sim/target/debug/zf-sim.exe --emit-samples ./sim/scenarios

[unix]
sim-emit-samples: sim-build
	./sim/target/debug/zf-sim --emit-samples ./sim/scenarios

# Replay an authored CBOR scenario file (deterministic, multi-threaded) instead
# of random traffic, in ONE command: the agent loads and starts the mock driver,
# which replays the scenario and exits with a pass/fail code the agent
# propagates. The scenario path rides to the daemon via inherited environment.
#   just sim-scenario ./sim/scenarios/mixed_v4v6_parallel.cbor
# ZF_SIM_THREADS sets the worker-pool size (default 4).
[windows]
sim-scenario file: sim-build
	#!pwsh.exe -File
	$env:ZF_SIM_PIPE = "ZenithFence"
	$env:ZF_SIM_DAEMON = (Resolve-Path ./sim/target/debug/zf-sim.exe).Path
	# just args are positional; tolerate a stray `file=` prefix either way.
	$env:ZF_SIM_SCENARIO = ("{{file}}" -replace '^file=', '')
	& "./kext_tester.exe"

[unix]
sim-scenario file: sim-build
	#!/usr/bin/env bash
	set -euo pipefail
	export ZF_SIM_PIPE=ZenithFence
	export ZF_SIM_DAEMON="$(realpath ./sim/target/debug/zf-sim)"
	# just args are positional; tolerate a stray `file=` prefix either way.
	file='{{file}}'
	export ZF_SIM_SCENARIO="${file#file=}"
	exec ./kext_tester/kext_tester

# Like `sim-scenario`, but loop the file forever: when the daemon reaches the end
# it restarts from the top and keeps going until you Ctrl+C (which stops both the
# agent and the daemon). A soak/stress replay -- the driver's global state (the
# connection/packet caches) persists across iterations. Same args as
# `sim-scenario`; ZF_SIM_THREADS sets the worker-pool size.
#   just sim-scenario-loop ./sim/scenarios/dns_and_connect.cbor
[windows]
sim-scenario-loop file: sim-build
	#!pwsh.exe -File
	$env:ZF_SIM_PIPE = "ZenithFence"
	$env:ZF_SIM_DAEMON = (Resolve-Path ./sim/target/debug/zf-sim.exe).Path
	# just args are positional; tolerate a stray `file=` prefix either way.
	$env:ZF_SIM_SCENARIO = ("{{file}}" -replace '^file=', '')
	$env:ZF_SIM_LOOP = "1"
	& "./kext_tester.exe"

[unix]
sim-scenario-loop file: sim-build
	#!/usr/bin/env bash
	set -euo pipefail
	export ZF_SIM_PIPE=ZenithFence
	export ZF_SIM_DAEMON="$(realpath ./sim/target/debug/zf-sim)"
	# just args are positional; tolerate a stray `file=` prefix either way.
	file='{{file}}'
	export ZF_SIM_SCENARIO="${file#file=}"
	export ZF_SIM_LOOP=1
	exec ./kext_tester/kext_tester

# Host unit tests for the sim crate (scenario format round-trip, delta logic,
# tuple validation). No driver device required.
sim-test:
	cargo test --manifest-path ./sim/Cargo.toml
