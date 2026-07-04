set windows-shell := ["powershell.exe", "-NoProfile", "-NoLogo", "-Command"]

default:
	@just --list

[working-directory: './driver']
build arg="":
	cargo build {{arg}}

link arg="":
	#!powershell.exe -File
	just build {{arg}}

	$DriverVarient="{{ if arg == "--release" { "release" } else { "debug" } }}"
	cp ./driver/target/x86_64-pc-windows-msvc/$DriverVarient/driver.lib .
	link.exe /OUT:driver.sys /RELEASE /DEBUG /NOLOGO /NXCOMPAT /NODEFAULTLIB /SUBSYSTEM:NATIVE /DRIVER /DYNAMICBASE /MANIFEST:NO /PDBALTPATH:D:\ZenithFence\driver.pdb /MACHINE:X64 /OPT:REF,ICF /MACHINE:X64 /SUBSYSTEM:NATIVE,6.01 /ENTRY:FxDriverEntry "/MERGE:.edata=.rdata;_TEXT=.text;_PAGE=PAGE" /MERGE:.rustc=.data /INTEGRITYCHECK driver.lib
	signtool sign /a /s PrivateCertStore /n DriverCertificate /fd SHA256 /t http://timestamp.digicert.com driver.sys

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

# Host property/regression tests for the driver, built against the mock WDK
# (see mock_wdk/). Runs natively on the existing MSVC toolchain -- no kernel.
[working-directory: './driver']
test-driver:
	cargo test --no-default-features --features mock

# Alias kept for discoverability; same as `test-driver`.
proptest: test-driver

# Coverage-guided fuzzing. Requires a nightly toolchain + `cargo install cargo-fuzz`,
# and is most reliable on Linux/WSL (libFuzzer + AddressSanitizer). `target` is one
# of the names under driver/fuzz/fuzz_targets/. Example: `just fuzz callouts 120`.
[working-directory: './driver/fuzz']
fuzz target time="60":
	cargo +nightly fuzz run {{target}} -- -max_total_time={{time}}

# Coverage-guided fuzzing under ThreadSanitizer -- the deep data-race detector
# for the multithreaded `callouts_mt` target (stresses one shared device from
# many threads). Linux/WSL + nightly only. Example: `just fuzz-tsan callouts_mt 120`.
[working-directory: './driver/fuzz']
fuzz-tsan target="callouts_mt" time="60":
	cargo +nightly fuzz run {{target}} --sanitizer thread -- -max_total_time={{time}}

# Smoke-build every fuzz target so the harnesses don't bit-rot.
[working-directory: './driver/fuzz']
fuzz-build:
	cargo +nightly fuzz build

# Windows-runnable: random-input smoke loop, or replay specific input files.
# Coverage-guided fuzzing needs Linux (`just fuzz`); this runs anywhere.
#   just fuzz-replay callouts                       # random smoke loop (env ITERS, SEED)
#   just fuzz-replay callouts crash-abc             # replay a crash/corpus file
[working-directory: './driver/fuzz']
fuzz-replay target *files:
	cargo run --bin replay -- {{target}} {{files}}

test: kext-interface-gen test-protocol test-kext-interface test-driver

# ---------------------------------------------------------------------------
# Real-world userspace simulation (see sim/).
#
# The fake-driver daemon (Rust, runs the real driver over mock_wdk) exposes the
# driver on a Windows named pipe; the *real* Go agent (kext_tester) drives it
# exactly as it would the kernel device. By default the agent *loads and starts
# the mock driver itself* -- it spawns the daemon (ZF_SIM_DAEMON), mirroring how
# production loads and starts the kernel driver -- so a single command runs the
# whole thing. Fake OS network events are injected by the daemon. Windows-only.
# ---------------------------------------------------------------------------

# Build the fake-driver daemon and the Go agent. The repo-root go.work makes the
# agent build against the local kext_interface (incl. pipe_connection.go).
sim-build:
	cargo build --manifest-path ./sim/Cargo.toml
	go build -C ./kext_tester -o ../kext_tester.exe

# Run the fake driver daemon STANDALONE (no agent): generate random network
# traffic forever, exiting non-zero the moment a driver invariant breaks. Rarely
# needed now that `just sim-run` starts the daemon itself; use it to run the
# daemon under a debugger, then attach the agent with `just sim-attach`.
mock-run: sim-build
	#!pwsh.exe -File
	./sim/target/debug/zf-sim.exe

# Run the whole simulation with ONE command: the agent loads and starts the mock
# driver (spawns the daemon), then reads events and answers verdicts. The daemon
# generates random traffic forever, exiting non-zero the moment a driver
# invariant breaks; the seed is fixed, so any failure reproduces. Ctrl+C stops
# both.
sim-run: sim-build
	#!pwsh.exe -File
	$env:ZF_SIM_PIPE = "ZenithFence"
	$env:ZF_SIM_DAEMON = (Resolve-Path ./sim/target/debug/zf-sim.exe).Path
	& "./kext_tester.exe"

# Attach the agent to a daemon started separately (`just mock-run`), leaving
# ZF_SIM_DAEMON unset so the agent does NOT start one. For debugging the daemon.
sim-attach: sim-build
	#!pwsh.exe -File
	$env:ZF_SIM_PIPE = "ZenithFence"
	& "./kext_tester.exe"

# Regenerate the reference CBOR scenario files under sim/scenarios/. Writes the
# fixtures only -- no driver load. Run after changing the sample builders.
sim-emit-samples: sim-build
	#!pwsh.exe -File
	./sim/target/debug/zf-sim.exe --emit-samples ./sim/scenarios

# Replay an authored CBOR scenario file (deterministic, multi-threaded) instead
# of random traffic, in ONE command: the agent loads and starts the mock driver,
# which replays the scenario and exits with a pass/fail code the agent
# propagates. The scenario path rides to the daemon via inherited environment.
#   just sim-scenario ./sim/scenarios/mixed_v4v6_parallel.cbor
# ZF_SIM_THREADS sets the worker-pool size (default 4).
sim-scenario file: sim-build
	#!pwsh.exe -File
	$env:ZF_SIM_PIPE = "ZenithFence"
	$env:ZF_SIM_DAEMON = (Resolve-Path ./sim/target/debug/zf-sim.exe).Path
	# just args are positional; tolerate a stray `file=` prefix either way.
	$env:ZF_SIM_SCENARIO = ("{{file}}" -replace '^file=', '')
	& "./kext_tester.exe"

# Host unit tests for the sim crate (scenario format round-trip, delta logic,
# tuple validation). No driver device required.
sim-test:
	cargo test --manifest-path ./sim/Cargo.toml
