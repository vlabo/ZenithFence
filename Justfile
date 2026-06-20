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
# of the names under fuzz/fuzz_targets/. Example: `just fuzz packet_redirect 120`.
[working-directory: './fuzz']
fuzz target time="60":
	cargo +nightly fuzz run {{target}} -- -max_total_time={{time}}

# Smoke-build every fuzz target so the harnesses don't bit-rot.
[working-directory: './fuzz']
fuzz-build:
	cargo +nightly fuzz build

# Windows-runnable: random-input smoke loop, or replay specific input files.
# Coverage-guided fuzzing needs Linux (`just fuzz`); this runs anywhere.
#   just fuzz-replay device_write                  # random smoke loop (env ITERS, SEED)
#   just fuzz-replay protocol_command crash-abc    # replay a crash/corpus file
[working-directory: './fuzz']
fuzz-replay target *files:
	cargo run --bin replay -- {{target}} {{files}}

test: kext-interface-gen test-protocol test-kext-interface test-driver
