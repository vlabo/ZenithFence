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
