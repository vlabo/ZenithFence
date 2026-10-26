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

# The driver's own unit tests (#[cfg(test)] in driver/src), built for the host
# over the mock WDK (mock/driver) -- no kernel needed.
[working-directory: './mock']
test-driver:
	cargo test -p driver-mock

test: kext-interface-gen test-protocol test-kext-interface test-driver

# Regenerate the LLM reference files under docs/LLMs/ (see docs/LLMs/README.md).
gen-llm-docs:
	go run ./tools/godoc-gen .
	cargo run -q --manifest-path tools/rustdoc-gen/Cargo.toml -- .

# ---------------------------------------------------------------------------
# Userspace simulation (see sim/README.md).
#
# The Python module `zfsim` loads the real driver over mock_wdk in-process and
# serves it on the agent's named pipe (a Unix socket on Linux/macOS). A script
# injects traffic the way the OS would while a real agent decides, and asserts
# on what happens. Recipes that differ by OS have a
# [windows] (pwsh) and a [unix] (bash) variant.
# ---------------------------------------------------------------------------

python := if os_family() == "windows" { "python" } else { "python3" }

# Build the Python extension `zfsim._native` into sim/python/zfsim/. Plain
# cargo + copy, no maturin.
#   just sim-build            # debug
#   just sim-build --release
sim-build *args:
	{{python}} ./sim/build.py {{args}}

# Build the Go test agent. The repo-root go.work makes it build against the
# local kext_interface (incl. the sim transports).
[windows]
sim-build-agent:
	go build -C ./kext_tester -o ../kext_tester.exe

# (Unix: the agent can't sit at ./kext_tester, which is its source directory.)
[unix]
sim-build-agent:
	go build -C ./kext_tester -o kext_tester

# The scenario tests in sim/tests: Python plays the OS; a PipeAgent (or
# kext_tester) attached through Sim.serve() decides.
[windows]
sim-test: sim-build sim-build-agent
	#!pwsh.exe -File
	$env:PYTHONPATH = (Resolve-Path ./sim/python).Path
	{{python}} -m unittest discover -v -s ./sim/tests

[unix]
sim-test: sim-build sim-build-agent
	PYTHONPATH=./sim/python {{python}} -m unittest discover -v -s ./sim/tests

# Serve the mock driver to a REAL agent on \\.\pipe\ZenithFence (Unix: the
# ZenithFence socket), with traffic slow enough to follow in the logs: every
# second a real DNS lookup, then a faked HTTPS connection to the address it
# returned, all under this script's PID (sim/scripts/serve.py). After the agent
# disconnects the driver is reloaded for the next one. Start this first, then
# the agent: nexufend built with `just agent build-mock-kext`, or
# `just sim-attach`. Ctrl+C to stop.
mock-serve: sim-build
	{{python}} ./sim/scripts/serve.py

# The REAL Linux agent attached to the mock driver in a Docker container, for
# debugging (sim/docker). Build the agent first in nexufend:
# `just agent build-mock-kext-linux`; its bootstrap data goes in sim/docker/.env
# (NX_BOOTSTRAP=...). Both processes log to the console and to /data/logs.
#   just mock-docker            # build and run in the foreground
#   just mock-docker -d         # in the background (docker logs -f zfsim-agent)
[windows]
mock-docker *args:
	#!pwsh.exe -File
	New-Item -ItemType Directory -Force ./sim/docker/agent | Out-Null
	Copy-Item ../nexufend/cmds/agent/testdata/nexufend-agent-mock-kext ./sim/docker/agent/
	docker compose -f ./sim/docker/compose.yaml up --build {{args}}

[unix]
mock-docker *args:
	mkdir -p ./sim/docker/agent
	cp ../nexufend/cmds/agent/testdata/nexufend-agent-mock-kext ./sim/docker/agent/
	docker compose -f ./sim/docker/compose.yaml up --build {{args}}

# Attach the Go test agent (kext_tester) to a served mock driver (`just mock-serve`).
[windows]
sim-attach: sim-build-agent
	#!pwsh.exe -File
	$env:ZF_SIM_PIPE = "ZenithFence"
	& "./kext_tester.exe"

[unix]
sim-attach: sim-build-agent
	ZF_SIM_PIPE=ZenithFence ./kext_tester/kext_tester
