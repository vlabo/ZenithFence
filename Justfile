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

test: kext-interface-gen test-protocol test-kext-interface
