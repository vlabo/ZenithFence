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
	link.exe /OUT:driver.sys /RELEASE /DEBUG /NOLOGO /NXCOMPAT /NODEFAULTLIB /SUBSYSTEM:NATIVE /DRIVER /DYNAMICBASE /MANIFEST:NO /PDBALTPATH:driver.pdb /MACHINE:X64 /OPT:REF,ICF /SUBSYSTEM:NATIVE,6.01 /ENTRY:GsDriverEntry "/MERGE:.edata=.rdata;_TEXT=.text;_PAGE=PAGE" /MERGE:.rustc=.data /INTEGRITYCHECK driver.lib
	signtool sign /a /s PrivateCertStore /n DriverCertificate /fd SHA256 /t http://timestamp.digicert.com driver.sys

rebrand name: link
	./scripts/rebrand-driver.ps1 -Name {{name}} -Sign

# Tag HEAD with the version from kext_interface/version.txt
tag:
	#!powershell.exe -File
	$ErrorActionPreference = "Stop"
	if (git status --porcelain ./kext_interface/version.txt) {
		Write-Error "kext_interface/version.txt has uncommitted changes; commit the version bump first"
	}
	$Parts = (Get-Content ./kext_interface/version.txt -Raw).Trim().Trim("[", "]").Split(",") | ForEach-Object { [int]$_.Trim() }
	$Version = "v$($Parts[0]).$($Parts[1]).$($Parts[2])"
	git tag -a $Version -m $Version
	if ($LASTEXITCODE -ne 0) { exit 1 }
	Write-Host "Created tag $Version"

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
