module kext_tester

go 1.20

replace github.com/vlabo/portmaster_windows_rust_kext/kext_interface => ../kext_interface

require (
	github.com/google/flatbuffers v23.5.26+incompatible
	github.com/vlabo/portmaster_windows_rust_kext/kext_interface v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.12.0
)
