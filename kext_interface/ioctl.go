//go:build windows
// +build windows

package kext_interface

import (
	"golang.org/x/sys/windows"
)

const (
	METHOD_BUFFERED   = 0
	METHOD_IN_DIRECT  = 1
	METHOD_OUT_DIRECT = 2
	METHOD_NEITHER    = 3

	SIOCTL_TYPE = 40000
)

func ctlCode(device_type, function, method, access uint32) uint32 {
	return (device_type << 16) | (access << 14) | (function << 2) | method
}

var (
	IOCTL_VERSION          = ctlCode(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA)
	IOCTL_SHUTDOWN_REQUEST = ctlCode(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA)
)

// ReadVersion queries the driver's version. A simulation pipe (OpenPipe) has no
// IOCTL channel; the daemon runs the driver built from this same tree, so the
// interface version is reported instead.
func ReadVersion(file *KextFile) ([]uint8, error) {
	if file.pipe {
		version := InterfaceVersion
		return version[:], nil
	}

	data := make([]uint8, 4)
	err := file.deviceIOControl(IOCTL_VERSION, nil, data)

	if err != nil {
		return nil, err
	}
	return data, nil
}
