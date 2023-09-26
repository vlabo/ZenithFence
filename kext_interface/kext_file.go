//go:build windows
// +build windows

package kext_interface

import (
	"golang.org/x/sys/windows"
)

type KextFile struct {
	handle windows.Handle
}

func (f *KextFile) Read(buffer []byte) (int, error) {
	var count uint32 = 0
	overlapped := &windows.Overlapped{}
	err := windows.ReadFile(f.handle, buffer, &count, overlapped)
	return int(count), err
}

func (f *KextFile) Write(buffer []byte) (int, error) {
	var count uint32 = 0
	overlapped := &windows.Overlapped{}
	err := windows.WriteFile(f.handle, buffer, &count, overlapped)
	return int(count), err
}

func (f *KextFile) Close() error {
	return windows.CloseHandle(f.handle)
}
