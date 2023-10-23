//go:build windows
// +build windows

package kext_interface

import (
	"log"

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
	err := windows.CloseHandle(f.handle)
	f.handle = winInvalidHandleValue
	return err
}

func (f *KextFile) deviceIOControl(code uint32, inData []byte, outData []byte) (*windows.Overlapped, error) {
	var inDataPtr *byte = nil
	var inDataSize uint32 = 0
	if inData != nil {
		inDataPtr = &inData[0]
		inDataSize = uint32(len(inData))
	}

	var outDataPtr *byte = nil
	var outDataSize uint32 = 0
	if outData != nil {
		outDataPtr = &outData[0]
		outDataSize = uint32(len(outData))
	}

	overlapped := &windows.Overlapped{}
	err := windows.DeviceIoControl(f.handle,
		code,
		inDataPtr, inDataSize,
		outDataPtr, outDataSize,
		nil, overlapped)

	if err != nil {
		return nil, err
	}

	return overlapped, nil

}
