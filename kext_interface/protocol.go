//go:build windows
// +build windows

package kext_interface

import (
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

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

// Driver structs

const (
	InfoConnectionIPV4 = 0
)

type Connection struct {
	Id         uint64
	ProcessId  uint64
	Direction  byte
	Protocol   byte
	LocalIp    [4]byte
	RemoteIp   [4]byte
	LocalPort  uint16
	RemotePort uint16
}

type Info struct {
	Connection *Connection
}

const (
	CommandShutdown   = 0
	CommandVerdict    = 1
	CommandRedirectV4 = 2
	CommandUpdateV4   = 3
	CommandClearCache = 4
	CommandGetLogs    = 5
)

type Verdict struct {
	command uint8
	Id      uint64
	Verdict uint8
}

type RedirectV4 struct {
	command       uint8
	Id            uint64
	RemoteAddress [4]byte
	RemotePort    uint16
}

type UpdateV4 struct {
	command         uint8
	Protocol        uint8
	LocalAddress    [4]byte
	LocalPort       uint16
	RemoteAddress   [4]byte
	RemotePort      uint16
	Verdict         uint8
	RedirectAddress [4]byte
	RedirectPort    uint16
}

func WriteShutdownCommand(writer io.Writer) error {
	_, err := writer.Write([]byte{CommandShutdown})
	return err
}

func WriteVerdictCommand(verdict Verdict, writer io.Writer) error {
	verdict.command = CommandVerdict
	return binary.Write(writer, binary.LittleEndian, verdict)
}

func WriteRedirectCommand(redirect RedirectV4, writer io.Writer) error {
	redirect.command = CommandRedirectV4
	return binary.Write(writer, binary.LittleEndian, redirect)
}

func WriteUpdateCommand(update UpdateV4, writer io.Writer) error {
	update.command = CommandUpdateV4
	return binary.Write(writer, binary.LittleEndian, update)
}

func WriteClearCacheCommand(writer io.Writer) error {
	_, err := writer.Write([]byte{CommandClearCache})
	return err
}

func WriteGetLogsCommand(writer io.Writer) error {
	_, err := writer.Write([]byte{CommandGetLogs})
	return err
}

func ReadInfo(reader io.Reader) (*Info, error) {
	var infoType byte
	_, err := reader.Read(asByteArray(&infoType))
	if err != nil {
		return nil, err
	}
	switch infoType {
	case InfoConnectionIPV4:
		{
			var new Connection
			_, err = reader.Read(asByteArray(&new))
			if err != nil {
				return nil, err
			}
			return &Info{Connection: &new}, nil
		}
	}
	return nil, fmt.Errorf("unsupported info type: %d", infoType)
}

func ReadVersion(file *KextFile) ([]uint8, error) {
	data := make([]uint8, 4)
	_, err := file.deviceIOControl(IOCTL_VERSION, nil, data)

	if err != nil {
		return nil, err
	}
	return data, nil
}

func asByteArray[T any](obj *T) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(obj)), unsafe.Sizeof(*obj))
}
