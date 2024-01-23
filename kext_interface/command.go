//go:build windows
// +build windows

package kext_interface

import (
	"encoding/binary"
	"io"
)

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

func SendShutdownCommand(writer io.Writer) error {
	_, err := writer.Write([]byte{CommandShutdown})
	return err
}

func SendVerdictCommand(verdict Verdict, writer io.Writer) error {
	verdict.command = CommandVerdict
	return binary.Write(writer, binary.LittleEndian, verdict)
}

func SendRedirectCommand(redirect RedirectV4, writer io.Writer) error {
	redirect.command = CommandRedirectV4
	return binary.Write(writer, binary.LittleEndian, redirect)
}

func SendUpdateCommand(update UpdateV4, writer io.Writer) error {
	update.command = CommandUpdateV4
	return binary.Write(writer, binary.LittleEndian, update)
}

func SendClearCacheCommand(writer io.Writer) error {
	_, err := writer.Write([]byte{CommandClearCache})
	return err
}

func SendGetLogsCommand(writer io.Writer) error {
	_, err := writer.Write([]byte{CommandGetLogs})
	return err
}
