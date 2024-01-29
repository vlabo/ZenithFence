//go:build windows
// +build windows

package kext_interface

import (
	"encoding/binary"
	"io"
)

const (
	CommandShutdown       = 0
	CommandVerdict        = 1
	CommandRedirectV4     = 2
	CommandRedirectV6     = 3
	CommandUpdateV4       = 4
	CommandUpdateV6       = 5
	CommandClearCache     = 6
	CommandGetLogs        = 7
	CommandBandwidthStats = 8
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

type RedirectV6 struct {
	command       uint8
	Id            uint64
	RemoteAddress [16]byte
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

type UpdateV6 struct {
	command         uint8
	Protocol        uint8
	LocalAddress    [16]byte
	LocalPort       uint16
	RemoteAddress   [16]byte
	RemotePort      uint16
	Verdict         uint8
	RedirectAddress [16]byte
	RedirectPort    uint16
}

func SendShutdownCommand(writer io.Writer) error {
	_, err := writer.Write([]byte{CommandShutdown})
	return err
}

func SendVerdictCommand(writer io.Writer, verdict Verdict) error {
	verdict.command = CommandVerdict
	return binary.Write(writer, binary.LittleEndian, verdict)
}

func SendRedirectV4Command(writer io.Writer, redirect RedirectV4) error {
	redirect.command = CommandRedirectV4
	return binary.Write(writer, binary.LittleEndian, redirect)
}

func SendRedirectV6Command(writer io.Writer, redirect RedirectV6) error {
	redirect.command = CommandRedirectV6
	return binary.Write(writer, binary.LittleEndian, redirect)
}

func SendUpdateV4Command(writer io.Writer, update UpdateV4) error {
	update.command = CommandUpdateV4
	return binary.Write(writer, binary.LittleEndian, update)
}

func SendUpdateV6Command(writer io.Writer, update UpdateV6) error {
	update.command = CommandUpdateV6
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

func SendGetBandwidthStatsCommand(writer io.Writer) error {
	_, err := writer.Write([]byte{CommandBandwidthStats})
	return err
}
