//go:build windows
// +build windows

package kext_interface

import (
	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/vlabo/portmaster_windows_rust_kext/kext_interface/Protocol"
)

func GetShutdownRequest() []byte {
	builder := flatbuffers.NewBuilder(0)

	// Shutdown command
	Protocol.ShutdownStart(builder)
	shutdownBuffer := Protocol.ShutdownEnd(builder)

	// Command wrapper
	Protocol.CommandStart(builder)
	Protocol.CommandAddCommandType(builder, Protocol.CommandUnionShutdown)
	Protocol.CommandAddCommand(builder, shutdownBuffer)
	command := Protocol.CommandEnd(builder)

	// Finish
	builder.Finish(command)
	return builder.FinishedBytes()
}

func ParsePacket(data []byte) *Protocol.Packet {
	return Protocol.GetRootAsPacket(data, 0)
}
