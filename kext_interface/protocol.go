//go:build windows
// +build windows

package kext_interface

import (
	"encoding/binary"
	"io"
	"log"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/vlabo/portmaster_windows_rust_kext/kext_interface/Protocol"
)

func GetShutdownRequest() []byte {
	builder := flatbuffers.NewBuilder(0)

	// Shutdown command
	Protocol.ShutdownStart(builder)
	shutdownBuffer := Protocol.ShutdownEnd(builder)

	return buildCommand(builder, Protocol.CommandUnionShutdown, shutdownBuffer)
}

func GetVerdirctResponse(id uint64, verdict int8) []byte {
	builder := flatbuffers.NewBuilder(0)

	// VerdictReponse command
	Protocol.VerdictResponseStart(builder)
	Protocol.VerdictResponseAddId(builder, id)
	Protocol.VerdictResponseAddVerdict(builder, verdict)
	responseBuffer := Protocol.VerdictResponseEnd(builder)

	// Finish
	return buildCommand(builder, Protocol.CommandUnionResponse, responseBuffer)
}

func GetRedirectResponse(id uint64, ip []byte, port uint16) []byte {
	builder := flatbuffers.NewBuilder(0)
	bufferIp := builder.CreateByteVector(ip)

	// RedirectReponse command
	Protocol.RedirectResponseStart(builder)
	Protocol.RedirectResponseAddId(builder, id)
	Protocol.RedirectResponseAddIpv6(builder, false)
	Protocol.RedirectResponseAddRemoteIp(builder, bufferIp)
	Protocol.RedirectResponseAddRemotePort(builder, port)
	responseBuffer := Protocol.RedirectResponseEnd(builder)

	// Finish
	return buildCommand(builder, Protocol.CommandUnionRedirect, responseBuffer)
}

func buildCommand(builder *flatbuffers.Builder, commandType Protocol.CommandUnion, commandBuffer flatbuffers.UOffsetT) []byte {
	// Command wrapper
	Protocol.CommandStart(builder)
	Protocol.CommandAddCommandType(builder, commandType)
	Protocol.CommandAddCommand(builder, commandBuffer)
	command := Protocol.CommandEnd(builder)

	builder.Finish(command)
	return builder.FinishedBytes()
}

func ParseInfo(data []byte) *Protocol.Info {
	return Protocol.GetRootAsInfo(data, 0)
}

func ReadPacket(data *Protocol.Info) *Protocol.Packet {
	unionTable := new(flatbuffers.Table)
	if data.Value(unionTable) {
		packet := new(Protocol.Packet)
		packet.Init(unionTable.Bytes, unionTable.Pos)
		return packet
	}
	return nil
}

func ReadLogLine(info *Protocol.Info) *Protocol.LogLine {
	unionTable := new(flatbuffers.Table)
	if info.Value(unionTable) {
		logLine := new(Protocol.LogLine)
		logLine.Init(unionTable.Bytes, unionTable.Pos)
		return logLine
	}
	return nil
}

func ReadInfo(reader io.Reader, dataChan chan *Protocol.Info) {
	var readBuffer []byte = make([]byte, 500)
	var buffer []byte = nil
	var structBuf []byte = nil
	var structSize uint32 = 0
	var fillIndex int = 0

	for true {
		if buffer == nil {
			// Read data from the file
			count, err := reader.Read(readBuffer)
			if err != nil {
				log.Printf("failed to read from driver: %s", err)
				return
			}

			if count == 0 {
				log.Printf("failed to read from driver: empty buffer")
				return
			}

			log.Printf("recived %d bytes", count)

			// Slice only with the actual data
			buffer = readBuffer[0:count]
		}

		// Extract data
		if structBuf == nil {
			// Beginig of a struct
			// The first 4 bytes conain the size of the struct (it may be bigger then the read buffer).
			structSize = binary.LittleEndian.Uint32(buffer[0:4])
			buffer = buffer[4:]
			structBuf = make([]byte, structSize)

			if len(buffer) >= int(structSize) {
				// The read buffer contains the whole struct
				copy(structBuf, buffer[0:structSize])
				dataChan <- ParseInfo(structBuf)
				structBuf = nil
				fillIndex = 0

				// Check if there is more data at the end
				if len(buffer) == int(structSize) {
					buffer = nil
				} else {
					buffer = buffer[structSize:]
				}
			} else {
				// The read buffer is not big enough for the whole struct.
				// copy the data and read again.
				copy(structBuf, buffer)
				fillIndex += len(buffer)
				buffer = nil
			}
		} else {
			// Filling the next part of the struct.
			if int(structSize)-fillIndex > len(buffer) {
				// There is more data, copy and read again.
				copy(structBuf[fillIndex:], buffer)
				fillIndex += len(buffer)
				buffer = nil
			} else {
				// This is the last part of the struct.
				size := int(structSize) - fillIndex
				copy(structBuf[fillIndex:], buffer[0:size])
				_ = ParseInfo(structBuf)
				dataChan <- ParseInfo(structBuf)
				structBuf = nil
				fillIndex = 0

				// Check if there is more data at the end
				if len(buffer) == size {
					buffer = nil
				} else {
					buffer = buffer[size:]
				}
			}
		}

	}

}
