//go:build windows
// +build windows

package kext_interface

import (
	"encoding/binary"
	"encoding/json"
	"github.com/fxamacker/cbor/v2"
	"io"
	"log"
)

const use_json = true

// Driver structs
type Connection struct {
	Id          uint64   `json:"id"`
	ProcessId   *uint64  `json:"process_id"`
	ProcessPath *string  `json:"process_path"`
	Direction   byte     `json:"direction"`
	IpV6        bool     `json:"ip_v6"`
	Protocol    byte     `json:"protocol"`
	LocalIp     []uint32 `json:"local_ip"`
	RemoteIp    []uint32 `json:"remote_ip"`
	LocalPort   uint16   `json:"local_port"`
	RemotePort  uint16   `json:"remote_port"`
}

type Info struct {
	Connection *Connection
}

func ParseInfo(data []byte) (*Info, error) {
	var info Info
	var err error
	if use_json {
		// log.Printf("Info: %s\n", string(data))
		err = json.Unmarshal(data, &info)
	} else {
		err = cbor.Unmarshal(data, &info)
	}
	return &info, err
}

type Verdict struct {
	Id      uint64 `json:"id"`
	Verdict uint8  `json:"verdict"`
}

type Command struct {
	Shutdown *[]struct{} `json:"Shutdown,omitempty"`
	Verdict  *Verdict    `json:"Verdict,omitempty"`
}

func BuildShutdown() Command {
	return Command{Shutdown: &[]struct{}{}}
}

func BuildVerdict(id uint64, verdict uint8) Command {
	return Command{Verdict: &Verdict{Id: id, Verdict: verdict}}
}

func WriteCommand(writer io.Writer, command Command) {
	var data []byte
	var err error
	if use_json {
		data, err = json.Marshal(&command)
		// log.Printf("Command: %s\n", string(data))
	} else {
		data, err = cbor.Marshal(&command)
	}
	if err != nil {
		log.Printf("failed to marshal command: %s\n", err)
		return
	}
	writer.Write(data)
}

func ReadInfo(reader io.Reader, dataChan chan *Info) {
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
				log.Printf("failed to read from driver: %s\n", err)
				return
			}

			if count == 0 {
				log.Printf("failed to read from driver: empty buffer\n")
				return
			}

			// log.Printf("recived %d bytes", count)

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
				info, err := ParseInfo(structBuf)
				if err == nil {
					dataChan <- info
				} else {
					log.Printf("failed to parse info: %s", err)
				}
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
				info, err := ParseInfo(structBuf)
				if err == nil {
					dataChan <- info
				} else {
					log.Printf("failed to parse info: %s", err)
				}
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
