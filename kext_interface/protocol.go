//go:build windows
// +build windows

package kext_interface

import (
	"encoding/binary"
	"io"
	"log"

	"github.com/fxamacker/cbor/v2"
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
type Connection struct {
	Id          uint64  `json:"id"`
	ProcessId   *uint64 `json:"process_id"`
	ProcessPath *string `json:"process_path"`
	Direction   byte    `json:"direction"`
	IpV6        bool    `json:"ip_v6"`
	Protocol    byte    `json:"protocol"`
	LocalIp     []uint8 `json:"local_ip"`
	RemoteIp    []uint8 `json:"remote_ip"`
	LocalPort   uint16  `json:"local_port"`
	RemotePort  uint16  `json:"remote_port"`
}

type LogLine struct {
	Severity int    `json:"severity"`
	Line     string `json:"line"`
}

type Info struct {
	Connection *Connection `json:"Connection,omitempty"`
	LogLines   *[]LogLine  `json:"LogLines,omitempty"`
}

func ParseInfo(data []byte) (*Info, error) {
	var info Info
	err := cbor.Unmarshal(data, &info)
	return &info, err
}

type Verdict struct {
	Id      uint64 `json:"id"`
	Verdict uint8  `json:"verdict"`
}

type Redirect struct {
	Id            uint64  `json:"id"`
	RemoteAddress []uint8 `json:"remote_address"`
	RemotePort    uint16  `json:"remote_port"`
}

type Update struct {
	Protocol      uint8   `json:"protocol"`
	Port          uint16  `json:"port"`
	Verdict       uint8   `json:"verdict"`
	RemoteAddress []uint8 `json:"remote_address"`
	RemotePort    uint16  `json:"remote_port"`
}

type Command struct {
	Shutdown   *[]struct{} `json:"Shutdown,omitempty"`
	Verdict    *Verdict    `json:"Verdict,omitempty"`
	Redirect   *Redirect   `json:"Redirect,omitempty"`
	Update     *Update     `json:"Update,omitempty"`
	ClearCache *[]struct{} `json:"ClearCache,omitempty"`
	GetLogs    *[]struct{} `json:"GetLogs,omitempty"`
}

func BuildShutdown() Command {
	return Command{Shutdown: &[]struct{}{}}
}

func BuildVerdict(verdict Verdict) Command {
	return Command{Verdict: &verdict}
}

func BuildRedirect(redirect Redirect) Command {
	return Command{Redirect: &redirect}
}

func BuildUpdate(update Update) Command {
	return Command{Update: &update}
}

func BuildClearCache() Command {
	return Command{ClearCache: &[]struct{}{}}
}

func BuildGetLogs() Command {
	return Command{GetLogs: &[]struct{}{}}
}

func WriteCommand(writer io.Writer, command Command) {
	data, err := cbor.Marshal(&command)
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

			// log.Printf("received %d bytes", count)

			// Slice only with the actual data
			buffer = readBuffer[0:count]
		}

		// Extract data
		if structBuf == nil {
			// Begging of a struct
			// The first 4 bytes contain the size of the struct (it may be bigger then the read buffer).
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

func ReadVersion(file *KextFile) ([]uint8, error) {
	data := make([]uint8, 4)
	_, err := file.deviceIOControl(IOCTL_VERSION, nil, data)

	if err != nil {
		return nil, err
	}
	return data, nil
}
