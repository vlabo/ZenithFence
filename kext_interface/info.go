//go:build windows
// +build windows

package kext_interface

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	InfoLogLine              = 0
	InfoConnectionIpv4       = 1
	InfoConnectionIpv6       = 2
	InfoConnectionEndEventV4 = 3
	InfoConnectionEndEventV6 = 4
)

var ErrorUnknownInfoType = errors.New("unknown info type")

type ConnectionV4 struct {
	Id         uint64
	ProcessId  uint64
	Direction  byte
	Protocol   byte
	LocalIp    [4]byte
	RemoteIp   [4]byte
	LocalPort  uint16
	RemotePort uint16
}

type ConnectionV6 struct {
	Id         uint64
	ProcessId  uint64
	Direction  byte
	Protocol   byte
	LocalIp    [16]byte
	RemoteIp   [16]byte
	LocalPort  uint16
	RemotePort uint16
}

type ConnectionEndV4 struct {
	ProcessId  uint64
	Direction  byte
	Protocol   byte
	LocalIp    [4]byte
	RemoteIp   [4]byte
	LocalPort  uint16
	RemotePort uint16
}

type ConnectionEndV6 struct {
	ProcessId  uint64
	Direction  byte
	Protocol   byte
	LocalIp    [16]byte
	RemoteIp   [16]byte
	LocalPort  uint16
	RemotePort uint16
}

type LogLine struct {
	Severity byte
	Line     string
}

type Info struct {
	ConnectionV4    *ConnectionV4
	ConnectionV6    *ConnectionV6
	ConnectionEndV4 *ConnectionEndV4
	ConnectionEndV6 *ConnectionEndV6
	LogLine         *LogLine
}

func readInfo(reader io.Reader) (*Info, error) {
	var infoType byte
	err := binary.Read(reader, binary.LittleEndian, &infoType)
	if err != nil {
		return nil, err
	}
	switch infoType {
	case InfoConnectionIpv4:
		{
			var new ConnectionV4
			err = binary.Read(reader, binary.LittleEndian, &new)
			if err != nil {
				return nil, err
			}
			return &Info{ConnectionV4: &new}, nil
		}
	case InfoConnectionIpv6:
		{
			var new ConnectionV6
			err = binary.Read(reader, binary.LittleEndian, &new)
			if err != nil {
				return nil, err
			}
			return &Info{ConnectionV6: &new}, nil
		}
	case InfoConnectionEndEventV4:
		{
			var new ConnectionEndV4
			err = binary.Read(reader, binary.LittleEndian, &new)
			if err != nil {
				return nil, err
			}
			return &Info{ConnectionEndV4: &new}, nil
		}
	case InfoConnectionEndEventV6:
		{
			var new ConnectionEndV6
			err = binary.Read(reader, binary.LittleEndian, &new)
			if err != nil {
				return nil, err
			}
			return &Info{ConnectionEndV6: &new}, nil
		}
	case InfoLogLine:
		{
			var logLine = LogLine{}
			// Read severity
			err = binary.Read(reader, binary.LittleEndian, &logLine.Severity)
			if err != nil {
				return nil, err
			}
			// Read size
			var size uint32
			err = binary.Read(reader, binary.LittleEndian, &size)
			if err != nil {
				return nil, err
			}
			// Read string
			var line = make([]byte, size)
			err = binary.Read(reader, binary.LittleEndian, &line)
			logLine.Line = string(line)
			return &Info{LogLine: &logLine}, nil
		}
	}
	return nil, ErrorUnknownInfoType
}

func RecvInfo(file *KextFile) (*Info, error) {
	info, err := readInfo(file)
	if err != nil && errors.Is(err, ErrorUnknownInfoType) {
		// Info type is not recognized ignore the rest of the command.
		file.flush_buffer()
	}

	return info, err

}
