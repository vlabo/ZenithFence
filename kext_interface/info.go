package kext_interface

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	infoLogLine                 byte = 0
	infoConnectionIpv4          byte = 1
	infoConnectionIpv6          byte = 2
	infoConnectionEndEventV4    byte = 3
	infoConnectionEndEventV6    byte = 4
	infoConnectionUpdateEventV4 byte = 5
	infoConnectionUpdateEventV6 byte = 6
	infoConnectionUpdateEnd     byte = 7
)

const (
	SeverityTrace byte = 1
	SeverityDebug byte = 2
	SeverityInfo  byte = 3
	SeverityWarn  byte = 4
	SeverityError byte = 5
	SeverityFatal byte = 6
)

var ErrorUnknownInfoType = errors.New("unknown info type")

type LogLine struct {
	Severity byte
	Line     string
}

type connectionV4Internal struct {
	Id           uint64
	ProcessId    uint64
	Direction    byte
	Protocol     byte
	LocalIp      [4]byte
	RemoteIp     [4]byte
	LocalPort    uint16
	RemotePort   uint16
	PayloadLayer uint8
}

type ConnectionV4 struct {
	connectionV4Internal
	Payload []byte
}

func (c *ConnectionV4) Compare(other *ConnectionV4) bool {
	return c.Id == other.Id &&
		c.ProcessId == other.ProcessId &&
		c.Direction == other.Direction &&
		c.Protocol == other.Protocol &&
		c.LocalIp == other.LocalIp &&
		c.RemoteIp == other.RemoteIp &&
		c.LocalPort == other.LocalPort &&
		c.RemotePort == other.RemotePort
}

type connectionV6Internal struct {
	Id           uint64
	ProcessId    uint64
	Direction    byte
	Protocol     byte
	LocalIp      [16]byte
	RemoteIp     [16]byte
	LocalPort    uint16
	RemotePort   uint16
	PayloadLayer uint8
}

type ConnectionV6 struct {
	connectionV6Internal
	Payload []byte
}

func (c ConnectionV6) Compare(other *ConnectionV6) bool {
	return c.Id == other.Id &&
		c.ProcessId == other.ProcessId &&
		c.Direction == other.Direction &&
		c.Protocol == other.Protocol &&
		c.LocalIp == other.LocalIp &&
		c.RemoteIp == other.RemoteIp &&
		c.LocalPort == other.LocalPort &&
		c.RemotePort == other.RemotePort
}

type ConnectionEndV4 struct {
	ProcessId  uint64
	Direction  byte
	Protocol   byte
	LocalIp    [4]byte
	RemoteIp   [4]byte
	LocalPort  uint16
	RemotePort uint16
	RxBytes    uint64
	RxPackets  uint64
	TxBytes    uint64
	TxPackets  uint64
}

type ConnectionEndV6 struct {
	ProcessId  uint64
	Direction  byte
	Protocol   byte
	LocalIp    [16]byte
	RemoteIp   [16]byte
	LocalPort  uint16
	RemotePort uint16
	RxBytes    uint64
	RxPackets  uint64
	TxBytes    uint64
	TxPackets  uint64
}

type ConnectionUpdateV4 struct {
	Protocol   byte
	LocalIp    [4]byte
	RemoteIp   [4]byte
	LocalPort  uint16
	RemotePort uint16
	RxBytes    uint64
	RxPackets  uint64
	TxBytes    uint64
	TxPackets  uint64
}

type ConnectionUpdateV6 struct {
	Protocol   byte
	LocalIp    [16]byte
	RemoteIp   [16]byte
	LocalPort  uint16
	RemotePort uint16
	RxBytes    uint64
	RxPackets  uint64
	TxBytes    uint64
	TxPackets  uint64
}

type ConnectionUpdateEnd struct{}

func parseGenericInfo[T any](data []byte) (Info, error) {
	var new T
	reader := bytes.NewReader(data)

	err := binary.Read(reader, binary.LittleEndian, &new)
	if err != nil {
		return nil, err
	}
	return &new, nil
}

func parseEmptyInfo[T any](data []byte) (Info, error) {
	var new T
	return &new, nil
}

func parseConnectionV4(data []byte) (Info, error) {
	conn := &ConnectionV4{}
	reader := bytes.NewReader(data)

	// Read fixed size values
	err := binary.Read(reader, binary.LittleEndian, &conn.connectionV4Internal)
	if err != nil {
		return nil, err
	}

	// Read size of payload
	var size uint32
	err = binary.Read(reader, binary.LittleEndian, &size)
	if err != nil {
		return nil, err
	}

	// Read the array
	conn.Payload = make([]byte, size)
	err = binary.Read(reader, binary.LittleEndian, conn.Payload)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func parseConnectionV6(data []byte) (Info, error) {
	conn := &ConnectionV6{}
	reader := bytes.NewReader(data)

	// Read fixed size values
	err := binary.Read(reader, binary.LittleEndian, &conn.connectionV6Internal)
	if err != nil {
		return nil, err
	}

	// Read size of payload
	var size uint32
	err = binary.Read(reader, binary.LittleEndian, &size)
	if err != nil {
		return nil, err
	}

	// Read the array
	conn.Payload = make([]byte, size)
	err = binary.Read(reader, binary.LittleEndian, conn.Payload)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func parseLogLine(data []byte) (Info, error) {
	var logLine LogLine
	reader := bytes.NewReader(data)

	err := binary.Read(reader, binary.LittleEndian, &logLine.Severity)
	if err != nil {
		return nil, err
	}
	// Read string
	line := make([]byte, len(data)-1) // -1 for the severity enum.
	err = binary.Read(reader, binary.LittleEndian, &line)
	if err != nil {
		return nil, err
	}
	logLine.Line = string(line)
	return &logLine, nil
}

type Info any

func RecvInfo(reader io.Reader) (Info, error) {
	var infoType byte
	err := binary.Read(reader, binary.LittleEndian, &infoType)
	if err != nil {
		return nil, err
	}

	// Read size of data
	var size uint32
	err = binary.Read(reader, binary.LittleEndian, &size)
	if err != nil {
		return nil, err
	}

	data := make([]byte, size)
	n, err := reader.Read(data)
	if err != nil {
		return nil, err
	}

	if n != int(size) {
		return nil, errors.New("not enough data read")
	}

	// Map of infoType to parser functions
	parsers := map[byte]func([]byte) (Info, error){
		infoLogLine:                 parseLogLine,
		infoConnectionIpv4:          parseConnectionV4,
		infoConnectionIpv6:          parseConnectionV6,
		infoConnectionEndEventV4:    parseGenericInfo[ConnectionEndV4],
		infoConnectionEndEventV6:    parseGenericInfo[ConnectionEndV6],
		infoConnectionUpdateEventV4: parseGenericInfo[ConnectionUpdateV4],
		infoConnectionUpdateEventV6: parseGenericInfo[ConnectionUpdateV6],
		infoConnectionUpdateEnd:     parseEmptyInfo[ConnectionUpdateEnd],
	}

	parser, ok := parsers[infoType]
	if ok {
		return parser(data)
	}

	return nil, ErrorUnknownInfoType
}
