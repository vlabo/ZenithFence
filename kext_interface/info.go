package kext_interface

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	infoLogLine              byte = 0
	infoConnectionIpv4       byte = 1
	infoConnectionIpv6       byte = 2
	infoConnectionEndEventV4 byte = 3
	infoConnectionEndEventV6 byte = 4
	infoBandwidthStatsV4     byte = 5
	infoBandwidthStatsV6     byte = 6
)

var ErrorUnknownInfoType = errors.New("unknown info type")

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

type BandwidthValueV4 struct {
	LocalIP          [4]byte
	LocalPort        uint16
	RemoteIP         [4]byte
	RemotePort       uint16
	TransmittedBytes uint64
	ReceivedBytes    uint64
}

type BandwidthValueV6 struct {
	LocalIP          [16]byte
	LocalPort        uint16
	RemoteIP         [16]byte
	RemotePort       uint16
	TransmittedBytes uint64
	ReceivedBytes    uint64
}

type BandwidthStatsV4 struct {
	Protocol uint8
	Values   []BandwidthValueV4
}

type BandwidthStatsV6 struct {
	Protocol uint8
	Values   []BandwidthValueV6
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

func parseConnectionEndV6(data []byte) (Info, error) {
	var new ConnectionEndV6
	reader := bytes.NewReader(data)

	err := binary.Read(reader, binary.LittleEndian, &new)
	if err != nil {
		return nil, err
	}
	return &new, nil
}

func parseConnectionEndV4(data []byte) (Info, error) {
	var new ConnectionEndV4
	reader := bytes.NewReader(data)

	err := binary.Read(reader, binary.LittleEndian, &new)
	if err != nil {
		return nil, err
	}
	return &new, nil
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
	logLine.Line = string(line)
	return &logLine, nil
}

func parseBandwidthStatsV4(data []byte) (Info, error) {
	var bandwidth BandwidthStatsV4
	reader := bytes.NewReader(data)

	// Read Protocol
	err := binary.Read(reader, binary.LittleEndian, &bandwidth.Protocol)
	if err != nil {
		return nil, err
	}
	// Read size of array
	var size uint32
	err = binary.Read(reader, binary.LittleEndian, &size)
	if err != nil {
		return nil, err
	}
	// Read array
	bandwidth.Values = make([]BandwidthValueV4, size)
	for i := 0; i < int(size); i++ {
		binary.Read(reader, binary.LittleEndian, &bandwidth.Values[i])
	}
	return &bandwidth, nil
}

func parseBandwidthStatsV6(data []byte) (Info, error) {
	var bandwidth BandwidthStatsV6
	reader := bytes.NewReader(data)

	// Read Protocol
	err := binary.Read(reader, binary.LittleEndian, &bandwidth.Protocol)
	if err != nil {
		return nil, err
	}
	// Read size of array
	var size uint32
	err = binary.Read(reader, binary.LittleEndian, &size)
	if err != nil {
		return nil, err
	}
	// Read array
	bandwidth.Values = make([]BandwidthValueV6, size)
	for i := 0; i < int(size); i++ {
		binary.Read(reader, binary.LittleEndian, &bandwidth.Values[i])
	}
	return &bandwidth, nil
}

type Info interface{}

func RecvInfo(reader io.Reader) (Info, error) {
	var infoType byte
	err := binary.Read(reader, binary.LittleEndian, &infoType)
	if err != nil {
		return nil, err
	}

	// Read size of data
	var size uint32
	err = binary.Read(reader, binary.LittleEndian, &size)

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
		infoConnectionIpv4:       parseConnectionV4,
		infoConnectionIpv6:       parseConnectionV6,
		infoConnectionEndEventV4: parseConnectionEndV4,
		infoConnectionEndEventV6: parseConnectionEndV6,
		infoLogLine:              parseLogLine,
		infoBandwidthStatsV4:     parseBandwidthStatsV4,
		infoBandwidthStatsV6:     parseBandwidthStatsV6,
	}

	parser, ok := parsers[infoType]
	if ok {
		return parser(data)
	}

	return nil, ErrorUnknownInfoType
}
