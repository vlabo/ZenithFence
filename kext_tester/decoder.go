package main

type PacketInfo struct {
	Id                uint32
	ProcessId         uint64
	Direction         uint8
	IpV6              bool
	Protocol          uint8
	Flags             uint8
	LocalIp           [4]uint32
	RemoteIp          [4]uint32
	LocalPort         uint16
	RemotePort        uint16
	CompartmentId     uint64
	InterfaceIndex    uint32
	SubInterfaceIndex uint32
	PacketSize        uint32
}
