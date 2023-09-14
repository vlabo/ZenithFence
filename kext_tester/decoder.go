package main

type PacketInfo struct {
	Id                uint32    `cbor:"id"`
	ProcessId         *uint64   `cbor:"process_id"`
	ProcessPath       *string   `cbor:"process_path"`
	Direction         uint8     `cbor:"direction"`
	IpV6              bool      `cbor:"ip_v6"`
	Protocol          uint8     `cbor:"protocol"`
	Flags             uint8     `cbor:"flags"`
	LocalIp           [4]uint32 `cbor:"local_ip"`
	RemoteIp          [4]uint32 `cbor:"remote_ip"`
	LocalPort         uint16    `cbor:"local_port"`
	RemotePort        uint16    `cbor:"remote_port"`
	CompartmentId     uint64    `cbor:"compartment_id"`
	InterfaceIndex    uint32    `cbor:"interface_index"`
	SubInterfaceIndex uint32    `cbor:"sub_interface_index"`
	PacketSize        uint32    `cbor:"packet_size"`
}
