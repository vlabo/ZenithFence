use crate::connection_members::Direction;
use alloc::format;
use core::fmt::Display;
use smoltcp::wire::{IpProtocol, Ipv4Address};
use wdk::{
    err,
    filter_engine::{
        callout_data::CalloutData,
        layer::{self, Layer},
    },
};

#[derive(Clone)]
pub struct PacketInfoV4 {
    pub process_id: Option<u64>,
    pub direction: Direction,
    pub protocol: IpProtocol,
    pub local_ip: Ipv4Address,
    pub remote_ip: Ipv4Address,
    pub local_port: u16,
    pub remote_port: u16,
    pub interface_index: u32,
    pub sub_interface_index: u32,
}

impl PacketInfoV4 {
    pub fn from_callout_data(data: &CalloutData) -> Self {
        match data.layer {
            Layer::FwpmLayerInboundIppacketV4 => {
                type Field = layer::FwpsFieldsInboundIppacketV4;
                Self {
                    direction: Direction::Inbound,
                    local_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpLocalAddress as usize)
                            .to_be_bytes(),
                    ),
                    remote_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpRemoteAddress as usize)
                            .to_be_bytes(),
                    ),
                    interface_index: data.get_value_u32(Field::InterfaceIndex as usize),
                    sub_interface_index: data.get_value_u32(Field::SubInterfaceIndex as usize),
                    ..Default::default()
                }
            }
            Layer::FwpmLayerOutboundIppacketV4 => {
                type Field = layer::FwpsFieldsOutboundIppacketV4;
                Self {
                    direction: Direction::Outbound,
                    local_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpLocalAddress as usize)
                            .to_be_bytes(),
                    ),
                    remote_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpRemoteAddress as usize)
                            .to_be_bytes(),
                    ),
                    interface_index: data.get_value_u32(Field::InterfaceIndex as usize),
                    sub_interface_index: data.get_value_u32(Field::SubInterfaceIndex as usize),
                    ..Default::default()
                }
            }
            Layer::FwpmLayerAleAuthConnectV4 => {
                type Field = layer::FwpsFieldsAleAuthConnectV4;
                Self {
                    process_id: data.get_process_id(),
                    direction: Direction::Outbound,
                    protocol: IpProtocol::from(data.get_value_u8(Field::IpProtocol as usize)),
                    local_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpLocalAddress as usize)
                            .to_be_bytes(),
                    ),
                    remote_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpRemoteAddress as usize)
                            .to_be_bytes(),
                    ),
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    remote_port: data.get_value_u16(Field::IpRemotePort as usize),
                    interface_index: data.get_value_u32(Field::InterfaceIndex as usize),
                    sub_interface_index: data.get_value_u32(Field::SubInterfaceIndex as usize),
                    ..Default::default()
                }
            }
            Layer::FwpmLayerAleAuthRecvAcceptV4 => {
                type Field = layer::FwpsFieldsAleAuthRecvAcceptV4;
                Self {
                    process_id: data.get_process_id(),
                    direction: Direction::Inbound,
                    protocol: IpProtocol::from(data.get_value_u8(Field::IpProtocol as usize)),
                    local_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpLocalAddress as usize)
                            .to_be_bytes(),
                    ),
                    remote_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpRemoteAddress as usize)
                            .to_be_bytes(),
                    ),
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    remote_port: data.get_value_u16(Field::IpRemotePort as usize),
                    interface_index: data.get_value_u32(Field::InterfaceIndex as usize),
                    sub_interface_index: data.get_value_u32(Field::SubInterfaceIndex as usize),
                    ..Default::default()
                }
            }

            Layer::FwpmLayerAleAuthListenV4 => {
                type Field = layer::FwpsFieldsAleAuthListenV4;
                Self {
                    process_id: data.get_process_id(),
                    direction: Direction::Inbound,
                    protocol: IpProtocol::Tcp,
                    local_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpLocalAddress as usize)
                            .to_be_bytes(),
                    ),
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    ..Default::default()
                }
            }
            Layer::FwpmLayerAleConnectRedirectV4 => {
                type Field = layer::FwpsFieldsAleConnectRedirectV4;
                Self {
                    process_id: data.get_process_id(),
                    direction: Direction::Outbound,
                    protocol: IpProtocol::from(data.get_value_u8(Field::IpProtocol as usize)),
                    local_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpLocalAddress as usize)
                            .to_be_bytes(),
                    ),
                    remote_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpRemoteAddress as usize)
                            .to_be_bytes(),
                    ),
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    remote_port: data.get_value_u16(Field::IpRemotePort as usize),
                    ..Default::default()
                }
            }
            Layer::FwpmLayerAleResourceAssignmentV4 => {
                type Field = layer::FwpsFieldsAleResourceAssignmentV4;
                Self {
                    process_id: data.get_process_id(),
                    direction: Direction::NotApplicable,
                    protocol: IpProtocol::from(data.get_value_u8(Field::IpProtocol as usize)),
                    local_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpLocalAddress as usize)
                            .to_be_bytes(),
                    ),
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    ..Default::default()
                }
            }
            Layer::FwpmLayerAleResourceReleaseV4 => {
                type Field = layer::FwpsFieldsAleResourceReleaseV4;
                Self {
                    process_id: data.get_process_id(),
                    direction: Direction::NotApplicable,
                    protocol: IpProtocol::from(data.get_value_u8(Field::IpProtocol as usize)),
                    local_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpLocalAddress as usize)
                            .to_be_bytes(),
                    ),
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    ..Default::default()
                }
            }
            Layer::FwpmLayerAleEndpointClosureV4 => {
                type Field = layer::FwpsFieldsAleEndpointClosureV4;
                Self {
                    process_id: data.get_process_id(),
                    direction: Direction::NotApplicable,
                    protocol: IpProtocol::from(data.get_value_u8(Field::IpProtocol as usize)),
                    local_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpLocalAddress as usize)
                            .to_be_bytes(),
                    ),
                    remote_ip: Ipv4Address::from_bytes(
                        &data
                            .get_value_u32(Field::IpRemoteAddress as usize)
                            .to_be_bytes(),
                    ),
                    local_port: data.get_value_u16(Field::IpLocalPort as usize),
                    remote_port: data.get_value_u16(Field::IpRemotePort as usize),
                    ..Default::default()
                }
            }
            _ => {
                let guid = data.layer.get_guid();
                err!("unsupported layer: {:#x}", guid.data1);
                Self::default()
            }
        }
    }
}

impl Display for PacketInfoV4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let local = format!("{}:{}", self.local_ip, self.local_port);
        let remote = format!("{}:{}", self.remote_ip, self.remote_port);

        f.debug_struct("Packet")
            .field("local", &local)
            .field("remote", &remote)
            .field("protocol", &self.protocol)
            .field("direction", &self.direction)
            .finish()
    }
}

impl Default for PacketInfoV4 {
    fn default() -> Self {
        Self {
            process_id: None,
            direction: Direction::NotApplicable,
            protocol: IpProtocol::Unknown(0xFF),
            local_ip: Ipv4Address::UNSPECIFIED,
            remote_ip: Ipv4Address::UNSPECIFIED,
            local_port: 0,
            remote_port: 0,
            interface_index: 0,
            sub_interface_index: 0,
        }
    }
}
