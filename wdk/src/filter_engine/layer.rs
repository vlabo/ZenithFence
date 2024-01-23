#![allow(dead_code)]

use windows_sys::{
    core::GUID,
    Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V4_DISCARD,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_CONNECT_V6_DISCARD,
        FWPM_LAYER_ALE_AUTH_LISTEN_V4, FWPM_LAYER_ALE_AUTH_LISTEN_V4_DISCARD,
        FWPM_LAYER_ALE_AUTH_LISTEN_V6, FWPM_LAYER_ALE_AUTH_LISTEN_V6_DISCARD,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD,
        FWPM_LAYER_ALE_BIND_REDIRECT_V4, FWPM_LAYER_ALE_BIND_REDIRECT_V6,
        FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
        FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4, FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6,
        FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD,
        FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6, FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD,
        FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD,
        FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD,
        FWPM_LAYER_ALE_RESOURCE_RELEASE_V4, FWPM_LAYER_ALE_RESOURCE_RELEASE_V6,
        FWPM_LAYER_DATAGRAM_DATA_V4, FWPM_LAYER_DATAGRAM_DATA_V4_DISCARD,
        FWPM_LAYER_DATAGRAM_DATA_V6, FWPM_LAYER_DATAGRAM_DATA_V6_DISCARD,
        FWPM_LAYER_INBOUND_ICMP_ERROR_V4, FWPM_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD,
        FWPM_LAYER_INBOUND_ICMP_ERROR_V6, FWPM_LAYER_INBOUND_ICMP_ERROR_V6_DISCARD,
        FWPM_LAYER_INBOUND_IPPACKET_V4, FWPM_LAYER_INBOUND_IPPACKET_V4_DISCARD,
        FWPM_LAYER_INBOUND_IPPACKET_V6, FWPM_LAYER_INBOUND_IPPACKET_V6_DISCARD,
        FWPM_LAYER_INBOUND_TRANSPORT_V4, FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD,
        FWPM_LAYER_INBOUND_TRANSPORT_V6, FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD,
        FWPM_LAYER_IPFORWARD_V4, FWPM_LAYER_IPFORWARD_V4_DISCARD, FWPM_LAYER_IPFORWARD_V6,
        FWPM_LAYER_IPFORWARD_V6_DISCARD, FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4,
        FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD, FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6,
        FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6_DISCARD, FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD, FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        FWPM_LAYER_OUTBOUND_IPPACKET_V6_DISCARD, FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        FWPM_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD, FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        FWPM_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD, FWPM_LAYER_STREAM_V4,
        FWPM_LAYER_STREAM_V4_DISCARD, FWPM_LAYER_STREAM_V6, FWPM_LAYER_STREAM_V6_DISCARD,
    },
};

#[repr(C)]
pub(crate) struct Value {
    value_type: ValueType,
    pub(crate) value: ValueData,
}

#[repr(C)]
pub(crate) struct FwpsIncomingValues {
    pub(crate) layer_id: u16,
    pub(crate) value_count: u32,
    pub(crate) incoming_value_array: *const Value,
}

#[repr(C)]
pub(crate) union ValueData {
    pub(crate) uint8: u8,
    pub(crate) uint16: u16,
    pub(crate) uint32: u32,
    pub(crate) uint64: *const u64,
    pub(crate) byte_array16: *const [u8; 16],
    // TODO: add the rest of possible values.
}

#[repr(C)]
pub enum ValueType {
    FwpEmpty = 0,
    FwpUint8 = 2,
    FwpUint16 = 3,
    FwpUint32 = 4,
    FwpUint64 = 5,
    FwpInt8 = 6,
    FwpInt16 = 8,
    FwpInt32 = 9,
    FwpInt64 = 10,
    FwpFloat = 11,
    FwpDouble = 12,
    FwpByteArray16Type = 13,
    FwpByteBlobType = 14,
    FwpSid = 15,
    FwpSecurityDescriptorType = 16,
    FwpTokenInformationType = 17,
    FwpTokenAccessInformationType = 18,
    FwpUnicodeStringType = 19,
    FwpByteArray6Type = 20,
    FwpSingleDataTypeMax = 0xff,
    FwpV4AddrMask = 0xff + 1,
    FwpV6AddrMask = 0xff + 2,
    FwpRangeType = 0xff + 3,
    FwpDataTypeMax = 0xff + 4,
}

#[derive(Copy, Clone)]
pub enum Layer {
    FwpmLayerInboundIppacketV4,
    FwpmLayerInboundIppacketV4Discard,
    FwpmLayerInboundIppacketV6,
    FwpmLayerInboundIppacketV6Discard,
    FwpmLayerOutboundIppacketV4,
    FwpmLayerOutboundIppacketV4Discard,
    FwpmLayerOutboundIppacketV6,
    FwpmLayerOutboundIppacketV6Discard,
    FwpmLayerIpforwardV4,
    FwpmLayerIpforwardV4Discard,
    FwpmLayerIpforwardV6,
    FwpmLayerIpforwardV6Discard,
    FwpmLayerInboundTransportV4,
    FwpmLayerInboundTransportV4Discard,
    FwpmLayerInboundTransportV6,
    FwpmLayerInboundTransportV6Discard,
    FwpmLayerOutboundTransportV4,
    FwpmLayerOutboundTransportV4Discard,
    FwpmLayerOutboundTransportV6,
    FwpmLayerOutboundTransportV6Discard,
    FwpmLayerStreamV4,
    FwpmLayerStreamV4Discard,
    FwpmLayerStreamV6,
    FwpmLayerStreamV6Discard,
    FwpmLayerDatagramDataV4,
    FwpmLayerDatagramDataV4Discard,
    FwpmLayerDatagramDataV6,
    FwpmLayerDatagramDataV6Discard,
    FwpmLayerInboundIcmpErrorV4,
    FwpmLayerInboundIcmpErrorV4Discard,
    FwpmLayerInboundIcmpErrorV6,
    FwpmLayerInboundIcmpErrorV6Discard,
    FwpmLayerOutboundIcmpErrorV4,
    FwpmLayerOutboundIcmpErrorV4Discard,
    FwpmLayerOutboundIcmpErrorV6,
    FwpmLayerOutboundIcmpErrorV6Discard,
    FwpmLayerAleResourceAssignmentV4,
    FwpmLayerAleResourceAssignmentV4Discard,
    FwpmLayerAleResourceAssignmentV6,
    FwpmLayerAleResourceAssignmentV6Discard,
    FwpmLayerAleAuthListenV4,
    FwpmLayerAleAuthListenV4Discard,
    FwpmLayerAleAuthListenV6,
    FwpmLayerAleAuthListenV6Discard,
    FwpmLayerAleAuthRecvAcceptV4,
    FwpmLayerAleAuthRecvAcceptV4Discard,
    FwpmLayerAleAuthRecvAcceptV6,
    FwpmLayerAleAuthRecvAcceptV6Discard,
    FwpmLayerAleAuthConnectV4,
    FwpmLayerAleAuthConnectV4Discard,
    FwpmLayerAleAuthConnectV6,
    FwpmLayerAleAuthConnectV6Discard,
    FwpmLayerAleFlowEstablishedV4,
    FwpmLayerAleFlowEstablishedV4Discard,
    FwpmLayerAleFlowEstablishedV6,
    FwpmLayerAleFlowEstablishedV6Discard,
    FwpmLayerAleConnectRedirectV4,
    FwpmLayerAleConnectRedirectV6,
    FwpmLayerAleBindRedirectV4,
    FwpmLayerAleBindRedirectV6,
    FwpmLayerAleResourceReleaseV4,
    FwpmLayerAleResourceReleaseV6,
    FwpmLayerAleEndpointClosureV4,
    FwpmLayerAleEndpointClosureV6,
}
impl Layer {
    pub fn get_guid(&self) -> GUID {
        match self {
            Layer::FwpmLayerInboundIppacketV4 => FWPM_LAYER_INBOUND_IPPACKET_V4,
            Layer::FwpmLayerInboundIppacketV4Discard => FWPM_LAYER_INBOUND_IPPACKET_V4_DISCARD,
            Layer::FwpmLayerInboundIppacketV6 => FWPM_LAYER_INBOUND_IPPACKET_V6,
            Layer::FwpmLayerInboundIppacketV6Discard => FWPM_LAYER_INBOUND_IPPACKET_V6_DISCARD,
            Layer::FwpmLayerOutboundIppacketV4 => FWPM_LAYER_OUTBOUND_IPPACKET_V4,
            Layer::FwpmLayerOutboundIppacketV4Discard => FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD,
            Layer::FwpmLayerOutboundIppacketV6 => FWPM_LAYER_OUTBOUND_IPPACKET_V6,
            Layer::FwpmLayerOutboundIppacketV6Discard => FWPM_LAYER_OUTBOUND_IPPACKET_V6_DISCARD,
            Layer::FwpmLayerIpforwardV4 => FWPM_LAYER_IPFORWARD_V4,
            Layer::FwpmLayerIpforwardV4Discard => FWPM_LAYER_IPFORWARD_V4_DISCARD,
            Layer::FwpmLayerIpforwardV6 => FWPM_LAYER_IPFORWARD_V6,
            Layer::FwpmLayerIpforwardV6Discard => FWPM_LAYER_IPFORWARD_V6_DISCARD,
            Layer::FwpmLayerInboundTransportV4 => FWPM_LAYER_INBOUND_TRANSPORT_V4,
            Layer::FwpmLayerInboundTransportV4Discard => FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD,
            Layer::FwpmLayerInboundTransportV6 => FWPM_LAYER_INBOUND_TRANSPORT_V6,
            Layer::FwpmLayerInboundTransportV6Discard => FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD,
            Layer::FwpmLayerOutboundTransportV4 => FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            Layer::FwpmLayerOutboundTransportV4Discard => FWPM_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD,
            Layer::FwpmLayerOutboundTransportV6 => FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
            Layer::FwpmLayerOutboundTransportV6Discard => FWPM_LAYER_OUTBOUND_TRANSPORT_V6_DISCARD,
            Layer::FwpmLayerStreamV4 => FWPM_LAYER_STREAM_V4,
            Layer::FwpmLayerStreamV4Discard => FWPM_LAYER_STREAM_V4_DISCARD,
            Layer::FwpmLayerStreamV6 => FWPM_LAYER_STREAM_V6,
            Layer::FwpmLayerStreamV6Discard => FWPM_LAYER_STREAM_V6_DISCARD,
            Layer::FwpmLayerDatagramDataV4 => FWPM_LAYER_DATAGRAM_DATA_V4,
            Layer::FwpmLayerDatagramDataV4Discard => FWPM_LAYER_DATAGRAM_DATA_V4_DISCARD,
            Layer::FwpmLayerDatagramDataV6 => FWPM_LAYER_DATAGRAM_DATA_V6,
            Layer::FwpmLayerDatagramDataV6Discard => FWPM_LAYER_DATAGRAM_DATA_V6_DISCARD,
            Layer::FwpmLayerInboundIcmpErrorV4 => FWPM_LAYER_INBOUND_ICMP_ERROR_V4,
            Layer::FwpmLayerInboundIcmpErrorV4Discard => FWPM_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD,
            Layer::FwpmLayerInboundIcmpErrorV6 => FWPM_LAYER_INBOUND_ICMP_ERROR_V6,
            Layer::FwpmLayerInboundIcmpErrorV6Discard => FWPM_LAYER_INBOUND_ICMP_ERROR_V6_DISCARD,
            Layer::FwpmLayerOutboundIcmpErrorV4 => FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4,
            Layer::FwpmLayerOutboundIcmpErrorV4Discard => FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD,
            Layer::FwpmLayerOutboundIcmpErrorV6 => FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6,
            Layer::FwpmLayerOutboundIcmpErrorV6Discard => FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6_DISCARD,
            Layer::FwpmLayerAleResourceAssignmentV4 => FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
            Layer::FwpmLayerAleResourceAssignmentV4Discard => {
                FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD
            }
            Layer::FwpmLayerAleResourceAssignmentV6 => FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
            Layer::FwpmLayerAleResourceAssignmentV6Discard => {
                FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD
            }
            Layer::FwpmLayerAleAuthListenV4 => FWPM_LAYER_ALE_AUTH_LISTEN_V4,
            Layer::FwpmLayerAleAuthListenV4Discard => FWPM_LAYER_ALE_AUTH_LISTEN_V4_DISCARD,
            Layer::FwpmLayerAleAuthListenV6 => FWPM_LAYER_ALE_AUTH_LISTEN_V6,
            Layer::FwpmLayerAleAuthListenV6Discard => FWPM_LAYER_ALE_AUTH_LISTEN_V6_DISCARD,
            Layer::FwpmLayerAleAuthRecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            Layer::FwpmLayerAleAuthRecvAcceptV4Discard => {
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD
            }
            Layer::FwpmLayerAleAuthRecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            Layer::FwpmLayerAleAuthRecvAcceptV6Discard => {
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6_DISCARD
            }
            Layer::FwpmLayerAleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Layer::FwpmLayerAleAuthConnectV4Discard => FWPM_LAYER_ALE_AUTH_CONNECT_V4_DISCARD,
            Layer::FwpmLayerAleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            Layer::FwpmLayerAleAuthConnectV6Discard => FWPM_LAYER_ALE_AUTH_CONNECT_V6_DISCARD,
            Layer::FwpmLayerAleFlowEstablishedV4 => FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
            Layer::FwpmLayerAleFlowEstablishedV4Discard => {
                FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD
            }
            Layer::FwpmLayerAleFlowEstablishedV6 => FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
            Layer::FwpmLayerAleFlowEstablishedV6Discard => {
                FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6_DISCARD
            }
            Layer::FwpmLayerAleConnectRedirectV4 => FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
            Layer::FwpmLayerAleConnectRedirectV6 => FWPM_LAYER_ALE_CONNECT_REDIRECT_V6,
            Layer::FwpmLayerAleBindRedirectV4 => FWPM_LAYER_ALE_BIND_REDIRECT_V4,
            Layer::FwpmLayerAleBindRedirectV6 => FWPM_LAYER_ALE_BIND_REDIRECT_V6,
            Layer::FwpmLayerAleResourceReleaseV4 => FWPM_LAYER_ALE_RESOURCE_RELEASE_V4,
            Layer::FwpmLayerAleResourceReleaseV6 => FWPM_LAYER_ALE_RESOURCE_RELEASE_V6,
            Layer::FwpmLayerAleEndpointClosureV4 => FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,
            Layer::FwpmLayerAleEndpointClosureV6 => FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6,
        }
    }
}

#[repr(usize)]
pub enum FwpsFieldsInboundIppacketV4 {
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalAddressType,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    Flags,
    InterfaceType,
    TunnelType,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsInboundIppacketV6 {
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalAddressType,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    Flags,
    InterfaceType,
    TunnelType,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsOutboundIppacketV4 {
    IpLocalAddress,
    IpLocalAddressType,
    IpRemoteAddress,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    Flags,
    InterfaceType,
    TunnelType,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsOutboundIppacketV6 {
    IpLocalAddress,
    IpLocalAddressType,
    IpRemoteAddress,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    Flags,
    InterfaceType,
    TunnelType,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsIpforwardV4 {
    IpSourceAddress,
    IpDestinationAddress,
    IpDestinationAddressType,
    IpLocalInterface,
    IpForwardInterface,
    SourceInterfaceIndex,
    SourceSubInterfaceIndex,
    DestinationInterfaceIndex,
    DestinationSubInterfaceIndex,
    Flags,
    IpPhysicalArrivalInterface,
    ArrivalInterfaceProfileId,
    IpPhysicalNexthopInterface,
    NexthopInterfaceProfileId,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsIpforwardV6 {
    IpSourceAddress,
    IpDestinationAddress,
    IpDestinationAddressType,
    IpLocalInterface,
    IpForwardInterface,
    SourceInterfaceIndex,
    SourceSubInterfaceIndex,
    DestinationInterfaceIndex,
    DestinationSubInterfaceIndex,
    Flags,
    IpPhysicalArrivalInterface,
    ArrivalInterfaceProfileId,
    IpPhysicalNexthopInterface,
    NexthopInterfaceProfileId,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsInboundTransportV4 {
    IpProtocol,
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpRemotePort,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    Flags,
    InterfaceType,
    TunnelType,
    ProfileId,
    IpsecSecurityRealmId,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsInboundTransportFas {
    FwpsFieldInboundTransportFastMax,
}

#[repr(usize)]
pub enum FwpsFieldsOutboundTransportFas {
    FwpsFieldOutboundTransportFastMax,
}

// #define FWPS_FIELD_INBOUND_TRANSPORT_V4_ICMP_TYPE \
//         FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT

// #define FWPS_FIELD_INBOUND_TRANSPORT_V4_ICMP_CODE \
//         FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsInboundTransportV6 {
    IpProtocol,
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpRemotePort,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    Flags,
    InterfaceType,
    TunnelType,
    ProfileId,
    IpsecSecurityRealmId,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_INBOUND_TRANSPORT_V6_ICMP_TYPE \
//         FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT

// #define FWPS_FIELD_INBOUND_TRANSPORT_V6_ICMP_CODE \
//         FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsOutboundTransportV4 {
    IpProtocol,
    IpLocalAddress,
    IpLocalAddressType,
    IpRemoteAddress,
    IpLocalPort,
    IpRemotePort,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    IpDestinationAddressType,
    Flags,
    InterfaceType,
    TunnelType,
    ProfileId,
    IpsecSecurityRealmId,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_OUTBOUND_TRANSPORT_V4_ICMP_TYPE \
//         FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT

// #define FWPS_FIELD_OUTBOUND_TRANSPORT_V4_ICMP_CODE \
//         FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsOutboundTransportV6 {
    IpProtocol,
    IpLocalAddress,
    IpLocalAddressType,
    IpRemoteAddress,
    IpLocalPort,
    IpRemotePort,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    IpDestinationAddressType,
    Flags,
    InterfaceType,
    TunnelType,
    ProfileId,
    IpsecSecurityRealmId,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_OUTBOUND_TRANSPORT_V6_ICMP_TYPE \
//         FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT

// #define FWPS_FIELD_OUTBOUND_TRANSPORT_V6_ICMP_CODE \
//         FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsStreamV4 {
    IpLocalAddress,
    IpLocalAddressType,
    IpRemoteAddress,
    IpLocalPort,
    IpRemotePort,
    Direction,
    Flags,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsStreamV6 {
    IpLocalAddress,
    IpLocalAddressType,
    IpRemoteAddress,
    IpLocalPort,
    IpRemotePort,
    Direction,
    Flags,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsDatagramDataV4 {
    IpProtocol,
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpRemotePort,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    Direction,
    Flags,
    InterfaceType,
    TunnelType,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_DATAGRAM_DATA_V4_ICMP_TYPE \
//         FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT

// #define FWPS_FIELD_DATAGRAM_DATA_V4_ICMP_CODE \
//         FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsDatagramDataV6 {
    IpProtocol,
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpRemotePort,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    Direction,
    Flags,
    InterfaceType,
    TunnelType,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_DATAGRAM_DATA_V6_ICMP_TYPE \
//         FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT

// #define FWPS_FIELD_DATAGRAM_DATA_V6_ICMP_CODE \
//         FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsStreamPacketV4 {
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalPort,
    IpRemotePort,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    Direction,
    Flags,
    InterfaceType,
    TunnelType,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsStreamPacketV6 {
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalPort,
    IpRemotePort,
    IpLocalInterface,
    InterfaceIndex,
    SubInterfaceIndex,
    Direction,
    Flags,
    InterfaceType,
    TunnelType,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsInboundIcmpErrorV4 {
    EmbeddedProtocol,
    IpLocalAddress,
    IpRemoteAddress,
    EmbeddedRemoteAddress,
    EmbeddedLocalAddressType,
    EmbeddedLocalPort,
    EmbeddedRemotePort,
    IpLocalInterface,
    IcmpType,
    IcmpCode,
    InterfaceIndex,    // of local/delivery interface
    SubInterfaceIndex, // of arrival interface
    InterfaceType,     // of local/delivery interface
    TunnelType,        // of local/delivery interface
    IpArrivalInterface,
    ArrivalInterfaceIndex,
    ArrivalInterfaceType,
    ArrivalTunnelType,
    Flags,
    ArrivalInterfaceProfileId,
    InterfaceQuarantineEpoch,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_INBOUND_ICMP_ERROR_V4_LOCAL_INTERFACE_INDEX \
//         FWPS_FIELD_INBOUND_ICMP_ERROR_V4_INTERFACE_INDEX

// #define FWPS_FIELD_INBOUND_ICMP_ERROR_V4_ARRIVAL_SUB_INTERFACE_INDEX \
//         FWPS_FIELD_INBOUND_ICMP_ERROR_V4_SUB_INTERFACE_INDEX

// #define FWPS_FIELD_INBOUND_ICMP_ERROR_V4_LOCAL_INTERFACE_TYPE \
//         FWPS_FIELD_INBOUND_ICMP_ERROR_V4_INTERFACE_TYPE

// #define FWPS_FIELD_INBOUND_ICMP_ERROR_V4_LOCAL_TUNNEL_TYPE \
//         FWPS_FIELD_INBOUND_ICMP_ERROR_V4_TUNNEL_TYPE

#[repr(usize)]
pub enum FwpsFieldsInboundIcmpErrorV6 {
    EmbeddedProtocol,
    IpLocalAddress,
    IpRemoteAddress,
    EmbeddedRemoteAddress,
    EmbeddedLocalAddressType,
    EmbeddedLocalPort,
    EmbeddedRemotePort,
    IpLocalInterface,
    IcmpType,
    IcmpCode,
    InterfaceIndex,    // of local/delivery interface
    SubInterfaceIndex, // of arrival interface
    InterfaceType,     // of local/delivery interface
    TunnelType,        // of local/delivery interface
    IpArrivalInterface,
    ArrivalInterfaceIndex,
    ArrivalInterfaceType,
    ArrivalTunnelType,
    Flags,
    ArrivalInterfaceProfileId,
    InterfaceQuarantineEpoch,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_INBOUND_ICMP_ERROR_V6_LOCAL_INTERFACE_INDEX \
//         FWPS_FIELD_INBOUND_ICMP_ERROR_V6_INTERFACE_INDEX

// #define FWPS_FIELD_INBOUND_ICMP_ERROR_V6_ARRIVAL_SUB_INTERFACE_INDEX \
//         FWPS_FIELD_INBOUND_ICMP_ERROR_V6_SUB_INTERFACE_INDEX

// #define FWPS_FIELD_INBOUND_ICMP_ERROR_V6_LOCAL_INTERFACE_TYPE \
//         FWPS_FIELD_INBOUND_ICMP_ERROR_V6_INTERFACE_TYPE

// #define FWPS_FIELD_INBOUND_ICMP_ERROR_V6_LOCAL_TUNNEL_TYPE \
//         FWPS_FIELD_INBOUND_ICMP_ERROR_V6_TUNNEL_TYPE

#[repr(usize)]
pub enum FwpsFieldsOutboundIcmpErrorV4 {
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalAddressType,
    IpLocalInterface,
    IcmpType,
    IcmpCode,
    InterfaceIndex,
    SubInterfaceIndex,
    InterfaceType,
    TunnelType,
    Flags,
    NexthopInterfaceProfileId,
    InterfaceQuarantineEpoch,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsOutboundIcmpErrorV6 {
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalAddressType,
    IpLocalInterface,
    IpLocalPort,
    IpRemotePort,
    InterfaceIndex,
    SubInterfaceIndex,
    InterfaceType,
    TunnelType,
    Flags,
    NexthopInterfaceProfileId,
    InterfaceQuarantineEpoch,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_OUTBOUND_ICMP_ERROR_V6_ICMP_TYPE \
//         FWPS_FIELD_OUTBOUND_ICMP_ERROR_V6_IP_LOCAL_PORT

// #define FWPS_FIELD_OUTBOUND_ICMP_ERROR_V6_ICMP_CODE \
//         FWPS_FIELD_OUTBOUND_ICMP_ERROR_V6_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsAleResourceAssignmentV4 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    AlePromiscuousMode,
    IpLocalInterface,
    Flags,
    InterfaceType,
    TunnelType,
    LocalInterfaceProfileId,
    SioFirewallSocketProperty,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    Reserved0,
    Reserved1,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsAleResourceAssignmentV6 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    AlePromiscuousMode,
    IpLocalInterface,
    Flags,
    InterfaceType,
    TunnelType,
    LocalInterfaceProfileId,
    SioFirewallSocketProperty,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    Reserved0,
    Reserved1,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsAleResourceReleaseV4 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpLocalInterface,
    Flags,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsAleResourceReleaseV6 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpLocalInterface,
    Flags,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsAleEndpointClosureV4 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpRemotePort,
    IpLocalInterface,
    Flags,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsAleEndpointClosureV6 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpRemotePort,
    IpLocalInterface,
    Flags,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsAleAuthListenV4 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpLocalInterface,
    Flags,
    InterfaceType,
    TunnelType,
    LocalInterfaceProfileId,
    SioFirewallSocketProperty,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsAleAuthListenV6 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpLocalInterface,
    Flags,
    InterfaceType,
    TunnelType,
    LocalInterfaceProfileId,
    SioFirewallSocketProperty,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsAleAuthRecvAcceptV4 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpRemotePort,
    AleRemoteUserId,
    AleRemoteMachineId,
    IpLocalInterface,
    Flags,
    SioFirewallSystemPort,
    NapContext,
    InterfaceType,     // of local/delivery interface
    TunnelType,        // of local/delivery interface
    InterfaceIndex,    // of local/delivery interface
    SubInterfaceIndex, // of arrival interface
    IpArrivalInterface,
    ArrivalInterfaceType,
    ArrivalTunnelType,
    ArrivalInterfaceIndex,
    NexthopSubInterfaceIndex,
    IpNexthopInterface,
    NexthopInterfaceType,
    NexthopTunnelType,
    NexthopInterfaceIndex,
    OriginalProfileId,
    CurrentProfileId,
    ReauthorizeReason,
    OriginalIcmpType,
    InterfaceQuarantineEpoch,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    Reserved0,
    Reserved1,
    Reserved2,
    Reserved3,
    Max,
}

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ICMP_TYPE \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ICMP_CODE \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_LOCAL_INTERFACE_TYPE \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_TYPE

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_LOCAL_TUNNEL_TYPE \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_TUNNEL_TYPE

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_LOCAL_INTERFACE_INDEX \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_INTERFACE_INDEX

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ARRIVAL_SUB_INTERFACE_INDEX \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_SUB_INTERFACE_INDEX

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_SIO_FIREWALL_SOCKET_PROPERTY \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_SIO_FIREWALL_SYSTEM_PORT

#[repr(usize)]
pub enum FwpsFieldsAleAuthRecvAcceptV6 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpRemotePort,
    AleRemoteUserId,
    AleRemoteMachineId,
    IpLocalInterface,
    Flags,
    SioFirewallSystemPort,
    NapContext,
    InterfaceType,     // of local/delivery interface
    TunnelType,        // of local/delivery interface
    InterfaceIndex,    // of local/delivery interface
    SubInterfaceIndex, // of arrival interface
    IpArrivalInterface,
    ArrivalInterfaceType,
    ArrivalTunnelType,
    ArrivalInterfaceIndex,
    NexthopSubInterfaceIndex,
    IpNexthopInterface,
    NexthopInterfaceType,
    NexthopTunnelType,
    NexthopInterfaceIndex,
    OriginalProfileId,
    CurrentProfileId,
    ReauthorizeReason,
    OriginalIcmpType,
    InterfaceQuarantineEpoch,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    Reserved0,
    Reserved1,
    Reserved2,
    Reserved3,
    Max,
}

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ICMP_TYPE \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ICMP_CODE \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_LOCAL_INTERFACE_TYPE \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_INTERFACE_TYPE

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_LOCAL_TUNNEL_TYPE \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_TUNNEL_TYPE

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_LOCAL_INTERFACE_INDEX \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_INTERFACE_INDEX

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ARRIVAL_SUB_INTERFACE_INDEX \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_SUB_INTERFACE_INDEX

// #define FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_SIO_FIREWALL_SOCKET_PROPERTY \
//         FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_SIO_FIREWALL_SYSTEM_PORT

#[repr(usize)]
pub enum FwpsFieldsAleBindRedirectV4 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    Flags,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsAleBindRedirectV6 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    Flags,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsAleConnectRedirectV4 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpDestinationAddressType,
    IpRemotePort,
    Flags,
    AleOriginalAppId,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ICMP_TYPE \
//         FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT

// #define FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_ICMP_CODE \
//         FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsAleConnectRedirectV6 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpDestinationAddressType,
    IpRemotePort,
    Flags,
    AleOriginalAppId,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ICMP_TYPE \
//         FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_LOCAL_PORT

// #define FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_ICMP_CODE \
//         FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsAleAuthConnectV4 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpRemotePort,
    AleRemoteUserId,
    AleRemoteMachineId,
    IpDestinationAddressType,
    IpLocalInterface,
    Flags,
    InterfaceType,
    TunnelType,
    InterfaceIndex,
    SubInterfaceIndex,
    IpArrivalInterface,
    ArrivalInterfaceType,
    ArrivalTunnelType,
    ArrivalInterfaceIndex,
    NexthopSubInterfaceIndex,
    IpNexthopInterface,
    NexthopInterfaceType,
    NexthopTunnelType,
    NexthopInterfaceIndex,
    OriginalProfileId,
    CurrentProfileId,
    ReauthorizeReason,
    PeerName,
    OriginalIcmpType,
    InterfaceQuarantineEpoch,
    AleOriginalAppId,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    AleEffectiveName,
    CompartmentId,
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    Reserved0,
    Reserved1,
    Reserved2,
    Reserved3,
    Max,
}

// #define FWPS_FIELD_ALE_AUTH_CONNECT_V4_ICMP_TYPE \
//         FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT

// #define FWPS_FIELD_ALE_AUTH_CONNECT_V4_ICMP_CODE \
//         FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsAleAuthConnectV6 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpRemotePort,
    AleRemoteUserId,
    AleRemoteMachineId,
    IpDestinationAddressType,
    IpLocalInterface,
    Flags,
    InterfaceType,
    TunnelType,
    InterfaceIndex,
    SubInterfaceIndex,
    IpArrivalInterface,
    ArrivalInterfaceType,
    ArrivalTunnelType,
    ArrivalInterfaceIndex,
    NexthopSubInterfaceIndex,
    IpNexthopInterface,
    NexthopInterfaceType,
    NexthopTunnelType,
    NexthopInterfaceIndex,
    OriginalProfileId,
    CurrentProfileId,
    ReauthorizeReason,
    PeerName,
    OriginalIcmpType,
    InterfaceQuarantineEpoch,
    AleOriginalAppId,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    AleEffectiveName,
    CompartmentId,
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    Reserved0,
    Reserved1,
    Reserved2,
    Reserved3,
    Max,
}

// #define FWPS_FIELD_ALE_AUTH_CONNECT_V6_ICMP_TYPE \
//         FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT

// #define FWPS_FIELD_ALE_AUTH_CONNECT_V6_ICMP_CODE \
//         FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsAleFlowEstablishedV4 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpRemotePort,
    AleRemoteUserId,
    AleRemoteMachineId,
    IpDestinationAddressType,
    IpLocalInterface,
    Direction,
    InterfaceType,
    TunnelType,
    Flags,
    AleOriginalAppId,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    Reserved0,
    Reserved1,
    Reserved2,
    Reserved3,
    Max,
}

// #define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ICMP_TYPE \
//         FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT

// #define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ICMP_CODE \
//         FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsAleFlowEstablishedV6 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpRemotePort,
    AleRemoteUserId,
    AleRemoteMachineId,
    IpDestinationAddressType,
    IpLocalInterface,
    Direction,
    InterfaceType,
    TunnelType,
    Flags,
    AleOriginalAppId,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    //
    // These reserved fields MUST be in this order. DO NOT change their order
    //
    Reserved0,
    Reserved1,
    Reserved2,
    Reserved3,
    Max,
}

// #define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ICMP_TYPE \
//         FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT

// #define FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ICMP_CODE \
//         FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsNameResolutionCacheV4 {
    AleUserId,
    AleAppId,
    IpRemoteAddress,
    PeerName,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsNameResolutionCacheV6 {
    AleUserId,
    AleAppId,
    IpRemoteAddress,
    PeerName,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsInboundMacFrameEthernet {
    InterfaceMacAddress,
    MacLocalAddress,
    MacRemoteAddress,
    MacLocalAddressType,
    MacRemoteAddressType,
    EtherType,
    VlanId,
    Interface,
    InterfaceIndex,
    NdisPort,
    L2Flags,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsOutboundMacFrameEthernet {
    InterfaceMacAddress,
    MacLocalAddress,
    MacRemoteAddress,
    MacLocalAddressType,
    MacRemoteAddressType,
    EtherType,
    VlanId,
    Interface,
    InterfaceIndex,
    NdisPort,
    L2Flags,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsInboundMacFrameNative {
    NdisMediaType,
    NdisPhysicalMediaType,
    Interface,
    InterfaceType,
    InterfaceIndex,
    NdisPort,
    L2Flags,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsInboundMacFrameNativeFast {
    FastMax,
}

#[repr(usize)]
pub enum FwpsFieldsOutboundMacFrameNative {
    NdisMediaType,
    NdisPhysicalMediaType,
    Interface,
    InterfaceType,
    InterfaceIndex,
    NdisPort,
    L2Flags,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsOutboundMacFrameNativeFast {
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsIngressVswitchEthernet {
    MacSourceAddress,
    MacSourceAddressType,
    MacDestinationAddress,
    MacDestinationAddressType,
    EtherType,
    VlanId,
    VswitchTenantNetworkId,
    VswitchId,
    VswitchNetworkType,
    VswitchSourceInterfaceId,
    VswitchSourceInterfaceType,
    VswitchSourceVmId,
    L2Flags,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsEgressVswitchEthernet {
    MacSourceAddress,
    MacSourceAddressType,
    MacDestinationAddress,
    MacDestinationAddressType,
    EtherType,
    VlanId,
    VswitchTenantNetworkId,
    VswitchId,
    VswitchNetworkType,
    VswitchSourceInterfaceId,
    VswitchSourceInterfaceType,
    VswitchSourceVmId,
    VswitchDestinationInterfaceId,
    VswitchDestinationInterfaceType,
    VswitchDestinationVmId,
    L2Flags,
    CompartmentId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsIngressVswitchTransportV4 {
    IpSourceAddress,
    IpDestinationAddress,
    IpProtocol,
    IpSourcePort,
    IpDestinationPort,
    VlanId,
    VswitchTenantNetworkId,
    VswitchId,
    VswitchNetworkType,
    VswitchSourceInterfaceId,
    VswitchSourceInterfaceType,
    VswitchSourceVmId,
    L2Flags,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_ICMP_TYPE \
//         FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_SOURCE_PORT

// #define FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_ICMP_CODE \
//         FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V4_IP_DESTINATION_PORT

#[repr(usize)]
pub enum FwpsFieldsIngressVswitchTransportV6 {
    IpSourceAddress,
    IpDestinationAddress,
    IpProtocol,
    IpSourcePort,
    IpDestinationPort,
    VlanId,
    VswitchTenantNetworkId,
    VswitchId,
    VswitchNetworkType,
    VswitchSourceInterfaceId,
    VswitchSourceInterfaceType,
    VswitchSourceVmId,
    L2Flags,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V6_ICMP_TYPE \
//         FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V6_IP_SOURCE_PORT

// #define FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V6_ICMP_CODE \
//         FWPS_FIELD_INGRESS_VSWITCH_TRANSPORT_V6_IP_DESTINATION_PORT

#[repr(usize)]
pub enum FwpsFieldsEgressVswitchTransportV4 {
    IpSourceAddress,
    IpDestinationAddress,
    IpProtocol,
    IpSourcePort,
    IpDestinationPort,
    VlanId,
    VswitchTenantNetworkId,
    VswitchId,
    VswitchNetworkType,
    VswitchSourceInterfaceId,
    VswitchSourceInterfaceType,
    VswitchSourceVmId,
    VswitchDestinationInterfaceId,
    VswitchDestinationInterfaceType,
    VswitchDestinationVmId,
    L2Flags,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_ICMP_TYPE \
//         FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_IP_SOURCE_PORT

// #define FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_ICMP_CODE \
//         FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V4_IP_DESTINATION_PORT

#[repr(usize)]
pub enum FwpsFieldsEgressVswitchTransportV6 {
    IpSourceAddress,
    IpDestinationAddress,
    IpProtocol,
    IpSourcePort,
    IpDestinationPort,
    VlanId,
    VswitchTenantNetworkId,
    VswitchId,
    VswitchNetworkType,
    VswitchSourceInterfaceId,
    VswitchSourceInterfaceType,
    VswitchSourceVmId,
    VswitchDestinationInterfaceId,
    VswitchDestinationInterfaceType,
    VswitchDestinationVmId,
    L2Flags,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V6_ICMP_TYPE \
//         FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V6_IP_SOURCE_PORT

// #define FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V6_ICMP_CODE \
//         FWPS_FIELD_EGRESS_VSWITCH_TRANSPORT_V6_IP_DESTINATION_PORT

#[repr(usize)]
pub enum FwpsFieldsIpsecKmDemuxV4 {
    IpLocalAddress,
    IpRemoteAddress,
    QmMode,
    IpLocalInterface,
    CurrentProfileId,
    IpsecSecurityRealmId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsIpsecKmDemuxV6 {
    IpLocalAddress,
    IpRemoteAddress,
    QmMode,
    IpLocalInterface,
    CurrentProfileId,
    IpsecSecurityRealmId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsIpsecV4 {
    IpProtocol,
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalPort,
    IpRemotePort,
    IpLocalInterface,
    ProfileId,
    IpsecSecurityRealmId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsIpsecV6 {
    IpProtocol,
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalPort,
    IpRemotePort,
    IpLocalInterface,
    ProfileId,
    IpsecSecurityRealmId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsIkeextV4 {
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalInterface,
    ProfileId,
    IpsecSecurityRealmId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsIkeextV6 {
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalInterface,
    ProfileId,
    IpsecSecurityRealmId,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsRpcUm {
    RemoteUserToken,
    AuthLevel,
    AuthType,
    DcomAppId,
    IfFlag,
    IfUuid,
    IfVersion,
    ImageName,
    LocalAddrV4,
    LocalAddrV6,
    LocalPort,
    Max,
    Pipe,
    Protocol,
    RemoteAddrV4,
    RemoteAddrV6,
    SecEncryptAlgorithm,
    SecKeySize,
}

#[repr(usize)]
pub enum FwpsFieldsRpcEpmap {
    RemoteUserToken,
    IfUuid,
    IfVersion,
    Protocol,
    AuthType,
    AuthLevel,
    SecEncryptAlgorithm,
    SecKeySize,
    LocalAddrV4,
    LocalAddrV6,
    LocalPort,
    Pipe,
    RemoteAddrV4,
    RemoteAddrV6,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsRpcEpAdd {
    ProcessWithRpcIfUuid,
    Protocol,
    EpValue,
    EpFlags,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsRpcProxyConn {
    ClientToken,
    ServerName,
    ServerPort,
    ProxyAuthType,
    ClientCertKeyLength,
    ClientCertOid,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsRpcProxyIf {
    ClientToken,
    IfUuid,
    IfVersion,
    ServerName,
    ServerPort,
    ProxyAuthType,
    ClientCertKeyLength,
    ClientCertOid,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsKmAuthorization {
    RemoteId,
    AuthenticationType,
    KmType,
    Direction,
    KmMode,
    IpsecPolicyKey,
    NapContext,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsInboundReserved2 {
    Reserved0,
    Reserved1,
    Reserved2,
    Reserved3,
    Reserved4,
    Reserved5,
    Reserved6,
    Reserved7,
    Reserved8,
    Reserved9,
    Reserved10,
    Reserved11,
    Reserved12,
    Reserved13,
    Reserved14,
    Reserved15,
    Max,
}

#[repr(usize)]
pub enum FwpsFieldsOutboundNetworkConnectionPolicyV4 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpDestinationAddressType,
    IpRemotePort,
    Flags,
    AleOriginalAppId,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}

// #define FWPS_FIELD_OUTBOUND_NETWORK_CONNECTION_POLICY_V4_ICMP_TYPE \
//         FWPS_FIELD_OUTBOUND_NETWORK_CONNECTION_POLICY_V4_IP_LOCAL_PORT

// #define FWPS_FIELD_OUTBOUND_NETWORK_CONNECTION_POLICY_V4_ICMP_CODE \
//         FWPS_FIELD_OUTBOUND_NETWORK_CONNECTION_POLICY_V4_IP_REMOTE_PORT

#[repr(usize)]
pub enum FwpsFieldsOutboundNetworkConnectionPolicyV6 {
    AleAppId,
    AleUserId,
    IpLocalAddress,
    IpLocalAddressType,
    IpLocalPort,
    IpProtocol,
    IpRemoteAddress,
    IpDestinationAddressType,
    IpRemotePort,
    Flags,
    AleOriginalAppId,
    AlePackageId,
    AleSecurityAttributeFqbnValue,
    CompartmentId,
    Max,
}
