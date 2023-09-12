#![allow(dead_code)]

use windows_sys::core::GUID;

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
    pub(crate) uint64: u64,
    pub(crate) byte_array16: [u8; 16],
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
}

impl Layer {
    pub fn get_guid(&self) -> GUID {
        match self {
            Layer::FwpmLayerInboundIppacketV4 => {
                GUID::from_u128(0xc86fd1bf_21cd_497e_a0bb_17425c885c58)
            }
            Layer::FwpmLayerInboundIppacketV4Discard => {
                GUID::from_u128(0xb5a230d0_a8c0_44f2_916e_991b53ded1f7)
            }
            Layer::FwpmLayerInboundIppacketV6 => {
                GUID::from_u128(0xf52032cb_991c_46e7_971d_2601459a91ca)
            }
            Layer::FwpmLayerInboundIppacketV6Discard => {
                GUID::from_u128(0xbb24c279_93b4_47a2_83ad_ae1698b50885)
            }
            Layer::FwpmLayerOutboundIppacketV4 => {
                GUID::from_u128(0x1e5c9fae_8a84_4135_a331_950b54229ecd)
            }
            Layer::FwpmLayerOutboundIppacketV4Discard => {
                GUID::from_u128(0x08e4bcb5_b647_48f3_953c_e5ddbd03937e)
            }
            Layer::FwpmLayerOutboundIppacketV6 => {
                GUID::from_u128(0xa3b3ab6b_3564_488c_9117_f34e82142763)
            }
            Layer::FwpmLayerOutboundIppacketV6Discard => {
                GUID::from_u128(0x9513d7c4_a934_49dc_91a7_6ccb80cc02e3)
            }
            Layer::FwpmLayerIpforwardV4 => GUID::from_u128(0xa82acc24_4ee1_4ee1_b465_fd1d25cb10a4),
            Layer::FwpmLayerIpforwardV4Discard => {
                GUID::from_u128(0x9e9ea773_2fae_4210_8f17_34129ef369eb)
            }
            Layer::FwpmLayerIpforwardV6 => GUID::from_u128(0x7b964818_19c7_493a_b71f_832c3684d28c),
            Layer::FwpmLayerIpforwardV6Discard => {
                GUID::from_u128(0x31524a5d_1dfe_472f_bb93_518ee945d8a2)
            }
            Layer::FwpmLayerInboundTransportV4 => {
                GUID::from_u128(0x5926dfc8_e3cf_4426_a283_dc393f5d0f9d)
            }
            Layer::FwpmLayerInboundTransportV4Discard => {
                GUID::from_u128(0xac4a9833_f69d_4648_b261_6dc84835ef39)
            }
            Layer::FwpmLayerInboundTransportV6 => {
                GUID::from_u128(0x634a869f_fc23_4b90_b0c1_bf620a36ae6f)
            }
            Layer::FwpmLayerInboundTransportV6Discard => {
                GUID::from_u128(0x2a6ff955_3b2b_49d2_9848_ad9d72dcaab7)
            }
            Layer::FwpmLayerOutboundTransportV4 => {
                GUID::from_u128(0x09e61aea_d214_46e2_9b21_b26b0b2f28c8)
            }
            Layer::FwpmLayerOutboundTransportV4Discard => {
                GUID::from_u128(0xc5f10551_bdb0_43d7_a313_50e211f4d68a)
            }
            Layer::FwpmLayerOutboundTransportV6 => {
                GUID::from_u128(0xe1735bde_013f_4655_b351_a49e15762df0)
            }
            Layer::FwpmLayerOutboundTransportV6Discard => {
                GUID::from_u128(0xf433df69_ccbd_482e_b9b2_57165658c3b3)
            }
            Layer::FwpmLayerStreamV4 => GUID::from_u128(0x3b89653c_c170_49e4_b1cd_e0eeeee19a3e),
            Layer::FwpmLayerStreamV4Discard => {
                GUID::from_u128(0x25c4c2c2_25ff_4352_82f9_c54a4a4726dc)
            }
            Layer::FwpmLayerStreamV6 => GUID::from_u128(0x47c9137a_7ec4_46b3_b6e4_48e926b1eda4),
            Layer::FwpmLayerStreamV6Discard => {
                GUID::from_u128(0x10a59fc7_b628_4c41_9eb8_cf37d55103cf)
            }
            Layer::FwpmLayerDatagramDataV4 => {
                GUID::from_u128(0x3d08bf4e_45f6_4930_a922_417098e20027)
            }
            Layer::FwpmLayerDatagramDataV4Discard => {
                GUID::from_u128(0x18e330c6_7248_4e52_aaab_472ed67704fd)
            }
            Layer::FwpmLayerDatagramDataV6 => {
                GUID::from_u128(0xfa45fe2f_3cba_4427_87fc_57b9a4b10d00)
            }
            Layer::FwpmLayerDatagramDataV6Discard => {
                GUID::from_u128(0x09d1dfe1_9b86_4a42_be9d_8c315b92a5d0)
            }
            Layer::FwpmLayerInboundIcmpErrorV4 => {
                GUID::from_u128(0x61499990_3cb6_4e84_b950_53b94b6964f3)
            }
            Layer::FwpmLayerInboundIcmpErrorV4Discard => {
                GUID::from_u128(0xa6b17075_ebaf_4053_a4e7_213c8121ede5)
            }
            Layer::FwpmLayerInboundIcmpErrorV6 => {
                GUID::from_u128(0x65f9bdff_3b2d_4e5d_b8c6_c720651fe898)
            }
            Layer::FwpmLayerInboundIcmpErrorV6Discard => {
                GUID::from_u128(0xa6e7ccc0_08fb_468d_a472_9771d5595e09)
            }
            Layer::FwpmLayerOutboundIcmpErrorV4 => {
                GUID::from_u128(0x41390100_564c_4b32_bc1d_718048354d7c)
            }
            Layer::FwpmLayerOutboundIcmpErrorV4Discard => {
                GUID::from_u128(0xb3598d36_0561_4588_a6bf_e955e3f6264b)
            }
            Layer::FwpmLayerOutboundIcmpErrorV6 => {
                GUID::from_u128(0x7fb03b60_7b8d_4dfa_badd_980176fc4e12)
            }
            Layer::FwpmLayerOutboundIcmpErrorV6Discard => {
                GUID::from_u128(0x65f2e647_8d0c_4f47_b19b_33a4d3f1357c)
            }
            Layer::FwpmLayerAleResourceAssignmentV4 => {
                GUID::from_u128(0x1247d66d_0b60_4a15_8d44_7155d0f53a0c)
            }
            Layer::FwpmLayerAleResourceAssignmentV4Discard => {
                GUID::from_u128(0x0b5812a2_c3ff_4eca_b88d_c79e20ac6322)
            }
            Layer::FwpmLayerAleResourceAssignmentV6 => {
                GUID::from_u128(0x55a650e1_5f0a_4eca_a653_88f53b26aa8c)
            }
            Layer::FwpmLayerAleResourceAssignmentV6Discard => {
                GUID::from_u128(0xcbc998bb_c51f_4c1a_bb4f_9775fcacab2f)
            }
            Layer::FwpmLayerAleAuthListenV4 => {
                GUID::from_u128(0x88bb5dad_76d7_4227_9c71_df0a3ed7be7e)
            }
            Layer::FwpmLayerAleAuthListenV4Discard => {
                GUID::from_u128(0x371dfada_9f26_45fd_b4eb_c29eb212893f)
            }
            Layer::FwpmLayerAleAuthListenV6 => {
                GUID::from_u128(0x7ac9de24_17dd_4814_b4bd_a9fbc95a321b)
            }
            Layer::FwpmLayerAleAuthListenV6Discard => {
                GUID::from_u128(0x60703b07_63c8_48e9_ada3_12b1af40a617)
            }
            Layer::FwpmLayerAleAuthRecvAcceptV4 => {
                GUID::from_u128(0xe1cd9fe7_f4b5_4273_96c0_592e487b8650)
            }
            Layer::FwpmLayerAleAuthRecvAcceptV4Discard => {
                GUID::from_u128(0x9eeaa99b_bd22_4227_919f_0073c63357b1)
            }
            Layer::FwpmLayerAleAuthRecvAcceptV6 => {
                GUID::from_u128(0xa3b42c97_9f04_4672_b87e_cee9c483257f)
            }
            Layer::FwpmLayerAleAuthRecvAcceptV6Discard => {
                GUID::from_u128(0x89455b97_dbe1_453f_a224_13da895af396)
            }
            Layer::FwpmLayerAleAuthConnectV4 => {
                GUID::from_u128(0xc38d57d1_05a7_4c33_904f_7fbceee60e82)
            }
            Layer::FwpmLayerAleAuthConnectV4Discard => {
                GUID::from_u128(0xd632a801_f5ba_4ad6_96e3_607017d9836a)
            }
            Layer::FwpmLayerAleAuthConnectV6 => {
                GUID::from_u128(0x4a72393b_319f_44bc_84c3_ba54dcb3b6b4)
            }
            Layer::FwpmLayerAleAuthConnectV6Discard => {
                GUID::from_u128(0xc97bc3b8_c9a3_4e33_8695_8e17aad4de09)
            }
            Layer::FwpmLayerAleFlowEstablishedV4 => {
                GUID::from_u128(0xaf80470a_5596_4c13_9992_539e6fe57967)
            }
            Layer::FwpmLayerAleFlowEstablishedV4Discard => {
                GUID::from_u128(0x146ae4a9_a1d2_4d43_a31a_4c42682b8e4f)
            }
            Layer::FwpmLayerAleFlowEstablishedV6 => {
                GUID::from_u128(0x7021d2b3_dfa4_406e_afeb_6afaf7e70efd)
            }
            Layer::FwpmLayerAleFlowEstablishedV6Discard => {
                GUID::from_u128(0x46928636_bbca_4b76_941d_0fa7f5d7d372)
            }
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

// #define FWPS_FIELD_OUTBOUND_NETWORK_CONNECTION_POLICY_V6_ICMP_TYPE \
//         FWPS_FIELD_OUTBOUND_NETWORK_CONNECTION_POLICY_V6_IP_LOCAL_PORT

// #define FWPS_FIELD_OUTBOUND_NETWORK_CONNECTION_POLICY_V6_ICMP_CODE \
//         FWPS_FIELD_OUTBOUND_NETWORK_CONNECTION_POLICY_V6_IP_REMOTE_PORT
