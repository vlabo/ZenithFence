use alloc::vec::Vec;
use wdk::filter_engine::callout::FilterType;
use wdk::{
    consts,
    filter_engine::{callout::Callout, layer::Layer},
};

use crate::{ale_callouts, packet_callouts};

pub fn get_callout_vec() -> Vec<Callout> {
    alloc::vec![
        // -----------------------------------------
        // ALE Auth layers
        Callout::new(
            "AleLayerOutboundV4",
            "ALE layer for outbound connection for ipv4",
            0x3a090083_27e3_497f_ae5c_8172504f421e,
            Layer::AleAuthConnectV4,
            consts::FWP_ACTION_CALLOUT_TERMINATING,
            FilterType::Resettable,
            ale_callouts::ale_layer_connect_v4,
        ),
        Callout::new(
            "AleLayerInboundV4",
            "ALE layer for inbound connections for ipv4",
            0xf27704a5_172f_4306_9a49_dcfefe6aa236,
            Layer::AleAuthRecvAcceptV4,
            consts::FWP_ACTION_CALLOUT_TERMINATING,
            FilterType::Resettable,
            ale_callouts::ale_layer_accept_v4,
        ),
        Callout::new(
            "AleLayerOutboundV6",
            "ALE layer for outbound connections for ipv6",
            0x897a8324_f7e8_4713_b2d8_4084773ab47f,
            Layer::AleAuthConnectV6,
            consts::FWP_ACTION_CALLOUT_TERMINATING,
            FilterType::Resettable,
            ale_callouts::ale_layer_connect_v6,
        ),
        Callout::new(
            "AleLayerInboundV6",
            "ALE layer for inbound connections for ipv6",
            0x56874651_3785_4dc9_b134_4849a54de6d0,
            Layer::AleAuthRecvAcceptV6,
            consts::FWP_ACTION_CALLOUT_TERMINATING,
            FilterType::Resettable,
            ale_callouts::ale_layer_accept_v6,
        ),
        // -----------------------------------------
        // ALE connection end layers
        Callout::new(
            "AleEndpointClosureV4",
            "ALE layer for indicating closing of connection for ipv4",
            0x7aa9954a_253e_416e_949d_829ce0c215d7,
            Layer::AleEndpointClosureV4,
            consts::FWP_ACTION_CALLOUT_INSPECTION,
            FilterType::NonResettable,
            ale_callouts::endpoint_closure_v4,
        ),
        Callout::new(
            "AleEndpointClosureV6",
            "ALE layer for indicating closing of connection for ipv6",
            0x021a53c4_e149_4ba9_aa5f_7159a1466100,
            Layer::AleEndpointClosureV6,
            consts::FWP_ACTION_CALLOUT_INSPECTION,
            FilterType::NonResettable,
            ale_callouts::endpoint_closure_v6,
        ),
        // -----------------------------------------
        // ALE resource assignment and release.
        // Callout::new(
        //     "AleResourceAssignmentV4",
        //     "Ipv4 Port assignment monitoring",
        //     0x9d2d7ed8_42d4_4d73_ae9a_c888e0decbf1,
        //     Layer::AleResourceAssignmentV4Discard,
        //     consts::FWP_ACTION_CALLOUT_INSPECTION,
        //     FilterType::NonResettable,
        //     ale_callouts::ale_resource_monitor,
        // ),
        Callout::new(
            "AleResourceReleaseV4",
            "Ipv4 Port release monitor",
            0x23b3f70f_f6a4_4330_b7d0_43426a59237b,
            Layer::AleResourceReleaseV4,
            consts::FWP_ACTION_CALLOUT_INSPECTION,
            FilterType::NonResettable,
            ale_callouts::ale_resource_monitor,
        ),
        // Callout::new(
        //     "AleResourceAssignmentV6",
        //     "Ipv4 Port assignment monitor",
        //     0x7f0246f8_dddf_4b60_b693_76943b5e5fe4,
        //     Layer::AleResourceAssignmentV6Discard,
        //     consts::FWP_ACTION_CALLOUT_INSPECTION,
        //     FilterType::NonResettable,
        //     ale_callouts::ale_resource_monitor,
        // ),
        Callout::new(
            "AleResourceReleaseV6",
            "Ipv6 Port release monitor",
            0xff60e5b5_f00b_46fd_be35_04aa316b8ff8,
            Layer::AleResourceReleaseV6,
            consts::FWP_ACTION_CALLOUT_INSPECTION,
            FilterType::NonResettable,
            ale_callouts::ale_resource_monitor,
        ),
        // -----------------------------------------
        // Packet layers
        Callout::new(
            "IPPacketOutboundV4",
            "IP packet outbound network layer callout for Ipv4",
            0x6081493f_9032_49a7_9cca_5e61c28d428d,
            Layer::OutboundIppacketV4,
            consts::FWP_ACTION_CALLOUT_TERMINATING,
            FilterType::NonResettable,
            packet_callouts::ip_packet_layer_outbound_v4,
        ),
        Callout::new(
            "IPPacketInboundV4",
            "IP packet inbound network layer callout for Ipv4",
            0x92a81d84_7942_4281_a29e_f9de59e8d844,
            Layer::InboundIppacketV4,
            consts::FWP_ACTION_CALLOUT_TERMINATING,
            FilterType::NonResettable,
            packet_callouts::ip_packet_layer_inbound_v4,
        ),
        Callout::new(
            "IPPacketOutboundV6",
            "IP packet outbound network layer callout for Ipv6",
            0xfad4e2a7_0ed0_4332_a5e5_634ee2fb1329,
            Layer::OutboundIppacketV6,
            consts::FWP_ACTION_CALLOUT_TERMINATING,
            FilterType::NonResettable,
            packet_callouts::ip_packet_layer_outbound_v6,
        ),
        Callout::new(
            "IPPacketInboundV6",
            "IP packet inbound network layer callout for Ipv6",
            0xf2605e9c_c72d_4375_9ebd_2aabbbaec54c,
            Layer::InboundIppacketV6,
            consts::FWP_ACTION_CALLOUT_TERMINATING,
            FilterType::NonResettable,
            packet_callouts::ip_packet_layer_inbound_v6,
        )
    ]
}
