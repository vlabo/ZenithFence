#![allow(dead_code)]

use windows_sys::core::GUID;

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
        return match self {
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
        };
    }
}
