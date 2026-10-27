use core::ffi::c_void;

use windows_sys::{
    core::GUID,
    Wdk::Foundation::{DEVICE_OBJECT, DRIVER_OBJECT, MDL},
    Win32::{
        Foundation::{BOOLEAN, HANDLE, NTSTATUS, UNICODE_STRING},
        NetworkManagement::WindowsFilteringPlatform::{
            FWPM_PROVIDER_CONTEXT2, FWP_CONDITION_VALUE0, FWP_MATCH_TYPE, FWP_VALUE0,
        },
        Networking::WinSock::{ADDRESS_FAMILY, SCOPE_ID},
        System::Kernel::COMPARTMENT_ID,
    },
};

use crate::filter_engine::{
    classify::ClassifyOut, layer::IncomingValues, metadata::FwpsIncomingMetadataValues,
};

#[allow(non_camel_case_types, non_snake_case)]
pub(crate) type FwpsCalloutClassifyFn = unsafe extern "C" fn(
    inFixedValues: *const IncomingValues,
    inMetaValues: *const FwpsIncomingMetadataValues,
    layerData: *mut c_void,
    classifyContext: *mut c_void,
    filter: *const FWPS_FILTER2,
    flowContext: u64,
    classifyOut: *mut ClassifyOut,
);

#[allow(non_camel_case_types, non_snake_case)]
pub(crate) type FwpsCalloutNotifyFn = unsafe extern "C" fn(
    notifyType: u32,
    filterKey: *const GUID,
    filter: *mut FWPS_FILTER2,
) -> NTSTATUS;

#[allow(non_camel_case_types, non_snake_case)]
pub(crate) type FwpsCalloutFlowDeleteNotifyFn =
    unsafe extern "C" fn(layerId: u16, calloutId: u32, flowContext: u64);

/// The FWPS_ACTION0 structure specifies the run-time action that the filter engine takes if all of the filter's filtering conditions are true.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub(crate) struct FWPS_ACTION0 {
    r#type: u32,
    calloutId: u32,
}

/// The FWPS_FILTER_CONDITION0 structure defines a run-time filtering condition for a filter.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub(crate) struct FWPS_FILTER_CONDITION0 {
    fieldId: u16,
    reserved: u16,
    matchType: FWP_MATCH_TYPE,
    conditionValue: FWP_CONDITION_VALUE0,
}

/// The FWPS_FILTER2 structure defines a run-time filter in the filter engine.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub(crate) struct FWPS_FILTER2 {
    pub(crate) filterId: u64,
    pub(crate) weight: FWP_VALUE0,
    pub(crate) subLayerWeight: u16,
    pub(crate) flags: u16,
    pub(crate) numFilterConditions: u32,
    pub(crate) filterCondition: *mut FWPS_FILTER_CONDITION0,
    pub(crate) action: FWPS_ACTION0,
    pub(crate) context: u64,
    pub(crate) providerContext: *mut FWPM_PROVIDER_CONTEXT2,
}

/// The FWPS_CALLOUT3 structure defines the data that is required for a callout driver to register a callout with the filter engine.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub(crate) struct FWPS_CALLOUT3 {
    pub(crate) calloutKey: GUID,
    pub(crate) flags: u32,
    pub(crate) classifyFn: Option<FwpsCalloutClassifyFn>,
    pub(crate) notifyFn: Option<FwpsCalloutNotifyFn>,
    pub(crate) flowDeleteFn: Option<FwpsCalloutFlowDeleteNotifyFn>,
}

/// The filter engine calls a callout's completionFn callout function whenever packet data, described by the netBufferList parameter in one of the packet injection functions, has been injected into the network stack.
#[allow(non_camel_case_types)]
type FWPS_INJECT_COMPLETE0 = unsafe extern "C" fn(
    context: *mut c_void,
    net_buffer_list: *mut NET_BUFFER_LIST,
    dispatch_level: bool,
);

/// The FWPS_TRANSPORT_SEND_PARAMS1 structure defines properties of an outbound transport layer packet.
#[allow(non_camel_case_types)]
#[repr(C)]
pub(crate) struct FWPS_TRANSPORT_SEND_PARAMS1 {
    pub(crate) remote_address: *const u8,
    pub(crate) remote_scope_id: SCOPE_ID,
    pub(crate) control_data: *mut c_void, //WSACMSGHDR,
    pub(crate) control_data_length: u32,
    pub(crate) header_include_header: *mut u8,
    pub(crate) header_include_header_length: u32,
}

/// The FWPS_PACKET_INJECTION_STATE enumeration type specifies the injection state of a network buffer list.
#[allow(non_camel_case_types)]
#[repr(C)]
pub(crate) enum FWPS_PACKET_INJECTION_STATE {
    FWPS_PACKET_NOT_INJECTED,
    FWPS_PACKET_INJECTED_BY_SELF,
    FWPS_PACKET_INJECTED_BY_OTHER,
    FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF,
    FWPS_PACKET_INJECTION_STATE_MAX,
}

pub(crate) const FWPS_INJECTION_TYPE_STREAM: u32 = 0x00000001;
pub(crate) const FWPS_INJECTION_TYPE_TRANSPORT: u32 = 0x00000002;
pub(crate) const FWPS_INJECTION_TYPE_NETWORK: u32 = 0x00000004;
pub(crate) const FWPS_INJECTION_TYPE_FORWARD: u32 = 0x00000008;
pub(crate) const FWPS_INJECTION_TYPE_L2: u32 = 0x00000010;
pub(crate) const FWPS_INJECTION_TYPE_VSWITCH_TRANSPORT: u32 = 0x00000020;

pub(crate) const NDIS_OBJECT_TYPE_DEFAULT: u8 = 0x80; // used when object type is implicit in the API call
pub(crate) const NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1: u8 = 1;

/// The NBListHeader is the header of NET_BUFFER_LIST struct.
#[repr(C)]
pub(crate) struct NBListHeader {
    pub(crate) next: *mut NET_BUFFER_LIST,
    pub(crate) first_net_buffer: *mut NET_BUFFER,
}

/// A field aligned to MEMORY_ALLOCATION_ALIGNMENT (16 bytes on 64-bit), the
/// `DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT)` of the NDIS headers.
#[repr(C, align(16))]
pub(crate) struct Aligned16<T>(pub(crate) T);

/// The NET_BUFFER_LIST structure specifies a linked list of NET_BUFFER structures.
/// This is internal struct should never be allocated from the driver. Use provided functions by microsoft.
/// Layout checked against km/ndis/nbl.h (WDK 10.0.26100) by the assertions below.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub struct NET_BUFFER_LIST {
    pub(crate) Header: NBListHeader,
    pub(crate) Context: *mut c_void,
    pub(crate) ParentNetBufferList: *mut NET_BUFFER_LIST,
    pub(crate) NdisPoolHandle: NDIS_HANDLE,
    pub(crate) NdisReserved: Aligned16<[*mut c_void; 2]>,
    pub(crate) ProtocolReserved: Aligned16<[*mut c_void; 4]>,
    pub(crate) MiniportReserved: Aligned16<[*mut c_void; 2]>,
    pub(crate) Scratch: *mut c_void,
    pub(crate) SourceHandle: NDIS_HANDLE,
    pub(crate) NblFlags: u32,
    pub(crate) ChildRefCount: i32,
    pub(crate) Flags: u32,
    pub(crate) Status: NDIS_STATUS,
    pub(crate) NetBufferListInfo: [*mut c_void; 20], // Extra data at the end of the struct. The size of the array is not fixed.
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub union NBSize {
    pub DataLength: u32,
    pub stDataLength: u64,
}

/// This is internal struct should never be allocated from the driver. Use provided functions by microsoft.
/// The NET_BUFFER structure specifies data that is transmitted or received over the network.
/// Layout checked against km/ndis/nbl.h (WDK 10.0.26100) by the assertions below.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub struct NET_BUFFER {
    pub(crate) Next: *mut NET_BUFFER,
    pub(crate) CurrentMdl: *mut MDL,
    pub(crate) CurrentMdlOffset: u32,
    pub(crate) nbSize: NBSize,
    pub(crate) MdlChain: *mut MDL,
    pub(crate) DataOffset: u32,
    // The fields above are a NET_BUFFER_HEADER, a union with an SLIST_HEADER, which pads them to
    // 48 bytes.
    _HeaderPadding: u32,
    pub(crate) ChecksumBias: u16,
    pub(crate) Reserved: u16,
    pub(crate) NdisPoolHandle: NDIS_HANDLE,
    pub(crate) NdisReserved: Aligned16<[*mut c_void; 2]>,
    pub(crate) ProtocolReserved: Aligned16<[*mut c_void; 6]>,
    pub(crate) MiniportReserved: Aligned16<[*mut c_void; 4]>,
    pub(crate) DataPhysicalAddress: u64,
    pub(crate) SharedMemoryInfo: *mut c_void,
}

// Offsets of the NDIS structures as the WDK headers lay them out (x64). A mismatch means a field
// is read from the wrong place, so check it at compile time.
#[cfg(target_arch = "x86_64")]
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(offset_of!(NET_BUFFER_LIST, Context) == 16);
    assert!(offset_of!(NET_BUFFER_LIST, NdisReserved) == 48);
    assert!(offset_of!(NET_BUFFER_LIST, ProtocolReserved) == 64);
    assert!(offset_of!(NET_BUFFER_LIST, MiniportReserved) == 96);
    assert!(offset_of!(NET_BUFFER_LIST, Scratch) == 112);
    assert!(offset_of!(NET_BUFFER_LIST, NblFlags) == 128);
    assert!(offset_of!(NET_BUFFER_LIST, Status) == 140);
    assert!(offset_of!(NET_BUFFER_LIST, NetBufferListInfo) == 144);

    assert!(offset_of!(NET_BUFFER, MdlChain) == 32);
    assert!(offset_of!(NET_BUFFER, DataOffset) == 40);
    assert!(offset_of!(NET_BUFFER, ChecksumBias) == 48);
    assert!(offset_of!(NET_BUFFER, NdisPoolHandle) == 56);
    assert!(offset_of!(NET_BUFFER, NdisReserved) == 64);
    assert!(offset_of!(NET_BUFFER, ProtocolReserved) == 80);
    assert!(offset_of!(NET_BUFFER, MiniportReserved) == 128);
    assert!(offset_of!(NET_BUFFER, DataPhysicalAddress) == 160);
    assert!(size_of::<NET_BUFFER>() == 176);
};

/// This data type is used as the generic handle type in NDIS function calls.
#[allow(non_camel_case_types)]
pub type NDIS_HANDLE = *mut c_void;

/// This data type is used to indicate success and error states in numerous functions and object identifiers.
#[allow(non_camel_case_types)]
pub type NDIS_STATUS = i32;

/// The NDIS_OBJECT_HEADER structure packages the object type, version, and size information that is required in many NDIS 6.0 structures.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub(crate) struct NDIS_OBJECT_HEADER {
    pub(crate) Type: u8,
    pub(crate) Revision: u8,
    pub(crate) Size: u16,
}

/// The NET_BUFFER_LIST_POOL_PARAMETERS structure defines the parameters for a pool of NET_BUFFER_LIST structures.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
pub(crate) struct NET_BUFFER_LIST_POOL_PARAMETERS {
    pub(crate) Header: NDIS_OBJECT_HEADER,
    pub(crate) ProtocolId: u8,
    pub(crate) fAllocateNetBuffer: bool,
    pub(crate) ContextSize: u16,
    pub(crate) PoolTag: u32,
    pub(crate) DataSize: u32,
    pub(crate) Flags: u32,
}
#[link(name = "Fwpkclnt", kind = "static")]
#[link(name = "Fwpuclnt", kind = "static")]
// GsDriverEntry, the image entry point (link.exe /ENTRY): initializes the stack cookie and calls
// DriverEntry.
#[link(name = "BufferOverflowK", kind = "static")]
#[link(name = "uuid", kind = "static")]
#[link(name = "wdmsec", kind = "static")]
#[link(name = "wmilib", kind = "static")]
#[link(name = "NtosKrnl", kind = "static")]
#[link(name = "ndis", kind = "static")]
#[link(name = "hal", kind = "static")]
extern "C" {
    /// The FwpsCalloutUnregisterById0 function unregisters a callout from the filter engine.
    pub(crate) fn FwpsCalloutUnregisterById0(id: u32) -> NTSTATUS;

    /// The FwpsCalloutRegister3 function registers a callout with the filter engine.
    pub(crate) fn FwpsCalloutRegister3(
        deviceObject: *mut c_void,
        callout: *const FWPS_CALLOUT3,
        calloutId: *mut u32,
    ) -> NTSTATUS;

    /// The FwpsPendOperation0 function is called by a callout to suspend packet processing pending completion of another operation.
    pub(crate) fn FwpsPendOperation0(
        completionHandle: HANDLE,
        completionContext: *mut HANDLE,
    ) -> NTSTATUS;

    /// The FwpsCompleteOperation0 function is called by a callout to resume packet processing that was suspended pending completion of another operation.
    pub(crate) fn FwpsCompleteOperation0(
        completionContext: HANDLE,
        netBufferList: *mut NET_BUFFER_LIST,
    );

    /// The FwpsAcquireClassifyHandle0 function generates a classification handle that is used to identify asynchronous classification operations and requests for writable layer data.
    pub(crate) fn FwpsAcquireClassifyHandle0(
        classify_context: *mut c_void,
        reserved: u32, // Must be zero.
        classify_handle: *mut u64,
    ) -> NTSTATUS;

    /// A callout driver calls FwpsReleaseClassifyHandle0 to release a classification handle that was previously acquired through a call to FwpsAcquireClassifyHandle0.
    pub(crate) fn FwpsReleaseClassifyHandle0(classify_handle: u64);

    /// A callout's classifyFn function calls FwpsPendClassify0 to pend the current classify request. After the request is pended, the callout driver must complete the processing of the classify request asynchronously by calling FwpsCompleteClassify0.
    pub(crate) fn FwpsPendClassify0(
        classify_handle: u64,
        filterId: u64,
        flags: u32, // Must be zero.
        classifyOut: *const ClassifyOut,
    ) -> NTSTATUS;

    /// A callout driver calls FwpsCompleteClassify0 to asynchronously complete a pended classify request. The callout driver's classifyFn function must have previously called FwpsPendClassify0 to pend the classify request.
    pub(crate) fn FwpsCompleteClassify0(
        classify_handle: u64,
        flags: u32, // Must be zero.
        classifyOut: *const ClassifyOut,
    );

    /// The FwpsAcquireWritableLayerDataPointer0 function returns layer-specific data that can be inspected and changed.
    pub(crate) fn FwpsAcquireWritableLayerDataPointer0(
        classify_handle: u64,
        filter_id: u64,
        flags: u32,
        writable_layer_data: *mut c_void,
        classify_out: *mut ClassifyOut,
    ) -> NTSTATUS;

    /// The FwpsApplyModifiedLayerData0 function applies changes to layer-specific data made after a call to FwpsAcquireWritableLayerDataPointer0.
    pub(crate) fn FwpsApplyModifiedLayerData0(
        classifyHandle: u64,
        modifiedLayerData: *mut *mut c_void,
        flags: u32,
    );

    /// The IoCreateDeviceSecure routine creates a named device object and applies the specified security settings.
    /// It is a macro for this function in wdmsec.h; the implementation is in wdmsec.lib.
    pub(crate) fn WdmlibIoCreateDeviceSecure(
        driver_object: *mut DRIVER_OBJECT,
        device_extension_size: u32,
        device_name: *const UNICODE_STRING,
        device_type: u32,
        device_characteristics: u32,
        exclusive: BOOLEAN,
        default_sddl_string: *const UNICODE_STRING,
        device_class_guid: *const GUID,
        device_object: *mut *mut DEVICE_OBJECT,
    ) -> NTSTATUS;

    /// Security descriptor that gives the system and administrators full access, and nobody else any.
    /// Defined in wdmsec.lib as "D:P(A;;GA;;;SY)(A;;GA;;;BA)".
    pub(crate) static SDDL_DEVOBJ_SYS_ALL_ADM_ALL: UNICODE_STRING;

    /// The FwpsInjectNetworkSendAsync0 function injects packet data into the send data path.
    pub(crate) fn FwpsInjectNetworkSendAsync0(
        injectionHandle: HANDLE,
        injectionContext: HANDLE,
        flags: u32,
        compartmentId: COMPARTMENT_ID,
        netBufferList: *mut NET_BUFFER_LIST,
        completionFn: FWPS_INJECT_COMPLETE0,
        completionContext: *mut c_void,
    ) -> NTSTATUS;

    /// The FwpsInjectNetworkReceiveAsync0 function injects packet data into the receive data path.
    pub(crate) fn FwpsInjectNetworkReceiveAsync0(
        injectionHandle: HANDLE,
        injectionContext: HANDLE,
        flags: u32,
        compartmentId: COMPARTMENT_ID,
        interfaceIndex: u32,
        subInterfaceIndex: u32,
        netBufferList: *mut NET_BUFFER_LIST,
        completionFn: FWPS_INJECT_COMPLETE0,
        completionContext: *mut c_void,
    ) -> NTSTATUS;

    /// The FwpsInjectTransportSendAsync1 function injects packet data from the transport, datagram data, or ICMP error layers into the send data path. This function differs from the previous version (FwpsInjectTransportSendAsync0) in that it takes an updated parameters structure as an argument.
    pub(crate) fn FwpsInjectTransportSendAsync1(
        injectionHandle: HANDLE,
        injectionContext: HANDLE,
        endpointHandle: u64,
        flags: u32,
        sendArgs: *mut FWPS_TRANSPORT_SEND_PARAMS1,
        addressFamily: ADDRESS_FAMILY,
        compartmentId: COMPARTMENT_ID,
        netBufferList: *mut NET_BUFFER_LIST,
        completionFn: FWPS_INJECT_COMPLETE0,
        completionContext: *mut c_void,
    ) -> NTSTATUS;

    /// The FwpsInjectTransportReceiveAsync0 function injects packet data from the transport, datagram data, or ICMP error layers into the receive data path.
    pub(crate) fn FwpsInjectTransportReceiveAsync0(
        injectionHandle: HANDLE,
        injectionContext: HANDLE,
        reserved: *const c_void,
        flags: u32,
        addressFamily: ADDRESS_FAMILY,
        compartmentId: COMPARTMENT_ID,
        interfaceIndex: u32,
        subInterfaceIndex: u32,
        netBufferList: *mut NET_BUFFER_LIST,
        completionFn: FWPS_INJECT_COMPLETE0,
        completionContext: *mut c_void,
    ) -> NTSTATUS;

    /// The FwpsInjectionHandleCreate0 function creates a handle that can be used by packet injection functions to inject packet or stream data into the TCP/IP network stack and by the FwpsQueryPacketInjectionState0 function to query the packet injection state.
    pub(crate) fn FwpsInjectionHandleCreate0(
        addressFamily: ADDRESS_FAMILY,
        flags: u32,
        injectionHandle: &mut HANDLE,
    ) -> NTSTATUS;

    /// The FwpsQueryPacketInjectionState0 function is called by a callout to query the injection state of packet data.
    pub(crate) fn FwpsQueryPacketInjectionState0(
        injectionHandle: HANDLE,
        netBufferList: *const NET_BUFFER_LIST,
        injectionContext: *mut HANDLE,
    ) -> FWPS_PACKET_INJECTION_STATE;

    /// The FwpsInjectionHandleDestroy0 function destroys an injection handle that was previously created by calling the FwpsInjectionHandleCreate0 function.
    pub(crate) fn FwpsInjectionHandleDestroy0(injectionHandle: HANDLE) -> NTSTATUS;

    /// The FwpsReferenceNetBufferList0 function increments the reference count for a NET_BUFFER_LIST structure.
    pub(crate) fn FwpsReferenceNetBufferList0(
        netBufferList: *mut NET_BUFFER_LIST,
        intendToModify: bool,
    );

    /// The FwpsDereferenceNetBufferList0 function decrements the reference count for a NET_BUFFER_LIST structure that a callout driver had acquired earlier using the FwpsReferenceNetBufferList0 function.
    pub(crate) fn FwpsDereferenceNetBufferList0(
        netBufferList: *mut NET_BUFFER_LIST,
        dispatchLevel: bool,
    );

    /// Call the NdisGetDataBuffer function to gain access to a contiguous block of data from a NET_BUFFER structure.
    pub(crate) fn NdisGetDataBuffer(
        NetBuffer: *const NET_BUFFER,
        BytesNeeded: u32,
        Storage: *mut u8,
        AlignMultiple: u32,
        AlignOffset: u32,
    ) -> *mut u8;

    /// Call the NdisAllocateCloneNetBufferList function to create a new clone NET_BUFFER_LIST structure.
    pub(crate) fn NdisAllocateCloneNetBufferList(
        OriginalNetBufferList: *mut NET_BUFFER_LIST,
        NetBufferListPoolHandle: NDIS_HANDLE,
        NetBufferPoolHandle: NDIS_HANDLE,
        AllocateCloneFlag: u32,
    ) -> *mut NET_BUFFER_LIST;

    /// Call the NdisFreeCloneNetBufferList function to free a NET_BUFFER_LIST structure and all associated NET_BUFFER structures and MDL chains that were previously allocated by calling the NdisAllocateCloneNetBufferList function.
    pub(crate) fn NdisFreeCloneNetBufferList(
        CloneNetBufferList: *mut NET_BUFFER_LIST,
        FreeCloneFlags: u32,
    );

    /// The FwpsAllocateNetBufferAndNetBufferList0 function allocates a new NET_BUFFER_LIST structure.
    pub(crate) fn FwpsAllocateNetBufferAndNetBufferList0(
        poolHandle: NDIS_HANDLE,
        contextSize: u16,
        contextBackFill: u16,
        mdlChain: *mut MDL,
        dataOffset: u32,
        dataLength: u64,
        netBufferList: *mut *mut NET_BUFFER_LIST,
    ) -> NTSTATUS;

    /// The FwpsFreeNetBufferList0 function frees a NET_BUFFER_LIST structure that was previously allocated by a call to the FwpsAllocateNetBufferAndNetBufferList0 function.
    pub(crate) fn FwpsFreeNetBufferList0(netBufferList: *mut NET_BUFFER_LIST);

    /// Call the NdisAllocateNetBufferListPool function to allocate a pool of NET_BUFFER_LIST structures.
    pub(crate) fn NdisAllocateNetBufferListPool(
        NdisHandle: NDIS_HANDLE,
        Parameters: *const NET_BUFFER_LIST_POOL_PARAMETERS,
    ) -> NDIS_HANDLE;

    /// Call the NdisFreeNetBufferListPool function to free a NET_BUFFER_LIST structure pool.
    pub(crate) fn NdisFreeNetBufferListPool(PoolHandle: NDIS_HANDLE);

    /// Call the NdisRetreatNetBufferDataStart function to access more used data space in the MDL chain of a NET_BUFFER structure.
    pub(crate) fn NdisRetreatNetBufferDataStart(
        NetBuffer: *mut NET_BUFFER,
        DataOffsetDelta: u32,
        DataBackFill: u32,
        AllocateMdlHandler: *mut c_void,
    ) -> NDIS_STATUS;

    /// Call the NdisAdvanceNetBufferDataStart function to release the used data space that was added with the NdisRetreatNetBufferDataStart function.
    pub(crate) fn NdisAdvanceNetBufferDataStart(
        NetBuffer: *mut NET_BUFFER,
        DataOffsetDelta: u32,
        FreeMdl: bool,
        FreeMdlHandler: *mut c_void,
    );

    /// The KeQueryPerformanceCounter routine retrieves the current value and frequency of the performance counter.
    /// Use KeQueryPerformanceCounter to acquire high resolution (<1µs) time stamps for time interval measurements.
    pub(crate) fn KeQueryPerformanceCounter(frequency: *mut i64) -> i64;

    /// The KeGetCurrentIrql routine returns the current IRQL.
    pub(crate) fn KeGetCurrentIrql() -> u8;

    /// The KeDelayExecutionThread routine puts the current thread into an alertable or
    /// nonalertable wait state for a given interval.
    /// `interval` is a count of 100-nanosecond units: negative is relative to now, positive is an
    /// absolute system time. Callable only at IRQL <= APC_LEVEL (PASSIVE_LEVEL if alertable).
    pub(crate) fn KeDelayExecutionThread(
        wait_mode: i8,
        alertable: u8,
        interval: *const i64,
    ) -> NTSTATUS;
}
