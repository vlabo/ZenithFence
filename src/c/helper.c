
/*
 *  Name:        helper.c
 */

#include <stdlib.h>
#include <wchar.h>

#define NDIS61 1                // Need to declare this to compile WFP stuff on Win7, I'm not sure why

#include "Ntifs.h"
#include <ntddk.h>              // Windows Driver Development Kit
#include <wdf.h>                // Windows Driver Foundation

#pragma warning(push)
#pragma warning(disable: 4201)  // Disable "Nameless struct/union" compiler warning for fwpsk.h only!
#include <fwpsk.h>              // Functions and enumerated types used to implement callouts in kernel mode
#pragma warning(pop)            // Re-enable "Nameless struct/union" compiler warning

#include <fwpmk.h>              // Functions used for managing IKE and AuthIP main mode (MM) policy and security associations
#include <fwpvi.h>              // Mappings of OS specific function versions (i.e. fn's that end in 0 or 1)
#include <guiddef.h>            // Used to define GUID's
#include <initguid.h>           // Used to define GUID's
#include "devguid.h"
#include <stdarg.h>
#include <stdbool.h>
#include <ntstrsafe.h>


/************************************
    Private Data and Prototypes
************************************/
// Global handle to the WFP Base Filter Engine

// #define PORTMASTER_DEVICE_NAME L"PortmasterTest"
// #define PORTMASTER_DEVICE_STRING L"\\Device\\" PORTMASTER_DEVICE_NAME //L"\\Device\\PortmasterTest"
// #define PORTMASTER_DOS_DEVICE_STRING L"\\??\\" PORTMASTER_DEVICE_NAME

EVT_WDF_DRIVER_UNLOAD emptyEventUnload;

NTSTATUS c_init_driver_object(DRIVER_OBJECT * driverObject, UNICODE_STRING * registryPath, WDFDRIVER * driver, WDFDEVICE * device, wchar_t *win_device_name, wchar_t *dos_device_name) {
	UNICODE_STRING deviceName = { 0 };
	RtlInitUnicodeString(&deviceName, win_device_name);

	UNICODE_STRING deviceSymlink = { 0 };
	RtlInitUnicodeString(&deviceSymlink, dos_device_name);

	// Create a WDFDRIVER for this driver
	WDF_DRIVER_CONFIG config = { 0 };
	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
	config.DriverInitFlags = WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = emptyEventUnload; // <-- Necessary for this driver to unload correctly
	NTSTATUS status = WdfDriverCreate(driverObject, registryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, driver);
	if (!NT_SUCCESS(status)) {
      return status;
	}

	// Create a WDFDEVICE for this driver
	PWDFDEVICE_INIT deviceInit = WdfControlDeviceInitAllocate(*driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);  // only admins and kernel can access device
	if (!deviceInit) {
	    return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Configure the WDFDEVICE_INIT with a name to allow for access from user mode
	WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_NETWORK);
	WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, false);
	(void) WdfDeviceInitAssignName(deviceInit, &deviceName);
	(void) WdfPdoInitAssignRawDevice(deviceInit, &GUID_DEVCLASS_NET);
	WdfDeviceInitSetDeviceClass(deviceInit, &GUID_DEVCLASS_NET);

	status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, device);
	if (!NT_SUCCESS(status)) {
	  WdfDeviceInitFree(deviceInit);
		return status;
	}
	status = WdfDeviceCreateSymbolicLink(*device, &deviceSymlink);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	WdfControlFinishInitializing(*device);
	return STATUS_SUCCESS;
}

void emptyEventUnload(WDFDRIVER Driver) {
  UNREFERENCED_PARAMETER(Driver);
}

NTSTATUS c_create_filter_engine(HANDLE *handle) {
    FWPM_SESSION wdfSession = { 0 };
    wdfSession.flags = FWPM_SESSION_FLAG_DYNAMIC;
    return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &wdfSession, handle);
}

DEVICE_OBJECT* c_get_device_object(WDFDEVICE device) {
    return WdfDeviceWdmGetDeviceObject(device);
}

NTSTATUS c_register_sublayer(HANDLE filter_engine_handle, wchar_t* name, wchar_t* description, GUID guid) {
    FWPM_SUBLAYER sublayer = { 0 };
    sublayer.subLayerKey = guid;
    sublayer.displayData.name = name;
    sublayer.displayData.description = description;
    sublayer.flags = 0;
    sublayer.weight = 0xFFFF;
    return FwpmSubLayerAdd(filter_engine_handle, &sublayer, NULL);
}

NTSTATUS genericNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    FWPS_FILTER* filter) {

    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    switch (notifyType) {
    case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
        // INFO("A new filter has registered a callout as its action");
        break;
    case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
        // INFO("A filter has just been deleted");
        break;
    }
    return STATUS_SUCCESS;
}

void genericFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext) {
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}


NTSTATUS c_register_callout(
    DEVICE_OBJECT* device_object, HANDLE filter_engine_handle, wchar_t* name, wchar_t* description, GUID guid, GUID layer_guid, void (*callout_fn)(
        const FWPS_INCOMING_VALUES* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const FWPS_FILTER* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT* classifyOut),
        UINT32 *callout_id) {

    FWPS_CALLOUT sCallout = { 0 };
    FWPM_CALLOUT mCallout = { 0 };
    FWPM_DISPLAY_DATA displayData = { 0 };

    displayData.name = name;
    displayData.description = description;

    // Register callout
    sCallout.calloutKey = guid;
    sCallout.classifyFn = *callout_fn;
    sCallout.notifyFn = genericNotify;
    sCallout.flowDeleteFn = genericFlowDelete;
    NTSTATUS status = FwpsCalloutRegister((void*)device_object, &sCallout, callout_id);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    mCallout.calloutKey = guid;
    mCallout.displayData = displayData;
    mCallout.applicableLayer = layer_guid;
    mCallout.flags = 0;
    return FwpmCalloutAdd(filter_engine_handle, &mCallout, NULL, NULL);
}

NTSTATUS c_register_filter(
    HANDLE filter_negine_handle,
    GUID sublayer_guid,
    wchar_t *name,
    wchar_t *description,
    GUID callout_guid,
    GUID layer_guid,
    UINT32 action,
    UINT64 *filter_id) {

    FWPM_FILTER filter = { 0 };
    filter.displayData.name = name;
    filter.displayData.description = description;
    filter.action.type = action;   // Says this filter's callout MUST make a block/permit decision. Also see doc excerpts below.
    filter.subLayerKey = sublayer_guid;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 15;     // The weight of this filter within its sublayer
    filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
    filter.numFilterConditions = 0;    // If you specify 0, this filter invokes its callout for all traffic in its layer
    filter.layerKey = layer_guid;   // This layer must match the layer that ExampleCallout is registered to
    filter.action.calloutKey = callout_guid;
    return FwpmFilterAdd(filter_negine_handle, &filter, NULL, filter_id);

}
