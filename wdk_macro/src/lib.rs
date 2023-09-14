extern crate proc_macro;
use darling::{export::NestedMeta, Error, FromMeta};
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

extern crate darling;

#[derive(Debug, FromMeta)]
struct DriverArgs {
    name: String,
    ioctl_fn: bool,
    read_fn: bool,
    write_fn: bool,
}

#[proc_macro_attribute]
pub fn driver_entry(args: TokenStream, input: TokenStream) -> TokenStream {
    let attr_args = match NestedMeta::parse_meta_list(args.into()) {
        Ok(v) => v,
        Err(e) => {
            return TokenStream::from(Error::from(e).write_errors());
        }
    };

    let input_copy = input.clone();
    let input_fn = parse_macro_input!(input as ItemFn);
    let args = match DriverArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => {
            return TokenStream::from(e.write_errors());
        }
    };
    let name = input_fn.sig.ident;
    let path1 = format!("\\Device\\{}", args.name);
    let path2 = format!("\\??\\{}", args.name);

    let ioctl_token = if args.ioctl_fn {
        quote! {
            // Ungly compier hack that fixes wrong function type in windows-rs bindings.
            type DeviceControlType = Option<unsafe extern "system" fn(&mut windows_sys::Wdk::Foundation::DEVICE_OBJECT, &mut windows_sys::Wdk::Foundation::IRP) -> windows_sys::Win32::Foundation::NTSTATUS>;
            let device_control_fn: DeviceControlType = Some(internal_wdk_driver_read);
            (*driver_object).MajorFunction[windows_sys::Wdk::System::SystemServices::IRP_MJ_DEVICE_CONTROL as usize] = core::mem::transmute(device_control_fn);
        }
    } else {
        quote! {}
    };

    let read_token = if args.read_fn {
        quote! {
            // Ungly compier hack that fixes wrong function type in windows-rs bindings.
            type ReadType = Option<unsafe extern "system" fn(&mut windows_sys::Wdk::Foundation::DEVICE_OBJECT, &mut windows_sys::Wdk::Foundation::IRP) -> windows_sys::Win32::Foundation::NTSTATUS>;
            let driver_read_fn: ReadType = Some(internal_wdk_driver_read);
            (*driver_object).MajorFunction[windows_sys::Wdk::System::SystemServices::IRP_MJ_READ as usize] = core::mem::transmute(driver_read_fn);
        }
    } else {
        quote! {}
    };

    let write_token = if args.write_fn {
        quote! {
            // Ungly compier hack that fixes wrong function type in windows-rs bindings.
            type WriteType = Option<unsafe extern "system" fn(&mut windows_sys::Wdk::Foundation::DEVICE_OBJECT, &mut windows_sys::Wdk::Foundation::IRP) -> windows_sys::Win32::Foundation::NTSTATUS>;
            let driver_write_fn: WriteType = Some(internal_wdk_driver_write);
            (*driver_object).MajorFunction[windows_sys::Wdk::System::SystemServices::IRP_MJ_WRITE as usize] = core::mem::transmute(driver_write_fn);
        }
    } else {
        quote! {}
    };

    let mut token = TokenStream::from(quote! {
        #[no_mangle]
        pub extern "system" fn DriverEntry(
            driver_object: *mut windows_sys::Wdk::Foundation::DRIVER_OBJECT,
            registry_path: *mut windows_sys::Win32::Foundation::UNICODE_STRING,
        ) -> windows_sys::Win32::Foundation::NTSTATUS {
            // Initialize driver object
            let driver = match interface::init_driver_object(
                driver_object,
                registry_path,
                #path1,
                #path2,
            ) {
                Ok(driver) => driver,
                Err(status) => {
                    err!("driver_entry: failed to initialize driver: {}", status);
                    return windows_sys::Win32::Foundation::STATUS_FAILED_DRIVER_ENTRY;
                }
            };

            // Set unload function.
            unsafe {
                // Ungly compier hack that fixes wrong function type in windows-rs bindings.
                let driver_unload_fn: windows_sys::Wdk::System::SystemServices::DRIVER_UNLOAD = Some(internal_wdk_driver_unload);
                (*driver_object).DriverUnload = core::mem::transmute(driver_unload_fn);
                #ioctl_token
                #read_token
                #write_token
            }

            #name(driver);
            return windows_sys::Win32::Foundation::STATUS_SUCCESS;
        }
    });
    token.extend(input_copy);
    return token;
}

#[proc_macro_attribute]
pub fn driver_unload(_metadata: TokenStream, input: TokenStream) -> TokenStream {
    let input_copy = input.clone();
    let input_fn = parse_macro_input!(input as ItemFn);
    let name = input_fn.sig.ident;
    let mut token = TokenStream::from(quote! {
        extern "system" fn internal_wdk_driver_unload(_self: *const windows_sys::Wdk::Foundation::DRIVER_OBJECT) {
            #name();
        }
    });
    token.extend(input_copy);
    return token;
}

#[proc_macro_attribute]
pub fn driver_read(_metadata: TokenStream, input: TokenStream) -> TokenStream {
    let input_copy = input.clone();
    let input_fn = parse_macro_input!(input as ItemFn);
    let name = input_fn.sig.ident;
    let mut token = TokenStream::from(quote! {
         unsafe extern "system" fn internal_wdk_driver_read(
             _device_object: &mut windows_sys::Wdk::Foundation::DEVICE_OBJECT,
             irp: &mut windows_sys::Wdk::Foundation::IRP,
         ) -> windows_sys::Win32::Foundation::NTSTATUS {
             #name(wdk::utils::ReadRequest::new(irp));
             return windows_sys::Win32::Foundation::STATUS_SUCCESS;
         }
    });
    token.extend(input_copy);
    return token;
}

#[proc_macro_attribute]
pub fn driver_write(_metadata: TokenStream, input: TokenStream) -> TokenStream {
    let input_copy = input.clone();
    let input_fn = parse_macro_input!(input as ItemFn);
    let name = input_fn.sig.ident;
    let mut token = TokenStream::from(quote! {
         unsafe extern "system" fn internal_wdk_driver_write(
             _device_object: &mut windows_sys::Wdk::Foundation::DEVICE_OBJECT,
             irp: &mut windows_sys::Wdk::Foundation::IRP,
         ) -> windows_sys::Win32::Foundation::NTSTATUS {
             #name(wdk::utils::WriteRequest::new(irp));
             return windows_sys::Win32::Foundation::STATUS_SUCCESS;
         }
    });
    token.extend(input_copy);
    return token;
}
