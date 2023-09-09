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
        quote! {(*driver_object).MajorFunction[winapi::km::wdm::IRP_MJ::IOCTL as usize] = Some(internal_wdk_driver_ioctl);}
    } else {
        quote! {}
    };

    let read_token = if args.read_fn {
        quote! {(*driver_object).MajorFunction[winapi::km::wdm::IRP_MJ::READ as usize] = Some(internal_wdk_driver_read);}
    } else {
        quote! {}
    };

    let write_token = if args.write_fn {
        quote! {(*driver_object).MajorFunction[winapi::km::wdm::IRP_MJ::WRITE as usize] = Some(internal_wdk_driver_write);}
    } else {
        quote! {}
    };
    let mut token = TokenStream::from(quote! {
        #[no_mangle]
        pub extern "system" fn DriverEntry(
            driver_object: *mut DRIVER_OBJECT,
            registry_path: *mut UNICODE_STRING,
        ) -> NTSTATUS {
            // Initialize driver object
            let driver = match interface::init_driver_object(
                driver_object,
                registry_path,
                #path1,
                #path2,
            ) {
                Ok(driver) => driver,
                Err(status) => {
                    log!("driver_entry: failed to initialize driver: {}", status);
                    return windows_sys::Win32::Foundation::STATUS_FAILED_DRIVER_ENTRY;
                }
            };

            // Set unload function.
            unsafe {
                (*driver_object).DriverUnload = Some(internal_wdk_driver_unload);
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
        extern "system" fn internal_wdk_driver_unload(_self: &mut DRIVER_OBJECT) {
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
             _device_object: &mut DEVICE_OBJECT,
             irp: &mut IRP,
         ) -> NTSTATUS {
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
             _device_object: &mut DEVICE_OBJECT,
             irp: &mut IRP,
         ) -> NTSTATUS {
             #name(wdk::utils::WriteRequest::new(irp));
             return windows_sys::Win32::Foundation::STATUS_SUCCESS;
         }
    });
    token.extend(input_copy);
    return token;
}
