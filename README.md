# Portmaster Windows kext
Implementation of Safing's Portmaster Windows kernel extension in Rust.

> This is still work in progress.

### Building

The Windows Portmaster Kernel Extension is currently only developed and tested for the amd64 (64-bit) architecture.

__Prerequesites:__

- Visual Studio 2022
    - Install C++ and Windows 11 SDK (22H2) components
- Windows 11 WDK (22H2) (https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
    - Install Visual Studio extension
- Rust
    - https://www.rust-lang.org/tools/install
- Cargo make
    - https://github.com/sagiegurari/cargo-make



__Setup Test Signing:__

In order to test the driver on your machine, you will have to test sign it (starting with Windows 10).


Create a new certificate for test signing:

    :: Open a *x64 Free Build Environment* console as Administrator.

    :: Run the MakeCert.exe tool to create a test certificate:
    MakeCert -r -pe -ss PrivateCertStore -n "CN=DriverCertificate" DriverCertificate.cer

    :: Install the test certificate with CertMgr.exe:
    CertMgr /add DriverCertificate.cer /s /r localMachine root


Enable Test Signing on the dev machine:

    :: Before you can load test-signed drivers, you must enable Windows test mode. To do this, run this command:
    Bcdedit.exe -set TESTSIGNING ON
    :: Then, restart Windows. For more information, see The TESTSIGNING Boot Configuration Option.


__Build driver:__

```
cd driver
cargo make sign
```

### Test
- Install go
    - https://go.dev/dl/

```
cd kext_tester
go run .
```

> make sure the hardcoded path in main.go is pointing to the correct `.sys` file
