#[cfg(target_arch = "x86_64")]
fn main() {
    println!("cargo:rustc-link-search=native=../libs/x64");
}

#[cfg(target_arch = "aarch64")]
fn main() {
    println!("cargo:rustc-link-search=native=../libs/arm64");
}
