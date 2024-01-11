fn main() {
    println!("cargo:rustc-link-search=native=../libs");

    // C Helper
    println!("cargo:rerun-if-changed=../c_helper/x64/c_helper.lib");
    println!("cargo:rustc-link-search=native=../c_helper/x64");
}
