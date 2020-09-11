extern crate cc;

const SRC: &str = "src/netlink.c";

fn main() {
    println!("cargo:rerun-if-changed={}", SRC);

    cc::Build::new()
        .file(SRC)
        .include("/usr/include/libnl3")
        .compile("libnetlink.a");
}
