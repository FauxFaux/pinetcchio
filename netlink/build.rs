extern crate gcc;

const SRC: &str = "src/netlink.c";

fn main() {
    println!("cargo:rerun-if-changed={}", SRC);

    gcc::Build::new()
        .file(SRC)
        .include("/usr/include/libnl3")
        .compile("libnetlink.a");
}
