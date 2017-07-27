extern crate gcc;

const SRC: &str = "src/netlink.c";

fn main() {
//    gcc::compile_library(, &[SRC]);
    gcc::Config::new()
        .file(SRC)
        .cpp(true)
        .include("/usr/include/libnl3")
        .compile("libnetlink.a");
}
