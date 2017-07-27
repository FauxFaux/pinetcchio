error_chain! {
    foreign_links {
        Io(::std::io::Error);
        Utf8(::std::str::Utf8Error);
        Nix(::nix::Error);
    }
}
