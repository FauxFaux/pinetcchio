error_chain! {
    foreign_links {
        Exec(::exec::Error);
        Io(::std::io::Error);
        Utf8(::std::str::Utf8Error);
        Nix(::nix::Error);
    }
}
