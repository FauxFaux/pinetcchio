error_chain! {
    foreign_links {
        Io(::std::io::Error);
        Nix(::nix::Error);
    }

    links {
        Namespace(::namespace::Error, ::namespace::ErrorKind);
    }
}
