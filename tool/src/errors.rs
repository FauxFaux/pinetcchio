error_chain! {
    foreign_links {
        Io(::std::io::Error);
    }

    links {
        Namespace(::namespace::Error, ::namespace::ErrorKind);
    }
}
