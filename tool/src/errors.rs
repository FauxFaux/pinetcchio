error_chain! {
    foreign_links {
        Cast(::cast::Error);
        Io(::std::io::Error);
        Time(::std::time::SystemTimeError);
    }

    links {
        Namespace(::namespace::Error, ::namespace::ErrorKind);
        PcapFile(::pcap_file::Error, ::pcap_file::ErrorKind);
    }
}
