extern crate byteorder;
extern crate cast;
#[macro_use]
extern crate error_chain;
extern crate fdns_format;
extern crate hex;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate mio;
extern crate namespace;
extern crate pcap_file;
extern crate pretty_env_logger;
extern crate rand;

mod collect;
mod csum;
mod dns;
mod errors;
mod icmp;
mod ip;

use errors::*;

fn run() -> Result<()> {
    pretty_env_logger::formatted_builder()
        .unwrap()
        .filter(None, log::LevelFilter::Info)
        .init();

    let (mut child_proc, tun_fd) = namespace::prepare()?;

    collect::watch(tun_fd)?;

    child_proc.wait()?;
    Ok(())
}

quick_main!(run);
