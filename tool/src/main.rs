// totally trivial methods; could inline if necessary
#![feature(duration_extras)]

extern crate byteorder;
extern crate cast;
#[macro_use]
extern crate error_chain;
extern crate fdns_parse;
extern crate hex;
extern crate itertools;
extern crate mio;
extern crate namespace;
extern crate pcap_file;

mod collect;
mod csum;
mod dns;
mod errors;
mod icmp;

use errors::*;

fn run() -> Result<()> {
    let (mut child_proc, tun_fd) = namespace::prepare()?;

    collect::watch(tun_fd)?;

    child_proc.wait()?;
    Ok(())
}

quick_main!(run);
