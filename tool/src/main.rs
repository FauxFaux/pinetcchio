#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

mod collect;
mod csum;
mod dns;
mod errors;
mod icmp;
mod ip;

use crate::errors::*;

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
