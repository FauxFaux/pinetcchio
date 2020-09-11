#[macro_use]
extern crate log;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;

mod collect;
mod csum;
mod dns;
mod icmp;
mod ip;

fn main() -> Result<()> {
    pretty_env_logger::formatted_builder()
        .filter(None, log::LevelFilter::Info)
        .init();

    let (mut child_proc, tun_fd) = namespace::prepare()?;

    collect::watch(tun_fd)?;

    child_proc.wait()?;
    Ok(())
}
