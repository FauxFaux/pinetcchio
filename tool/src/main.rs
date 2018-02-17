#[macro_use]
extern crate error_chain;
extern crate hex;
extern crate namespace;
extern crate nix;

mod collect;
mod errors;

use errors::*;

fn run() -> Result<()> {
    let (mut child_proc, tun_fd) = namespace::prepare()?;

    collect::watch(tun_fd)?;

    child_proc.wait()?;
    Ok(())
}

quick_main!(run);
