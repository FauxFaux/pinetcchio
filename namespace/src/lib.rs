#[macro_use]
extern crate error_chain;
extern crate libc;
#[macro_use]
extern crate nix;

mod bind;
mod errors;

use errors::*;

pub fn prepare() -> Result<()> {
    use nix::sys::socket::*;
    let (to_namespace, to_host) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        libc::AF_UNIX | libc::O_CLOEXEC,
        SockFlag::empty(),
    )?;

    Ok(())
}

pub fn inside() -> Result<()> {
    // setup namespace
    let tun_device = bind::tun_alloc()?;
    // setup addresses / routing via. netlink

    // exec victim

    Ok(())
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
