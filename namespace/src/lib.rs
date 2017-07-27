#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate netlink;
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
    // get existing effective uid/gid
    // unshare
    // deal with setgroups, uidmap, gidmap

    let tun_device = bind::tun_alloc()?;

    setup_addresses(
        tun_device.name.as_str(),
        "192.168.33.2",
        "192.168.33.1",
        24,
    )?;

    // exec victim

    Ok(())
}


fn setup_addresses(
    device: &str,
    local_addr: &str,
    gateway_addr: &str,
    prefix_len: u8,
) -> Result<()> {

    let mut nl = netlink::Netlink::new()
        .chain_err(|| "creating netlink")?;

    let if_index = nl.index_of_link_name(device)
        .chain_err(|| "looking up interface index")?;

    let mut addr = netlink::Address::new()?;

    addr.set_index(if_index);

    {
        let local_addr = netlink::Address::from_string_inet(local_addr)
            .chain_err(|| "translating local address")?;

        addr.set_local(&local_addr)
            .chain_err(|| "setting local address")?;
    }

    addr.set_prefix_len(prefix_len);

    nl.add_address(&addr)
        .chain_err(|| "adding address")?;

    {
        let gateway_addr = netlink::Address::from_string_inet(gateway_addr)
            .chain_err(|| "translating gateway address")?;

        nl.add_route(if_index, &gateway_addr)
            .chain_err(|| "adding route")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
