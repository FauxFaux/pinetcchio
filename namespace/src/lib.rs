extern crate exec;
#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate netlink;
#[macro_use]
extern crate nix;

mod bind;
mod errors;

use std::fs;
use std::io;
use std::process;

use std::io::Write;

use errors::*;

pub fn prepare() -> Result<()> {
    use nix::sys::socket::*;

    let (to_namespace, to_host) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        libc::AF_UNIX | libc::O_CLOEXEC,
        SockFlag::empty(),
    )?;

    use nix::unistd::*;
    match fork()? {
        ForkResult::Child => { inside().expect("setup"); }
        ForkResult::Parent { .. } => { }
    }

    Ok(())
}

pub fn inside() -> Result<()> {
    let real_euid = nix::unistd::geteuid();
    let real_egid = nix::unistd::getegid();

    {
        use nix::sched::*;
        unshare(CLONE_NEWNET | CLONE_NEWUSER).chain_err(
            || "unsharing",
        )?;
    }

    if true {
        drop_setgroups()?;

        fs::OpenOptions::new()
            .write(true)
            .open("/proc/self/uid_map")?
            .write_all(format!("0 {} 1", real_euid).as_bytes())?;

        fs::OpenOptions::new()
            .write(true)
            .open("/proc/self/gid_map")?
            .write_all(format!("0 {} 1", real_egid).as_bytes())?;
    }

    let tun_device = bind::tun_alloc()?;

    setup_addresses(tun_device.name.as_str(), "192.168.33.2", "192.168.33.1", 24)?;

    // launch copy-out

//    Err(Error::with_chain(
//        exec::Command::new("/bin/bash").exec(),
//        "executing",
//    ))

    std::process::Command::new("/bin/bash").spawn()?;

    Ok(())
}

fn drop_setgroups() -> Result<()> {
    match fs::OpenOptions::new().write(true).open(
        "/proc/self/setgroups",
    ) {
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            // Maybe the system doesn't care?
            Ok(())
        }
        Ok(mut file) => {
            file.write_all(b"deny")?;
            Ok(())
        }
        Err(e) => Err(Error::with_chain(e, "unknown error opening setgroups")),
    }
}


fn setup_addresses(
    device: &str,
    local_addr: &str,
    gateway_addr: &str,
    prefix_len: u8,
) -> Result<()> {

    let mut nl = netlink::Netlink::new().chain_err(|| "creating netlink")?;

    let if_index = nl.index_of_link_name(device).chain_err(
        || "looking up interface index",
    )?;

    let mut addr = netlink::Address::new()?;

    addr.set_index(if_index);

    {
        let local_addr = netlink::Address::from_string_inet(local_addr).chain_err(
            || "translating local address",
        )?;

        addr.set_local(&local_addr).chain_err(
            || "setting local address",
        )?;
    }

    addr.set_prefix_len(prefix_len);

    nl.add_address(&addr).chain_err(|| "adding address")?;

    {
        let gateway_addr = netlink::Address::from_string_inet(gateway_addr).chain_err(
            || "translating gateway address",
        )?;

        nl.add_route(if_index, &gateway_addr).chain_err(
            || "adding route",
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
