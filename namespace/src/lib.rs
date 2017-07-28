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
use std::os::unix::process::CommandExt;
use std::os::unix::io::RawFd;

pub use errors::*;

pub fn prepare() -> Result<()> {
    use nix::sys::socket::*;

    let (to_namespace, to_host) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
//        libc::AF_UNIX | libc::O_CLOEXEC,
        0,
        SockFlag::empty(),
    ).chain_err(|| "creating socket pair")?;

    let mut child = process::Command::new("/bin/bash")
        .before_exec(move || {
            inside(to_host).expect("really should work out how to pass this");
            Ok(())
        })
        .spawn()?;

    let mut space = CmsgSpace::<[RawFd; 1]>::new();
    let msgs = recvmsg(to_namespace, &[], Some(&mut space), MsgFlags::empty())?;
    let mut iter = msgs.cmsgs();
    let fd = if let Some(ControlMessage::ScmRights(fds)) = iter.next() {
        fds[0]
    } else {
        panic!("no fds");
    };

    println!("got an fd! {}", fd);

    child.wait()?;
    Ok(())
}

pub fn inside(to_host: RawFd) -> Result<()> {
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

    use nix::sys::socket::*;
    let arr = [tun_device.fd.fd];
    let cmsg = [ControlMessage::ScmRights(&arr)];
    nix::sys::socket::sendmsg(to_host, &[], &cmsg, MsgFlags::empty(), None)?;

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

        if let Err(e) = nl.add_route(if_index, &gateway_addr).chain_err(
            || "adding route",
        ) {
            println!("couldn't add route; meh: {:?}", e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
