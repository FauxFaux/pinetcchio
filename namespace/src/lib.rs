#[macro_use]
extern crate error_chain;
extern crate exec;
extern crate libc;
extern crate netlink;
#[macro_use]
extern crate nix;
extern crate rand;

mod bind;
mod errors;

use std::fs;
use std::io;
use std::mem;
use std::process;

use std::io::Write;
use std::net::Ipv6Addr;
use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;

use rand::Rng;

use bind::OwnedFd;
pub use errors::*;

pub fn prepare() -> Result<(std::process::Child, RawFd)> {
    use nix::sys::socket::*;

    let (to_namespace, to_host) = socketpair(
        AddressFamily::Unix,
        SockType::Datagram,
        None,
        SockFlag::empty(),
    )
    .chain_err(|| "creating socket pair")?;

    let to_namespace = OwnedFd::new(to_namespace);
    let to_host = OwnedFd::new(to_host);

    let child = {
        let child_to_host = to_host.fd;
        let child_to_namespace = to_namespace.fd;
        process::Command::new("/bin/bash")
            .before_exec(move || {
                mem::drop(OwnedFd::new(child_to_namespace));
                let to_host = OwnedFd::new(child_to_host);
                inside(to_host).expect("really should work out how to pass this");
                Ok(())
            })
            .spawn()?
    };

    close_stdin()?;
    mem::drop(to_host);

    let mut space = CmsgSpace::<[RawFd; 1]>::new();
    let msgs = recvmsg(to_namespace.fd, &[], Some(&mut space), MsgFlags::empty())?;
    let mut iter = msgs.cmsgs();

    let child_tun = if let Some(ControlMessage::ScmRights(fds)) = iter.next() {
        assert_eq!(1, fds.len());
        fds[0]
    } else {
        panic!("no fds");
    };

    mem::drop(to_namespace);

    Ok((child, child_tun))
}

/// Super dodgy reopen here; should re-do freopen?
fn close_stdin() -> Result<()> {
    nix::unistd::close(0)?;

    use nix::fcntl::*;
    // Third argument ignored, as we're not creating the file.
    assert_eq!(
        0,
        open(
            "/dev/null",
            OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::S_IRUSR,
        )?
    );

    Ok(())
}

fn ula_zero() -> Ipv6Addr {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfd;
    bytes[1..6].copy_from_slice(&rand::thread_rng().gen::<[u8; 5]>());
    bytes.into()
}

pub fn inside(to_host: OwnedFd) -> Result<()> {
    let real_euid = nix::unistd::geteuid();
    let real_egid = nix::unistd::getegid();

    {
        use nix::sched::*;
        unshare(CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUSER).chain_err(|| "unsharing")?;
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

    let v6_prefix = ula_zero().octets();
    let mut v6_gateway = v6_prefix.clone();
    v6_gateway[15] = 1;
    let mut v6_local = v6_prefix.clone();
    v6_local[15] = 2;

    setup_addresses(
        tun_device.name.as_str(),
        netlink::Family::Ipv4,
        &[192, 168, 33, 2],
        &[192, 168, 33, 2],
        24,
    )?;
    setup_addresses(
        tun_device.name.as_str(),
        netlink::Family::Ipv6,
        &v6_local,
        &v6_gateway,
        48,
    )?;

    use nix::sys::socket::*;
    let arr = [tun_device.fd.fd];
    let cmsg = [ControlMessage::ScmRights(&arr)];
    nix::sys::socket::sendmsg(to_host.fd, &[], &cmsg, MsgFlags::empty(), None)?;

    Ok(())
}

fn drop_setgroups() -> Result<()> {
    match fs::OpenOptions::new()
        .write(true)
        .open("/proc/self/setgroups")
    {
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
    family: netlink::Family,
    local_addr: &[u8],
    gateway_addr: &[u8],
    prefix_len: u8,
) -> Result<()> {
    let mut nl = netlink::Netlink::new().chain_err(|| "creating netlink")?;

    let if_index = nl
        .index_of_link_name(device)
        .chain_err(|| "looking up interface index")?;

    let mut addr = netlink::Address::new()?;

    addr.set_index(if_index);

    {
        let local_addr = netlink::Address::from_bytes_inet(family, local_addr)
            .chain_err(|| "translating local address")?;

        addr.set_local(&local_addr)
            .chain_err(|| "setting local address")?;
    }

    addr.set_prefix_len(prefix_len);

    nl.add_address(&addr).chain_err(|| "adding address")?;

    {
        let gateway_addr = netlink::Address::from_bytes_inet(family, gateway_addr)
            .chain_err(|| "translating gateway address")?;

        nl.add_route(family, if_index, &gateway_addr)
            .chain_err(|| "adding route")?;
    }

    Ok(())
}
