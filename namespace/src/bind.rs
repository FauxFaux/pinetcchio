use nix;
use libc;

use std::os::unix::io::RawFd;
use std::str;

use errors::*;

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

const IFF_UP: libc::c_short = 1<<0;

pub struct Tun {
    pub name: String,
    pub fd: OwnedFd,
}

pub fn tun_alloc() -> Result<Tun> {
    use nix::fcntl::*;
    // Third argument ignored, as we're not creating the file.
    let tun = OwnedFd::new(open(
        "/dev/net/tun",
        OFlag::O_RDWR | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::S_IRUSR,
    ).chain_err(|| "opening /dev/net/tun")?);

    let mut req = ioctl::IfReqFlags::default();
    req.ifr_flags = IFF_TUN | IFF_NO_PI;

    unsafe { ioctl::tun_set_iff(tun.fd, &req) }.chain_err(
        || "tun_set_iff",
    )?;

    raise_interface(&mut req)?;

    Ok(Tun {
        name: str::from_utf8(&req.ifr_name)?
            .trim_right_matches('\0')
            .to_string(),
        fd: tun,
    })
}

fn raise_interface(req: &mut ioctl::IfReqFlags) -> Result<()> {
    let sock = OwnedFd::new(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) });

    unsafe { ioctl::sock_get_flags(sock.fd, req)?; }

    req.ifr_flags |= IFF_UP;

    unsafe { ioctl::sock_set_flags(sock.fd, req)?; }

    Ok(())
}

pub struct OwnedFd {
    pub fd: RawFd,
}

impl OwnedFd {
    pub fn new(fd: RawFd) -> Self {
        OwnedFd { fd }
    }

    fn close(&mut self) -> Result<()> {
        if -1 == self.fd {
            return Ok(());
        }
        nix::unistd::close(self.fd)?;
        self.fd = -1;
        Ok(())
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        self.close().expect("closing during drop")
    }
}

mod ioctl {
    use libc;
    use super::RawFd;
    use super::Result;

    const TUN_IOC_MAGIC: u8 = 'T' as u8;
    const TUN_IOC_SET_IFF: u8 = 202;

    const TUNSETIFF: u64 = iow!(TUN_IOC_MAGIC, TUN_IOC_SET_IFF, 4);

    /// socket interface get flags
    const SIOCGIFFLAGS: u64 = 0x8913;

    /// socket interface set flags
    const SIOCSIFFLAGS: u64 = 0x8914;

    const IFNAMSIZ: usize = 16;

    #[repr(C)]
    #[derive(Debug, Default)]
    pub struct IfReqFlags {
        pub ifr_name: [u8; IFNAMSIZ],
        pub ifr_flags: libc::c_short,

        /// the flags are actually part of a big union;
        /// and the struct size must be correct.
        padding: [u8; 22],
    }

    // the ioctl! macro doesn't seem to be able to cope with the iow! having that magic 4,
    // and passing a struct. I.. I don't know.
    // this is super-sensitive to the type of `flags`; libc::ioctl has *no types*.
    pub unsafe fn tun_set_iff(fd: RawFd, flags: &IfReqFlags) -> Result<()> {
        assert_eq!(0, libc::ioctl(fd, TUNSETIFF, flags));
        Ok(())
    }

    ioctl!(bad read sock_get_flags with SIOCGIFFLAGS; IfReqFlags);
    ioctl!(bad write_ptr sock_set_flags with SIOCSIFFLAGS; IfReqFlags);
}
