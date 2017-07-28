use nix;
use libc;

use std::os::unix::io::RawFd;
use std::str;

use errors::*;

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

pub struct Tun {
    pub name: String,
    pub fd: OwnedFd,
}

pub fn tun_alloc() -> Result<Tun> {
    use nix::fcntl::*;
    // Third argument ignored, as we're not creating the file.
    let tun = OwnedFd::new(open(
        "/dev/net/tun",
        O_RDWR | O_CLOEXEC,
        nix::sys::stat::S_IRUSR,
    ).chain_err(|| "opening /dev/net/tun")?);

    let mut req = ioctl::IfReqFlags::default();
    req.ifr_flags = IFF_TUN | IFF_NO_PI;

    unsafe { ioctl::tun_set_iff(tun.fd, &req) }.chain_err(
        || "tun_set_iff",
    )?;

    Ok(Tun {
        name: str::from_utf8(&req.ifr_name)?
            .trim_right_matches('\0')
            .to_string(),
        fd: tun,
    })
}

pub struct OwnedFd {
    pub fd: RawFd,
}

impl OwnedFd {
    fn new(fd: RawFd) -> Self {
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

    // this is super-sensitive to the type of `flags`; libc::ioctl has *no types*.
    pub unsafe fn tun_set_iff(fd: RawFd, flags: &IfReqFlags) -> Result<()> {
        assert_eq!(0, libc::ioctl(fd, TUNSETIFF, flags));
        Ok(())
    }
//    ioctl!(write_ptr tun_set_iff with TUN_IOC_MAGIC, TUN_IOC_SET_IFF; IfReqFlags);
}
