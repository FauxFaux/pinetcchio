extern crate libc;

use std::io;
use std::ptr;

mod raw;

struct Netlink {
    sock: raw::NlSock,
    cache: raw::NlCache,
}

impl Netlink {
    pub fn new() -> io::Result<Netlink> {
        let mut sock: raw::NlSock = ptr::null_mut();
        let mut cache: raw::NlCache = ptr::null_mut();
        let result = unsafe { raw::make_nl(&mut sock, &mut cache) };

        if 0 == result {
            Ok(Netlink {
                sock,
                cache,
            })
        } else if result < 0 {
            Err(io::ErrorKind::Other.into())
        } else {
            Err(io::Error::from_raw_os_error(result))
        }
    }
}

impl Drop for Netlink {
    fn drop(&mut self) {
        unsafe {
            raw::free_nl(self.sock, self.cache)
        }
    }
}