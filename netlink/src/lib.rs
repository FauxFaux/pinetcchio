use std::ffi::CString;
use std::io;
use std::ptr;

mod raw;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Family {
    Ipv4,
    Ipv6,
}

pub struct Netlink {
    sock: raw::NlSock,
    cache: raw::NlCache,
}

pub struct Address {
    ptr: raw::NlAddr,
}

impl Netlink {
    pub fn new() -> io::Result<Netlink> {
        let mut sock: raw::NlSock = ptr::null_mut();
        let mut cache: raw::NlCache = ptr::null_mut();
        let result = unsafe { raw::make_nl(&mut sock, &mut cache) };

        if 0 == result {
            Ok(Netlink { sock, cache })
        } else if result < 0 {
            Err(io::ErrorKind::Other.into())
        } else {
            Err(io::Error::from_raw_os_error(result))
        }
    }

    pub fn index_of_link_name(&mut self, name: &str) -> io::Result<i32> {
        let name = CString::new(name).unwrap();
        match unsafe { raw::link_name_index(self.cache, name.as_ptr()) } {
            0 => Err(io::ErrorKind::NotFound.into()),
            index => Ok(index),
        }
    }

    pub fn add_address(&mut self, addr: &Address) -> io::Result<()> {
        if 0 == unsafe { raw::rtnl_addr_add(self.sock, addr.ptr, 0) } {
            Ok(())
        } else {
            Err(io::ErrorKind::InvalidData.into())
        }
    }

    pub fn add_route(
        &mut self,
        family: Family,
        if_index: i32,
        gateway: &Address,
    ) -> io::Result<()> {
        if 0 == unsafe { raw::add_route(family.raw(), self.sock, if_index, gateway.ptr) } {
            Ok(())
        } else {
            Err(io::ErrorKind::InvalidData.into())
        }
    }
}

impl Drop for Netlink {
    fn drop(&mut self) {
        unsafe { raw::free_nl(self.sock, self.cache) }
    }
}

impl Address {
    pub fn new() -> io::Result<Self> {
        let ptr = unsafe { raw::rtnl_addr_alloc() };
        if ptr.is_null() {
            Err(io::ErrorKind::Other.into())
        } else {
            Ok(Self { ptr })
        }
    }

    /// e.g. `(Family::Ipv4, "192.168.1.1")`
    pub fn from_string_inet(family: Family, text: &str) -> io::Result<Self> {
        let text = CString::new(text).unwrap();
        let ptr = unsafe { raw::parse_inet_address(family.raw(), text.as_ptr()) };
        if ptr.is_null() {
            Err(io::ErrorKind::InvalidData.into())
        } else {
            Ok(Self { ptr })
        }
    }

    /// e.g. `(Family::Ipv4, &[192, 168, 1, 1])`
    pub fn from_bytes_inet(family: Family, data: &[u8]) -> io::Result<Self> {
        let ptr = unsafe {
            raw::build_inet_address(
                family.raw(),
                data.as_ptr() as *const libc::c_void,
                data.len(),
            )
        };
        if ptr.is_null() {
            Err(io::ErrorKind::InvalidData.into())
        } else {
            Ok(Self { ptr })
        }
    }

    pub fn set_index(&mut self, index: i32) {
        unsafe {
            raw::rtnl_addr_set_ifindex(self.ptr, index);
        }
    }

    pub fn set_local(&mut self, local: &Self) -> io::Result<()> {
        if 0 == unsafe { raw::rtnl_addr_set_local(self.ptr, local.ptr) } {
            Ok(())
        } else {
            Err(io::ErrorKind::Other.into())
        }
    }

    pub fn set_prefix_len(&mut self, prefix_len: u8) {
        unsafe {
            raw::rtnl_addr_set_prefixlen(self.ptr, i32::from(prefix_len));
        }
    }
}

impl Drop for Address {
    fn drop(&mut self) {
        unsafe { raw::rtnl_addr_put(self.ptr) }
    }
}

impl Family {
    fn raw(&self) -> i32 {
        match *self {
            Family::Ipv4 => raw::AF_INET,
            Family::Ipv6 => raw::AF_INET6,
        }
    }
}
