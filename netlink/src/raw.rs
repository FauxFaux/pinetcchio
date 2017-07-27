use libc;

pub type NlSock = *mut libc::c_void;
pub type NlCache = *mut libc::c_void;

#[link(name = "netlink", kind = "static")]
#[link(name = "nl")]
extern "C" {
    pub fn make_nl(sock: *mut NlSock, cache: *mut NlCache) -> i32;
    pub fn free_nl(sock: NlSock, cache: NlCache);
}

