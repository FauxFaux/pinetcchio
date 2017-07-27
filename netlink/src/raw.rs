use libc::c_char;
use libc::c_int;
use libc::c_void;

pub type NlSock = *mut c_void;
pub type NlCache = *mut c_void;
pub type NlAddr = *mut c_void;

#[link(name = "netlink", kind = "static")]
#[link(name = "nl")]
extern "C" {
    pub fn make_nl(sock: *mut NlSock, cache: *mut NlCache) -> i32;
    pub fn free_nl(sock: NlSock, cache: NlCache);

    pub fn link_name_index(cache: NlCache, name: *const c_char) -> i32;
    pub fn parse_inet_address(text: *const c_char) -> NlAddr;

    pub fn rtnl_addr_alloc() -> NlAddr;
    pub fn rtnl_addr_add(sk: NlSock, addr: NlAddr, flags: c_int) -> c_int;
    pub fn rtnl_addr_put(addr: NlAddr); // void

    pub fn rtnl_addr_set_ifindex(addr: NlAddr, index: c_int); // void
    pub fn rtnl_addr_set_local(addr: NlAddr, local: NlAddr) -> c_int;
    pub fn rtnl_addr_set_prefixlen(addr: NlAddr, prefix_len: c_int); // void
}

