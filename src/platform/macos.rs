#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case, dead_code)]
#[cfg(not(all(target_pointer_width = "64", any(target_arch = "x86_64", target_arch = "aarch64"))))]
compile_error!("STP's in-crate Darwin ABI bindings cover 64-bit x86_64/aarch64 macOS only"); pub use core::ffi::c_void;
pub type c_char = i8; pub type c_int = i32; pub type c_uint = u32; pub type size_t = usize; pub type ssize_t = isize;
pub type socklen_t = u32; pub type sa_family_t = u8;
#[repr(C)] #[derive(Copy, Clone, Debug)]
pub struct sockaddr { pub sa_len: u8, pub sa_family: sa_family_t, pub sa_data: [c_char; 14] }
#[repr(C)] #[derive(Copy, Clone, Debug, PartialEq, Eq)] pub struct in_addr { pub s_addr: u32 }
#[repr(C)] #[derive(Copy, Clone, Debug)]
pub struct sockaddr_in { pub sin_len: u8, pub sin_family: sa_family_t, pub sin_port: u16, pub sin_addr: in_addr, pub sin_zero: [c_char; 8] }
#[repr(C, align(4))] #[derive(Copy, Clone, Debug, PartialEq, Eq)] pub struct in6_addr { pub s6_addr: [u8; 16] }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct sockaddr_in6 {
    pub sin6_len: u8, pub sin6_family: sa_family_t, pub sin6_port: u16, pub sin6_flowinfo: u32, pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32, }
#[repr(C)] #[derive(Copy, Clone)]
pub struct sockaddr_storage { pub ss_len: u8, pub ss_family: sa_family_t, __ss_pad1: [u8; 6], __ss_align: i64, __ss_pad2: [u8; 112] }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct iovec { pub iov_base: *mut c_void, pub iov_len: size_t }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct msghdr {
    pub msg_name: *mut c_void, pub msg_namelen: socklen_t, pub msg_iov: *mut iovec, pub msg_iovlen: c_int,
    pub msg_control: *mut c_void, pub msg_controllen: socklen_t,
    pub msg_flags: c_int, }
#[repr(C)] #[derive(Copy, Clone, Debug)]
pub struct cmsghdr { pub cmsg_len: socklen_t, pub cmsg_level: c_int, pub cmsg_type: c_int }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct in6_pktinfo { pub ipi6_addr: in6_addr, pub ipi6_ifindex: c_uint }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct timeval { pub tv_sec: i64, pub tv_usec: i32 }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct rusage {
    pub ru_utime: timeval, pub ru_stime: timeval, pub ru_maxrss: i64, pub ru_ixrss: i64, pub ru_idrss: i64,
    pub ru_isrss: i64, pub ru_minflt: i64, pub ru_majflt: i64, pub ru_nswap: i64, pub ru_inblock: i64,
    pub ru_oublock: i64, pub ru_msgsnd: i64, pub ru_msgrcv: i64, pub ru_nsignals: i64, pub ru_nvcsw: i64,
    pub ru_nivcsw: i64, }
pub const RUSAGE_SELF: c_int = 0;
#[repr(C)] #[derive(Copy, Clone, Debug, Default)] pub struct mach_timebase_info { pub numer: u32, pub denom: u32 }
pub const AF_INET: c_int = 2; pub const AF_INET6: c_int = 30; pub const SOCK_DGRAM: c_int = 2;
pub const IPPROTO_IP: c_int = 0; pub const IPPROTO_UDP: c_int = 17; pub const IPPROTO_IPV6: c_int = 41;
pub const SOL_SOCKET: c_int = 0xffff; pub const IP_TOS: c_int = 3; pub const IPV6_V6ONLY: c_int = 27;
pub const IPV6_RECVTCLASS: c_int = 35; pub const IPV6_TCLASS: c_int = 36; pub const IPV6_PKTINFO: c_int = 46;
pub const IPV6_RECVPKTINFO: c_int = 61; pub const IPV6_DONTFRAG: c_int = 62; pub const F_GETFL: c_int = 3;
pub const F_SETFL: c_int = 4; pub const O_NONBLOCK: c_int = 0x4; pub const MSG_TRUNC: c_int = 0x10;
pub const EINTR: c_int = 4; pub const EBADF: c_int = 9; pub const EINVAL: c_int = 22; pub const EAGAIN: c_int = 35;
pub const EWOULDBLOCK: c_int = EAGAIN; pub const EMSGSIZE: c_int = 40; pub const ENOPROTOOPT: c_int = 42;
pub const EAFNOSUPPORT: c_int = 47; pub const EADDRNOTAVAIL: c_int = 49; pub const ENETDOWN: c_int = 50;
pub const ENETUNREACH: c_int = 51; pub const ENOBUFS: c_int = 55; pub const ECONNREFUSED: c_int = 61;
pub const EHOSTDOWN: c_int = 64; pub const EHOSTUNREACH: c_int = 65; pub const GETENTROPY_MAX: usize = 256;
unsafe extern "C" { pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, len: socklen_t) -> c_int;
    pub fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *mut c_void, len: *mut socklen_t) -> c_int;
    pub fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;
    pub fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;
    pub fn getsockname(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int;
    pub fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t;
    pub fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t; pub fn close(fd: c_int) -> c_int;
    pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int; pub fn getentropy(buf: *mut c_void, len: size_t) -> c_int;
    pub fn getrusage(who: c_int, usage: *mut rusage) -> c_int; pub fn mach_absolute_time() -> u64;
    pub fn mach_timebase_info(info: *mut mach_timebase_info) -> c_int; }
#[inline] pub const fn CMSG_ALIGN(len: usize) -> usize { (len + 3) & !3 }
#[inline]
pub const fn CMSG_SPACE(len: u32) -> u32 { (CMSG_ALIGN(core::mem::size_of::<cmsghdr>()) + CMSG_ALIGN(len as usize)) as u32 }
#[inline] pub const fn CMSG_LEN(len: u32) -> u32 { (CMSG_ALIGN(core::mem::size_of::<cmsghdr>()) + len as usize) as u32 }
/// # Safety
/// `cmsg` must point at a header inside a control buffer.
#[inline] pub unsafe fn CMSG_DATA(cmsg: *const cmsghdr) -> *mut u8 {
    unsafe { (cmsg as *mut u8).add(CMSG_ALIGN(core::mem::size_of::<cmsghdr>())) } }
/// # Safety
/// `msg` must point at a valid msghdr.
#[inline] pub unsafe fn CMSG_FIRSTHDR(msg: *const msghdr) -> *mut cmsghdr {
    let msg = unsafe { &*msg };
    if msg.msg_controllen as usize >= core::mem::size_of::<cmsghdr>() { msg.msg_control as *mut cmsghdr } else { core::ptr::null_mut() } }
/// # Safety
/// `msg` must point at a valid msghdr and `cmsg` be null or a header inside its control buffer.
#[inline] pub unsafe fn CMSG_NXTHDR(msg: *const msghdr, cmsg: *const cmsghdr) -> *mut cmsghdr {
    if cmsg.is_null() { return unsafe { CMSG_FIRSTHDR(msg) }; }
    let msg = unsafe { &*msg }; let step = CMSG_ALIGN(unsafe { (*cmsg).cmsg_len } as usize);
    let end = (msg.msg_control as usize).saturating_add(msg.msg_controllen as usize);
    let next = (cmsg as usize).saturating_add(step);
    if next.saturating_add(CMSG_ALIGN(core::mem::size_of::<cmsghdr>())) > end { core::ptr::null_mut() } else { next as *mut cmsghdr } }
pub fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    for chunk in buf.chunks_mut(GETENTROPY_MAX) {
        loop {
            if unsafe { getentropy(chunk.as_mut_ptr().cast(), chunk.len()) } == 0 { break; }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(EINTR) { return Err(err); } } }
    Ok(()) }
const _: () = { use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<sockaddr>() == 16 && size_of::<sockaddr_in>() == 16 && size_of::<sockaddr_in6>() == 28 && size_of::<sockaddr_storage>() == 128);
    assert!(offset_of!(sockaddr_in6, sin6_family) == 1 && offset_of!(sockaddr_in6, sin6_port) == 2 && offset_of!(sockaddr_in6, sin6_addr) == 8 && offset_of!(sockaddr_in6, sin6_scope_id) == 24);
    assert!(offset_of!(sockaddr_in, sin_addr) == 4 && offset_of!(sockaddr_storage, ss_family) == 1 && align_of::<sockaddr_storage>() == 8);
    assert!(size_of::<msghdr>() == 48 && offset_of!(msghdr, msg_iov) == 16 && offset_of!(msghdr, msg_iovlen) == 24);
    assert!(offset_of!(msghdr, msg_control) == 32 && offset_of!(msghdr, msg_controllen) == 40 && offset_of!(msghdr, msg_flags) == 44);
    assert!(size_of::<cmsghdr>() == 12 && size_of::<in6_pktinfo>() == 20 && size_of::<mach_timebase_info>() == 8);
    assert!(size_of::<timeval>() == 16 && size_of::<rusage>() == 144 && offset_of!(rusage, ru_maxrss) == 32);
    assert!(CMSG_LEN(4) == 16 && CMSG_SPACE(4) == 16 && CMSG_SPACE(20) == 32 && CMSG_SPACE(1) == 16); };
