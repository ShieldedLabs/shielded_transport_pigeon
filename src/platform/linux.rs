#![allow(non_camel_case_types, non_upper_case_globals, non_snake_case, dead_code)]
#[cfg(not(all(
    target_pointer_width = "64", target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64", target_arch = "loongarch64"), )))]
compile_error!("STP's in-crate Linux ABI bindings cover 64-bit little-endian x86_64/aarch64/riscv64/loongarch64 only");
pub use core::ffi::c_void; pub type c_char = i8; pub type c_int = i32; pub type c_uint = u32; pub type c_long = i64;
pub type c_short = i16; pub type size_t = usize; pub type ssize_t = isize; pub type socklen_t = u32;
pub type sa_family_t = u16; pub type nfds_t = u64; pub type clockid_t = c_int; pub type time_t = i64;
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct sockaddr { pub sa_family: sa_family_t, pub sa_data: [c_char; 14] }
#[repr(C)] #[derive(Copy, Clone, Debug, PartialEq, Eq)] pub struct in_addr { pub s_addr: u32 }
#[repr(C)] #[derive(Copy, Clone, Debug)]
pub struct sockaddr_in { pub sin_family: sa_family_t, pub sin_port: u16, pub sin_addr: in_addr, pub sin_zero: [u8; 8] }
#[repr(C, align(4))] #[derive(Copy, Clone, Debug, PartialEq, Eq)] pub struct in6_addr { pub s6_addr: [u8; 16] }
#[repr(C)] #[derive(Copy, Clone, Debug)]
pub struct sockaddr_in6 { pub sin6_family: sa_family_t, pub sin6_port: u16, pub sin6_flowinfo: u32, pub sin6_addr: in6_addr, pub sin6_scope_id: u32 }
#[repr(C)] #[derive(Copy, Clone)]
pub struct sockaddr_storage { pub ss_family: sa_family_t, __ss_padding: [u8; 118], __ss_align: u64 }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct iovec { pub iov_base: *mut c_void, pub iov_len: size_t }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct msghdr {
    pub msg_name: *mut c_void, pub msg_namelen: socklen_t, pub msg_iov: *mut iovec, pub msg_iovlen: size_t,
    pub msg_control: *mut c_void, pub msg_controllen: size_t,
    pub msg_flags: c_int, }
#[repr(C)] #[derive(Copy, Clone, Debug)]
pub struct cmsghdr { pub cmsg_len: size_t, pub cmsg_level: c_int, pub cmsg_type: c_int }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct in6_pktinfo { pub ipi6_addr: in6_addr, pub ipi6_ifindex: c_uint }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct pollfd { pub fd: c_int, pub events: c_short, pub revents: c_short }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct timespec { pub tv_sec: time_t, pub tv_nsec: c_long }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct ifaddrs {
    pub ifa_next: *mut ifaddrs, pub ifa_name: *mut c_char, pub ifa_flags: c_uint, pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr, pub ifa_ifu: *mut sockaddr,
    pub ifa_data: *mut c_void, }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct timeval { pub tv_sec: time_t, pub tv_usec: i64 }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct rusage {
    pub ru_utime: timeval, pub ru_stime: timeval, pub ru_maxrss: c_long, pub ru_ixrss: c_long, pub ru_idrss: c_long,
    pub ru_isrss: c_long, pub ru_minflt: c_long, pub ru_majflt: c_long, pub ru_nswap: c_long, pub ru_inblock: c_long,
    pub ru_oublock: c_long, pub ru_msgsnd: c_long, pub ru_msgrcv: c_long, pub ru_nsignals: c_long, pub ru_nvcsw: c_long,
    pub ru_nivcsw: c_long, }
#[repr(C)] #[derive(Copy, Clone, Debug)] pub struct rlimit { pub rlim_cur: u64, pub rlim_max: u64 }
pub const AF_UNIX: c_int = 1; pub const AF_INET: c_int = 2; pub const AF_INET6: c_int = 10;
pub const SOCK_DGRAM: c_int = 2; pub const IPPROTO_IP: c_int = 0; pub const IPPROTO_UDP: c_int = 17;
pub const IPPROTO_IPV6: c_int = 41; pub const SOL_SOCKET: c_int = 1; pub const SO_REUSEADDR: c_int = 2;
pub const SO_SNDBUF: c_int = 7; pub const SO_RCVBUF: c_int = 8; pub const SO_REUSEPORT: c_int = 15;
pub const SO_SNDBUFFORCE: c_int = 32; pub const SO_RCVBUFFORCE: c_int = 33; pub const SO_MEMINFO: c_int = 55;
pub const SK_MEMINFO_VARS: usize = 9; pub const SK_MEMINFO_DROPS: usize = 8; pub const IP_TOS: c_int = 1;
pub const IP_MTU_DISCOVER: c_int = 10; pub const IP_RECVTOS: c_int = 13; pub const IP_PMTUDISC_PROBE: c_int = 3;
pub const IPV6_MTU_DISCOVER: c_int = 23; pub const IPV6_V6ONLY: c_int = 26; pub const IPV6_RECVPKTINFO: c_int = 49;
pub const IPV6_PKTINFO: c_int = 50; pub const IPV6_RECVTCLASS: c_int = 66; pub const IPV6_TCLASS: c_int = 67;
pub const IPV6_DONTFRAG: c_int = 62; pub const IPV6_PMTUDISC_PROBE: c_int = 3; pub const F_GETFD: c_int = 1;
pub const F_GETFL: c_int = 3; pub const F_SETFL: c_int = 4; pub const F_DUPFD_CLOEXEC: c_int = 1030;
pub const O_NONBLOCK: c_int = 0o4000; pub const O_CLOEXEC: c_int = 0o2000000;
pub const EFD_NONBLOCK: c_int = O_NONBLOCK; pub const EFD_CLOEXEC: c_int = O_CLOEXEC; pub const POLLIN: c_short = 0x1;
pub const MSG_TRUNC: c_int = 0x20; pub const CLOCK_MONOTONIC_RAW: clockid_t = 4; pub const RLIMIT_NOFILE: c_int = 7;
pub const RUSAGE_SELF: c_int = 0; pub const RUSAGE_THREAD: c_int = 1; pub const FUTEX_WAIT: c_int = 0;
pub const FUTEX_WAKE: c_int = 1; pub const FUTEX_PRIVATE_FLAG: c_int = 128;
#[cfg(target_arch = "x86_64")] pub const SYS_futex: c_long = 202;
#[cfg(not(target_arch = "x86_64"))] pub const SYS_futex: c_long = 98;
#[cfg(target_arch = "x86_64")] pub const SYS_getrandom: c_long = 318;
#[cfg(not(target_arch = "x86_64"))] pub const SYS_getrandom: c_long = 278;
pub const EPERM: c_int = 1; pub const EINTR: c_int = 4; pub const EBADF: c_int = 9; pub const EAGAIN: c_int = 11;
pub const EWOULDBLOCK: c_int = EAGAIN; pub const EINVAL: c_int = 22; pub const ENOSYS: c_int = 38;
pub const EMSGSIZE: c_int = 90; pub const ENOPROTOOPT: c_int = 92; pub const EAFNOSUPPORT: c_int = 97;
pub const EADDRNOTAVAIL: c_int = 99; pub const ENETDOWN: c_int = 100; pub const ENETUNREACH: c_int = 101;
pub const ENOBUFS: c_int = 105; pub const ECONNREFUSED: c_int = 111; pub const EHOSTDOWN: c_int = 112;
pub const EHOSTUNREACH: c_int = 113;
unsafe extern "C" { pub fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    pub fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, len: socklen_t) -> c_int;
    pub fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *mut c_void, len: *mut socklen_t) -> c_int;
    pub fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;
    pub fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;
    pub fn getsockname(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int;
    pub fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t;
    pub fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t; pub fn close(fd: c_int) -> c_int;
    pub fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t;
    pub fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t;
    pub fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    pub fn poll(fds: *mut pollfd, nfds: nfds_t, timeout_ms: c_int) -> c_int;
    pub fn ppoll(fds: *mut pollfd, nfds: nfds_t, timeout: *const timespec, sigmask: *const c_void) -> c_int;
    pub fn eventfd(initval: c_uint, flags: c_int) -> c_int;
    pub fn clock_gettime(clock: clockid_t, ts: *mut timespec) -> c_int; pub fn syscall(number: c_long, ...) -> c_long;
    pub fn getifaddrs(ifap: *mut *mut ifaddrs) -> c_int; pub fn freeifaddrs(ifa: *mut ifaddrs);
    pub fn getrlimit(resource: c_int, rlim: *mut rlimit) -> c_int;
    pub fn getrusage(who: c_int, usage: *mut rusage) -> c_int; }
#[cfg(not(cosmo))] #[inline] pub fn futex_wait(word: &core::sync::atomic::AtomicU32, expected: u32) {
    unsafe { syscall(SYS_futex, word.as_ptr(), FUTEX_WAIT | FUTEX_PRIVATE_FLAG, expected, core::ptr::null::<timespec>()); } }
#[cfg(not(cosmo))] #[inline] pub fn futex_wake_all(word: &core::sync::atomic::AtomicU32) {
    unsafe { syscall(SYS_futex, word.as_ptr(), FUTEX_WAKE | FUTEX_PRIVATE_FLAG, i32::MAX); } }
#[cfg(not(cosmo))] pub fn thread_cpu_time_us() -> Option<(u64, u64)> {
    let mut ru: rusage = unsafe { core::mem::zeroed() };
    if unsafe { getrusage(RUSAGE_THREAD, &mut ru) } != 0 { return None; }
    let us = |t: timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    Some((us(ru.ru_utime), us(ru.ru_stime))) }
const CMSG_ALIGN_TO: usize = core::mem::size_of::<usize>();
#[inline] pub const fn CMSG_ALIGN(len: usize) -> usize { (len + CMSG_ALIGN_TO - 1) & !(CMSG_ALIGN_TO - 1) }
#[inline]
pub const fn CMSG_SPACE(len: u32) -> u32 { (CMSG_ALIGN(len as usize) + CMSG_ALIGN(core::mem::size_of::<cmsghdr>())) as u32 }
#[inline] pub const fn CMSG_LEN(len: u32) -> u32 { (CMSG_ALIGN(core::mem::size_of::<cmsghdr>()) + len as usize) as u32 }
/// # Safety
/// `cmsg` must point at a header inside a control buffer.
#[inline] pub unsafe fn CMSG_DATA(cmsg: *const cmsghdr) -> *mut u8 {
    unsafe { (cmsg as *mut u8).add(CMSG_ALIGN(core::mem::size_of::<cmsghdr>())) } }
/// # Safety
/// `msg` must point at a valid msghdr.
#[inline] pub unsafe fn CMSG_FIRSTHDR(msg: *const msghdr) -> *mut cmsghdr {
    let msg = unsafe { &*msg };
    if msg.msg_controllen >= core::mem::size_of::<cmsghdr>() { msg.msg_control as *mut cmsghdr } else { core::ptr::null_mut() } }
/// # Safety
/// `msg` must point at a valid msghdr and `cmsg` at a header inside its control buffer.
#[inline] pub unsafe fn CMSG_NXTHDR(msg: *const msghdr, cmsg: *const cmsghdr) -> *mut cmsghdr {
    let hdr = core::mem::size_of::<cmsghdr>(); let msg = unsafe { &*msg }; let len = unsafe { (*cmsg).cmsg_len };
    if len < hdr { return core::ptr::null_mut(); }
    let end = (msg.msg_control as usize).saturating_add(msg.msg_controllen);
    let next = (cmsg as usize).saturating_add(CMSG_ALIGN(len));
    if next.saturating_add(hdr) > end { return core::ptr::null_mut(); }
    let next_len = unsafe { (*(next as *const cmsghdr)).cmsg_len };
    if next.saturating_add(CMSG_ALIGN(next_len)) > end { return core::ptr::null_mut(); }
    next as *mut cmsghdr }
#[cfg(not(cosmo))] pub fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    fill_random_with(buf, |rest| {
        let n = unsafe { syscall(SYS_getrandom, rest.as_mut_ptr(), rest.len(), 0 as c_uint) };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) } }) }
#[cfg(not(cosmo))]
pub(super) fn fill_random_with(buf: &mut [u8], mut read: impl FnMut(&mut [u8]) -> std::io::Result<usize>) -> std::io::Result<()> {
    let mut rest = &mut buf[..];
    while !rest.is_empty() {
        let n = match read(rest) {
            Ok(n) => n,
            Err(err) if err.raw_os_error() == Some(EINTR) => continue,
            Err(err) => return Err(err), };
        if n == 0 || n > rest.len() { return Err(std::io::Error::other("getrandom returned an impossible length")); }
        rest = &mut rest[n..]; }
    Ok(()) }
