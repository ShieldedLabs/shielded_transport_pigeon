#![allow(unused_unsafe)]
#[allow(unused_imports)]
use crate::platform::sys;
pub use std::net::Ipv6Addr;
#[derive(Debug)]
pub(crate) struct NetworkWake {
    #[cfg(target_os = "linux")]
    fd: sys::c_int,
    #[cfg(cosmo)]
    tx: sys::c_int,
    pending: std::sync::atomic::AtomicBool,
}
impl NetworkWake {
    pub(crate) fn new() -> std::io::Result<Self> {
        #[cfg(all(target_os = "linux", not(cosmo)))]
        {
            let fd = unsafe { sys::eventfd(0, sys::EFD_NONBLOCK | sys::EFD_CLOEXEC) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self {
                fd,
                pending: std::sync::atomic::AtomicBool::new(false),
            })
        }
        #[cfg(cosmo)]
        {
            let mut pair = [-1 as sys::c_int; 2];
            let ty = sys::SOCK_STREAM | sys::SOCK_NONBLOCK | sys::SOCK_CLOEXEC;
            if unsafe { sys::socketpair(sys::AF_UNIX, ty, 0, pair.as_mut_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self {
                fd: pair[0],
                tx: pair[1],
                pending: std::sync::atomic::AtomicBool::new(false),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self {
                pending: std::sync::atomic::AtomicBool::new(false),
            })
        }
    }
    pub(crate) fn notify(&self) {
        if self.pending.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        #[cfg(all(target_os = "linux", not(cosmo)))]
        unsafe {
            let one = 1u64;
            sys::write(self.fd, &one as *const u64 as *const sys::c_void, 8);
        }
        #[cfg(cosmo)]
        unsafe {
            let one = 1u8;
            sys::write(self.tx, &one as *const u8 as *const sys::c_void, 1);
        }
    }
    pub(crate) fn wait(&self, socket: SockHandle, timeout: std::time::Duration) {
        #[cfg(target_os = "linux")]
        socket.wait_readable(self.fd, timeout);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = socket;
            std::thread::park_timeout(timeout.min(std::time::Duration::from_micros(150)));
        }
        self.pending
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}
impl Drop for NetworkWake {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        unsafe {
            sys::close(self.fd);
        }
        #[cfg(cosmo)]
        unsafe {
            sys::close(self.tx);
        }
    }
}
pub const ASSUMED_UDP_PAYLOAD_SIZE_WITH_GUARANTEED_DELIVERY: usize = 1204;
pub const ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE: usize = 9216;
pub type PacketMemory = Box<[u8; ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE]>;
#[allow(unsafe_code)]
pub fn new_packet_memory() -> PacketMemory {
    unsafe {
        Box::<[u8; ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE]>::new_uninit()
            .assume_init()
    }
}
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Dscp {
    BestEffort = 0,
    Af11 = 10,
    Af21 = 18,
    Ef = 46,
}
impl Dscp {
    #[inline]
    pub fn from_u8(v: u8) -> Dscp {
        match v & 0b11_1111 {
            0 => Dscp::BestEffort,
            10 => Dscp::Af11,
            18 => Dscp::Af21,
            46 => Dscp::Ef,
            _ => Dscp::BestEffort,
        }
    }
}
const PROBE_V4: [u8; 4] = [1, 1, 1, 1];
const PROBE_V6: [u8; 16] = [
    0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11,
];
fn usable_probed_v4(addr: Ipv6Addr) -> Option<Ipv6Addr> {
    if addr.is_unspecified() || addr.is_loopback() || addr.is_unicast_link_local() {
        None
    } else {
        Some(addr)
    }
}
fn usable_probed_v6(addr: Ipv6Addr) -> Option<Ipv6Addr> {
    let seg = addr.segments();
    if addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_multicast()
        || addr.is_unicast_link_local()
        || (seg[4] == 0 && seg[5] == 0 && seg[6] == 0 && seg[7] == 0)
    {
        None
    } else {
        Some(addr)
    }
}
#[inline]
fn tclass_byte(dscp: Dscp, ecn_signal: bool) -> u8 {
    ((dscp as u8) << 2) | if ecn_signal { 0b11 } else { 0b10 }
}
#[inline]
fn decode_tclass(tclass: u8) -> (bool, bool, Dscp) {
    let ecn_bits = tclass & 0b11;
    (ecn_bits == 0b11, ecn_bits != 0, Dscp::from_u8(tclass >> 2))
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
mod posix {
    use super::*;
    #[inline]
    pub(super) unsafe fn setsockopt_int(
        fd: sys::c_int,
        level: sys::c_int,
        opt: sys::c_int,
        val: sys::c_int,
    ) -> sys::c_int {
        unsafe {
            sys::setsockopt(
                fd,
                level,
                opt,
                &val as *const _ as *const sys::c_void,
                std::mem::size_of_val(&val) as sys::socklen_t,
            )
        }
    }
    pub(super) fn setup_failed<T>(fd: Option<sys::c_int>, what: std::fmt::Arguments) -> Option<T> {
        let err = std::io::Error::last_os_error();
        eprintln!("{what}: {err}");
        if let Some(fd) = fd {
            unsafe {
                sys::close(fd);
            }
        }
        None
    }
    pub(super) fn set_nonblocking(fd: sys::c_int) -> Result<(), &'static str> {
        unsafe {
            let flags = sys::fcntl(fd, sys::F_GETFL);
            if flags < 0 {
                return Err("fcntl(F_GETFL) failed");
            }
            if sys::fcntl(fd, sys::F_SETFL, flags | sys::O_NONBLOCK) < 0 {
                return Err("fcntl(F_SETFL) failed");
            }
        }
        Ok(())
    }
    #[inline]
    pub(super) fn msghdr(
        name: *mut sys::c_void,
        namelen: sys::socklen_t,
        iov: &mut sys::iovec,
        control: &mut [u8],
    ) -> sys::msghdr {
        let mut msg: sys::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = name;
        msg.msg_namelen = namelen;
        msg.msg_iov = iov as *mut sys::iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut sys::c_void;
        msg.msg_controllen = control.len() as _;
        msg
    }
    #[inline]
    pub(super) fn sockaddr_in6(octets: [u8; 16], port: u16) -> sys::sockaddr_in6 {
        let mut addr: sys::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = sys::AF_INET6 as _;
        addr.sin6_port = port.to_be();
        addr.sin6_addr = sys::in6_addr { s6_addr: octets };
        addr
    }
    unsafe fn probe_local<T>(family: sys::c_int, dst: &T, ip: &str) -> Option<T> {
        unsafe {
            let fd = sys::socket(family, sys::SOCK_DGRAM, sys::IPPROTO_UDP);
            if fd < 0 {
                panic!("socket() failed: {}", std::io::Error::last_os_error());
            }
            let len = std::mem::size_of::<T>() as sys::socklen_t;
            let ret = if sys::connect(fd, dst as *const T as *const sys::sockaddr, len) != 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(sys::ENETUNREACH) | Some(sys::EHOSTUNREACH) | Some(sys::EADDRNOTAVAIL) => {
                        None
                    }
                    _ => panic!("{ip} probe connect() failed: {}", err),
                }
            } else {
                let mut local: T = std::mem::zeroed();
                let mut local_len = len;
                if sys::getsockname(
                    fd,
                    &mut local as *mut T as *mut sys::sockaddr,
                    &mut local_len,
                ) != 0
                {
                    panic!(
                        "{ip} probe getsockname() failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
                Some(local)
            };
            if sys::close(fd) != 0 {
                panic!("close() failed: {}", std::io::Error::last_os_error());
            }
            ret
        }
    }
    pub(super) fn probe_v4_source() -> Option<Ipv6Addr> {
        let mut dst: sys::sockaddr_in = unsafe { std::mem::zeroed() };
        dst.sin_family = sys::AF_INET as _;
        dst.sin_port = 53u16.to_be();
        dst.sin_addr = sys::in_addr {
            s_addr: u32::from_be_bytes(PROBE_V4),
        };
        let local = unsafe { probe_local(sys::AF_INET, &dst, "ipv4") }?;
        usable_probed_v4(
            std::net::Ipv4Addr::from(u32::from_be(local.sin_addr.s_addr)).to_ipv6_mapped(),
        )
    }
    pub(super) fn probe_v6_source() -> Option<Ipv6Addr> {
        let dst = sockaddr_in6(PROBE_V6, 53);
        let local = unsafe { probe_local(sys::AF_INET6, &dst, "ipv6") }?;
        usable_probed_v6(Ipv6Addr::from(local.sin6_addr.s6_addr))
    }
}
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux {
    use super::posix::*;
    use super::*;
    #[inline]
    pub fn socket_setup() {}
    #[inline]
    pub fn monotonic_clock_setup() {}
    #[inline]
    pub fn monotonic_clock_ns() -> u64 {
        unsafe {
            let mut ts: sys::timespec = std::mem::zeroed();
            if sys::clock_gettime(sys::CLOCK_MONOTONIC_RAW, &mut ts) != 0 {
                panic!(
                    "clock_gettime() failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            (ts.tv_sec as u64) * 1_000_000_000u64 + (ts.tv_nsec as u64)
        }
    }
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct SockHandle(sys::c_int, Option<Ipv6Addr>);
    impl SockHandle {
        pub(crate) fn wait_readable(self, wake: sys::c_int, timeout: std::time::Duration) {
            let mut fds = [
                sys::pollfd {
                    fd: self.0,
                    events: sys::POLLIN,
                    revents: 0,
                },
                sys::pollfd {
                    fd: wake,
                    events: sys::POLLIN,
                    revents: 0,
                },
            ];
            let ts = sys::timespec {
                tv_sec: timeout.as_secs() as _,
                tv_nsec: timeout.subsec_nanos() as _,
            };
            unsafe {
                sys::ppoll(fds.as_mut_ptr(), 2, &ts, std::ptr::null());
                if fds[1].revents & sys::POLLIN != 0 {
                    let mut count = 0u64;
                    sys::read(wake, &mut count as *mut u64 as *mut sys::c_void, 8);
                }
            }
        }
        /// Caller must own the socket and never use any copy after this call.
        pub(crate) unsafe fn close(self) {
            unsafe {
                sys::close(self.0);
            }
        }
    }
    pub fn udp_socket_kernel_rx_drops(sock: SockHandle) -> Option<u64> {
        const SO_MEMINFO: sys::c_int = 55;
        const SK_MEMINFO_VARS: usize = 9;
        let mut mi = [0u32; SK_MEMINFO_VARS];
        let mut len = std::mem::size_of_val(&mi) as sys::socklen_t;
        let r = unsafe {
            sys::getsockopt(
                sock.0,
                sys::SOL_SOCKET,
                SO_MEMINFO,
                mi.as_mut_ptr() as *mut sys::c_void,
                &mut len,
            )
        };
        if r == 0 && len as usize >= SK_MEMINFO_VARS * 4 {
            return Some(mi[8] as u64);
        }
        let file = std::mem::ManuallyDrop::new(unsafe {
            <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(sock.0)
        });
        let Ok(st) = file.metadata() else { return None };
        let inode = std::os::unix::fs::MetadataExt::ino(&st).to_string();
        for f in ["/proc/net/udp6", "/proc/net/udp"] {
            let Ok(text) = std::fs::read_to_string(f) else {
                continue;
            };
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 13 && cols[9] == inode {
                    return cols[12].parse().ok();
                }
            }
        }
        None
    }
    #[inline]
    fn first_usable_ipv6() -> Option<Ipv6Addr> {
        unsafe {
            let mut ifap: *mut sys::ifaddrs = std::ptr::null_mut();
            if sys::getifaddrs(&mut ifap) != 0 {
                panic!("getifaddrs failed: {}", std::io::Error::last_os_error());
            }
            let mut index = 0;
            let mut first_is_loopback = false;
            let mut cur = ifap;
            while !cur.is_null() {
                let ifa = &*cur;
                if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == sys::AF_INET6 {
                    index += 1;
                    let sin6 = &*(ifa.ifa_addr as *const sys::sockaddr_in6);
                    let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                    if addr.is_loopback() {
                        cur = (*cur).ifa_next;
                        if index == 1 {
                            first_is_loopback = true;
                        }
                        continue;
                    }
                    if addr.is_multicast() {
                        cur = (*cur).ifa_next;
                        continue;
                    }
                    if (addr.segments()[0] & 0xffc0) == 0xfe80 {
                        cur = (*cur).ifa_next;
                        continue;
                    }
                    let seg = addr.segments();
                    if seg[4] == 0 && seg[5] == 0 && seg[6] == 0 && seg[7] == 0 {
                        cur = (*cur).ifa_next;
                        continue;
                    }
                    sys::freeifaddrs(ifap);
                    if index == 2 && first_is_loopback {
                        return None;
                    }
                    eprintln!(
                        "[WARNING] This linux machine has incorrectly configured it's ipv6 addresses causing a bug when sending ipv6 packets. We will be overriding the sender ip field with '{}' in order to try and work around this issue.",
                        addr
                    );
                    return Some(addr);
                }
                cur = (*cur).ifa_next;
            }
            sys::freeifaddrs(ifap);
            None
        }
    }
    fn set_pmtu_probe(fd: sys::c_int) -> Option<()> {
        let probe: &[(sys::c_int, sys::c_int, sys::c_int, &str)] = &[
            (
                sys::IPPROTO_IP,
                sys::IP_MTU_DISCOVER,
                sys::IP_PMTUDISC_PROBE,
                "IP_MTU_DISCOVER=IP_PMTUDISC_PROBE",
            ),
            (
                sys::IPPROTO_IPV6,
                sys::IPV6_MTU_DISCOVER,
                sys::IPV6_PMTUDISC_PROBE,
                "IPV6_MTU_DISCOVER=IPV6_PMTUDISC_PROBE",
            ),
        ];
        #[cfg(cosmo)]
        let probe: &[(sys::c_int, sys::c_int, sys::c_int, &str)] = if sys::host() == sys::Host::Xnu
        {
            &[(sys::IPPROTO_IPV6, sys::IPV6_DONTFRAG, 1, "IPV6_DONTFRAG=1")]
        } else {
            probe
        };
        for &(level, option, value, name) in probe {
            if unsafe { setsockopt_int(fd, level, option, value) } != 0 {
                return setup_failed(Some(fd), format_args!("Failed to set {name}"));
            }
        }
        Some(())
    }
    #[inline]
    fn linux_host() -> bool {
        #[cfg(cosmo)]
        return sys::host() == sys::Host::Linux;
        #[cfg(not(cosmo))]
        return true;
    }
    #[inline]
    pub fn setup_and_bind_udp_socket(port: u16) -> Option<SockHandle> {
        setup_and_bind_udp_socket_on(port, None)
    }
    pub fn setup_and_bind_udp_socket_on(
        port: u16,
        bind_ip: Option<std::net::IpAddr>,
    ) -> Option<SockHandle> {
        let bind_addr: Ipv6Addr = match bind_ip {
            None => Ipv6Addr::UNSPECIFIED,
            Some(std::net::IpAddr::V4(v4)) => v4.to_ipv6_mapped(),
            Some(std::net::IpAddr::V6(v6)) => v6,
        };
        let fd = unsafe { sys::socket(sys::AF_INET6, sys::SOCK_DGRAM, sys::IPPROTO_UDP) };
        if fd < 0 {
            return setup_failed(None, format_args!("socket() failed"));
        }
        unsafe {
            if linux_host() && setsockopt_int(fd, sys::SOL_SOCKET, sys::SO_REUSEADDR, 1) != 0 {
                return setup_failed(Some(fd), format_args!("Failed to enable SO_REUSEADDR"));
            }
            if linux_host() && setsockopt_int(fd, sys::SOL_SOCKET, sys::SO_REUSEPORT, 1) != 0 {
                return setup_failed(Some(fd), format_args!("Failed to enable SO_REUSEPORT"));
            }
            let want: sys::c_int = 16 << 20;
            for (force, plain, name) in [
                (sys::SO_RCVBUFFORCE, sys::SO_RCVBUF, "SO_RCVBUF"),
                (sys::SO_SNDBUFFORCE, sys::SO_SNDBUF, "SO_SNDBUF"),
            ] {
                if setsockopt_int(fd, sys::SOL_SOCKET, force, want) != 0
                    && setsockopt_int(fd, sys::SOL_SOCKET, plain, want) != 0
                {
                    eprintln!("Failed to set {name}: {}", std::io::Error::last_os_error());
                }
                let mut got: sys::c_int = 0;
                let mut got_len = std::mem::size_of_val(&got) as sys::socklen_t;
                sys::getsockopt(
                    fd,
                    sys::SOL_SOCKET,
                    plain,
                    &mut got as *mut _ as *mut sys::c_void,
                    &mut got_len,
                );
                if (got as i64) < want as i64 {
                    eprintln!(
                        "{name} is {got} bytes (wanted {want}); raise net.core.{}mem_max for more",
                        if plain == sys::SO_RCVBUF { "r" } else { "w" }
                    );
                }
            }
        }
        if let Err(what) = set_nonblocking(fd) {
            return setup_failed(Some(fd), format_args!("{what}"));
        }
        if unsafe { setsockopt_int(fd, sys::IPPROTO_IPV6, sys::IPV6_V6ONLY, 0) } != 0 {
            return setup_failed(Some(fd), format_args!("Failed to disable IPV6_V6ONLY"));
        }
        let known_good_ipv6_address = if bind_ip.is_none() && linux_host() {
            first_usable_ipv6()
        } else {
            None
        };
        let addr = sockaddr_in6(bind_addr.octets(), port);
        if unsafe {
            sys::bind(
                fd,
                &addr as *const _ as *const sys::sockaddr,
                std::mem::size_of::<sys::sockaddr_in6>() as sys::socklen_t,
            )
        } != 0
        {
            return setup_failed(
                Some(fd),
                format_args!("bind([{}]:{}) failed", bind_addr, port),
            );
        }
        unsafe {
            if setsockopt_int(fd, sys::IPPROTO_IP, sys::IP_RECVTOS, 1) != 0 {
                eprintln!(
                    "Failed to Enable IPv4 TOS, error: {}",
                    std::io::Error::last_os_error()
                );
            }
            if setsockopt_int(fd, sys::IPPROTO_IPV6, sys::IPV6_RECVTCLASS, 1) != 0 {
                eprintln!(
                    "Failed to Enable IPv6 TOS, error: {}",
                    std::io::Error::last_os_error()
                );
            }
            if setsockopt_int(fd, sys::IPPROTO_IPV6, sys::IPV6_RECVPKTINFO, 1) != 0 {
                eprintln!(
                    "Failed to Enable IPv6 PKTINFO, error: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        set_pmtu_probe(fd)?;
        Some(SockHandle(fd, known_good_ipv6_address))
    }
    #[inline]
    pub fn udp_send_with_congestion_and_dscp(
        udp_socket: SockHandle,
        dst_ip6: Ipv6Addr,
        dst_port: u16,
        payload: &[u8],
        dscp: Dscp,
        ecn_signal: bool,
    ) -> Option<u64> {
        let fd = udp_socket.0;
        let known_good_ipv6_address = udp_socket.1;
        let mut iov = sys::iovec {
            iov_base: payload.as_ptr() as *mut sys::c_void,
            iov_len: payload.len(),
        };
        let is_v4 = dst_ip6.to_ipv4_mapped().is_some();
        #[cfg(cosmo)]
        let is_v4 = is_v4 && sys::host() != sys::Host::Xnu;
        let sin6 = sockaddr_in6(dst_ip6.octets(), dst_port);
        let mut name_buf = vec![0u8; std::mem::size_of::<sys::sockaddr_in6>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &sin6 as *const _ as *const u8,
                name_buf.as_mut_ptr(),
                name_buf.len(),
            )
        };
        let name_len = name_buf.len() as sys::socklen_t;
        let mut cbuf = [0u8; 256];
        let mut msg = msghdr(
            name_buf.as_mut_ptr() as *mut sys::c_void,
            name_len,
            &mut iov,
            &mut cbuf,
        );
        let tclass_byte = tclass_byte(dscp, ecn_signal);
        unsafe {
            let cmsg = sys::CMSG_FIRSTHDR(&msg as *const _ as *mut _);
            if cmsg.is_null() {
                panic!("CMSG_FIRSTHDR returned null");
            }
            let val: sys::c_int = tclass_byte as sys::c_int;
            (*cmsg).cmsg_level = if is_v4 {
                sys::IPPROTO_IP
            } else {
                sys::IPPROTO_IPV6
            };
            (*cmsg).cmsg_type = if is_v4 { sys::IP_TOS } else { sys::IPV6_TCLASS };
            (*cmsg).cmsg_len = sys::CMSG_LEN(std::mem::size_of::<sys::c_int>() as _) as _;
            let data = sys::CMSG_DATA(cmsg) as *mut sys::c_int;
            *data = val;
            let mut used = sys::CMSG_SPACE(std::mem::size_of::<sys::c_int>() as _) as usize;
            if !is_v4 {
                if let Some(ip6) = known_good_ipv6_address {
                    let cmsg2 = sys::CMSG_NXTHDR(&msg as *const _ as *mut _, cmsg);
                    if cmsg2.is_null() {
                        panic!("CMSG_NXTHDR returned null");
                    }
                    (*cmsg2).cmsg_level = sys::IPPROTO_IPV6;
                    (*cmsg2).cmsg_type = sys::IPV6_PKTINFO;
                    (*cmsg2).cmsg_len =
                        sys::CMSG_LEN(std::mem::size_of::<sys::in6_pktinfo>() as _) as _;
                    let pkt6 = sys::CMSG_DATA(cmsg2) as *mut sys::in6_pktinfo;
                    std::ptr::write_bytes(
                        pkt6 as *mut u8,
                        0,
                        std::mem::size_of::<sys::in6_pktinfo>(),
                    );
                    (*pkt6).ipi6_ifindex = 0;
                    (*pkt6).ipi6_addr = sys::in6_addr {
                        s6_addr: ip6.octets(),
                    };
                    used += sys::CMSG_SPACE(std::mem::size_of::<sys::in6_pktinfo>() as _) as usize;
                }
            }
            msg.msg_controllen = used as _;
            #[cfg(cosmo)]
            if sys::host() == sys::Host::Windows {
                for (level, option) in [
                    (sys::IPPROTO_IP, sys::IP_TOS),
                    (sys::IPPROTO_IPV6, sys::IPV6_TCLASS),
                ] {
                    if setsockopt_int(fd, level, option, tclass_byte as sys::c_int) != 0 {
                        let err = std::io::Error::last_os_error();
                        if !matches!(err.raw_os_error(), Some(sys::EINVAL | sys::ENOPROTOOPT)) {
                            panic!("UDP Socket error: {}", err);
                        }
                    }
                }
                msg.msg_control = core::ptr::null_mut();
                msg.msg_controllen = 0;
            }
            let timestamp_ns = monotonic_clock_ns();
            let n = sys::sendmsg(fd, &msg as *const _ as *mut _, 0);
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err
                    .raw_os_error()
                    .is_some_and(|e| e == sys::EAGAIN || e == sys::EWOULDBLOCK || e == sys::ENOBUFS)
                {
                    #[cfg(feature = "research_cohort_observer")]
                    crate::cohort_observe::udp_send_backpressure(payload);
                    return None;
                }
                if matches!(
                    err.raw_os_error(),
                    Some(
                        sys::EMSGSIZE
                            | sys::ENETUNREACH
                            | sys::EHOSTUNREACH
                            | sys::ENETDOWN
                            | sys::ECONNREFUSED
                            | sys::EHOSTDOWN
                            | sys::EAFNOSUPPORT
                    )
                ) {
                    #[cfg(feature = "research_cohort_observer")]
                    crate::cohort_observe::udp_send_tolerated(
                        payload,
                        err.raw_os_error().unwrap_or(0),
                    );
                    return Some(timestamp_ns);
                }
                panic!("UDP Socket error: {}", err);
            }
            let sent = n as usize;
            if sent != payload.len() {
                panic!("partial UDP send: {sent} of {}", payload.len());
            }
            #[cfg(feature = "research_cohort_observer")]
            crate::cohort_observe::udp_send_full(payload);
            Some(timestamp_ns)
        }
    }
    #[inline]
    pub fn udp_recv_with_congestion_and_dscp(
        udp_socket: SockHandle,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, Ipv6Addr, u16, bool, bool, Dscp, u64)> {
        let fd = udp_socket.0;
        let mut iov = sys::iovec {
            iov_base: buf.as_mut_ptr() as *mut sys::c_void,
            iov_len: buf.len(),
        };
        let mut addr_storage: sys::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut cbuf = [0u8; 128];
        let addr_len = std::mem::size_of::<sys::sockaddr_storage>() as sys::socklen_t;
        let mut msg = msghdr(
            (&mut addr_storage as *mut _) as *mut sys::c_void,
            addr_len,
            &mut iov,
            &mut cbuf,
        );
        let n = unsafe { sys::recvmsg(fd, &mut msg as *mut sys::msghdr, 0) };
        let timestamp_ns = monotonic_clock_ns();
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if (msg.msg_flags & sys::MSG_TRUNC) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UDP datagram truncated (buffer too small)",
            ));
        }
        let (src_ip6, src_port) = if (addr_storage.ss_family as i32) == sys::AF_INET {
            let sin: &sys::sockaddr_in =
                unsafe { &*(&addr_storage as *const _ as *const sys::sockaddr_in) };
            let ip4 = std::net::Ipv4Addr::from(sin.sin_addr.s_addr);
            let port = u16::from_be(sin.sin_port);
            (ip4.to_ipv6_mapped(), port)
        } else if (addr_storage.ss_family as i32) == sys::AF_INET6 {
            let sin6: &sys::sockaddr_in6 =
                unsafe { &*(&addr_storage as *const _ as *const sys::sockaddr_in6) };
            let ip6 = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            (ip6, port)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown sockaddr family",
            ));
        };
        let mut congested = false;
        let mut ecn_enabled = false;
        let mut dscp = Dscp::BestEffort;
        unsafe {
            let mut cmsg_ptr = sys::CMSG_FIRSTHDR(&msg as *const _);
            while !cmsg_ptr.is_null() {
                let cmsg = &*cmsg_ptr;
                let tclass_opt = if cmsg.cmsg_level == sys::IPPROTO_IP
                    && cmsg.cmsg_type == sys::IP_TOS
                {
                    Some(*(sys::CMSG_DATA(cmsg_ptr) as *const u8))
                } else if cmsg.cmsg_level == sys::IPPROTO_IPV6 && cmsg.cmsg_type == sys::IPV6_TCLASS
                {
                    Some(*(sys::CMSG_DATA(cmsg_ptr) as *const sys::c_int) as u8)
                } else {
                    None
                };
                if let Some(tclass) = tclass_opt {
                    (congested, ecn_enabled, dscp) = decode_tclass(tclass);
                    break;
                }
                cmsg_ptr = sys::CMSG_NXTHDR(&msg as *const _, cmsg_ptr);
            }
        }
        Ok((
            n as usize,
            src_ip6,
            src_port,
            congested,
            ecn_enabled,
            dscp,
            timestamp_ns,
        ))
    }
    #[inline]
    pub fn udp_probe_source_addresses(
        udp_socket: SockHandle,
    ) -> (Option<Ipv6Addr>, Option<Ipv6Addr>) {
        let ipv4 = probe_v4_source();
        let known_good_ipv6_address = udp_socket.1;
        if known_good_ipv6_address.is_some() {
            return (ipv4, known_good_ipv6_address);
        }
        (ipv4, probe_v6_source())
    }
}
#[cfg(not(target_os = "linux"))]
pub fn setup_and_bind_udp_socket_on(
    port: u16,
    bind_ip: Option<std::net::IpAddr>,
) -> Option<SockHandle> {
    if let Some(ip) = bind_ip {
        eprintln!("binding a specific address ({ip}) is only supported on Linux");
        return None;
    }
    setup_and_bind_udp_socket(port)
}
#[cfg(not(target_os = "linux"))]
pub fn udp_socket_kernel_rx_drops(_sock: SockHandle) -> Option<u64> {
    None
}
#[cfg(target_os = "windows")]
pub use windows::*;
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod windows {
    use super::*;
    use crate::platform::sys::*;
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::ptr::null_mut;
    const CMSG_IP_ECN: i32 = 50;
    const CMSG_IPV6_ECN: i32 = 50;
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct SockAddrInRaw {
        sin_family: u16,
        sin_port: u16,
        sin_addr: [u8; 4],
        sin_zero: [u8; 8],
    }
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct SockAddrIn6Raw {
        sin6_family: u16,
        sin6_port: u16,
        sin6_flowinfo: u32,
        sin6_addr: [u8; 16],
        sin6_scope_id: u32,
    }
    type WsaRecvMsgFn = unsafe extern "system" fn(
        s: SOCKET,
        lpMsg: *mut WSAMSG,
        lpdwNumberOfBytesRecvd: *mut u32,
        lpOverlapped: *mut OVERLAPPED,
        lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32;
    #[inline]
    fn wsa_last_error() -> std::io::Error {
        unsafe { std::io::Error::from_raw_os_error(WSAGetLastError()) }
    }
    #[inline]
    fn setsockopt_val<T: Copy>(sock: SOCKET, level: i32, optname: i32, val: T) -> i32 {
        unsafe {
            setsockopt(
                sock,
                level,
                optname,
                &val as *const T as *const u8,
                size_of::<T>() as i32,
            )
        }
    }
    #[inline]
    fn cmsg_align(n: usize) -> usize {
        let a = size_of::<usize>() - 1;
        (n + a) & !a
    }
    #[inline]
    fn cmsg_hdr_aligned_len() -> usize {
        cmsg_align(size_of::<CMSGHDR>())
    }
    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn QueryPerformanceCounter(counter: *mut i64) -> i32;
        fn QueryPerformanceFrequency(frequency: *mut i64) -> i32;
    }
    static mut QPC_INV_FREQ_SCALE: u128 = 0;
    #[inline]
    pub fn socket_setup() {
        unsafe {
            #[link(name = "winmm")]
            unsafe extern "system" {
                fn timeBeginPeriod(uPeriod: u32) -> u32;
                fn timeEndPeriod(uPeriod: u32) -> u32;
            }
            timeBeginPeriod(1);
            let mut data: WSADATA = zeroed();
            let ver: u16 = 0x0202;
            let rc = WSAStartup(ver, &mut data as *mut _);
            if rc != 0 {
                panic!(
                    "WSAStartup failed: {}",
                    std::io::Error::from_raw_os_error(rc)
                );
            }
        }
    }
    #[inline]
    pub fn monotonic_clock_setup() {
        unsafe {
            let mut freq: u128 = 0;
            QueryPerformanceFrequency(&mut freq as *mut _ as *mut i64);
            QPC_INV_FREQ_SCALE = ((1_000_000_000u128 << 64) / freq);
        }
    }
    #[inline]
    pub fn monotonic_clock_ns() -> u64 {
        unsafe {
            let mut counter: u128 = 0;
            QueryPerformanceCounter(&mut counter as *mut _ as *mut i64);
            ((counter * QPC_INV_FREQ_SCALE) >> 64) as u64
        }
    }
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct SockHandle(SOCKET, WsaRecvMsgFn);
    impl SockHandle {
        /// Caller must own the socket and never use any copy after this call.
        pub(crate) unsafe fn close(self) {
            unsafe {
                closesocket(self.0);
            }
        }
    }
    #[inline]
    fn get_wsarecvmsg(sock: SOCKET) -> WsaRecvMsgFn {
        unsafe {
            let mut bytes: u32 = 0;
            let mut recvmsg_opt: LPFN_WSARECVMSG = None;
            let mut guid = WSAID_WSARECVMSG;
            let rc = WSAIoctl(
                sock,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                &mut guid as *mut _ as *mut c_void,
                size_of::<GUID>() as u32,
                &mut recvmsg_opt as *mut _ as *mut c_void,
                size_of::<LPFN_WSARECVMSG>() as u32,
                &mut bytes as *mut u32,
                null_mut(),
                None,
            );
            if rc == SOCKET_ERROR {
                panic!(
                    "WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER/WSARecvMsg) failed: {}",
                    wsa_last_error()
                );
            }
            recvmsg_opt.expect("WSARecvMsg extension pointer was null")
        }
    }
    #[inline]
    pub fn setup_and_bind_udp_socket(port: u16) -> Option<SockHandle> {
        let sock = unsafe { socket(AF_INET6 as i32, SOCK_DGRAM as i32, IPPROTO_UDP as i32) };
        if sock == INVALID_SOCKET {
            eprintln!(
                "socket(AF_INET6, SOCK_DGRAM, UDP) failed: {}",
                wsa_last_error()
            );
            return None;
        }
        use std::os::windows::io::{FromRawSocket, IntoRawSocket, OwnedSocket};
        let owned = unsafe { OwnedSocket::from_raw_socket(sock as _) };
        unsafe {
            let mut nonblocking: u32 = 1;
            if ioctlsocket(sock, FIONBIO as i32, &mut nonblocking as *mut u32) == SOCKET_ERROR {
                eprintln!("ioctlsocket(FIONBIO) failed: {}", wsa_last_error());
                return None;
            }
        }
        if setsockopt_val(sock, IPPROTO_IPV6 as i32, IPV6_V6ONLY as i32, 0u32) == SOCKET_ERROR {
            eprintln!("setsockopt(IPV6_V6ONLY=0) failed: {}", wsa_last_error());
            return None;
        }
        let addr = SockAddrIn6Raw {
            sin6_family: AF_INET6 as u16,
            sin6_port: port.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: [0; 16],
            sin6_scope_id: 0,
        };
        let rc = unsafe {
            bind(
                sock,
                &addr as *const _ as *const SOCKADDR,
                size_of::<SockAddrIn6Raw>() as i32,
            )
        };
        if rc == SOCKET_ERROR {
            eprintln!("bind([::]:{}) failed: {}", port, wsa_last_error());
            return None;
        }
        let rc_v4_tos = setsockopt_val(sock, IPPROTO_IP as i32, IP_RECVTOS as i32, 1u32);
        if rc_v4_tos == SOCKET_ERROR {
            let e = unsafe { WSAGetLastError() };
            if e != WSAEINVAL {
                eprintln!(
                    "setsockopt(IP_RECVTOS=1) failed: {}",
                    std::io::Error::from_raw_os_error(e)
                );
                return None;
            }
        }
        if setsockopt_val(sock, IPPROTO_IPV6 as i32, IPV6_RECVTCLASS as i32, 1u32) == SOCKET_ERROR {
            eprintln!("setsockopt(IPV6_RECVTCLASS=1) failed: {}", wsa_last_error());
            return None;
        }
        for (level, option, name) in [
            (IPPROTO_IP, IP_MTU_DISCOVER, "IP_MTU_DISCOVER"),
            (IPPROTO_IPV6, IPV6_MTU_DISCOVER, "IPV6_MTU_DISCOVER"),
        ] {
            if setsockopt_val(sock, level, option, IP_PMTUDISC_PROBE as u32) == SOCKET_ERROR {
                eprintln!(
                    "setsockopt({name}=IP_PMTUDISC_PROBE) failed: {}",
                    wsa_last_error()
                );
                return None;
            }
        }
        let recvmsg = get_wsarecvmsg(sock);
        Some(SockHandle(owned.into_raw_socket() as SOCKET, recvmsg))
    }
    #[inline]
    pub fn udp_send_with_congestion_and_dscp(
        udp_socket: SockHandle,
        dst_ip6: Ipv6Addr,
        dst_port: u16,
        payload: &[u8],
        dscp: Dscp,
        ecn_signal: bool,
    ) -> Option<u64> {
        let sock = udp_socket.0;
        let tclass_i32 = tclass_byte(dscp, ecn_signal) as i32;
        for &(proto, opt) in &[
            (IPPROTO_IP as i32, IP_TOS as i32),
            (IPPROTO_IPV6 as i32, IPV6_TCLASS as i32),
        ] {
            if setsockopt_val(sock, proto, opt, tclass_i32) == SOCKET_ERROR {
                let e = unsafe { WSAGetLastError() };
                if e != WSAEINVAL && e != WSAENOPROTOOPT {
                    panic!("UDP Socket error: {}", std::io::Error::from_raw_os_error(e));
                }
            }
        }
        let dst = SockAddrIn6Raw {
            sin6_family: AF_INET6 as u16,
            sin6_port: dst_port.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: dst_ip6.octets(),
            sin6_scope_id: 0,
        };
        let timestamp_ns = monotonic_clock_ns();
        let n = unsafe {
            sendto(
                sock,
                payload.as_ptr() as *const u8,
                payload.len() as i32,
                0,
                &dst as *const _ as *const SOCKADDR,
                size_of::<SockAddrIn6Raw>() as i32,
            )
        };
        if n == SOCKET_ERROR {
            let e = unsafe { WSAGetLastError() };
            if e == WSAEWOULDBLOCK || e == WSAENOBUFS {
                return None;
            }
            if e == WSAEMSGSIZE
                || e == WSAENETUNREACH
                || e == WSAEHOSTUNREACH
                || e == WSAECONNREFUSED
                || e == WSAECONNRESET
                || e == WSAEINVAL
                || e == WSAEHOSTDOWN
            {
                return Some(timestamp_ns);
            }
            panic!("UDP Socket error: {}", std::io::Error::from_raw_os_error(e));
        }
        if n as usize != payload.len() {
            panic!("partial UDP send: {} of {}", n, payload.len());
        }
        Some(timestamp_ns)
    }
    #[inline]
    pub fn udp_recv_with_congestion_and_dscp(
        udp_socket: SockHandle,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, Ipv6Addr, u16, bool, bool, Dscp, u64)> {
        let sock = udp_socket.0;
        let mut data_wsa = WSABUF {
            len: buf.len() as u32,
            buf: buf.as_mut_ptr() as *mut u8,
        };
        let mut name_storage = [0u8; 128];
        let mut control = [0u8; 256];
        let mut msg = WSAMSG {
            name: name_storage.as_mut_ptr() as *mut SOCKADDR,
            namelen: name_storage.len() as i32,
            lpBuffers: &mut data_wsa as *mut WSABUF,
            dwBufferCount: 1,
            Control: WSABUF {
                len: control.len() as u32,
                buf: control.as_mut_ptr() as *mut u8,
            },
            dwFlags: 0,
        };
        let mut nbytes: u32 = 0;
        let rc = unsafe {
            (udp_socket.1)(
                sock,
                &mut msg as *mut WSAMSG,
                &mut nbytes as *mut u32,
                null_mut(),
                None,
            )
        };
        let timestamp_ns = monotonic_clock_ns();
        if rc == SOCKET_ERROR {
            let e = unsafe { WSAGetLastError() };
            if e == WSAEMSGSIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UDP datagram truncated (buffer too small)",
                ));
            }
            return Err(std::io::Error::from_raw_os_error(e));
        }
        if (msg.dwFlags & (MSG_TRUNC as u32)) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UDP datagram truncated (buffer too small)",
            ));
        }
        let family = u16::from_ne_bytes([name_storage[0], name_storage[1]]) as i32;
        let (src_ip6, src_port) = if family == AF_INET6 as i32 {
            if (msg.namelen as usize) < size_of::<SockAddrIn6Raw>() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "short sockaddr_in6",
                ));
            }
            let sin6 = unsafe { &*(name_storage.as_ptr() as *const SockAddrIn6Raw) };
            (Ipv6Addr::from(sin6.sin6_addr), u16::from_be(sin6.sin6_port))
        } else if family == AF_INET as i32 {
            if (msg.namelen as usize) < size_of::<SockAddrInRaw>() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "short sockaddr_in",
                ));
            }
            let sin = unsafe { &*(name_storage.as_ptr() as *const SockAddrInRaw) };
            let ip4 = std::net::Ipv4Addr::new(
                sin.sin_addr[0],
                sin.sin_addr[1],
                sin.sin_addr[2],
                sin.sin_addr[3],
            );
            (ip4.to_ipv6_mapped(), u16::from_be(sin.sin_port))
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown sockaddr family: {}", family),
            ));
        };
        let mut congested = false;
        let mut ecn_enabled = false;
        let mut dscp = Dscp::BestEffort;
        let ctl_len = msg.Control.len as usize;
        let hdr_aligned = cmsg_hdr_aligned_len();
        let mut off = 0usize;
        while off + size_of::<CMSGHDR>() <= ctl_len {
            let hdr = unsafe { &*(control.as_ptr().add(off) as *const CMSGHDR) };
            let cmsg_len = hdr.cmsg_len as usize;
            if cmsg_len < hdr_aligned {
                break;
            }
            if off + cmsg_len > ctl_len {
                break;
            }
            let data_off = off + hdr_aligned;
            let data_len = cmsg_len - hdr_aligned;
            let level = hdr.cmsg_level;
            let ty = hdr.cmsg_type;
            if (level == IPPROTO_IP as i32 && ty == IP_TOS as i32)
                || (level == IPPROTO_IPV6 as i32 && ty == IPV6_TCLASS as i32)
            {
                let tclass: u8 = if data_len >= 1 { control[data_off] } else { 0 };
                (congested, ecn_enabled, dscp) = decode_tclass(tclass);
                break;
            }
            if (level == IPPROTO_IP as i32 && ty == CMSG_IP_ECN)
                || (level == IPPROTO_IPV6 as i32 && ty == CMSG_IPV6_ECN)
            {
                if data_len >= size_of::<i32>() {
                    let ecn_val = unsafe { *(control.as_ptr().add(data_off) as *const i32) } as u8;
                    (congested, ecn_enabled, dscp) = decode_tclass(ecn_val & 0b11);
                    break;
                }
            }
            let step = cmsg_align(cmsg_len);
            if step == 0 {
                break;
            }
            off = off.saturating_add(step);
        }
        Ok((
            nbytes as usize,
            src_ip6,
            src_port,
            congested,
            ecn_enabled,
            dscp,
            timestamp_ns,
        ))
    }
    unsafe fn probe_local<T: Copy>(family: u16, dst: &T, ip: &str) -> Option<T> {
        unsafe {
            let probe_sock = socket(family as i32, SOCK_DGRAM as i32, IPPROTO_UDP as i32);
            if probe_sock == INVALID_SOCKET {
                let af = if family == AF_INET as u16 {
                    "AF_INET"
                } else {
                    "AF_INET6"
                };
                panic!("socket({af}) failed: {}", wsa_last_error());
            }
            let ret = if connect(
                probe_sock,
                dst as *const T as *const SOCKADDR,
                size_of::<T>() as i32,
            ) == SOCKET_ERROR
            {
                match WSAGetLastError() {
                    WSAENETUNREACH | WSAEHOSTUNREACH | WSAEADDRNOTAVAIL => None,
                    e => panic!(
                        "{ip} probe connect() failed: {}",
                        std::io::Error::from_raw_os_error(e)
                    ),
                }
            } else {
                let mut local: T = zeroed();
                let mut local_len = size_of::<T>() as i32;
                if getsockname(
                    probe_sock,
                    &mut local as *mut T as *mut SOCKADDR,
                    &mut local_len as *mut _,
                ) == SOCKET_ERROR
                {
                    panic!("{ip} probe getsockname() failed: {}", wsa_last_error());
                }
                Some(local)
            };
            if closesocket(probe_sock) == SOCKET_ERROR {
                panic!("closesocket() failed: {}", wsa_last_error());
            }
            ret
        }
    }
    #[inline]
    pub fn udp_probe_source_addresses(
        _udp_socket: SockHandle,
    ) -> (Option<Ipv6Addr>, Option<Ipv6Addr>) {
        let ipv4 = SockAddrInRaw {
            sin_family: AF_INET as u16,
            sin_port: 53u16.to_be(),
            sin_addr: PROBE_V4,
            sin_zero: [0; 8],
        };
        let ipv4 = unsafe { probe_local(AF_INET as u16, &ipv4, "ipv4") }.and_then(|local| {
            usable_probed_v4(std::net::Ipv4Addr::from(local.sin_addr).to_ipv6_mapped())
        });
        let ipv6 = SockAddrIn6Raw {
            sin6_family: AF_INET6 as u16,
            sin6_port: 53u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: PROBE_V6,
            sin6_scope_id: 0,
        };
        let ipv6 = unsafe { probe_local(AF_INET6 as u16, &ipv6, "ipv6") }
            .and_then(|local| usable_probed_v6(Ipv6Addr::from(local.sin6_addr)));
        (ipv4, ipv6)
    }
}
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos {
    use super::posix::*;
    use super::*;
    #[inline]
    pub fn socket_setup() {}
    #[inline]
    pub fn monotonic_clock_setup() {}
    #[inline]
    pub fn monotonic_clock_ns() -> u64 {
        unsafe {
            let time = sys::mach_absolute_time();
            let mut info = std::mem::zeroed::<sys::mach_timebase_info>();
            sys::mach_timebase_info(&mut info);
            time * info.numer as u64 / info.denom as u64
        }
    }
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct SockHandle(sys::c_int);
    impl SockHandle {
        /// Caller must own the socket and never use any copy after this call.
        pub(crate) unsafe fn close(self) {
            unsafe {
                sys::close(self.0);
            }
        }
    }
    #[inline]
    pub fn setup_and_bind_udp_socket(port: u16) -> Option<SockHandle> {
        let fd = unsafe { sys::socket(sys::AF_INET6, sys::SOCK_DGRAM, sys::IPPROTO_UDP) };
        if fd < 0 {
            return setup_failed(None, format_args!("socket() failed"));
        }
        if let Err(what) = set_nonblocking(fd) {
            return setup_failed(Some(fd), format_args!("{what}"));
        }
        if unsafe { setsockopt_int(fd, sys::IPPROTO_IPV6, sys::IPV6_V6ONLY, 0) } != 0 {
            return setup_failed(Some(fd), format_args!("Failed to disable IPV6_V6ONLY"));
        }
        let addr = sockaddr_in6([0; 16], port);
        if unsafe {
            sys::bind(
                fd,
                &addr as *const _ as *const sys::sockaddr,
                std::mem::size_of::<sys::sockaddr_in6>() as sys::socklen_t,
            )
        } != 0
        {
            return setup_failed(Some(fd), format_args!("bind([::]:{}) failed", port));
        }
        unsafe {
            if setsockopt_int(fd, sys::IPPROTO_IPV6, sys::IPV6_RECVTCLASS, 1) != 0 {
                return setup_failed(Some(fd), format_args!("Failed to enable IPV6_RECVTCLASS"));
            }
            if setsockopt_int(fd, sys::IPPROTO_IPV6, sys::IPV6_RECVPKTINFO, 1) != 0 {
                return setup_failed(Some(fd), format_args!("Failed to enable IPV6_RECVPKTINFO"));
            }
            if setsockopt_int(fd, sys::IPPROTO_IPV6, sys::IPV6_DONTFRAG, 1) != 0 {
                return setup_failed(
                    Some(fd),
                    format_args!("Failed to set IPV6_DONTFRAG (required PMTU probing policy)"),
                );
            }
        }
        Some(SockHandle(fd))
    }
    #[inline]
    pub fn udp_send_with_congestion_and_dscp(
        udp_socket: SockHandle,
        dst_ip6: Ipv6Addr,
        dst_port: u16,
        payload: &[u8],
        dscp: Dscp,
        ecn_signal: bool,
    ) -> Option<u64> {
        const SO_NET_SERVICE_TYPE: sys::c_int = 0x1116;
        const NET_SERVICE_TYPE_BE: sys::c_int = 0;
        const NET_SERVICE_TYPE_BK: sys::c_int = 1;
        const NET_SERVICE_TYPE_SIG: sys::c_int = 2;
        const NET_SERVICE_TYPE_VO: sys::c_int = 4;
        let fd = udp_socket.0;
        unsafe {
            let svc: sys::c_int = match dscp {
                Dscp::BestEffort => NET_SERVICE_TYPE_BK,
                Dscp::Af11 => NET_SERVICE_TYPE_BE,
                Dscp::Af21 => NET_SERVICE_TYPE_SIG,
                Dscp::Ef => NET_SERVICE_TYPE_VO,
            };
            if setsockopt_int(fd, sys::SOL_SOCKET, SO_NET_SERVICE_TYPE, svc) != 0 {
                panic!("UDP Socket error: {}", std::io::Error::last_os_error());
            }
        }
        let mut sin6 = sockaddr_in6(dst_ip6.octets(), dst_port);
        let mut iov = sys::iovec {
            iov_base: payload.as_ptr() as *mut sys::c_void,
            iov_len: payload.len(),
        };
        let cmsg_space =
            unsafe { sys::CMSG_SPACE(std::mem::size_of::<sys::c_int>() as _) } as usize;
        let mut cbuf = vec![0u8; cmsg_space];
        let sin6_len = std::mem::size_of::<sys::sockaddr_in6>() as sys::socklen_t;
        let mut msg = msghdr(
            (&mut sin6 as *mut sys::sockaddr_in6).cast::<sys::c_void>(),
            sin6_len,
            &mut iov,
            &mut cbuf,
        );
        let tclass_byte = tclass_byte(dscp, ecn_signal);
        unsafe {
            let cmsg = sys::CMSG_FIRSTHDR(&msg as *const _ as *mut _);
            if cmsg.is_null() {
                panic!("CMSG_FIRSTHDR returned null");
            }
            (*cmsg).cmsg_level = sys::IPPROTO_IPV6;
            (*cmsg).cmsg_type = sys::IPV6_TCLASS;
            (*cmsg).cmsg_len = sys::CMSG_LEN(std::mem::size_of::<sys::c_int>() as _) as _;
            let data = sys::CMSG_DATA(cmsg).cast::<sys::c_int>();
            *data = tclass_byte as sys::c_int;
            msg.msg_controllen = sys::CMSG_SPACE(std::mem::size_of::<sys::c_int>() as _) as _;
            let timestamp_ns = monotonic_clock_ns();
            let n = sys::sendmsg(fd, &msg as *const _ as *mut _, 0);
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err
                    .raw_os_error()
                    .is_some_and(|e| e == sys::EAGAIN || e == sys::EWOULDBLOCK || e == sys::ENOBUFS)
                {
                    return None;
                }
                if matches!(
                    err.raw_os_error(),
                    Some(
                        sys::EMSGSIZE
                            | sys::ENETUNREACH
                            | sys::EHOSTUNREACH
                            | sys::ENETDOWN
                            | sys::ECONNREFUSED
                            | sys::EHOSTDOWN
                    )
                ) {
                    return Some(timestamp_ns);
                }
                panic!("UDP Socket error: {}", err);
            }
            if n as usize != payload.len() {
                panic!("partial UDP send: {n} of {}", payload.len());
            }
            Some(timestamp_ns)
        }
    }
    #[inline]
    pub fn udp_recv_with_congestion_and_dscp(
        udp_socket: SockHandle,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, Ipv6Addr, u16, bool, bool, Dscp, u64)> {
        let fd = udp_socket.0;
        let mut iov = sys::iovec {
            iov_base: buf.as_mut_ptr() as *mut sys::c_void,
            iov_len: buf.len(),
        };
        let mut addr_storage: sys::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut cbuf = [0u8; 128];
        let addr_len = std::mem::size_of::<sys::sockaddr_storage>() as sys::socklen_t;
        let mut msg = msghdr(
            (&mut addr_storage as *mut _) as *mut sys::c_void,
            addr_len,
            &mut iov,
            &mut cbuf,
        );
        let n = unsafe { sys::recvmsg(fd, &mut msg as *mut sys::msghdr, 0) };
        let timestamp_ns = monotonic_clock_ns();
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if (msg.msg_flags & sys::MSG_TRUNC) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UDP datagram truncated (buffer too small)",
            ));
        }
        let (src_ip6, src_port) = if (addr_storage.ss_family as i32) == sys::AF_INET {
            let sin: &sys::sockaddr_in =
                unsafe { &*(&addr_storage as *const _ as *const sys::sockaddr_in) };
            let ip4 = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            (ip4.to_ipv6_mapped(), port)
        } else if (addr_storage.ss_family as i32) == sys::AF_INET6 {
            let sin6: &sys::sockaddr_in6 =
                unsafe { &*(&addr_storage as *const _ as *const sys::sockaddr_in6) };
            let ip6 = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            (ip6, port)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown sockaddr family",
            ));
        };
        let mut congested = false;
        let mut ecn_enabled = false;
        let mut dscp = Dscp::BestEffort;
        unsafe {
            let mut cmsg_ptr = sys::CMSG_FIRSTHDR(&msg as *const _ as *mut _);
            while !cmsg_ptr.is_null() {
                let cmsg = &*cmsg_ptr;
                if cmsg.cmsg_level == sys::IPPROTO_IPV6 && cmsg.cmsg_type == sys::IPV6_TCLASS {
                    let data = sys::CMSG_DATA(cmsg_ptr) as *const sys::c_int;
                    (congested, ecn_enabled, dscp) = decode_tclass((*data as u32 & 0xFF) as u8);
                    break;
                }
                cmsg_ptr = sys::CMSG_NXTHDR(&msg as *const _ as *mut _, cmsg_ptr);
            }
        }
        Ok((
            n as usize,
            src_ip6,
            src_port,
            congested,
            ecn_enabled,
            dscp,
            timestamp_ns,
        ))
    }
    #[inline]
    pub fn udp_probe_source_addresses(
        _udp_socket: SockHandle,
    ) -> (Option<Ipv6Addr>, Option<Ipv6Addr>) {
        (probe_v4_source(), probe_v6_source())
    }
}
