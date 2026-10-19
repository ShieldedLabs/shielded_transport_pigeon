#![allow(unused_unsafe)]
pub use std::net::Ipv6Addr;

/// Coalescing command wakeup, polled together with the UDP descriptor on Linux.
/// Owned separately from SockHandle so shutdown cannot race descriptor reuse.
#[derive(Debug)]
pub(crate) struct NetworkWake {
    #[cfg(target_os = "linux")]
    fd: libc::c_int,
    pending: std::sync::atomic::AtomicBool,
}
impl NetworkWake {
    pub(crate) fn new() -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
            if fd < 0 { return Err(std::io::Error::last_os_error()); }
            Ok(Self { fd, pending: std::sync::atomic::AtomicBool::new(false) })
        }
        #[cfg(not(target_os = "linux"))]
        { Ok(Self { pending: std::sync::atomic::AtomicBool::new(false) }) }
    }
    pub(crate) fn notify(&self) {
        // One unread eventfd edge is sufficient throughout an active protocol
        // burst. The owner clears only AFTER wait/drain and before rechecking
        // ring predicates; clearing before drain can lose a concurrent wake.
        if self.pending.swap(true, std::sync::atomic::Ordering::SeqCst) { return; }
        #[cfg(target_os = "linux")]
        unsafe {
            let one = 1u64;
            // EAGAIN means an unread notification is already pending.
            libc::write(self.fd, &one as *const u64 as *const libc::c_void, 8);
        }
    }
    pub(crate) fn wait(&self, socket: SockHandle, timeout: std::time::Duration) {
        #[cfg(target_os = "linux")]
        socket.wait_readable(self.fd, timeout);
        #[cfg(not(target_os = "linux"))]
        { let _ = socket; std::thread::park_timeout(timeout.min(std::time::Duration::from_micros(150))); }
        self.pending.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}
impl Drop for NetworkWake {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        unsafe { libc::close(self.fd); }
    }
}

pub const ASSUMED_UDP_PAYLOAD_SIZE_WITH_GUARANTEED_DELIVERY: usize = 1204;
pub const ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE: usize = 9216;

pub type PacketMemory = Box<[u8; ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE]>;

// Note(Sam): We will be reusing this memory across packets so we already do not have memory safety with regards to contents.
#[allow(unsafe_code)]
pub fn new_packet_memory() -> PacketMemory { unsafe { Box::<[u8; ASSUMED_BIGGEST_POSSIBLE_UDP_PAYLOAD_ON_EXISTING_HARDWARE]>::new_uninit().assume_init() } }

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Dscp {
    BestEffort = 0, // I do not care about this packet. Dropped first.
    Af11       = 10, // Important but low priority packet. Make more effort to deliver this.
    Af21       = 18, // Important and high priority packet. High delivery effort and lower latency. QUIC control frames use this.
    Ef         = 46, // Expedited Forwarding. VoIP. Low Latency or useless. Very heavily policed, must be low bandwidth.
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

/// Public resolvers used only to learn which local source address the OS routes from:
/// connecting a UDP socket sends nothing. 1.1.1.1 and 2606:4700:4700::1111, port 53.
const PROBE_V4: [u8; 4] = [1, 1, 1, 1];
const PROBE_V6: [u8; 16] = [
    0x26, 0x06, 0x47, 0x00,
    0x47, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x11, 0x11,
];

/// A probed (v4-mapped) IPv4 source is usable unless unspecified, loopback or link-local.
fn usable_probed_v4(addr: Ipv6Addr) -> Option<Ipv6Addr> {
    if addr.is_unspecified() || addr.is_loopback() || addr.is_unicast_link_local() { None } else { Some(addr) }
}

/// A probed IPv6 source must also not be multicast nor a bare /64 prefix (zero interface id).
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

/// Traffic-class/TOS byte to send: DSCP in the top six bits, then ECN CE (`ecn_signal`) or ECT(0).
#[inline]
fn tclass_byte(dscp: Dscp, ecn_signal: bool) -> u8 {
    ((dscp as u8) << 2) | if ecn_signal { 0b11 } else { 0b10 }
}

/// Received traffic-class/TOS byte to (congested = ECN CE, ecn_enabled = any ECN codepoint, DSCP).
#[inline]
fn decode_tclass(tclass: u8) -> (bool, bool, Dscp) {
    let ecn_bits = tclass & 0b11;
    (ecn_bits == 0b11, ecn_bits != 0, Dscp::from_u8(tclass >> 2))
}

/// libc helpers shared by the Linux and macOS backends.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
mod posix {
    use super::*;

    #[inline]
    pub(super) unsafe fn setsockopt_int(fd: libc::c_int, level: libc::c_int, opt: libc::c_int, val: libc::c_int) -> libc::c_int {
        unsafe { libc::setsockopt(fd, level, opt, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t) }
    }

    /// Socket setup failure: report `what` with the OS error, close `fd` if given, give up.
    pub(super) fn setup_failed<T>(fd: Option<libc::c_int>, what: std::fmt::Arguments) -> Option<T> {
        let err = std::io::Error::last_os_error();
        eprintln!("{what}: {err}");
        if let Some(fd) = fd {
            unsafe { libc::close(fd); }
        }
        None
    }

    /// Adds O_NONBLOCK; on failure names the fcntl call that failed (errno is left intact).
    pub(super) fn set_nonblocking(fd: libc::c_int) -> Result<(), &'static str> {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 {
                return Err("fcntl(F_GETFL) failed");
            }
            if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err("fcntl(F_SETFL) failed");
            }
        }
        Ok(())
    }

    /// One-iovec msghdr over caller-owned name, payload and control buffers.
    #[inline]
    pub(super) fn msghdr(name: *mut libc::c_void, namelen: libc::socklen_t, iov: &mut libc::iovec, control: &mut [u8]) -> libc::msghdr {
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = name;
        msg.msg_namelen = namelen;
        msg.msg_iov = iov as *mut libc::iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len() as _;
        msg
    }

    #[inline]
    pub(super) fn sockaddr_in6(octets: [u8; 16], port: u16) -> libc::sockaddr_in6 {
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = libc::AF_INET6 as _;
        addr.sin6_port = port.to_be();
        addr.sin6_addr = libc::in6_addr { s6_addr: octets };
        addr
    }

    /// Learns the local address the kernel routes `dst` from: socket, connect, getsockname, close.
    /// An unreachable network or missing address gives None; any other failure panics.
    unsafe fn probe_local<T>(family: libc::c_int, dst: &T, ip: &str) -> Option<T> {
        unsafe {
            let fd = libc::socket(family, libc::SOCK_DGRAM, libc::IPPROTO_UDP);
            if fd < 0 {
                panic!("socket() failed: {}", std::io::Error::last_os_error());
            }
            let len = std::mem::size_of::<T>() as libc::socklen_t;
            let ret = if libc::connect(fd, dst as *const T as *const libc::sockaddr, len) != 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ENETUNREACH) | Some(libc::EHOSTUNREACH) | Some(libc::EADDRNOTAVAIL) => None,
                    _ => panic!("{ip} probe connect() failed: {}", err),
                }
            } else {
                let mut local: T = std::mem::zeroed();
                let mut local_len = len;
                if libc::getsockname(fd, &mut local as *mut T as *mut libc::sockaddr, &mut local_len) != 0 {
                    panic!("{ip} probe getsockname() failed: {}", std::io::Error::last_os_error());
                }
                Some(local)
            };
            if libc::close(fd) != 0 {
                panic!("close() failed: {}", std::io::Error::last_os_error());
            }
            ret
        }
    }

    pub(super) fn probe_v4_source() -> Option<Ipv6Addr> {
        let mut dst: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        dst.sin_family = libc::AF_INET as _;
        dst.sin_port = 53u16.to_be();
        dst.sin_addr = libc::in_addr { s_addr: u32::from_be_bytes(PROBE_V4) };
        let local = unsafe { probe_local(libc::AF_INET, &dst, "ipv4") }?;
        usable_probed_v4(std::net::Ipv4Addr::from(u32::from_be(local.sin_addr.s_addr)).to_ipv6_mapped())
    }

    pub(super) fn probe_v6_source() -> Option<Ipv6Addr> {
        let dst = sockaddr_in6(PROBE_V6, 53);
        let local = unsafe { probe_local(libc::AF_INET6, &dst, "ipv6") }?;
        usable_probed_v6(Ipv6Addr::from(local.sin6_addr.s6_addr))
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux {
    use super::*;
    use super::posix::*;

    #[inline]
    pub fn socket_setup() {} // Linux
    #[inline]
    pub fn monotonic_clock_setup() {} // Linux

    #[inline]
    pub fn monotonic_clock_ns() -> u64 { // Linux
        unsafe {
            let mut ts: libc::timespec = std::mem::zeroed();
            if libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut ts) != 0 {
                panic!("clock_gettime() failed: {}", std::io::Error::last_os_error());
            }
            (ts.tv_sec as u64) * 1_000_000_000u64 + (ts.tv_nsec as u64)
        }
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct SockHandle(libc::c_int, Option<Ipv6Addr>); // Linux
    impl SockHandle {
        pub(crate) fn wait_readable(self, wake: libc::c_int, timeout: std::time::Duration) {
            let mut fds = [
                libc::pollfd { fd: self.0, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: wake, events: libc::POLLIN, revents: 0 },
            ];
            let ts = libc::timespec { tv_sec: timeout.as_secs() as _, tv_nsec: timeout.subsec_nanos() as _ };
            unsafe {
                // A signal interruption simply makes the owner recheck its predicates.
                libc::ppoll(fds.as_mut_ptr(), 2, &ts, std::ptr::null());
                if fds[1].revents & libc::POLLIN != 0 {
                    let mut count = 0u64;
                    libc::read(wake, &mut count as *mut u64 as *mut libc::c_void, 8);
                }
            }
        }
        /// Caller must own the socket and never use any copy after this call.
        pub(crate) unsafe fn close(self) { unsafe { libc::close(self.0); } }
    }

    /// Datagrams the kernel dropped on this socket (sk_drops: receive buffer full, etc.),
    /// cumulative. SO_MEMINFO (SK_MEMINFO_DROPS, Linux 4.6+), else the `drops` column of
    /// /proc/net/udp6 and /proc/net/udp for the socket's inode. None if neither works.
    pub fn udp_socket_kernel_rx_drops(sock: SockHandle) -> Option<u64> { // Linux
        const SO_MEMINFO: libc::c_int = 55;
        const SK_MEMINFO_VARS: usize = 9;
        let mut mi = [0u32; SK_MEMINFO_VARS];
        let mut len = std::mem::size_of_val(&mi) as libc::socklen_t;
        let r = unsafe { libc::getsockopt(sock.0, libc::SOL_SOCKET, SO_MEMINFO, mi.as_mut_ptr() as *mut libc::c_void, &mut len) };
        if r == 0 && len as usize >= SK_MEMINFO_VARS * 4 { return Some(mi[8] as u64); }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(sock.0, &mut st) } != 0 { return None; }
        let inode = st.st_ino.to_string();
        for f in ["/proc/net/udp6", "/proc/net/udp"] {
            let Ok(text) = std::fs::read_to_string(f) else { continue };
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                // sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ref pointer drops
                if cols.len() >= 13 && cols[9] == inode { return cols[12].parse().ok(); }
            }
        }
        None
    }

    /*
        This procedure is needed because on some vps' the ipv6 setup is wrong so that
        we end up using only the prefix address. Here is an example bad setup.
2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000
    inet6 2001:19f0:5c00:48f2::/64 scope global noprefixroute
       valid_lft forever preferred_lft forever
    inet6 2001:19f0:5c00:48f2:5400:5ff:fec9:bad/64 scope global noprefixroute
       valid_lft forever preferred_lft forever
    inet6 fe80::5400:5ff:fec9:bad/64 scope link noprefixroute
       valid_lft forever preferred_lft forever

       Versus the good a setup.
2: enp5s0f3u1u2u1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000
    inet6 2001:2043:9c85:9800:1f2e:cb54:e493:5106/64 scope global dynamic noprefixroute
       valid_lft 304sec preferred_lft 303sec
    inet6 fd85:130a:53bf:0:39ee:50cb:ce14:1b86/64 scope global noprefixroute
       valid_lft forever preferred_lft forever
    inet6 fe80::8e37:1f3e:4c28:db95/64 scope link noprefixroute
       valid_lft forever preferred_lft forever

       I think it is as simple as the 128 bit full address not being at the top of
       the list. So instead of requiring Linux config to be run like most bad software
       this function puts in the effort to work around this issue.
    */
    #[inline]
    fn first_usable_ipv6() -> Option<Ipv6Addr> {
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) != 0 {
                panic!("getifaddrs failed: {}", std::io::Error::last_os_error());
            }

            let mut index = 0;
            let mut first_is_loopback = false;

            let mut cur = ifap;
            while !cur.is_null() {
                let ifa = &*cur;

                if !ifa.ifa_addr.is_null()
                    && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET6
                {
                    index += 1;
                    let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);

                    if addr.is_loopback() {
                        cur = (*cur).ifa_next;
                        if index == 1 { first_is_loopback = true; }
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

                    libc::freeifaddrs(ifap);

                    if index == 2 && first_is_loopback {
                        return None;
                    }
                    eprintln!("[WARNING] This linux machine has incorrectly configured it's ipv6 addresses causing a bug when sending ipv6 packets. We will be overriding the sender ip field with '{}' in order to try and work around this issue.", addr);
                    return Some(addr);
                }

                cur = (*cur).ifa_next;
            }

            libc::freeifaddrs(ifap);
            None
        }
    }

    #[inline]
    pub fn setup_and_bind_udp_socket(port: u16) -> Option<SockHandle> { // Linux
        setup_and_bind_udp_socket_on(port, None)
    }

    /// `bind_ip: None` binds the dual-stack wildcard `[::]`. `Some(v4)` binds the v4-mapped
    /// `::ffff:a.b.c.d` on the same dual-stack socket (IPV6_V6ONLY stays 0), so the send and
    /// receive paths keep their v4-mapped Ipv6Addr form; `Some(v6)` binds that IPv6 address.
    pub fn setup_and_bind_udp_socket_on(port: u16, bind_ip: Option<std::net::IpAddr>) -> Option<SockHandle> { // Linux
        let bind_addr: Ipv6Addr = match bind_ip {
            None => Ipv6Addr::UNSPECIFIED,
            Some(std::net::IpAddr::V4(v4)) => v4.to_ipv6_mapped(),
            Some(std::net::IpAddr::V6(v6)) => v6,
        };
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
        if fd < 0 {
            return setup_failed(None, format_args!("socket() failed"));
        }

        unsafe {
            if setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1) != 0 {
                return setup_failed(Some(fd), format_args!("Failed to enable SO_REUSEADDR"));
            }
            if setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1) != 0 {
                return setup_failed(Some(fd), format_args!("Failed to enable SO_REUSEPORT"));
            }

            // The kernel default (~208 KiB, about 20 jumbo packets) overflows at high rates and
            // the excess is dropped before STP sees it. Ask for 16 MiB: the *FORCE variants
            // ignore net.core.{r,w}mem_max but need CAP_NET_ADMIN; otherwise the plain options
            // are capped at those sysctls. Failure is not fatal.
            let want: libc::c_int = 16 << 20;
            for (force, plain, name) in [(libc::SO_RCVBUFFORCE, libc::SO_RCVBUF, "SO_RCVBUF"), (libc::SO_SNDBUFFORCE, libc::SO_SNDBUF, "SO_SNDBUF")] {
                if setsockopt_int(fd, libc::SOL_SOCKET, force, want) != 0 && setsockopt_int(fd, libc::SOL_SOCKET, plain, want) != 0 {
                    eprintln!("Failed to set {name}: {}", std::io::Error::last_os_error());
                }
                let mut got: libc::c_int = 0;
                let mut got_len = std::mem::size_of_val(&got) as libc::socklen_t;
                libc::getsockopt(fd, libc::SOL_SOCKET, plain, &mut got as *mut _ as *mut libc::c_void, &mut got_len);
                if (got as i64) < want as i64 {
                    eprintln!("{name} is {got} bytes (wanted {want}); raise net.core.{}mem_max for more", if plain == libc::SO_RCVBUF { "r" } else { "w" });
                }
            }
        }

        if let Err(what) = set_nonblocking(fd) {
            return setup_failed(Some(fd), format_args!("{what}"));
        }
        if unsafe { setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 0) } != 0 {
            return setup_failed(Some(fd), format_args!("Failed to disable IPV6_V6ONLY"));
        }

        // A socket bound to one address sends from it; overriding the source would fail.
        let known_good_ipv6_address = if bind_ip.is_none() { first_usable_ipv6() } else { None };

        let addr = sockaddr_in6(bind_addr.octets(), port);
        if unsafe { libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t) } != 0 {
            return setup_failed(Some(fd), format_args!("bind([{}]:{}) failed", bind_addr, port));
        }

        // Receive metadata, and disable fragmentation: with PMTUDISC_DO the kernel returns an
        // error instead of fragmenting. None of these failures is fatal.
        unsafe {
            if setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_RECVTOS, 1) != 0 {
                eprintln!("Failed to Enable IPv4 TOS, error: {}", std::io::Error::last_os_error());
            }
            if setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, 1) != 0 {
                eprintln!("Failed to Enable IPv6 TOS, error: {}", std::io::Error::last_os_error());
            }
            if setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1) != 0 {
                eprintln!("Failed to Enable IPv6 PKTINFO, error: {}", std::io::Error::last_os_error());
            }
            if setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, libc::IPV6_PMTUDISC_DO) != 0 {
                eprintln!("Failed to set IPV6_MTU_DISCOVER: {}", std::io::Error::last_os_error());
            }
            if setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, libc::IP_PMTUDISC_DO) != 0 {
                eprintln!("Failed to set IP_MTU_DISCOVER: {}", std::io::Error::last_os_error());
            }
        }
        Some(SockHandle(fd, known_good_ipv6_address))
    }

    #[inline]
    pub fn udp_send_with_congestion_and_dscp( // Linux
        udp_socket: SockHandle,
        dst_ip6: Ipv6Addr,
        dst_port: u16,
        payload: &[u8],
        dscp: Dscp,
        ecn_signal: bool,
    ) -> Option<u64> {
        let fd = udp_socket.0;
        let known_good_ipv6_address = udp_socket.1;

        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };

        // Address v4 peers as a v4-mapped sockaddr_in6 on the dual-stack
        // socket, not as a bare sockaddr_in. Linux's udpv6_sendmsg bridges a
        // v4 destination on a v6 socket, but XNU rejects that with EINVAL and
        // the STP network thread dies; the v4-mapped form is accepted by both.
        let is_v4 = dst_ip6.to_ipv4_mapped().is_some();
        let sin6 = sockaddr_in6(dst_ip6.octets(), dst_port);
        let mut name_buf = vec![0u8; std::mem::size_of::<libc::sockaddr_in6>()];
        unsafe { std::ptr::copy_nonoverlapping(&sin6 as *const _ as *const u8, name_buf.as_mut_ptr(), name_buf.len()) };
        let name_len = name_buf.len() as libc::socklen_t;

        let mut cbuf = [0u8; 256];
        let mut msg = msghdr(name_buf.as_mut_ptr() as *mut libc::c_void, name_len, &mut iov, &mut cbuf);
        let tclass_byte = tclass_byte(dscp, ecn_signal);

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg as *const _ as *mut _);
            if cmsg.is_null() {
                panic!("CMSG_FIRSTHDR returned null");
            }

            let val: libc::c_int = tclass_byte as libc::c_int;

            (*cmsg).cmsg_level = if is_v4 { libc::IPPROTO_IP } else { libc::IPPROTO_IPV6 };
            (*cmsg).cmsg_type = if is_v4 { libc::IP_TOS } else { libc::IPV6_TCLASS };
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) as _;

            let data = libc::CMSG_DATA(cmsg) as *mut libc::c_int;
            *data = val;

            let mut used = libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) as usize;

            if !is_v4 {
                if let Some(ip6) = known_good_ipv6_address {
                    let cmsg2 = libc::CMSG_NXTHDR(&msg as *const _ as *mut _, cmsg);
                    if cmsg2.is_null() {
                        panic!("CMSG_NXTHDR returned null");
                    }

                    (*cmsg2).cmsg_level = libc::IPPROTO_IPV6;
                    (*cmsg2).cmsg_type = libc::IPV6_PKTINFO;
                    (*cmsg2).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as _) as _;

                    let pkt6 = libc::CMSG_DATA(cmsg2) as *mut libc::in6_pktinfo;
                    std::ptr::write_bytes(pkt6 as *mut u8, 0, std::mem::size_of::<libc::in6_pktinfo>());

                    (*pkt6).ipi6_ifindex = 0;
                    (*pkt6).ipi6_addr = libc::in6_addr { s6_addr: ip6.octets() };

                    used += libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as _) as usize;
                }
            }

            msg.msg_controllen = used as _;

            let timestamp_ns = monotonic_clock_ns();
            let n = libc::sendmsg(fd, &msg as *const _ as *mut _, 0);
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error().is_some_and(|e| e == libc::EAGAIN || e == libc::EWOULDBLOCK || e == libc::ENOBUFS) {
                    #[cfg(feature = "research_cohort_observer")]
                    crate::cohort_observe::udp_send_backpressure(payload);
                    return None; // Local backpressure: the caller retains this datagram.
                }
                if matches!(err.raw_os_error(), Some(libc::EMSGSIZE | libc::ENETUNREACH | libc::EHOSTUNREACH | libc::ENETDOWN | libc::ECONNREFUSED
                    | libc::EHOSTDOWN /* @todo(judah): ensure we actually want to tolerate this error  */
                    // A socket bound to an IPv4 address cannot send to an IPv6 peer: unreachable.
                    | libc::EAFNOSUPPORT)) {
                    #[cfg(feature = "research_cohort_observer")]
                    crate::cohort_observe::udp_send_tolerated(payload, err.raw_os_error().unwrap_or(0));
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
    pub fn udp_recv_with_congestion_and_dscp( // Linux
        udp_socket: SockHandle,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, Ipv6Addr, u16, bool, bool, Dscp, u64)> {
        let fd = udp_socket.0;

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut cbuf = [0u8; 128];
        let addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let mut msg = msghdr((&mut addr_storage as *mut _) as *mut libc::c_void, addr_len, &mut iov, &mut cbuf);

        // The cosmo/XNU path rejects datagrams that carry cmsg metadata
        // (recvmsg fails whenever a packet actually arrives, so every datagram
        // was dropped). Receive the packet without the control buffer there:
        // the TCLASS/ECN metadata is advisory and not load-bearing.
        #[cfg(cosmo)]
        {
            msg.msg_control = core::ptr::null_mut();
            msg.msg_controllen = 0;
        }

        let n = unsafe { libc::recvmsg(fd, &mut msg as *mut libc::msghdr, 0) };
        let timestamp_ns = monotonic_clock_ns();
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }

        if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UDP datagram truncated (buffer too small)",
            ));
        }

        let (src_ip6, src_port) = if (addr_storage.ss_family as i32) == libc::AF_INET {
            let sin: &libc::sockaddr_in =
                unsafe { &*(&addr_storage as *const _ as *const libc::sockaddr_in) };
            let ip4 = std::net::Ipv4Addr::from(sin.sin_addr.s_addr);
            let port = u16::from_be(sin.sin_port);
            (ip4.to_ipv6_mapped(), port)
        } else if (addr_storage.ss_family as i32) == libc::AF_INET6 {
            let sin6: &libc::sockaddr_in6 =
                unsafe { &*(&addr_storage as *const _ as *const libc::sockaddr_in6) };
            let ip6 = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            (ip6, port)
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown sockaddr family"));
        };

        let mut congested = false;
        let mut ecn_enabled = false;
        let mut dscp = Dscp::BestEffort;

        unsafe {
            let mut cmsg_ptr = libc::CMSG_FIRSTHDR(&msg as *const _);
            while !cmsg_ptr.is_null() {
                let cmsg = &*cmsg_ptr;

                let tclass_opt = if cmsg.cmsg_level == libc::IPPROTO_IP && cmsg.cmsg_type == libc::IP_TOS {
                    Some(*(libc::CMSG_DATA(cmsg_ptr) as *const u8))
                } else if cmsg.cmsg_level == libc::IPPROTO_IPV6 && cmsg.cmsg_type == libc::IPV6_TCLASS {
                    Some(*(libc::CMSG_DATA(cmsg_ptr) as *const libc::c_int) as u8)
                } else {
                    None
                };
                if let Some(tclass) = tclass_opt {
                    (congested, ecn_enabled, dscp) = decode_tclass(tclass);
                    break;
                }

                cmsg_ptr = libc::CMSG_NXTHDR(&msg as *const _, cmsg_ptr);
            }
        }

        Ok((n as usize, src_ip6, src_port, congested, ecn_enabled, dscp, timestamp_ns))
    }

    #[inline]
    pub fn udp_probe_source_addresses( // Linux
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

/// Binding one specific address is implemented on Linux only; elsewhere `Some` fails.
#[cfg(not(target_os = "linux"))]
pub fn setup_and_bind_udp_socket_on(port: u16, bind_ip: Option<std::net::IpAddr>) -> Option<SockHandle> {
    if let Some(ip) = bind_ip {
        eprintln!("binding a specific address ({ip}) is only supported on Linux");
        return None;
    }
    setup_and_bind_udp_socket(port)
}

/// Kernel receive drops are only reported on Linux.
#[cfg(not(target_os = "linux"))]
pub fn udp_socket_kernel_rx_drops(_sock: SockHandle) -> Option<u64> { None }

#[cfg(target_os = "windows")]
pub use windows::*;
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
mod windows {
    use super::*;
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::ptr::{null_mut};

    use windows_sys::Win32::Networking::WinSock::*;
    use windows_sys::Win32::System::IO::OVERLAPPED;

    // Windows docs list IP_ECN / IPV6_ECN cmsg_type as 50 decimal.
    const CMSG_IP_ECN: i32 = 50;
    const CMSG_IPV6_ECN: i32 = 50;

    // Raw sockaddr layouts, avoids wrestling with Windows union field names.
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct SockAddrInRaw {
        sin_family: u16,
        sin_port: u16,
        sin_addr: [u8; 4], // network byte order bytes
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

    /// setsockopt with a 4-byte `i32` or `u32` option value.
    #[inline]
    fn setsockopt_val<T: Copy>(sock: SOCKET, level: i32, optname: i32, val: T) -> i32 {
        unsafe { setsockopt(sock, level, optname, &val as *const T as *const u8, size_of::<T>() as i32) }
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
        fn QueryPerformanceCounter(counter:     *mut i64) -> i32;
        fn QueryPerformanceFrequency(frequency: *mut i64) -> i32;
    }

    static mut QPC_INV_FREQ_SCALE: u128 = 0;

    #[inline]
    pub fn socket_setup() { // Windows
        unsafe {
            #[link(name = "winmm")]
            unsafe extern "system" {
                fn timeBeginPeriod(uPeriod: u32) -> u32;
                fn timeEndPeriod(uPeriod: u32) -> u32;
            }
            timeBeginPeriod(1);

            let mut data: WSADATA = zeroed();
            // MAKEWORD(2,2)
            let ver: u16 = 0x0202;
            let rc = WSAStartup(ver, &mut data as *mut _);
            if rc != 0 {
                panic!("WSAStartup failed: {}", std::io::Error::from_raw_os_error(rc));
            }
        }
    }

    #[inline]
    pub fn monotonic_clock_setup() { // Windows
        unsafe {
            let mut freq: u128 = 0; QueryPerformanceFrequency(&mut freq as *mut _ as *mut i64);
            QPC_INV_FREQ_SCALE = ((1_000_000_000u128 << 64) / freq);
        }
    }

    #[inline]
    pub fn monotonic_clock_ns() -> u64 { // Windows
        unsafe {
            let mut counter: u128 = 0; QueryPerformanceCounter(&mut counter as *mut _ as *mut i64);
            ((counter * QPC_INV_FREQ_SCALE) >> 64) as u64
        }
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct SockHandle(SOCKET, WsaRecvMsgFn); // Windows
    impl SockHandle {
        /// Caller must own the socket and never use any copy after this call.
        pub(crate) unsafe fn close(self) { unsafe { closesocket(self.0); } }
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
                size_of::<windows_sys::core::GUID>() as u32,
                &mut recvmsg_opt as *mut _ as *mut c_void,
                size_of::<LPFN_WSARECVMSG>() as u32,
                &mut bytes as *mut u32,
                null_mut(),
                None,
            );
            if rc == SOCKET_ERROR {
                panic!("WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER/WSARecvMsg) failed: {}", wsa_last_error());
            }

            recvmsg_opt.expect("WSARecvMsg extension pointer was null")
        }
    }

    #[inline]
    pub fn setup_and_bind_udp_socket(port: u16) -> Option<SockHandle> { // Windows
        let sock = unsafe { socket(AF_INET6 as i32, SOCK_DGRAM as i32, IPPROTO_UDP as i32) };
        if sock == INVALID_SOCKET {
            eprintln!("socket(AF_INET6, SOCK_DGRAM, UDP) failed: {}", wsa_last_error());
            return None;
        }

        // non-blocking
        unsafe {
            let mut nonblocking: u32 = 1;
            if ioctlsocket(sock, FIONBIO as i32, &mut nonblocking as *mut u32) == SOCKET_ERROR {
                eprintln!("ioctlsocket(FIONBIO) failed: {}", wsa_last_error());
                return None;
            }
        }

        // dual-stack: IPV6_V6ONLY = 0
        if setsockopt_val(sock, IPPROTO_IPV6 as i32, IPV6_V6ONLY as i32, 0u32) == SOCKET_ERROR {
            eprintln!("setsockopt(IPV6_V6ONLY=0) failed: {}", wsa_last_error());
            return None;
        }

        // Bind [::]:port
        let addr = SockAddrIn6Raw {
            sin6_family: AF_INET6 as u16,
            sin6_port: port.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: [0; 16], // in6addr_any
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

        // Receive ancillary metadata:
        // - IPv4 TOS on v4 packets (dual-stack)
        // - IPv6 traffic-class/ECN metadata on v6 packets
        //
        // On some systems, IPPROTO_IP setsockopt on a dual-stack socket can fail with WSAEINVAL
        // if IPv4 is disabled. We ignore only that case.
        let rc_v4_tos = setsockopt_val(sock, IPPROTO_IP as i32, IP_RECVTOS as i32, 1u32);
        if rc_v4_tos == SOCKET_ERROR {
            let e = unsafe { WSAGetLastError() };
            if e != WSAEINVAL {
                eprintln!("setsockopt(IP_RECVTOS=1) failed: {}", std::io::Error::from_raw_os_error(e));
                return None;
            }
        }

        if setsockopt_val(sock, IPPROTO_IPV6 as i32, IPV6_RECVTCLASS as i32, 1u32) == SOCKET_ERROR {
            eprintln!("setsockopt(IPV6_RECVTCLASS=1) failed: {}", wsa_last_error());
            return None;
        }

        // Disable fragmentation
        if setsockopt_val(sock, IPPROTO_IPV6 as i32, IPV6_DONTFRAG as i32, 1u32) == SOCKET_ERROR {
            eprintln!("setsockopt(IPV6_DONTFRAG=1) failed: {}", wsa_last_error());
            return None;
        }
        if setsockopt_val(sock, IPPROTO_IP as i32, IP_DONTFRAGMENT as i32, 1u32) == SOCKET_ERROR {
            eprintln!("setsockopt(IP_DONTFRAGMENT=1) failed: {}", wsa_last_error());
            return None;
        }

        let recvmsg = get_wsarecvmsg(sock);

        Some(SockHandle(sock, recvmsg))
    }

    #[inline]
    pub fn udp_send_with_congestion_and_dscp( // Windows
        udp_socket: SockHandle,
        dst_ip6: Ipv6Addr,
        dst_port: u16,
        payload: &[u8],
        dscp: Dscp,
        ecn_signal: bool,
    ) -> Option<u64> {
        let sock = udp_socket.0;

        let tclass_i32 = tclass_byte(dscp, ecn_signal) as i32;

        // Best-effort per-send TOS/TCLASS tagging. The socket is AF_INET6
        // dual-stack bound to [::], so try both IP_TOS and IPV6_TCLASS.
        // One or both may fail depending on Windows version and whether IPv4
        // is enabled — absorb WSAEINVAL/WSAENOPROTOOPT and send untagged.
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

        // Dual-stack sockets want AF_INET6 sockaddr, IPv4 must be IPv4-mapped IPv6.
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
            if e == WSAEWOULDBLOCK || e == WSAENOBUFS { return None; }
            if e == WSAEMSGSIZE || e == WSAENETUNREACH
                || e == WSAEHOSTUNREACH || e == WSAECONNREFUSED || e == WSAECONNRESET
                || e == WSAEINVAL || e == WSAEHOSTDOWN /* @todo(judah): ensure we actually want to tolerate this error */ {
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
    pub fn udp_recv_with_congestion_and_dscp( // Windows
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

        // Parse peer address.
        let family = u16::from_ne_bytes([name_storage[0], name_storage[1]]) as i32;

        let (src_ip6, src_port) = if family == AF_INET6 as i32 {
            if (msg.namelen as usize) < size_of::<SockAddrIn6Raw>() {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short sockaddr_in6"));
            }
            let sin6 = unsafe { &*(name_storage.as_ptr() as *const SockAddrIn6Raw) };
            (Ipv6Addr::from(sin6.sin6_addr), u16::from_be(sin6.sin6_port))
        } else if family == AF_INET as i32 {
            if (msg.namelen as usize) < size_of::<SockAddrInRaw>() {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short sockaddr_in"));
            }
            let sin = unsafe { &*(name_storage.as_ptr() as *const SockAddrInRaw) };
            let ip4 = std::net::Ipv4Addr::new(sin.sin_addr[0], sin.sin_addr[1], sin.sin_addr[2], sin.sin_addr[3]);
            (ip4.to_ipv6_mapped(), u16::from_be(sin.sin_port))
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown sockaddr family: {}", family),
            ));
        };

        // Defaults if no ancillary info.
        let mut congested = false;
        let mut ecn_enabled = false;
        let mut dscp = Dscp::BestEffort;

        // Parse CMSGHDR chain manually.
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

            // Full TOS/TCLASS case (provider-dependent).
            if (level == IPPROTO_IP as i32 && ty == IP_TOS as i32)
                || (level == IPPROTO_IPV6 as i32 && ty == IPV6_TCLASS as i32)
            {
                // Some providers use 1 byte, some use int.
                let tclass: u8 = if data_len >= 1 {
                    control[data_off]
                } else {
                    0
                };

                (congested, ecn_enabled, dscp) = decode_tclass(tclass);
                break;
            }

            // Windows ECN-only cmsg case (documented for WSASetRecvIPEcn / IPV6_RECVTCLASS).
            if (level == IPPROTO_IP as i32 && ty == CMSG_IP_ECN)
                || (level == IPPROTO_IPV6 as i32 && ty == CMSG_IPV6_ECN)
            {
                if data_len >= size_of::<i32>() {
                    let ecn_val = unsafe {
                        *(control.as_ptr().add(data_off) as *const i32)
                    } as u8;

                    // DSCP is not available from ECN-only cmsg: zero DSCP bits decode as BestEffort.
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

        Ok((nbytes as usize, src_ip6, src_port, congested, ecn_enabled, dscp, timestamp_ns))
    }

    /// Learns the local address Windows routes `dst` from: socket, connect, getsockname, close.
    /// An unreachable network or missing address gives None; any other failure panics.
    unsafe fn probe_local<T: Copy>(family: u16, dst: &T, ip: &str) -> Option<T> {
        unsafe {
            let probe_sock = socket(family as i32, SOCK_DGRAM as i32, IPPROTO_UDP as i32);
            if probe_sock == INVALID_SOCKET {
                let af = if family == AF_INET as u16 { "AF_INET" } else { "AF_INET6" };
                panic!("socket({af}) failed: {}", wsa_last_error());
            }
            let ret = if connect(probe_sock, dst as *const T as *const SOCKADDR, size_of::<T>() as i32) == SOCKET_ERROR {
                match WSAGetLastError() {
                    WSAENETUNREACH | WSAEHOSTUNREACH | WSAEADDRNOTAVAIL => None,
                    e => panic!("{ip} probe connect() failed: {}", std::io::Error::from_raw_os_error(e)),
                }
            } else {
                let mut local: T = zeroed();
                let mut local_len = size_of::<T>() as i32;
                if getsockname(probe_sock, &mut local as *mut T as *mut SOCKADDR, &mut local_len as *mut _) == SOCKET_ERROR {
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
    pub fn udp_probe_source_addresses( // Windows
        _udp_socket: SockHandle,
    ) -> (Option<Ipv6Addr>, Option<Ipv6Addr>) {
        let ipv4 = SockAddrInRaw { sin_family: AF_INET as u16, sin_port: 53u16.to_be(), sin_addr: PROBE_V4, sin_zero: [0; 8] };
        let ipv4 = unsafe { probe_local(AF_INET as u16, &ipv4, "ipv4") }
            .and_then(|local| usable_probed_v4(std::net::Ipv4Addr::from(local.sin_addr).to_ipv6_mapped()));
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
    use super::*;
    use super::posix::*;

    #[inline]
    pub fn socket_setup() {} // Mac
    #[inline]
    pub fn monotonic_clock_setup() {} // Mac

    #[inline]
    pub fn monotonic_clock_ns() -> u64 { // Mac
        unsafe {
            let time = libc::mach_absolute_time();

            let mut info = std::mem::zeroed::<libc::mach_timebase_info>();
            libc::mach_timebase_info(&mut info);

            time * info.numer as u64 / info.denom as u64
        }
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct SockHandle(libc::c_int); // Mac
    impl SockHandle {
        /// Caller must own the socket and never use any copy after this call.
        pub(crate) unsafe fn close(self) { unsafe { libc::close(self.0); } }
    }

    #[inline]
    pub fn setup_and_bind_udp_socket(port: u16) -> Option<SockHandle> { // Mac
        // Create an IPv6 UDP socket (we'll run it dual-stack via IPV6_V6ONLY=0).
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
        if fd < 0 {
            return setup_failed(None, format_args!("socket() failed"));
        }
        if let Err(what) = set_nonblocking(fd) {
            return setup_failed(None, format_args!("{what}"));
        }

        // Dual-stack: allow IPv4-mapped IPv6 addresses (::ffff:a.b.c.d).
        if unsafe { setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 0) } != 0 {
            return setup_failed(None, format_args!("Failed to disable IPV6_V6ONLY"));
        }

        // Bind [::]:port
        let addr = sockaddr_in6([0; 16], port);
        if unsafe { libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t) } != 0 {
            return setup_failed(None, format_args!("bind([::]:{}) failed", port));
        }

        unsafe {
            // macOS: receive IPv6 Traffic Class as a cmsg (type IPV6_TCLASS).
            // On a dual-stack IPv6 socket this is the supported way to read DSCP/ECN.
            if setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS, 1) != 0 {
                return setup_failed(None, format_args!("Failed to enable IPV6_RECVTCLASS"));
            }
            // Receive IPV6_PKTINFO cmsg (dst addr + ifindex) on recvmsg (and usable for sendmsg).
            if setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1) != 0 {
                return setup_failed(None, format_args!("Failed to enable IPV6_RECVPKTINFO"));
            }
            // Disable fragmentation
            if setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1) != 0 {
                return setup_failed(None, format_args!("Failed to set IPV6_DONTFRAG"));
            }
            // Best-effort: on a dual-stack AF_INET6 socket, macOS rejects the
            // IPv4-level IP_DONTFRAG with EINVAL (the IPV6_DONTFRAG above already
            // covers fragmentation control). Don't treat this as fatal.
            if setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_DONTFRAG, 1) != 0 {
                eprintln!("Failed to set IP_DONTFRAG (non-fatal): {}", std::io::Error::last_os_error());
            }
        }

        Some(SockHandle(fd))
    }

    /// SEND one UDP packet to (dst_ip6, dst_port) on a dual-stack IPv6 socket.
    ///
    /// - Sets SO_NET_SERVICE_TYPE based on DSCP (inlined mapping).
    /// - Sets per-packet IPV6_TCLASS (DSCP + ECN).
    /// - Works for IPv6 and IPv4-mapped IPv6 destinations.
    /// Return value is a nanosecond timestamp of the send.
    #[inline]
    pub fn udp_send_with_congestion_and_dscp( // Mac
        udp_socket: SockHandle,
        dst_ip6: Ipv6Addr,
        dst_port: u16,
        payload: &[u8],
        dscp: Dscp,
        ecn_signal: bool,
    ) -> Option<u64> {
        // Darwin constants (not always exposed by Rust libc)
        const SO_NET_SERVICE_TYPE: libc::c_int = 0x1116;

        const NET_SERVICE_TYPE_BE: libc::c_int = 0;
        const NET_SERVICE_TYPE_BK: libc::c_int = 1;
        const NET_SERVICE_TYPE_SIG: libc::c_int = 2;
        const NET_SERVICE_TYPE_VO: libc::c_int = 4;

        let fd = udp_socket.0;

        // 1) Set SO_NET_SERVICE_TYPE (per-socket QoS intent) — inlined DSCP mapping.
        unsafe {
            let svc: libc::c_int = match dscp {
                Dscp::BestEffort => NET_SERVICE_TYPE_BK,
                Dscp::Af11       => NET_SERVICE_TYPE_BE,
                Dscp::Af21       => NET_SERVICE_TYPE_SIG,
                Dscp::Ef         => NET_SERVICE_TYPE_VO,
            };

            if setsockopt_int(fd, libc::SOL_SOCKET, SO_NET_SERVICE_TYPE, svc) != 0 {
                panic!("UDP Socket error: {}", std::io::Error::last_os_error());
            }
        }

        // 2) Destination: always sockaddr_in6 (works for IPv6 and IPv4-mapped IPv6).
        let mut sin6 = sockaddr_in6(dst_ip6.octets(), dst_port);

        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };

        // 3) Control buffer for one IPV6_TCLASS cmsg carrying an int.
        let cmsg_space =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) } as usize;
        let mut cbuf = vec![0u8; cmsg_space];

        let sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let mut msg = msghdr((&mut sin6 as *mut libc::sockaddr_in6).cast::<libc::c_void>(), sin6_len, &mut iov, &mut cbuf);
        let tclass_byte = tclass_byte(dscp, ecn_signal);

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg as *const _ as *mut _);
            if cmsg.is_null() {
                panic!("CMSG_FIRSTHDR returned null");
            }

            (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
            (*cmsg).cmsg_type = libc::IPV6_TCLASS;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as _) as _;

            let data = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
            *data = tclass_byte as libc::c_int;

            msg.msg_controllen =
                libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as _) as _;

            let timestamp_ns = monotonic_clock_ns();
            let n = libc::sendmsg(fd, &msg as *const _ as *mut _, 0);
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error().is_some_and(|e| e == libc::EAGAIN || e == libc::EWOULDBLOCK || e == libc::ENOBUFS) {
                    return None; // Local backpressure: the caller retains this datagram.
                }
                if matches!(err.raw_os_error(), Some(libc::EMSGSIZE | libc::ENETUNREACH | libc::EHOSTUNREACH | libc::ENETDOWN | libc::ECONNREFUSED
                    | libc::EHOSTDOWN /* @todo(judah): ensure we actually want to tolerate this error */)) {
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

    /// RECV one UDP packet, returning:
    /// (len, src_ip6, src_port, congested, ecn_enabled, dscp, timestamp_ns)
    ///
    /// - If the peer is IPv4, it is returned as an IPv4-mapped IPv6 address (::ffff:a.b.c.d).
    /// - congested=true iff ECN == CE (0b11).
    /// - If no TCLASS cmsg was provided by the kernel, returns congested=false, ecn_enabled=false,
    ///   and dscp=BestEffort.
    #[inline]
    pub fn udp_recv_with_congestion_and_dscp( // Mac
        udp_socket: SockHandle,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, Ipv6Addr, u16, bool, bool, Dscp, u64)> {
        let fd = udp_socket.0;

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

        // Control buffer: room for at least one IPV6_TCLASS (int) cmsg (plus some slack).
        let mut cbuf = [0u8; 128];
        let addr_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let mut msg = msghdr((&mut addr_storage as *mut _) as *mut libc::c_void, addr_len, &mut iov, &mut cbuf);

        let n = unsafe { libc::recvmsg(fd, &mut msg as *mut libc::msghdr, 0) };
        let timestamp_ns = monotonic_clock_ns();

        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }

        if (msg.msg_flags & libc::MSG_TRUNC) != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UDP datagram truncated (buffer too small)",
            ));
        }

        // Peer address -> always return IPv6 (IPv4 becomes v4-mapped IPv6)
        let (src_ip6, src_port) = if (addr_storage.ss_family as i32) == libc::AF_INET {
            let sin: &libc::sockaddr_in =
                unsafe { &*(&addr_storage as *const _ as *const libc::sockaddr_in) };
            // s_addr is in network byte order; from(u32) expects big-endian representation.
            let ip4 = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            (ip4.to_ipv6_mapped(), port)
        } else if (addr_storage.ss_family as i32) == libc::AF_INET6 {
            let sin6: &libc::sockaddr_in6 =
                unsafe { &*(&addr_storage as *const _ as *const libc::sockaddr_in6) };
            let ip6 = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            (ip6, port)
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unknown sockaddr family",
            ));
        };

        // Defaults if no cmsg
        let mut congested = false;
        let mut ecn_enabled = false;
        let mut dscp = Dscp::BestEffort;

        // macOS: Traffic Class arrives as IPV6_TCLASS with an `int` payload when IPV6_RECVTCLASS is enabled.
        unsafe {
            let mut cmsg_ptr = libc::CMSG_FIRSTHDR(&msg as *const _ as *mut _);
            while !cmsg_ptr.is_null() {
                let cmsg = &*cmsg_ptr;

                if cmsg.cmsg_level == libc::IPPROTO_IPV6 && cmsg.cmsg_type == libc::IPV6_TCLASS {
                    let data = libc::CMSG_DATA(cmsg_ptr) as *const libc::c_int;
                    (congested, ecn_enabled, dscp) = decode_tclass((*data as u32 & 0xFF) as u8);
                    break;
                }

                cmsg_ptr = libc::CMSG_NXTHDR(&msg as *const _ as *mut _, cmsg_ptr);
            }
        }

        Ok((n as usize, src_ip6, src_port, congested, ecn_enabled, dscp, timestamp_ns))
    }

    #[inline]
    pub fn udp_probe_source_addresses( // Mac
        _udp_socket: SockHandle,
    ) -> (Option<Ipv6Addr>, Option<Ipv6Addr>) {
        (probe_v4_source(), probe_v6_source())
    }

}

//#[test]
fn test_network_switch() {
    let socket = setup_and_bind_udp_socket(0).unwrap();
    loop {
        std::thread::yield_now();
        let time_before = monotonic_clock_ns();
        let (ipv4, ipv6) = udp_probe_source_addresses(socket);
        let time_after = monotonic_clock_ns();
        println!("{:?} {:?} took {} ns", ipv4, ipv6, time_after - time_before);
        /*  RESULTS
            Sams Laptop running manjaro: 13-18 us
            Sams m4 super mac: 100 us ish
        */
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn tclass_byte_round_trips_dscp_and_ecn() {
        for dscp in [Dscp::BestEffort, Dscp::Af11, Dscp::Af21, Dscp::Ef] {
            assert_eq!(tclass_byte(dscp, true), ((dscp as u8) << 2) | 0b11);
            assert_eq!(tclass_byte(dscp, false), ((dscp as u8) << 2) | 0b10);
            assert_eq!(decode_tclass(tclass_byte(dscp, true)), (true, true, dscp));
            assert_eq!(decode_tclass(tclass_byte(dscp, false)), (false, true, dscp));
        }
        assert_eq!(decode_tclass(0), (false, false, Dscp::BestEffort));
        assert_eq!(decode_tclass(0b01), (false, true, Dscp::BestEffort));
        assert_eq!(decode_tclass((7 << 2) | 0b11), (true, true, Dscp::BestEffort));
    }

    #[test]
    fn probed_source_filters() {
        let v4 = |a: [u8; 4]| std::net::Ipv4Addr::from(a).to_ipv6_mapped();
        assert_eq!(usable_probed_v4(v4([192, 168, 1, 7])), Some(v4([192, 168, 1, 7])));
        assert_eq!(usable_probed_v4(Ipv6Addr::UNSPECIFIED), None);
        assert_eq!(usable_probed_v4(Ipv6Addr::LOCALHOST), None);
        let ok: Ipv6Addr = "2001:db8::1:2".parse().unwrap();
        assert_eq!(usable_probed_v6(ok), Some(ok));
        for bad in ["::", "::1", "ff02::1", "fe80::1", "2001:db8:1:2::"] {
            assert_eq!(usable_probed_v6(bad.parse().unwrap()), None, "{bad}");
        }
        assert_eq!(Ipv6Addr::from(PROBE_V6), "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap());
        let (ipv4, ipv6) = udp_probe_source_addresses(setup_and_bind_udp_socket(0).unwrap());
        assert!(ipv4.is_none_or(|a| a.to_ipv4_mapped().is_some()));
        assert!(ipv6.is_none_or(|a| usable_probed_v6(a).is_some()));
    }

    #[test]
    fn sockaddr_and_msghdr_builders() {
        let ip: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let a = posix::sockaddr_in6(ip.octets(), 4433);
        assert_eq!((a.sin6_family as i32, u16::from_be(a.sin6_port), a.sin6_flowinfo, a.sin6_scope_id), (libc::AF_INET6, 4433, 0, 0));
        assert_eq!(Ipv6Addr::from(a.sin6_addr.s6_addr), ip);
        let (mut payload, mut name, mut control) = ([0u8; 3], [0u8; 28], [0u8; 64]);
        let mut iov = libc::iovec { iov_base: payload.as_mut_ptr() as *mut libc::c_void, iov_len: 3 };
        let msg = posix::msghdr(name.as_mut_ptr() as *mut libc::c_void, 28, &mut iov, &mut control);
        assert_eq!((msg.msg_name, msg.msg_namelen, msg.msg_iovlen, msg.msg_flags), (name.as_mut_ptr() as *mut libc::c_void, 28, 1, 0));
        assert_eq!((msg.msg_iov, msg.msg_control, msg.msg_controllen), (&mut iov as *mut libc::iovec, control.as_mut_ptr() as *mut libc::c_void, 64));
    }

    #[test]
    fn loopback_round_trip_carries_address_dscp_and_ecn() {
        let port = std::net::UdpSocket::bind("[::]:0").unwrap().local_addr().unwrap().port();
        let rx = setup_and_bind_udp_socket(port).unwrap();
        let tx = setup_and_bind_udp_socket_on(0, Some(std::net::Ipv4Addr::LOCALHOST.into())).unwrap();
        let tx_port = std::net::UdpSocket::bind("[::]:0").unwrap().local_addr().unwrap().port();
        let tx6 = setup_and_bind_udp_socket_on(tx_port, Some(Ipv6Addr::LOCALHOST.into())).unwrap();
        let mut buf = vec![0u8; 64];
        for (sock, dst, dscp, ce) in [
            (tx, std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(), Dscp::Af21, true),
            (tx6, Ipv6Addr::LOCALHOST, Dscp::Ef, false),
        ] {
            assert!(udp_send_with_congestion_and_dscp(sock, dst, port, b"pigeon", dscp, ce).is_some());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let got = loop {
                match udp_recv_with_congestion_and_dscp(rx, &mut buf) {
                    Ok(got) => break got,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && std::time::Instant::now() < deadline => std::thread::yield_now(),
                    Err(e) => panic!("recv: {e}"),
                }
            };
            assert_eq!((&buf[..got.0], got.1, got.3, got.4, got.5), (&b"pigeon"[..], dst, ce, true, dscp));
            if dst == Ipv6Addr::LOCALHOST { assert_eq!(got.2, tx_port); }
        }
        for s in [rx, tx, tx6] { unsafe { s.close() } }
    }
}
