#![allow(
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    dead_code,
    clippy::upper_case_acronyms
)]
pub use core::ffi::c_void;
pub type SOCKET = usize;
pub type ADDRESS_FAMILY = u16;
pub type HANDLE = *mut c_void;
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SOCKADDR {
    pub sa_family: ADDRESS_FAMILY,
    pub sa_data: [i8; 14],
}
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct WSABUF {
    pub len: u32,
    pub buf: *mut u8,
}
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct WSAMSG {
    pub name: *mut SOCKADDR,
    pub namelen: i32,
    pub lpBuffers: *mut WSABUF,
    pub dwBufferCount: u32,
    pub Control: WSABUF,
    pub dwFlags: u32,
}
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CMSGHDR {
    pub cmsg_len: usize,
    pub cmsg_level: i32,
    pub cmsg_type: i32,
}
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}
#[cfg(target_pointer_width = "64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct WSADATA {
    pub wVersion: u16,
    pub wHighVersion: u16,
    pub iMaxSockets: u16,
    pub iMaxUdpDg: u16,
    pub lpVendorInfo: *mut u8,
    pub szDescription: [u8; 257],
    pub szSystemStatus: [u8; 129],
}
#[cfg(target_pointer_width = "32")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct WSADATA {
    pub wVersion: u16,
    pub wHighVersion: u16,
    pub szDescription: [u8; 257],
    pub szSystemStatus: [u8; 129],
    pub iMaxSockets: u16,
    pub iMaxUdpDg: u16,
    pub lpVendorInfo: *mut u8,
}
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct OVERLAPPED {
    pub Internal: usize,
    pub InternalHigh: usize,
    pub Offset: u32,
    pub OffsetHigh: u32,
    pub hEvent: HANDLE,
}
pub type LPWSAOVERLAPPED_COMPLETION_ROUTINE = Option<
    unsafe extern "system" fn(
        dwError: u32,
        cbTransferred: u32,
        lpOverlapped: *mut OVERLAPPED,
        dwFlags: u32,
    ),
>;
pub type LPFN_WSARECVMSG = Option<
    unsafe extern "system" fn(
        s: SOCKET,
        lpMsg: *mut WSAMSG,
        lpdwNumberOfBytesRecvd: *mut u32,
        lpOverlapped: *mut OVERLAPPED,
        lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32,
>;
pub const WSAID_WSARECVMSG: GUID = GUID {
    data1: 0xf689d7c8,
    data2: 0x6f1f,
    data3: 0x436b,
    data4: [0x8a, 0x53, 0xe5, 0x4f, 0xe3, 0x51, 0xc3, 0x22],
};
pub const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
pub const FIONBIO: i32 = 0x8004_667Eu32 as i32;
pub const INVALID_SOCKET: SOCKET = !0;
pub const SOCKET_ERROR: i32 = -1;
pub const AF_INET: ADDRESS_FAMILY = 2;
pub const AF_INET6: ADDRESS_FAMILY = 23;
pub const SOCK_DGRAM: i32 = 2;
pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_UDP: i32 = 17;
pub const IPPROTO_IPV6: i32 = 41;
pub const IP_TOS: i32 = 3;
pub const IP_RECVTOS: i32 = 40;
pub const IP_ECN: i32 = 50;
pub const IP_MTU_DISCOVER: i32 = 71;
pub const IPV6_V6ONLY: i32 = 27;
pub const IPV6_TCLASS: i32 = 39;
pub const IPV6_RECVTCLASS: i32 = 40;
pub const IPV6_ECN: i32 = 50;
pub const IPV6_MTU_DISCOVER: i32 = 71;
pub const IP_PMTUDISC_PROBE: i32 = 3;
pub const MSG_TRUNC: i32 = 0x0100;
pub const WSAEINVAL: i32 = 10022;
pub const WSAEWOULDBLOCK: i32 = 10035;
pub const WSAEMSGSIZE: i32 = 10040;
pub const WSAENOPROTOOPT: i32 = 10042;
pub const WSAEAFNOSUPPORT: i32 = 10047;
pub const WSAEADDRNOTAVAIL: i32 = 10049;
pub const WSAENETDOWN: i32 = 10050;
pub const WSAENETUNREACH: i32 = 10051;
pub const WSAECONNRESET: i32 = 10054;
pub const WSAENOBUFS: i32 = 10055;
pub const WSAECONNREFUSED: i32 = 10061;
pub const WSAEHOSTDOWN: i32 = 10064;
pub const WSAEHOSTUNREACH: i32 = 10065;
pub const EMSGSIZE: i32 = WSAEMSGSIZE;
pub const ENETUNREACH: i32 = WSAENETUNREACH;
pub const EHOSTUNREACH: i32 = WSAEHOSTUNREACH;
pub const ENETDOWN: i32 = WSAENETDOWN;
pub const ECONNREFUSED: i32 = WSAECONNREFUSED;
pub const EHOSTDOWN: i32 = WSAEHOSTDOWN;
pub const EAFNOSUPPORT: i32 = WSAEAFNOSUPPORT;
pub const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
#[link(name = "ws2_32")]
unsafe extern "system" {
    pub fn WSAStartup(wVersionRequested: u16, lpWSAData: *mut WSADATA) -> i32;
    pub fn WSAGetLastError() -> i32;
    pub fn socket(af: i32, ty: i32, protocol: i32) -> SOCKET;
    pub fn closesocket(s: SOCKET) -> i32;
    pub fn ioctlsocket(s: SOCKET, cmd: i32, argp: *mut u32) -> i32;
    pub fn setsockopt(s: SOCKET, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    pub fn bind(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32;
    pub fn connect(s: SOCKET, name: *const SOCKADDR, namelen: i32) -> i32;
    pub fn getsockname(s: SOCKET, name: *mut SOCKADDR, namelen: *mut i32) -> i32;
    pub fn sendto(
        s: SOCKET,
        buf: *const u8,
        len: i32,
        flags: i32,
        to: *const SOCKADDR,
        tolen: i32,
    ) -> i32;
    pub fn WSAIoctl(
        s: SOCKET,
        dwIoControlCode: u32,
        lpvInBuffer: *const c_void,
        cbInBuffer: u32,
        lpvOutBuffer: *mut c_void,
        cbOutBuffer: u32,
        lpcbBytesReturned: *mut u32,
        lpOverlapped: *mut OVERLAPPED,
        lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32;
}
#[link(name = "bcrypt")]
unsafe extern "system" {
    pub fn BCryptGenRandom(
        hAlgorithm: *mut c_void,
        pbBuffer: *mut u8,
        cbBuffer: u32,
        dwFlags: u32,
    ) -> i32;
}
pub fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    for chunk in buf.chunks_mut(u32::MAX as usize) {
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(std::io::Error::other(format!(
                "BCryptGenRandom failed: NTSTATUS {:#010x}",
                status as u32
            )));
        }
    }
    Ok(())
}
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<SOCKADDR>() == 16 && size_of::<GUID>() == 16);
    #[cfg(target_pointer_width = "64")]
    {
        assert!(size_of::<WSABUF>() == 16 && offset_of!(WSABUF, buf) == 8);
        assert!(
            size_of::<WSAMSG>() == 56
                && offset_of!(WSAMSG, Control) == 32
                && offset_of!(WSAMSG, dwFlags) == 48
        );
        assert!(size_of::<CMSGHDR>() == 16 && offset_of!(CMSGHDR, cmsg_level) == 8);
        assert!(
            size_of::<WSADATA>() == 408
                && offset_of!(WSADATA, lpVendorInfo) == 8
                && offset_of!(WSADATA, szDescription) == 16
        );
        assert!(size_of::<OVERLAPPED>() == 32 && offset_of!(OVERLAPPED, hEvent) == 24);
    }
    #[cfg(target_pointer_width = "32")]
    {
        assert!(
            size_of::<WSABUF>() == 8 && size_of::<WSAMSG>() == 28 && size_of::<CMSGHDR>() == 12
        );
        assert!(size_of::<WSADATA>() == 400 && offset_of!(WSADATA, lpVendorInfo) == 396);
        assert!(size_of::<OVERLAPPED>() == 20);
    }
};
