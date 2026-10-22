//! Cosmopolitan (APE) build: `cfg(cosmo)` on an `os = "linux"` musl target.
//!
//! Contract with cosmo-compat (the shim cargo-cosmo links into every cosmo
//! binary; STP has no Cargo dependency on it): STP speaks Linux numbering and
//! Linux struct layouts through the plain libc names, and cosmo-compat
//! translates to the running host at the libc boundary, including errno back
//! to Linux values. So every type, constant and declaration is the Linux one.
//! What is added here is what Linux does not have: the host the APE landed
//! on (for capability decisions only; host-numbered values must never be
//! passed into a wrapped call, where they would be translated a second
//! time), a portable wake pair instead of eventfd (not in libcosmo), and
//! entropy through cosmo's portable getrandom.
#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

pub use super::linux::*;

pub const SOCK_STREAM: c_int = 1;
pub const SOCK_NONBLOCK: c_int = O_NONBLOCK;
pub const SOCK_CLOEXEC: c_int = O_CLOEXEC;

/// The operating system the APE is running on (libc/dce.h `__hostos` bits).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Host { Linux, Windows, Xnu, Other(c_int) }

const HOSTLINUX: c_int = 1;
const HOSTWINDOWS: c_int = 4;
const HOSTXNU: c_int = 8;

unsafe extern "C" {
    static __hostos: c_int;
    pub fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int;
    fn getrandom(buf: *mut c_void, len: size_t, flags: c_uint) -> ssize_t;
    // libc/thread/thread.h. Not wrapped by cosmo-compat: portable futex
    // (Linux futex, XNU ulock, Windows WaitOnAddress). pshared 0 = private.
    fn cosmo_futex_wait(word: *mut c_int, expected: c_int, pshared: c_char, clock: c_int, abstime: *const timespec) -> c_int;
    fn cosmo_futex_wake(word: *mut c_int, count: c_int, pshared: c_char) -> c_int;
}

/// Sleeps while `*word == expected` (no timeout); returns on mismatch, wake,
/// or interruption. Uses cosmo's portable futex instead of syscall(SYS_futex),
/// which Cosmopolitan does not implement off Linux.
#[inline]
pub fn futex_wait(word: &core::sync::atomic::AtomicU32, expected: u32) {
    // The clock is only consulted with a deadline; there is none here.
    unsafe { cosmo_futex_wait(word.as_ptr().cast(), expected as c_int, 0, 0, core::ptr::null()); }
}
/// Wakes every waiter on `word`.
#[inline]
pub fn futex_wake_all(word: &core::sync::atomic::AtomicU32) {
    unsafe { cosmo_futex_wake(word.as_ptr().cast(), i32::MAX, 0); }
}

/// The running host. Read after cosmo's startup has filled `__hostos`, which
/// precedes any Rust code.
pub fn host() -> Host {
    match unsafe { core::ptr::read_volatile(&raw const __hostos) } {
        HOSTLINUX => Host::Linux,
        HOSTWINDOWS => Host::Windows,
        HOSTXNU => Host::Xnu,
        other => Host::Other(other),
    }
}

/// Exact entropy fill through cosmo's getrandom (getrandom(2) on Linux,
/// getentropy on XNU, the system RNG on Windows), looping over partial
/// returns and EINTR (errno arrives in Linux numbering via cosmo-compat).
pub fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    let mut rest = &mut buf[..];
    while !rest.is_empty() {
        let n = unsafe { getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(EINTR) { continue; }
            return Err(err);
        }
        if n == 0 || n as usize > rest.len() {
            return Err(std::io::Error::other("getrandom returned an impossible length"));
        }
        rest = &mut rest[n as usize..];
    }
    Ok(())
}

/// (user, system) CPU microseconds of the calling thread on a Linux host.
/// getrusage is not translated by cosmo-compat and RUSAGE_THREAD is
/// Linux-numbered, so other hosts report None rather than a wrong scope.
pub fn thread_cpu_time_us() -> Option<(u64, u64)> {
    if host() != Host::Linux { return None; }
    let mut ru: rusage = unsafe { core::mem::zeroed() };
    if unsafe { getrusage(RUSAGE_THREAD, &mut ru) } != 0 { return None; }
    let us = |t: timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    Some((us(ru.ru_utime), us(ru.ru_stime)))
}
