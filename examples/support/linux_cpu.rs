#![allow(dead_code)]
use std::io::Write;
use std::os::fd::AsRawFd;
#[allow(non_camel_case_types)]
pub mod libc {
    use std::os::raw::{c_int, c_long};
    pub const STDOUT_FILENO: c_int = 1;
    pub const CLOCK_PROCESS_CPUTIME_ID: c_int = 2;
    pub type time_t = c_long;
    #[repr(C)]
    pub struct timespec {
        pub tv_sec: time_t,
        pub tv_nsec: c_long,
    }
    pub const _SC_CLK_TCK: c_int = 2;
    unsafe extern "C" {
        pub fn dup(fd: c_int) -> c_int;
        pub fn dup2(old: c_int, new: c_int) -> c_int;
        pub fn close(fd: c_int) -> c_int;
        pub fn clock_gettime(clk: c_int, ts: *mut timespec) -> c_int;
        pub fn sysconf(name: c_int) -> c_long;
        pub fn gettid() -> c_int;
    }
}
pub struct QuietStdout(i32);
impl QuietStdout {
    pub fn new() -> Self {
        std::io::stdout().flush().unwrap();
        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        let saved = unsafe { libc::dup(libc::STDOUT_FILENO) };
        assert!(saved >= 0);
        assert!(unsafe { libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) } >= 0);
        Self(saved)
    }
}
impl Drop for QuietStdout {
    fn drop(&mut self) {
        std::io::stdout().flush().unwrap();
        unsafe {
            libc::dup2(self.0, libc::STDOUT_FILENO);
            libc::close(self.0);
        }
    }
}
pub fn process_cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) },
        0
    );
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
