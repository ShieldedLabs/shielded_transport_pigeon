//! In-crate platform ABI bindings: the exact C/Win32 types, constants and
//! functions STP calls, per OS, with no Rust dependencies.
//!
//! `sys` is the module for the build target. Selection order: `cfg(cosmo)`
//! (APE; the target says `linux` but the binary runs on any host) takes
//! priority over Linux, then macOS, then Windows. Each OS module carries its
//! own layout assertions; nothing is reused across OSes with differing ABIs.
#![allow(unsafe_code)]

#[cfg(any(cosmo, target_os = "linux"))]
pub(crate) mod linux;

#[cfg(cosmo)]
pub(crate) mod cosmo;
#[cfg(cosmo)]
pub(crate) use cosmo as sys;

#[cfg(all(not(cosmo), target_os = "linux"))]
pub(crate) use linux as sys;

#[cfg(all(not(cosmo), target_os = "macos"))]
pub(crate) mod macos;
#[cfg(all(not(cosmo), target_os = "macos"))]
pub(crate) use macos as sys;

#[cfg(all(not(cosmo), windows))]
pub(crate) mod windows;
#[cfg(all(not(cosmo), windows))]
pub(crate) use windows as sys;

/// Fill all of `buf` from the operating system's CSPRNG, or fail.
///
/// Never succeeds partially: on error the buffer is zeroed and must not be
/// used. EINTR and short reads are retried internally. Supported: Linux
/// (getrandom(2), failing closed if unavailable or blocked), macOS
/// (getentropy), Windows (BCryptGenRandom, system-preferred RNG),
/// Cosmopolitan (cosmo getrandom), and other Unix via /dev/urandom.
pub(crate) fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    #[cfg(any(cosmo, target_os = "linux", target_os = "macos", windows))]
    let fill = sys::fill_random;
    #[cfg(all(unix, not(any(cosmo, target_os = "linux", target_os = "macos"))))]
    let fill = read_urandom;
    fill_random_using(buf, fill)
}

fn fill_random_using(buf: &mut [u8], fill: impl FnOnce(&mut [u8]) -> std::io::Result<()>) -> std::io::Result<()> {
    let result = fill(buf);
    if result.is_err() {
        buf.fill(0);
    }
    result
}

/// `read_exact` from /dev/urandom (retries EINTR; EOF is an error).
#[cfg(all(unix, not(any(cosmo, target_os = "linux", target_os = "macos"))))]
fn read_urandom(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

#[cfg(test)]
mod tests {
    #[test]
    fn fill_random_is_exact_and_distinct() {
        for len in [0usize, 1, 31, 255, 256, 257, 4096, 70_000] {
            let mut a = vec![0u8; len];
            super::fill_random(&mut a).unwrap();
            if len >= 31 {
                assert!(a.iter().any(|&b| b != 0), "len {len}");
                // The tail must be filled too (partial fills would leave zeros).
                assert!(a[len - 16..].iter().any(|&b| b != 0), "len {len}");
            }
        }
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        super::fill_random(&mut a).unwrap();
        super::fill_random(&mut b).unwrap();
        assert_ne!(a, b);
    }

    #[cfg(all(not(cosmo), target_os = "linux"))]
    #[test]
    fn linux_entropy_failures_are_closed_and_scrubbed() {
        for errno in [super::linux::ENOSYS, super::linux::EPERM, 5] {
            for prefix in [0, 7] {
                let mut out = [0xa5; 32];
                let mut calls = 0;
                let error = super::fill_random_using(&mut out, |buf| {
                    super::linux::fill_random_with(buf, |rest| {
                        calls += 1;
                        if prefix != 0 && calls == 1 {
                            rest[..prefix].fill(0x5a);
                            Ok(prefix)
                        } else {
                            Err(std::io::Error::from_raw_os_error(errno))
                        }
                    })
                }).unwrap_err();
                assert_eq!(error.raw_os_error(), Some(errno));
                assert_eq!(calls, if prefix == 0 { 1 } else { 2 });
                assert_eq!(out, [0; 32]);
            }
        }
    }

    #[cfg(all(not(cosmo), target_os = "linux"))]
    #[test]
    fn linux_entropy_retries_interrupts_and_partial_reads() {
        let mut out = [0xa5; 32];
        let mut calls = 0;
        super::fill_random_using(&mut out, |buf| {
            super::linux::fill_random_with(buf, |rest| {
                calls += 1;
                match calls {
                    1 | 3 => Err(std::io::Error::from_raw_os_error(super::linux::EINTR)),
                    2 => { rest[..7].fill(0x5a); Ok(7) }
                    4 => { assert_eq!(rest.len(), 25); rest.fill(0x79); Ok(25) }
                    _ => panic!("unexpected entropy read"),
                }
            })
        }).unwrap();
        assert_eq!(calls, 4);
        assert_eq!(&out[..7], &[0x5a; 7]);
        assert_eq!(&out[7..], &[0x79; 25]);
        super::linux::fill_random_with(&mut [], |_| panic!("empty fill read")).unwrap();
    }

    #[cfg(all(not(cosmo), target_os = "linux"))]
    #[test]
    fn linux_entropy_impossible_lengths_fail_and_scrub() {
        for count in [0, 33] {
            let mut out = [0xa5; 32];
            assert!(super::fill_random_using(&mut out, |buf| {
                super::linux::fill_random_with(buf, |_| Ok(count))
            }).is_err());
            assert_eq!(out, [0; 32]);
        }
    }

    #[cfg(all(unix, not(any(cosmo, target_os = "linux", target_os = "macos"))))]
    #[test]
    fn urandom_fallback_is_exact() {
        let mut a = vec![0u8; 10_000];
        super::read_urandom(&mut a).unwrap();
        assert!(a[9_984..].iter().any(|&b| b != 0));
    }
}
