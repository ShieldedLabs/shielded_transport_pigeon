#![allow(unsafe_code)]
#[cfg(any(cosmo, target_os = "linux"))] pub(crate) mod linux;
#[cfg(cosmo)] pub(crate) mod cosmo;
#[cfg(cosmo)] pub(crate) use cosmo as sys;
#[cfg(all(not(cosmo), target_os = "linux"))] pub(crate) use linux as sys;
#[cfg(all(not(cosmo), target_os = "macos"))] pub(crate) mod macos;
#[cfg(all(not(cosmo), target_os = "macos"))] pub(crate) use macos as sys;
#[cfg(all(not(cosmo), windows))] pub(crate) mod windows;
#[cfg(all(not(cosmo), windows))] pub(crate) use windows as sys;
/// Fill all of `buf` from the operating system's CSPRNG, or fail.
///
/// Never succeeds partially: on error the buffer is zeroed and must not be used. EINTR and short reads are retried internally.
/// Supported: Linux (getrandom(2), failing closed if unavailable or blocked), macOS (getentropy), Windows (BCryptGenRandom,
/// system-preferred RNG), Cosmopolitan (cosmo getrandom), and other Unix via /dev/urandom.
pub(crate) fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    #[cfg(any(cosmo, target_os = "linux", target_os = "macos", windows))] let fill = sys::fill_random;
    #[cfg(all(unix, not(any(cosmo, target_os = "linux", target_os = "macos"))))] let fill = read_urandom;
    fill_random_using(buf, fill) }
fn fill_random_using(buf: &mut [u8], fill: impl FnOnce(&mut [u8]) -> std::io::Result<()>) -> std::io::Result<()> {
    let result = fill(buf);
    if result.is_err() { buf.fill(0); }
    result }
#[cfg(all(unix, not(any(cosmo, target_os = "linux", target_os = "macos"))))]
fn read_urandom(buf: &mut [u8]) -> std::io::Result<()> { use std::io::Read; std::fs::File::open("/dev/urandom")?.read_exact(buf) }
