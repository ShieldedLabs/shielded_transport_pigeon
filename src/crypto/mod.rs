pub(crate) mod chacha20; pub(crate) mod rng;
#[inline(never)] fn wipe(bytes: &mut [u8]) {
    for byte in bytes { unsafe { core::ptr::write_volatile(byte, 0) }; }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst); }
