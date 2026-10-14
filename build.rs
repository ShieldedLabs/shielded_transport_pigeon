// Builds the vendored Wirehair fountain code (third_party/wirehair, upstream catid/wirehair
// c9f3d49, BSD-3-Clause) as a static C++ library for src/fec.rs. Only the classic C API
// (wirehair_init_/encoder/decoder) is compiled. gf256 picks SSSE3/AVX2/NEON kernels at
// runtime (CPUID + target attributes), so no -march flag is needed and the build stays
// portable to generic x86_64.
fn main() {
    let dir = std::path::Path::new("third_party/wirehair");
    let sources = ["wirehair.cpp", "WirehairCodec.cpp", "WirehairTools.cpp", "gf256.cpp"];
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++11")
        .include(dir)
        .include(dir.join("include"))
        .define("WIREHAIR_BUILDING", "1")
        .define("WIREHAIR_STATIC", "1")
        .opt_level(2)
        .warnings(false);
    for s in sources {
        build.file(dir.join(s));
    }
    build.compile("wirehair");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=third_party/wirehair");
}
