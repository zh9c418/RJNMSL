fn main() {
    // Npcap (the runtime install) does not ship import libraries, so the
    // wpcap.lib / Packet.lib in `.npcap/` were generated from the installed
    // DLLs with `dumpbin /exports` + `lib /def`. Point the linker at them.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".npcap");
    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rerun-if-changed=build.rs");
}
