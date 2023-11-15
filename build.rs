use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let mut target_board: Option<String> = None;

    for (name, _) in std::env::vars() {
        let prefix = "CARGO_FEATURE_TARGET_BOARD_";
        if name.starts_with("CARGO_FEATURE_TARGET_BOARD_") {
            let suffix = name[prefix.len()..].to_string();
            if let Some(previous) = &target_board {
                panic!(
                    "multiple target board features defined (at least {} and {})",
                    show_feature(previous),
                    show_feature(&suffix)
                );
            }

            target_board = Some(suffix);
        }
    }

    if target_board.is_none() {
        panic!("missing target-board-* feature");
    }

    // Could add a feature to make this optional
    gen_linker_script();
}

fn gen_linker_script() {
    // TODO Pull out into another crate?
    #[repr(C)]
    struct ImageHeader {
        magic: u32,
        total_image_len: u32,
        _pad: [u32; 16], // previous location of SAU entries
        version: u32,
        epoch: u32,
    }

    println!("cargo:rerun-if-changed=link.x.in");
    let base = std::fs::read("link.x.in").unwrap();

    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut linker_script = File::create(out.join("link.x")).unwrap();

    writeln!(
        linker_script,
        "_HUBRIS_IMAGE_HEADER_ALIGN = {:#x};",
        std::mem::align_of::<ImageHeader>()
    )
    .unwrap();
    writeln!(
        linker_script,
        "_HUBRIS_IMAGE_HEADER_SIZE = {:#x};",
        std::mem::size_of::<ImageHeader>()
    )
    .unwrap();

    linker_script.write_all(&base).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
}

fn show_feature(envvar: &str) -> String {
    let mut name = "target-board-".to_string();
    name.push_str(&envvar.to_ascii_lowercase().replace('_', "-"));
    name
}
