// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use anyhow::{bail, Result};
use clap::Parser;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Debug, Parser)]
enum Xtask {
    /// Packages bootleby into a hubris compatible archive
    Package {
        #[clap(long)]
        board: String,
        #[clap(long)]
        out: PathBuf,
    },
}

// borrowed from hubris
fn remap_paths() -> Result<BTreeMap<PathBuf, &'static str>> {
    // Panic messages in crates have a long prefix; we'll shorten it using
    // the --remap-path-prefix argument to reduce message size.  We'll remap
    // local (bootleby) crates to /bootleby, crates.io to /crates.io, and git
    // dependencies to /git
    let mut remap_paths = BTreeMap::new();

    if let Ok(home) = std::env::var("CARGO_HOME") {
        let cargo_home = PathBuf::from(home);
        let cargo_git = cargo_home.join("git").join("checkouts");
        remap_paths.insert(cargo_git, "/git");

        // This hash is canonical-ish: Cargo tries hard not to change it
        // https://github.com/rust-lang/cargo/blob/5dfdd59/src/cargo/core/source_id.rs#L755-L794
        //
        // It depends on system architecture, so this won't work on (for example)
        // a Raspberry Pi, but the only downside is that panic messages will
        // be longer.
        let cargo_registry = cargo_home
            .join("registry")
            .join("src")
            .join("github.com-1ecc6299db9ec823");
        remap_paths.insert(cargo_registry, "/crates.io");
        // If Cargo uses the sparse registry (stabilized since ~1.72) it caches fetched crates
        // in a slightly different path. Remap that one as well.
        //
        // This path has the same canonical-ish properties as above.
        let cargo_sparse_registry = cargo_home
            .join("registry")
            .join("src")
            .join("index.crates.io-6f17d22bba15001f");
        remap_paths.insert(cargo_sparse_registry, "/crates.io");
    }

    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let mut bootleby_dir = std::path::PathBuf::from(dir);
        bootleby_dir.pop();
        remap_paths.insert(bootleby_dir.to_path_buf(), "/bootleby");
    }
    Ok(remap_paths)
}

fn package(board: String, out: PathBuf) -> Result<()> {
    let remap_path_prefix = remap_paths()?.iter().fold(String::new(), |mut output, r| {
        let _ = write!(output, " --remap-path-prefix={}={}", r.0.display(), r.1);
        output
    });

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.arg("build");
    command.arg("--release");
    command.arg("--no-default-features");
    command.arg("--features");
    command.arg(format!("target-board-{}", board));

    // We need to make sure we explicitly set the path to our custom linker script
    // when setting our remap path args
    command.env(
        "RUSTFLAGS",
        &format!("{} -C link-arg=-Tlink.x", remap_path_prefix),
    );

    let mut child = command
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    let status = child.wait()?;

    if !status.success() {
        bail!("build failed: {}", status);
    }

    let archive = hubtools::bootleby_to_archive(
        "target/thumbv8m.main-none-eabihf/release/bootleby".into(),
        board.clone(),
        board.clone(),
        format!(
            "{}{}",
            env!("VERGEN_GIT_SHA"),
            if env!("VERGEN_GIT_DIRTY") == "true" {
                "-dirty"
            } else {
                ""
            }
        ),
    )?;

    std::fs::write(out, archive)?;
    Ok(())
}

fn main() -> Result<()> {
    let xtask = Xtask::parse();

    match xtask {
        Xtask::Package { board, out } => {
            package(board, out)?;
        }
    }
    Ok(())
}
