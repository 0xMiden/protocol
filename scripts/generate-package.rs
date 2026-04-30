#!/usr/bin/env cargo

---
[dependencies]
miden-protocol = { path = "../crates/miden-protocol" }
semver = "1"
---

use std::env;

use miden_protocol::ProtocolLib;

fn main() -> std::io::Result<()> {
    // Must be run from the workspace root (CARGO_TARGET_DIR is not set for cargo scripts).
    let workspace_root = env::current_dir().expect("could not read PWD");
    let packages_dir = workspace_root.join("target").join("packages");
    std::fs::create_dir_all(&packages_dir)?;

    let package = ProtocolLib::default().into_package();
    package.write_masp_file(&packages_dir)?;

    println!("wrote {}.masp to {}", package.name, packages_dir.display());
    Ok(())
}
