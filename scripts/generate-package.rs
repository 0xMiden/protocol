#!/usr/bin/env cargo

---
[dependencies]
miden-protocol = { path = "../crates/miden-protocol" }
miden-standards = { path = "../crates/miden-standards" }
semver = "1"
---

use std::env;

use miden_protocol::ProtocolLib;
use miden_standards::StandardsLib;

fn main() -> std::io::Result<()> {
    // Must be run from the workspace root (CARGO_TARGET_DIR is not set for cargo scripts).
    let workspace_root = env::current_dir().expect("could not read PWD");
    let packages_dir = workspace_root.join("target").join("packages");
    std::fs::create_dir_all(&packages_dir)?;

    let protocol_pkg = ProtocolLib::default().into_package();
    protocol_pkg.write_masp_file(&packages_dir)?;
    println!("wrote {}.masp to {}", protocol_pkg.name, packages_dir.display());

    let standards_pkg = StandardsLib::default().into_package();
    standards_pkg.write_masp_file(&packages_dir)?;
    println!("wrote {}.masp to {}", standards_pkg.name, packages_dir.display());

    Ok(())
}
