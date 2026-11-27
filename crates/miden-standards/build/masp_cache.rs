//! Job-local cache of the standards library and its component packages.
//! Each cache directory belongs to one checkout and fixed assembler toolchain.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use blake3::Hasher;
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr};
use walkdir::WalkDir;

pub fn key(source: &Path, upstream: impl Iterator<Item = Vec<u8>>) -> Result<String> {
    let mut hash = Hasher::new();
    hash.update(include_bytes!("../build.rs"));
    hash.update(miden_protocol_build_utils::BUILD_PROFILE.as_bytes());
    // Source paths can be embedded in the packages' debug information.
    hash.update(source.as_os_str().as_encoded_bytes());
    hash.update(tree_hash(source).into_diagnostic()?.as_bytes());
    for bytes in upstream {
        hash.update(blake3::hash(&bytes).as_bytes());
    }
    Ok(hash.finalize().to_hex().to_string())
}

/// Hash the names and contents together so renames and missing files invalidate a set.
fn tree_hash(root: &Path) -> io::Result<blake3::Hash> {
    let mut hash = Hasher::new();
    for entry in WalkDir::new(root).follow_links(true).sort_by_file_name() {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();
            let relative = path.strip_prefix(root).expect("walk stays under root");
            hash.update(blake3::hash(relative.as_os_str().as_encoded_bytes()).as_bytes());
            hash.update(blake3::hash(&fs::read(path)?).as_bytes());
        }
    }
    Ok(hash.finalize())
}

pub fn restore_or_build(
    cache: &Path,
    key: &str,
    target: &Path,
    assemble: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    fs::create_dir_all(cache).into_diagnostic()?;
    let mut lock = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(cache.join(format!("{key}.lock")))
        .into_diagnostic()?;
    lock.lock().into_diagnostic()?;

    let entry = cache.join(key);
    let assets = entry.join("assets");
    let hit = assets.is_dir()
        && fs::read(entry.join("checksum")).ok().as_deref()
            == Some(tree_hash(&assets).into_diagnostic()?.as_bytes().as_slice());
    if !hit {
        let staging = tempfile::tempdir_in(cache).into_diagnostic()?;
        let staged_assets = staging.path().join("assets");
        assemble(&staged_assets)?;
        let checksum = tree_hash(&staged_assets).into_diagnostic()?;
        fs::write(staging.path().join("checksum"), checksum.as_bytes()).into_diagnostic()?;
        if entry.exists() {
            fs::remove_dir_all(&entry).into_diagnostic()?;
        }
        fs::rename(staging.path(), &entry).into_diagnostic()?;
    }

    // Cargo owns this build's OUT_DIR. Remove obsolete generated components on a retry.
    if target.exists() {
        fs::remove_dir_all(target).into_diagnostic()?;
    }
    for file in WalkDir::new(&assets) {
        let file = file.into_diagnostic()?;
        let relative = file.path().strip_prefix(&assets).expect("walk stays under assets");
        let dest = target.join(relative);
        if file.file_type().is_dir() {
            fs::create_dir_all(dest).into_diagnostic()?;
        } else {
            fs::copy(file.path(), dest)
                .into_diagnostic()
                .wrap_err("restoring standards package")?;
        }
    }
    // The feature job counts actual build-script executions, including concurrent ones.
    writeln!(lock, "{}", if hit { "hit" } else { "miss" }).into_diagnostic()?;
    Ok(())
}
