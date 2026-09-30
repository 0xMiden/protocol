//! Build-time assembly of the shipped xUSDC MASM.
//!
//! Assembles:
//! - `asm/xreserve/` into a package,
//! - `asm/components/` into account components,
//! - `asm/notes/` into note scripts.
//!
//! It also extracts the MASM error constants into `$OUT_DIR/xreserve_errors.rs`.

use std::env;
use std::path::Path;

use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr};
use miden_assembly::ProjectTargetSelector;
use miden_core_lib::CoreLibrary;
use miden_package_registry::{InMemoryPackageRegistry, PackageCache};
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::ProtocolLib;
use miden_protocol_build_utils::{
    assemble_project, assemble_workspace, extract_all_masm_errors, generate_error_file,
    ErrorModule, PROJECT_MANIFEST,
};
use miden_standards::StandardsLib;

// CONSTANTS
// ================================================================================================

const ASM_DIR: &str = "asm";
const ASM_XRESERVE_DIR: &str = "xreserve";
const ASM_COMPONENTS_DIR: &str = "components";
const ASM_NOTES_DIR: &str = "notes";
const ASSETS_DIR: &str = "assets";

const XRESERVE_ERRORS_RS_FILE: &str = "xreserve_errors.rs";
const XRESERVE_ERRORS_ARRAY_NAME: &str = "XRESERVE_ERRORS";

// PRE-PROCESSING
// ================================================================================================

fn main() -> Result<()> {
    // re-build when the MASM code changes
    println!("cargo::rerun-if-changed={ASM_DIR}/");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set");
    let build_dir = env::var("OUT_DIR").expect("OUT_DIR is always set for build scripts");

    let source_dir = Path::new(&crate_dir).join(ASM_DIR);
    let target_dir = Path::new(&build_dir).join(ASSETS_DIR);

    let mut registry = build_registry()?;

    // The library is assembled first and seeded into the registry: both workspaces below declare it
    // as a dependency.
    let xreserve_lib = assemble_project(
        source_dir.join(ASM_XRESERVE_DIR).join(PROJECT_MANIFEST),
        ProjectTargetSelector::Library,
        &mut registry,
        &target_dir,
    )?;
    registry.cache_package(xreserve_lib).into_diagnostic()?;

    // Each package is written to a file named after itself (e.g. `xreserve-faucet-extension.masp`),
    // so the package name is the include path the Rust side uses.
    for workspace_dir in [ASM_COMPONENTS_DIR, ASM_NOTES_DIR] {
        assemble_workspace(
            source_dir.join(workspace_dir).join(PROJECT_MANIFEST),
            &mut registry,
            &target_dir.join(workspace_dir),
        )?;
    }

    generate_error_constants(&source_dir, &build_dir)
}

// ASSEMBLER & REGISTRY
// ================================================================================================

/// Builds the package registry that the declared dependencies resolve against.
///
/// The protocol package declares the kernel and the core packages, and the xreserve projects declare
/// the standards package, so all of them have to be present for dependency resolution to succeed.
fn build_registry() -> Result<InMemoryPackageRegistry> {
    let mut registry = InMemoryPackageRegistry::default();

    for package in [
        CoreLibrary::default().package(),
        ProtocolLib::default().package(),
        TransactionKernel::package(),
        StandardsLib::default().package(),
    ] {
        registry.cache_package(package).into_diagnostic()?;
    }

    Ok(registry)
}

// ERROR CONSTANTS FILE GENERATION
// ================================================================================================

/// Reads every MASM file under `asm_source_dir`, extracts its error constants and their messages,
/// and generates the Rust file that names them.
fn generate_error_constants(asm_source_dir: &Path, build_dir: &str) -> Result<()> {
    let errors =
        extract_all_masm_errors(asm_source_dir).context("failed to extract all masm errors")?;

    generate_error_file(
        ErrorModule {
            file_path: Path::new(build_dir).join(XRESERVE_ERRORS_RS_FILE),
            array_name: XRESERVE_ERRORS_ARRAY_NAME,
            // The generated constants live in this crate, which reaches `MasmError` through its
            // `miden-protocol` dependency rather than a local `crate::errors`.
            is_crate_local: false,
        },
        errors,
    )
}
