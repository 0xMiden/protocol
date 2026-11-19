use std::env;
use std::path::Path;

use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr};
use miden_assembly::{ProjectTargetSelector, Report};
use miden_core_lib::CoreLibrary;
use miden_package_registry::{InMemoryPackageRegistry, PackageCache};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::utils::serde::Serializable;
use miden_protocol::vm::Program;
use miden_protocol::{ProtocolLib, Word, word};
use miden_protocol_build_utils::{
    ErrorModule,
    PROJECT_MANIFEST,
    assemble_project,
    assemble_workspace,
    extract_all_masm_errors,
    generate_error_file,
};

// CONSTANTS
// ================================================================================================

const ASSETS_DIR: &str = "assets";
const ASM_DIR: &str = "asm";
const ASM_STANDARDS_DIR: &str = "standards";
const ASM_COMPONENTS_DIR: &str = "components";

const STANDARDS_ERRORS_RS_FILE: &str = "standards_errors.rs";
const STANDARDS_ERRORS_ARRAY_NAME: &str = "STANDARDS_ERRORS";

include!("src/note/encryption/p2id_v1_program_identity.rs");

// PRE-PROCESSING
// ================================================================================================

/// Builds the standards library, the P2ID encryption executable, and the account component
/// packages from `./asm`.
fn main() -> Result<()> {
    // re-build when the MASM code changes
    println!("cargo::rerun-if-changed={ASM_DIR}/");
    println!("cargo::rerun-if-changed=src/note/encryption/p2id_v1_program_identity.rs");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_dir = env::var("OUT_DIR").unwrap();

    // Read MASM sources directly from the crate's asm/ directory.
    // No copy to OUT_DIR is needed because this crate doesn't mutate the source tree.
    let source_dir = Path::new(&crate_dir).join(ASM_DIR);

    // set target directory to {OUT_DIR}/assets
    let target_dir = Path::new(&build_dir).join(ASSETS_DIR);

    // The miden-core library is provided through an in-memory registry
    let mut registry = InMemoryPackageRegistry::default();

    // The protocol package declares dependencies on the kernel and core packages, so all three
    // must be available in the registry for project dependency resolution to succeed.
    for package in [
        CoreLibrary::default().package(),
        ProtocolLib::default().package(),
        TransactionKernel::package(),
    ] {
        registry.cache_package(package).into_diagnostic()?;
    }

    // compile standards library (includes note scripts and transaction scripts) and seed it into
    // the registry
    let manifest_path = source_dir.join(ASM_STANDARDS_DIR).join(PROJECT_MANIFEST);
    let package = assemble_project(
        manifest_path,
        ProjectTargetSelector::Library,
        &mut registry,
        &target_dir,
    )?;
    registry.cache_package(package).into_diagnostic()?;

    // compile the P2ID encryption executable. Its verifier builds claims from the pinned program
    // identity, so the build fails if the assembled executable differs from that identity.
    let package = assemble_project(
        source_dir.join("note-encryption").join(PROJECT_MANIFEST),
        ProjectTargetSelector::Executable("p2id-envelope"),
        &mut registry,
        &target_dir,
    )?;
    check_p2id_encryption_program(&package.unwrap_program())?;

    // compile account components (each member of the components workspace becomes its own package)
    // and embed each component's manifest metadata into its package. Parsing the metadata here
    // makes a malformed schema fail the build instead of the first instantiation.
    assemble_workspace(
        source_dir.join(ASM_COMPONENTS_DIR).join(PROJECT_MANIFEST),
        &mut registry,
        &target_dir.join(ASM_COMPONENTS_DIR),
        |metadata| Ok(AccountComponentMetadata::from_toml(metadata).into_diagnostic()?.to_bytes()),
    )?;

    generate_error_constants(&source_dir, &build_dir)?;

    Ok(())
}

/// Checks that the assembled program has the identity the P2ID encryption verifier accepts: the
/// approved root and kernel procedures.
fn check_p2id_encryption_program(program: &Program) -> Result<()> {
    let kernel = program.kernel().proc_hashes();
    if program.hash() != P2ID_V1_PROGRAM_ROOT || kernel != P2ID_V1_KERNEL_PROCEDURES {
        let hex = |words: &[Word]| words.iter().map(Word::to_hex).collect::<Vec<_>>();
        return Err(Report::msg(format!(
            "the P2ID encryption program has root {} and kernel procedures {:?}, but its verifier \
             accepts root {P2ID_V1_PROGRAM_ROOT} and kernel procedures {:?}; update \
             src/note/encryption/p2id_v1_program_identity.rs only for a deliberate profile change",
            program.hash(),
            hex(kernel),
            hex(&P2ID_V1_KERNEL_PROCEDURES),
        )));
    }
    Ok(())
}

// ERROR CONSTANTS FILE GENERATION
// ================================================================================================

/// Reads all MASM files from the `asm_source_dir` and extracts its error constants and their
/// associated error message and generates a Rust file for each category of errors.
/// For example:
///
/// ```text
/// const ERR_PROLOGUE_NEW_ACCOUNT_VAULT_MUST_BE_EMPTY="new account must have an empty vault"
/// ```
///
/// would generate a Rust file for transaction kernel errors (since the error belongs to that
/// category, identified by the category extracted from `ERR_<CATEGORY>`) with - roughly - the
/// following content:
///
/// ```rust
/// pub const ERR_PROLOGUE_NEW_ACCOUNT_VAULT_MUST_BE_EMPTY: MasmError =
///     MasmError::from_static_str("new account must have an empty vault");
/// ```
///
/// and add the constant to the error constants array.
///
/// The function ensures that a constant is not defined twice, except if their error message is the
/// same. This can happen across multiple files.
///
/// The generated file is written to `build_dir` (i.e. `OUT_DIR`) and included via `include!`
/// in the source.
fn generate_error_constants(asm_source_dir: &Path, build_dir: &str) -> Result<()> {
    // Miden standards errors
    // ------------------------------------------

    let errors =
        extract_all_masm_errors(asm_source_dir).context("failed to extract all masm errors")?;
    generate_error_file(
        ErrorModule {
            file_path: Path::new(build_dir).join(STANDARDS_ERRORS_RS_FILE),
            array_name: STANDARDS_ERRORS_ARRAY_NAME,
            is_crate_local: false,
        },
        errors,
    )?;

    Ok(())
}
