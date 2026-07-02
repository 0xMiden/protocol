use std::env;
use std::path::Path;
use std::sync::Arc;

use miden_assembly::debuginfo::{DefaultSourceManager, SourceManager, SourceManagerExt};
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr};
use miden_assembly::{Assembler, Library, ProjectTargetSelector};
use miden_core_lib::CoreLibrary;
use miden_mast_package::{Package, PackageId, TargetType, Version};
use miden_package_registry::{InMemoryPackageRegistry, PackageCache};
use miden_project::Workspace;
use miden_protocol::ProtocolLib;
use miden_protocol::transaction::TransactionKernel;

// CONSTANTS
// ================================================================================================

const ASSETS_DIR: &str = "assets";
const ASM_DIR: &str = "asm";
const ASM_STANDARDS_DIR: &str = "standards";
const ASM_COMPONENTS_DIR: &str = "components";

/// Name of the manifest file defining a Miden project.
const PROJECT_MANIFEST: &str = "miden-project.toml";

/// The build profile used when assembling the Miden projects.
const BUILD_PROFILE: &str = "release";

const STANDARDS_ERRORS_RS_FILE: &str = "standards_errors.rs";
const STANDARDS_ERRORS_ARRAY_NAME: &str = "STANDARDS_ERRORS";

// PRE-PROCESSING
// ================================================================================================

/// Read and parse the contents from `./asm`.
/// - Compiles the contents of asm/standards directory into a package. Note scripts are included in
///   this library.
/// - Compiles the contents of asm/components directory into individual packages.
fn main() -> Result<()> {
    // re-build when the MASM code changes
    println!("cargo::rerun-if-changed={ASM_DIR}/");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_dir = env::var("OUT_DIR").unwrap();

    // Read MASM sources directly from the crate's asm/ directory.
    // No copy to OUT_DIR is needed because this crate doesn't mutate the source tree.
    let source_dir = Path::new(&crate_dir).join(ASM_DIR);

    // set target directory to {OUT_DIR}/assets
    let target_dir = Path::new(&build_dir).join(ASSETS_DIR);

    // The miden-core library is provided through an in-memory registry
    let mut registry = build_registry()?;

    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let assembler = Assembler::new(source_manager.clone()).with_warnings_as_errors(true);

    // compile standards library (includes note scripts) and seed it into the registry
    compile_standards_lib(&source_dir, &target_dir, assembler.clone(), &mut registry)?;

    // compile account components
    compile_account_components(
        &source_dir.join(ASM_COMPONENTS_DIR),
        &target_dir.join(ASM_COMPONENTS_DIR),
        &assembler,
        &mut registry,
        source_manager,
    )?;

    generate_error_constants(&source_dir, &build_dir)?;

    Ok(())
}

// ASSEMBLER & REGISTRY
// ================================================================================================

/// Builds a package registry seeded with the protocol library and its transitive `miden-tx-kernel`
/// and `miden-core` dependencies, so that the `miden-protocol` dependency declared by the standards
/// projects can be resolved during project assembly.
fn build_registry() -> Result<InMemoryPackageRegistry> {
    let mut registry = InMemoryPackageRegistry::default();

    // The protocol and kernel packages both declare a dependency on the `miden-core` library, so it
    // must be seeded into the registry for dependency resolution to succeed. This must be
    // constructed identically to the `miden-core` package in miden-protocol's build script so that
    // its digest matches the one recorded in those dependencies.
    let core_library = Arc::new(Library::from(CoreLibrary::default()));
    let core_package = Package::from_library(
        PackageId::from("miden-core"),
        Version::new(0, 23, 4),
        TargetType::Library,
        core_library,
        core::iter::empty(),
    );

    // The protocol package declares a dependency on the `miden-tx-kernel` package, so all three
    // must be available in the registry for dependency resolution to succeed.
    for package in [
        Arc::from(core_package),
        Arc::new(Package::from(ProtocolLib::default())),
        TransactionKernel::package(),
    ] {
        registry.cache_package(package).into_diagnostic()?;
    }

    Ok(registry)
}

// COMPILE STANDARDS LIB
// ================================================================================================

/// Assembles the standards library project in "{source_dir}/standards" into a package, saves it to
/// the `target_dir`, and seeds it into the `registry`.
fn compile_standards_lib(
    source_dir: &Path,
    target_dir: &Path,
    assembler: Assembler,
    registry: &mut InMemoryPackageRegistry,
) -> Result<()> {
    let manifest_path = source_dir.join(ASM_STANDARDS_DIR).join(PROJECT_MANIFEST);

    let package = assembler
        .for_project_at_path(manifest_path, registry)?
        .assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;

    package.write_masp_file(target_dir).into_diagnostic()?;
    registry.cache_package(package).into_diagnostic()?;

    Ok(())
}

// COMPILE ACCOUNT COMPONENTS
// ================================================================================================

/// Assembles each member of the account-components workspace in `source_dir` into a package and
/// saves it to `target_dir`. Each file is named after its package (e.g.
/// `miden-standards-auth-singlesig.masp`), so the include path used by `account_component_code!`
/// is the package name.
fn compile_account_components(
    source_dir: &Path,
    target_dir: &Path,
    assembler: &Assembler,
    registry: &mut InMemoryPackageRegistry,
    source_manager: Arc<dyn SourceManager>,
) -> Result<()> {
    let manifest =
        source_manager.load_file(&source_dir.join(PROJECT_MANIFEST)).into_diagnostic()?;
    let workspace = Workspace::load(manifest, source_manager.as_ref())?;

    for component in workspace.members() {
        let package = assembler
            .clone()
            .for_project(component.clone(), registry)?
            .assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;

        package.write_masp_file(target_dir).into_diagnostic()?;
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

    let errors = shared::extract_all_masm_errors(asm_source_dir)
        .context("failed to extract all masm errors")?;
    shared::generate_error_file(
        shared::ErrorModule {
            file_path: Path::new(build_dir).join(STANDARDS_ERRORS_RS_FILE),
            array_name: STANDARDS_ERRORS_ARRAY_NAME,
            is_crate_local: false,
        },
        errors,
    )?;

    Ok(())
}

/// This module should be kept in sync with the copy in miden-protocol's build.rs.
mod shared {
    use std::collections::BTreeMap;
    use std::fmt::Write;
    use std::io::{self};
    use std::path::{Path, PathBuf};

    use fs_err as fs;
    use miden_assembly::Report;
    use miden_assembly::diagnostics::{IntoDiagnostic, Result};
    use regex::Regex;
    use walkdir::WalkDir;

    /// Returns true if the provided path resolves to a file with `.masm` extension.
    ///
    /// # Errors
    /// Returns an error if the path could not be converted to a UTF-8 string.
    pub fn is_masm_file(path: &Path) -> io::Result<bool> {
        if let Some(extension) = path.extension() {
            let extension = extension
                .to_str()
                .ok_or_else(|| io::Error::other("invalid UTF-8 filename"))?
                .to_lowercase();
            Ok(extension == "masm")
        } else {
            Ok(false)
        }
    }

    /// Extract all masm errors from the given path and returns a map by error category.
    pub fn extract_all_masm_errors(asm_source_dir: &Path) -> Result<Vec<NamedError>> {
        // We use a BTree here to order the errors by their categories which is the first part after
        // the ERR_ prefix and to allow for the same error to be defined multiple times in
        // different files (as long as the constant name and error messages match).
        let mut errors = BTreeMap::new();

        // Walk all files of the kernel source directory.
        for entry in WalkDir::new(asm_source_dir) {
            let entry = entry.into_diagnostic()?;
            if !is_masm_file(entry.path()).into_diagnostic()? {
                continue;
            }
            let file_contents = std::fs::read_to_string(entry.path()).into_diagnostic()?;
            extract_masm_errors(&mut errors, &file_contents)?;
        }

        let errors = errors
            .into_iter()
            .map(|(error_name, error)| NamedError { name: error_name, message: error.message })
            .collect();

        Ok(errors)
    }

    /// Extracts the errors from a single masm file and inserts them into the provided map.
    pub fn extract_masm_errors(
        errors: &mut BTreeMap<ErrorName, ExtractedError>,
        file_contents: &str,
    ) -> Result<()> {
        let regex = Regex::new(r#"const\s*ERR_(?<name>.*)\s*=\s*"(?<message>.*)""#).unwrap();

        for capture in regex.captures_iter(file_contents) {
            let error_name = capture
                .name("name")
                .expect("error name should be captured")
                .as_str()
                .trim()
                .to_owned();
            let error_message = capture
                .name("message")
                .expect("error code should be captured")
                .as_str()
                .trim()
                .to_owned();

            if let Some(ExtractedError { message: existing_error_message, .. }) =
                errors.get(&error_name)
                && existing_error_message != &error_message
            {
                return Err(Report::msg(format!(
                    "Transaction kernel error constant ERR_{error_name} is already defined elsewhere but its error message is different"
                )));
            }

            // Enforce the "no trailing punctuation" rule from the Rust error guidelines on MASM
            // errors.
            if error_message.ends_with(".") {
                return Err(Report::msg(format!(
                    "Error messages should not end with a period: `ERR_{error_name}: {error_message}`"
                )));
            }

            errors.insert(error_name, ExtractedError { message: error_message });
        }

        Ok(())
    }

    pub fn is_new_error_category<'a>(
        last_error: &mut Option<&'a str>,
        current_error: &'a str,
    ) -> bool {
        let is_new = match last_error {
            Some(last_err) => {
                let last_category =
                    last_err.split("_").next().expect("there should be at least one entry");
                let new_category =
                    current_error.split("_").next().expect("there should be at least one entry");
                last_category != new_category
            },
            None => false,
        };

        last_error.replace(current_error);

        is_new
    }

    /// Generates the content of an error file for the given category and the set of errors and
    /// writes it to the file at the path specified in the module.
    pub fn generate_error_file(module: ErrorModule, errors: Vec<NamedError>) -> Result<()> {
        let mut output = String::new();

        if module.is_crate_local {
            writeln!(output, "use crate::errors::MasmError;\n").unwrap();
        } else {
            writeln!(output, "use miden_protocol::errors::MasmError;\n").unwrap();
        }

        writeln!(
            output,
            "// This file is generated by build.rs, do not modify manually.
// It is generated by extracting errors from the MASM files in the `./asm` directory.
//
// To add a new error, define a constant in MASM of the pattern `const ERR_<CATEGORY>_...`.
// Try to fit the error into a pre-existing category if possible (e.g. Account, Note, ...).
"
        )
        .unwrap();

        writeln!(
            output,
            "// {}
// ================================================================================================
",
            module.array_name.replace("_", " ")
        )
        .unwrap();

        let mut last_error = None;
        for named_error in errors.iter() {
            let NamedError { name, message } = named_error;

            // Group errors into blocks separate by newlines.
            if is_new_error_category(&mut last_error, name) {
                writeln!(output).into_diagnostic()?;
            }

            writeln!(output, "/// Error Message: \"{message}\"").into_diagnostic()?;
            writeln!(
                output,
                r#"pub const ERR_{name}: MasmError = MasmError::from_static_str("{message}");"#
            )
            .into_diagnostic()?;
        }

        fs::write(module.file_path, output).into_diagnostic()?;

        Ok(())
    }

    pub type ErrorName = String;

    #[derive(Debug, Clone)]
    pub struct ExtractedError {
        pub message: String,
    }

    #[derive(Debug, Clone)]
    pub struct NamedError {
        pub name: ErrorName,
        pub message: String,
    }

    #[derive(Debug, Clone)]
    pub struct ErrorModule {
        pub file_path: PathBuf,
        pub array_name: &'static str,
        pub is_crate_local: bool,
    }
}
