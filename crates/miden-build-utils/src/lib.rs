//! Build-time helpers shared by the `build.rs` scripts of the Miden workspace crates.
//!
//! These utilities locate MASM sources, extract MASM error constants into generated Rust
//! files, and set up the registry and assembler used to build and write MAST packages.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{env, io};

use fs_err as fs;
use miden_assembly::debuginfo::{DefaultSourceManager, SourceManager};
use miden_assembly::diagnostics::{IntoDiagnostic, Result};
use miden_assembly::{Assembler, ProjectTargetSelector, Report};
use miden_mast_package::Package;
use miden_package_registry::{InMemoryPackageRegistry, PackageCache};
use regex::Regex;
use walkdir::WalkDir;

// CONSTANTS
// ================================================================================================

/// Name of the manifest file defining a Miden project.
pub const PROJECT_MANIFEST: &str = "miden-project.toml";

/// The build profile used when assembling the Miden projects.
///
/// Packages are assembled with the debug-info (`dev`) so published packages carry debug
/// information; consumers can strip it as needed.
pub const BUILD_PROFILE: &str = "dev";

// PACKAGE ASSEMBLY HELPERS
// ================================================================================================

/// Returns a new [`Assembler`] using the provided source manager, with warnings treated as errors.
pub fn build_assembler(source_manager: Arc<dyn SourceManager>) -> Assembler {
    Assembler::new(source_manager).with_warnings_as_errors(true)
}

/// Creates an in-memory package registry seeded with `packages`.
///
/// The seed packages are the dependencies that projects assembled against this registry are
/// allowed to resolve (e.g. the core, kernel, and protocol libraries).
pub fn registry_with(
    packages: impl IntoIterator<Item = Arc<Package>>,
) -> Result<InMemoryPackageRegistry> {
    let mut registry = InMemoryPackageRegistry::default();
    for package in packages {
        registry.cache_package(package).into_diagnostic()?;
    }
    Ok(registry)
}

/// Assembles `selector` from the Miden project manifest at `manifest_path`, resolving
/// dependencies against `registry`, and returns the assembled package.
///
/// Uses a fresh default source manager and the shared [`BUILD_PROFILE`], with warnings treated
/// as errors (see [`build_assembler`]).
pub fn assemble_project_at_path(
    manifest_path: impl AsRef<Path>,
    selector: ProjectTargetSelector,
    registry: &mut InMemoryPackageRegistry,
) -> Result<Arc<Package>> {
    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    build_assembler(source_manager)
        .for_project_at_path(manifest_path.as_ref(), registry)?
        .assemble(selector, BUILD_PROFILE)
}

/// Writes the package to a fixed path: `<target>/<profile>/<name>.masp`.
pub fn write_release_package(package: &Package) -> Result<()> {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is always set for build scripts");
    let out_path = Path::new(&out_dir);
    // OUT_DIR is `<target>/<profile>/build/<pkg>-<hash>/out` so the profile dir is its 3rd
    // ancestor.
    let profile_dir = out_path
        .ancestors()
        .nth(3)
        .expect("OUT_DIR should live under <target>/<profile>/build/<pkg>/out");

    let name: &str = &package.name;
    let final_path = profile_dir.join(name).with_extension(Package::EXTENSION);

    let unique = out_path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    // Because multiple build-script runs may write this same path, the package is created as a temp
    // file and atomically renamed into place.
    let tmp_path = profile_dir.join(format!(".{name}.{unique}.masp.tmp"));

    package.write_to_file(&tmp_path).into_diagnostic()?;
    fs::rename(&tmp_path, &final_path).into_diagnostic()
}

// ERROR CONSTANTS EXTRACTION
// ================================================================================================

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

pub fn is_new_error_category<'a>(last_error: &mut Option<&'a str>, current_error: &'a str) -> bool {
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
