use std::env;
use std::path::Path;

use fs_err as fs;
use miden_assembly::diagnostics::{IntoDiagnostic, NamedSource, Result, WrapErr};
use miden_assembly::{Assembler, Library};
use miden_protocol::transaction::TransactionKernel;

// CONSTANTS
// ================================================================================================

/// Defines whether the build script should generate files in `/src`.
/// The docs.rs build pipeline has a read-only filesystem, so we have to avoid writing to `src`,
/// otherwise the docs will fail to build there. Note that writing to `OUT_DIR` is fine.
const BUILD_GENERATED_FILES_IN_SRC: bool = option_env!("BUILD_GENERATED_FILES_IN_SRC").is_some();

const ASSETS_DIR: &str = "assets";
const ASM_DIR: &str = "asm";
const ASM_STANDARDS_DIR: &str = "standards";
const ASM_ACCOUNT_COMPONENTS_DIR: &str = "account_components";

const STANDARDS_LIB_NAMESPACE: &str = "miden::standards";

const STANDARDS_ERRORS_FILE: &str = "src/errors/standards.rs";
const STANDARDS_ERRORS_ARRAY_NAME: &str = "STANDARDS_ERRORS";

// PRE-PROCESSING
// ================================================================================================

/// Read and parse the contents from `./asm`.
/// - Compiles the contents of asm/standards directory into a Miden library file (.masl) under
///   standards namespace. Note scripts are included in this library.
/// - Compiles the contents of asm/account_components directory into individual .masl files.
fn main() -> Result<()> {
    // re-build when the MASM code changes
    println!("cargo::rerun-if-changed={ASM_DIR}/");
    println!("cargo::rerun-if-env-changed=BUILD_GENERATED_FILES_IN_SRC");

    // Copies the MASM code to the build directory
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_dir = env::var("OUT_DIR").unwrap();
    let src = Path::new(&crate_dir).join(ASM_DIR);
    let dst = Path::new(&build_dir).to_path_buf();
    shared::copy_directory(src, &dst, ASM_DIR)?;

    // set source directory to {OUT_DIR}/asm
    let source_dir = dst.join(ASM_DIR);

    // set target directory to {OUT_DIR}/assets
    let target_dir = Path::new(&build_dir).join(ASSETS_DIR);

    // compile standards library (includes note scripts)
    let standards_lib =
        compile_standards_lib(&source_dir, &target_dir, TransactionKernel::assembler())?;

    let mut assembler = TransactionKernel::assembler();
    assembler.link_static_library(standards_lib)?;

    // compile account components
    compile_account_components(
        &source_dir.join(ASM_ACCOUNT_COMPONENTS_DIR),
        &target_dir.join(ASM_ACCOUNT_COMPONENTS_DIR),
        assembler,
    )?;

    generate_error_constants(&source_dir)?;

    Ok(())
}

// COMPILE PROTOCOL LIB
// ================================================================================================

/// Reads the MASM files from "{source_dir}/standards" directory, compiles them into a Miden
/// assembly library, saves the library into "{target_dir}/standards.masl", and returns the compiled
/// library.
fn compile_standards_lib(
    source_dir: &Path,
    target_dir: &Path,
    assembler: Assembler,
) -> Result<Library> {
    let source_dir = source_dir.join(ASM_STANDARDS_DIR);

    let standards_lib = assembler.assemble_library_from_dir(source_dir, STANDARDS_LIB_NAMESPACE)?;

    let output_file = target_dir.join("standards").with_extension(Library::LIBRARY_EXTENSION);
    standards_lib.write_to_file(output_file).into_diagnostic()?;

    Ok(standards_lib)
}

// COMPILE ACCOUNT COMPONENTS
// ================================================================================================

/// Compiles the account components in `source_dir` into MASL libraries and stores the compiled
/// files in `target_dir`, preserving the subdirectory structure.
fn compile_account_components(
    source_dir: &Path,
    target_dir: &Path,
    assembler: Assembler,
) -> Result<()> {
    if !target_dir.exists() {
        fs::create_dir_all(target_dir).unwrap();
    }

    for masm_file_path in shared::get_masm_files(source_dir).unwrap() {
        let component_name = masm_file_path
            .file_stem()
            .expect("masm file should have a file stem")
            .to_str()
            .expect("file stem should be valid UTF-8")
            .to_owned();

        let component_source_code = fs::read_to_string(&masm_file_path)
            .expect("reading the component's MASM source code should succeed");

        let named_source = NamedSource::new(component_name.clone(), component_source_code);

        let component_library = assembler
            .clone()
            .assemble_library([named_source])
            .expect("library assembly should succeed");

        // Preserve the subdirectory structure: compute relative path from source_dir
        let relative_dir = masm_file_path
            .parent()
            .and_then(|p| p.strip_prefix(source_dir).ok())
            .unwrap_or(Path::new(""));

        let output_dir = target_dir.join(relative_dir);
        if !output_dir.exists() {
            fs::create_dir_all(&output_dir).unwrap();
        }

        let component_file_path =
            output_dir.join(component_name).with_extension(Library::LIBRARY_EXTENSION);
        component_library.write_to_file(component_file_path).into_diagnostic()?;
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
/// Because the error files will be written to ./src/errors, this should be a no-op if ./src is
/// read-only. To enable writing to ./src, set the `BUILD_GENERATED_FILES_IN_SRC` environment
/// variable.
fn generate_error_constants(asm_source_dir: &Path) -> Result<()> {
    if !BUILD_GENERATED_FILES_IN_SRC {
        return Ok(());
    }

    // Miden standards errors
    // ------------------------------------------

    let errors = shared::extract_all_masm_errors(asm_source_dir)
        .context("failed to extract all masm errors")?;
    shared::generate_error_file(
        shared::ErrorModule {
            file_name: STANDARDS_ERRORS_FILE,
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
    use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr};
    use regex::Regex;
    use walkdir::WalkDir;

    /// Recursively copies `src` into `dst`.
    ///
    /// This function will overwrite the existing files if re-executed.
    pub fn copy_directory<T: AsRef<Path>, R: AsRef<Path>>(
        src: T,
        dst: R,
        asm_dir: &str,
    ) -> Result<()> {
        let mut prefix = src.as_ref().canonicalize().unwrap();
        // keep all the files inside the `asm` folder
        prefix.pop();

        let target_dir = dst.as_ref().join(asm_dir);
        if target_dir.exists() {
            // Clear existing asm files that were copied earlier which may no longer exist.
            fs::remove_dir_all(&target_dir)
                .into_diagnostic()
                .wrap_err("failed to remove ASM directory")?;
        }

        // Recreate the directory structure.
        fs::create_dir_all(&target_dir)
            .into_diagnostic()
            .wrap_err("failed to create ASM directory")?;

        let dst = dst.as_ref();
        let mut todo = vec![src.as_ref().to_path_buf()];

        while let Some(goal) = todo.pop() {
            for entry in fs::read_dir(goal).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    let src_dir = path.canonicalize().unwrap();
                    let dst_dir = dst.join(src_dir.strip_prefix(&prefix).unwrap());
                    if !dst_dir.exists() {
                        fs::create_dir_all(&dst_dir).unwrap();
                    }
                    todo.push(src_dir);
                } else {
                    let dst_file = dst.join(path.strip_prefix(&prefix).unwrap());
                    fs::copy(&path, dst_file).unwrap();
                }
            }
        }

        Ok(())
    }

    /// Returns a vector with paths to all MASM files in the specified directory and its
    /// subdirectories.
    ///
    /// All non-MASM files are skipped.
    pub fn get_masm_files<P: AsRef<Path>>(dir_path: P) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        let path = dir_path.as_ref();
        if path.is_dir() {
            for entry in WalkDir::new(path) {
                let entry = entry.into_diagnostic()?;
                let file_path = entry.path().to_path_buf();
                if is_masm_file(&file_path).into_diagnostic()? {
                    files.push(file_path);
                }
            }
        } else {
            println!("cargo:warn=The specified path is not a directory.");
        }

        Ok(files)
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
    /// writes it to the category's file.
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

        std::fs::write(module.file_name, output).into_diagnostic()?;

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

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct ErrorModule {
        pub file_name: &'static str,
        pub array_name: &'static str,
        pub is_crate_local: bool,
    }
}
