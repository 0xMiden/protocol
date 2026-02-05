use std::env;
use std::path::Path;

use fs_err as fs;
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr};
use miden_assembly::utils::Serializable;
use miden_assembly::{Assembler, Library, Report};
use miden_crypto::hash::keccak::{Keccak256, Keccak256Digest};
use miden_protocol::transaction::TransactionKernel;

// CONSTANTS
// ================================================================================================

/// Defines whether the build script should generate files in `/src`.
/// The docs.rs build pipeline has a read-only filesystem, so we have to avoid writing to `src`,
/// otherwise the docs will fail to build there. Note that writing to `OUT_DIR` is fine.
const BUILD_GENERATED_FILES_IN_SRC: bool = option_env!("BUILD_GENERATED_FILES_IN_SRC").is_some();

const ASSETS_DIR: &str = "assets";
const ASM_DIR: &str = "asm";
const ASM_NOTE_SCRIPTS_DIR: &str = "note_scripts";
const ASM_BRIDGE_DIR: &str = "bridge";

const AGGLAYER_ERRORS_FILE: &str = "src/errors/agglayer.rs";
const AGGLAYER_ERRORS_ARRAY_NAME: &str = "AGGLAYER_ERRORS";

// PRE-PROCESSING
// ================================================================================================

/// Read and parse the contents from `./asm`.
/// - Compiles the contents of asm/note_scripts directory into individual .masb files.
/// - Compiles the contents of asm/account_components directory into individual .masl files.
fn main() -> Result<()> {
    // re-build when the MASM code changes
    println!("cargo::rerun-if-changed={ASM_DIR}/");
    println!("cargo::rerun-if-env-changed=BUILD_GENERATED_FILES_IN_SRC");

    // Copies the MASM code to the build directory
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_dir = env::var("OUT_DIR").unwrap();
    let src = Path::new(&crate_dir).join(ASM_DIR);

    // generate canonical zeros in `asm/bridge/canonical_zeros.masm`
    generate_canonical_zeros(&src.join(ASM_BRIDGE_DIR))?;

    let dst = Path::new(&build_dir).to_path_buf();
    shared::copy_directory(src, &dst, ASM_DIR)?;

    // set source directory to {OUT_DIR}/asm
    let source_dir = dst.join(ASM_DIR);

    // set target directory to {OUT_DIR}/assets
    let target_dir = Path::new(&build_dir).join(ASSETS_DIR);

    // compile agglayer library
    let agglayer_lib =
        compile_agglayer_lib(&source_dir, &target_dir, TransactionKernel::assembler())?;

    let mut assembler = TransactionKernel::assembler();
    assembler.link_static_library(agglayer_lib)?;

    // compile note scripts
    compile_note_scripts(
        &source_dir.join(ASM_NOTE_SCRIPTS_DIR),
        &target_dir.join(ASM_NOTE_SCRIPTS_DIR),
        assembler.clone(),
    )?;

    generate_error_constants(&source_dir)?;

    Ok(())
}

// COMPILE AGGLAYER LIB
// ================================================================================================

/// Reads the MASM files from "{source_dir}/bridge" directory, compiles them into a Miden
/// assembly library, saves the library into "{target_dir}/agglayer.masl", and returns the compiled
/// library.
fn compile_agglayer_lib(
    source_dir: &Path,
    target_dir: &Path,
    mut assembler: Assembler,
) -> Result<Library> {
    let source_dir = source_dir.join(ASM_BRIDGE_DIR);

    // Add the miden-standards library to the assembler so agglayer components can use it
    let standards_lib = miden_standards::StandardsLib::default();
    assembler.link_static_library(standards_lib)?;

    let agglayer_lib = assembler.assemble_library_from_dir(source_dir, "miden::agglayer")?;

    let output_file = target_dir.join("agglayer").with_extension(Library::LIBRARY_EXTENSION);
    agglayer_lib.write_to_file(output_file).into_diagnostic()?;

    Ok(agglayer_lib)
}

// COMPILE EXECUTABLE MODULES
// ================================================================================================

/// Reads all MASM files from the "{source_dir}", complies each file individually into a MASB
/// file, and stores the compiled files into the "{target_dir}".
///
/// The source files are expected to contain executable programs.
fn compile_note_scripts(
    source_dir: &Path,
    target_dir: &Path,
    mut assembler: Assembler,
) -> Result<()> {
    fs::create_dir_all(target_dir)
        .into_diagnostic()
        .wrap_err("failed to create note_scripts directory")?;

    // Add the miden-standards library to the assembler so note scripts can use it
    let standards_lib = miden_standards::StandardsLib::default();
    assembler.link_static_library(standards_lib)?;

    for masm_file_path in shared::get_masm_files(source_dir).unwrap() {
        // read the MASM file, parse it, and serialize the parsed AST to bytes
        let code = assembler.clone().assemble_program(masm_file_path.clone())?;

        let bytes = code.to_bytes();

        let masm_file_name = masm_file_path
            .file_name()
            .expect("file name should exist")
            .to_str()
            .ok_or_else(|| Report::msg("failed to convert file name to &str"))?;
        let mut masb_file_path = target_dir.join(masm_file_name);

        // write the binary MASB to the output dir
        masb_file_path.set_extension("masb");
        fs::write(masb_file_path, bytes).unwrap();
    }
    Ok(())
}

// COMPILE ACCOUNT COMPONENTS (DEPRECATED)
// ================================================================================================

/// Compiles the agglayer library in `source_dir` into MASL libraries and stores the compiled
/// files in `target_dir`.
///
/// NOTE: This function is deprecated and replaced by compile_agglayer_lib
fn _compile_bridge_components(
    source_dir: &Path,
    target_dir: &Path,
    mut assembler: Assembler,
) -> Result<Library> {
    if !target_dir.exists() {
        fs::create_dir_all(target_dir).unwrap();
    }

    // Add the miden-standards library to the assembler so agglayer components can use it
    let standards_lib = miden_standards::StandardsLib::default();
    assembler.link_static_library(standards_lib)?;

    // Compile all components together as a single library under the "miden::agglayer" namespace
    // This allows cross-references between components (e.g., bridge_out using
    // miden::agglayer::local_exit_tree)
    let agglayer_library = assembler.assemble_library_from_dir(source_dir, "miden::agglayer")?;

    // Write the combined library
    let library_path = target_dir.join("agglayer").with_extension(Library::LIBRARY_EXTENSION);
    agglayer_library.write_to_file(library_path).into_diagnostic()?;

    // Also write individual component files for reference
    let masm_files = shared::get_masm_files(source_dir).unwrap();
    for masm_file_path in &masm_files {
        let component_name = masm_file_path
            .file_stem()
            .expect("masm file should have a file stem")
            .to_str()
            .expect("file stem should be valid UTF-8")
            .to_owned();

        let component_source_code = fs::read_to_string(masm_file_path)
            .expect("reading the component's MASM source code should succeed");

        let individual_file_path = target_dir.join(&component_name).with_extension("masm");
        fs::write(individual_file_path, component_source_code).into_diagnostic()?;
    }

    Ok(agglayer_library)
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

    // Miden agglayer errors
    // ------------------------------------------

    let errors = shared::extract_all_masm_errors(asm_source_dir)
        .context("failed to extract all masm errors")?;
    shared::generate_error_file(
        shared::ErrorModule {
            file_name: AGGLAYER_ERRORS_FILE,
            array_name: AGGLAYER_ERRORS_ARRAY_NAME,
            is_crate_local: false,
        },
        errors,
    )?;

    Ok(())
}

// CANONICAL ZEROS FILE GENERATION
// ================================================================================================

fn generate_canonical_zeros(target_dir: &Path) -> Result<()> {
    if !BUILD_GENERATED_FILES_IN_SRC {
        return Ok(());
    }

    const TREE_HEIGHT: u8 = 32;

    let mut zeros_by_height = Vec::with_capacity(TREE_HEIGHT as usize);

    // Push the zero of height 0 to the zeros vec. This is done separately because the zero of
    // height 0 is just a plain zero array ([0u8; 32]), it doesn't require to perform any hashing.
    zeros_by_height.push(Keccak256Digest::default());

    // Compute the canonical zeros for each height from 1 to TREE_HEIGHT
    // Zero of height `n` is computed as: `ZERO_N = Keccak256::merge(ZERO_{N-1}, ZERO_{N-1})`
    for _ in 1..TREE_HEIGHT {
        let current_height_zero =
            Keccak256::merge(&[*zeros_by_height.last().unwrap(), *zeros_by_height.last().unwrap()]);
        zeros_by_height.push(current_height_zero);
    }

    // convert the keccak digest into the sequence of u32 values and create two word constants from
    // them to represent the hash
    let mut zero_constants = String::from(
        "# This file is generated by build.rs, do not modify\n
# This file contains the canonical zeros for the Keccak hash function. 
# Zero of height `n` (ZERO_N) is the root of the binary tree of height `n` with leaves equal zero.
# 
# Since the Keccak hash is represented by eight u32 values, each constant consists of two Words.\n",
    );

    for (height, zero) in zeros_by_height.iter().enumerate() {
        let zero_as_u32_vec = zero
            .chunks(4)
            .map(|chunk_u32| u32::from_le_bytes(chunk_u32.try_into().unwrap()).to_string())
            .rev()
            .collect::<Vec<String>>();

        zero_constants.push_str(&format!(
            "\nconst ZERO_{height}_L = [{}]\n",
            zero_as_u32_vec[..4].join(", ")
        ));
        zero_constants
            .push_str(&format!("const ZERO_{height}_R = [{}]\n", zero_as_u32_vec[4..].join(", ")));
    }

    // remove once CANONICAL_ZEROS advice map is available
    zero_constants.push_str(
        "
use ::miden::agglayer::mmr_frontier32_keccak::mem_store_double_word
    
#! Inputs:  [zeros_ptr]
#! Outputs: []
pub proc load_zeros_to_memory\n",
    );

    for zero_index in 0..32 {
        zero_constants.push_str(&format!("\tpush.ZERO_{zero_index}_L.ZERO_{zero_index}_R exec.mem_store_double_word dropw dropw add.8\n"));
    }

    zero_constants.push_str("\tdrop\nend\n");

    // write the resulting masm content into the file
    fs::write(target_dir.join("canonical_zeros.masm"), zero_constants).into_diagnostic()?;

    Ok(())
}

/// This module should be kept in sync with the copy in miden-protocol's and miden-standards'
/// build.rs.
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

    /// Returns a vector with paths to all MASM files in the specified directory.
    ///
    /// All non-MASM files are skipped.
    pub fn get_masm_files<P: AsRef<Path>>(dir_path: P) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        let path = dir_path.as_ref();
        if path.is_dir() {
            let entries = fs::read_dir(path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read directory {}", path.display()))?;
            for entry in entries {
                let file = entry.into_diagnostic().wrap_err("failed to read directory entry")?;
                let file_path = file.path();
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
