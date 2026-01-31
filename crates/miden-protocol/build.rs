use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::Path;
use std::sync::Arc;

use fs_err as fs;
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr, miette};
use miden_assembly::{Assembler, DefaultSourceManager, KernelLibrary, Library};
use regex::Regex;
use walkdir::WalkDir;

// CONSTANTS
// ================================================================================================

/// Defines whether the build script should generate files in `/src`.
/// The docs.rs build pipeline has a read-only filesystem, so we have to avoid writing to `src`,
/// otherwise the docs will fail to build there. Note that writing to `OUT_DIR` is fine.
const BUILD_GENERATED_FILES_IN_SRC: bool = option_env!("BUILD_GENERATED_FILES_IN_SRC").is_some();

const ASSETS_DIR: &str = "assets";
const ASM_DIR: &str = "asm";
const ASM_PROTOCOL_DIR: &str = "protocol";

const SHARED_UTILS_DIR: &str = "shared_utils";
const SHARED_MODULES_DIR: &str = "shared_modules";
const ASM_TX_KERNEL_DIR: &str = "kernels/transaction";
const KERNEL_PROCEDURES_RS_FILE: &str = "src/transaction/kernel/procedures.rs";

const PROTOCOL_LIB_NAMESPACE: &str = "miden::protocol";

const TX_KERNEL_ERRORS_FILE: &str = "src/errors/tx_kernel.rs";
const PROTOCOL_LIB_ERRORS_FILE: &str = "src/errors/protocol.rs";

const TX_KERNEL_ERRORS_ARRAY_NAME: &str = "TX_KERNEL_ERRORS";
const PROTOCOL_LIB_ERRORS_ARRAY_NAME: &str = "PROTOCOL_LIB_ERRORS";

const TX_KERNEL_ERROR_CATEGORIES: [&str; 14] = [
    "KERNEL",
    "PROLOGUE",
    "EPILOGUE",
    "TX",
    "NOTE",
    "ACCOUNT",
    "FOREIGN_ACCOUNT",
    "FAUCET",
    "FUNGIBLE_ASSET",
    "NON_FUNGIBLE_ASSET",
    "VAULT",
    "LINK_MAP",
    "INPUT_NOTE",
    "OUTPUT_NOTE",
];

// PRE-PROCESSING
// ================================================================================================

/// Read and parse the contents from `./asm`.
/// - Compiles the contents of asm/protocol directory into a Protocol library file (.masl) under
///   miden::protocol namespace.
/// - Compiles the contents of asm/kernels into the transaction kernel library.
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

    // copy the shared modules to the kernel and protocol library folders
    copy_shared_modules(&source_dir)?;

    // set target directory to {OUT_DIR}/assets
    let target_dir = Path::new(&build_dir).join(ASSETS_DIR);

    // compile transaction kernel
    let mut assembler =
        compile_tx_kernel(&source_dir.join(ASM_TX_KERNEL_DIR), &target_dir.join("kernels"))?;

    // compile protocol library
    let protocol_lib = compile_protocol_lib(&source_dir, &target_dir, assembler.clone())?;
    assembler.link_dynamic_library(protocol_lib)?;

    generate_error_constants(&source_dir)?;

    generate_event_constants(&source_dir, &target_dir)?;

    Ok(())
}

// COMPILE TRANSACTION KERNEL
// ================================================================================================

/// Reads the transaction kernel MASM source from the `source_dir`, compiles it, saves the results
/// to the `target_dir`, and returns an [Assembler] instantiated with the compiled kernel.
///
/// Additionally it compiles the transaction script executor program, see the
/// [compile_tx_script_main] procedure for details.
///
/// `source_dir` is expected to have the following structure:
///
/// - {source_dir}/api.masm       -> defines exported procedures from the transaction kernel.
/// - {source_dir}/main.masm      -> defines the executable program of the transaction kernel.
/// - {source_dir}/tx_script_main -> defines the executable program of the arbitrary transaction
///   script.
/// - {source_dir}/lib            -> contains common modules used by both api.masm and main.masm.
///
/// The compiled files are written as follows:
///
/// - {target_dir}/tx_kernel.masl             -> contains kernel library compiled from api.masm.
/// - {target_dir}/tx_kernel.masb             -> contains the executable compiled from main.masm.
/// - {target_dir}/tx_script_main.masb        -> contains the executable compiled from
///   tx_script_main.masm.
/// - src/transaction/procedures/kernel_v0.rs -> contains the kernel procedures table.
fn compile_tx_kernel(source_dir: &Path, target_dir: &Path) -> Result<Assembler> {
    let shared_utils_path = std::path::Path::new(ASM_DIR).join(SHARED_UTILS_DIR);
    let kernel_path = miden_assembly::Path::kernel_path();

    let mut assembler = build_assembler(None)?;
    // add the shared util modules to the kernel lib under the ::$kernel::util namespace
    assembler.compile_and_statically_link_from_dir(&shared_utils_path, kernel_path)?;

    // assemble the kernel library and write it to the "tx_kernel.masl" file
    let kernel_lib = assembler
        .assemble_kernel_from_dir(source_dir.join("api.masm"), Some(source_dir.join("lib")))?;

    // generate kernel `procedures.rs` file
    generate_kernel_proc_hash_file(kernel_lib.clone())?;

    let output_file = target_dir.join("tx_kernel").with_extension(Library::LIBRARY_EXTENSION);
    kernel_lib.write_to_file(output_file).into_diagnostic()?;

    let assembler = build_assembler(Some(kernel_lib))?;

    // assemble the kernel program and write it to the "tx_kernel.masb" file
    let mut main_assembler = assembler.clone();
    // add the shared util modules to the kernel lib under the ::$kernel::util namespace
    main_assembler.compile_and_statically_link_from_dir(&shared_utils_path, kernel_path)?;
    main_assembler.compile_and_statically_link_from_dir(source_dir.join("lib"), kernel_path)?;

    let main_file_path = source_dir.join("main.masm");
    let kernel_main = main_assembler.clone().assemble_program(main_file_path)?;

    let masb_file_path = target_dir.join("tx_kernel.masb");
    kernel_main.write_to_file(masb_file_path).into_diagnostic()?;

    // compile the transaction script main program
    compile_tx_script_main(source_dir, target_dir, main_assembler)?;

    #[cfg(any(feature = "testing", test))]
    {
        let mut kernel_lib_assembler = assembler.clone();
        // Build kernel as a library and save it to file.
        // This is needed in test assemblers to access individual procedures which would otherwise
        // be hidden when using KernelLibrary (api.masm)

        // add the shared util modules to the kernel lib under the ::$kernel::util namespace
        kernel_lib_assembler
            .compile_and_statically_link_from_dir(&shared_utils_path, kernel_path)?;

        let test_lib = kernel_lib_assembler
            .assemble_library_from_dir(source_dir.join("lib"), kernel_path)
            .unwrap();

        let masb_file_path =
            target_dir.join("kernel_library").with_extension(Library::LIBRARY_EXTENSION);
        test_lib.write_to_file(masb_file_path).into_diagnostic()?;
    }

    Ok(assembler)
}

/// Reads the transaction script executor MASM source from the `source_dir/tx_script_main.masm`,
/// compiles it and saves the results to the `target_dir` as a `tx_script_main.masb` binary file.
fn compile_tx_script_main(
    source_dir: &Path,
    target_dir: &Path,
    main_assembler: Assembler,
) -> Result<()> {
    // assemble the transaction script executor program and write it to the "tx_script_main.masb"
    // file.
    let tx_script_main_file_path = source_dir.join("tx_script_main.masm");
    let tx_script_main = main_assembler.assemble_program(tx_script_main_file_path)?;

    let masb_file_path = target_dir.join("tx_script_main.masb");
    tx_script_main.write_to_file(masb_file_path).into_diagnostic()
}

/// Generates kernel `procedures.rs` file based on the kernel library
fn generate_kernel_proc_hash_file(kernel: KernelLibrary) -> Result<()> {
    // Because the kernel Rust file will be stored under ./src, this should be a no-op if we can't
    // write there
    if !BUILD_GENERATED_FILES_IN_SRC {
        return Ok(());
    }

    let (_, module_info, _) = kernel.into_parts();

    let to_exclude = BTreeSet::from_iter(["exec_kernel_proc"]);
    let offsets_filename =
        Path::new(ASM_DIR).join(ASM_PROTOCOL_DIR).join("kernel_proc_offsets.masm");
    let offsets = parse_proc_offsets(&offsets_filename)?;

    let generated_procs: BTreeMap<usize, String> = module_info
        .procedures()
        .filter(|(_, proc_info)| !to_exclude.contains::<str>(proc_info.name.as_ref()))
        .map(|(_, proc_info)| {
            let name = proc_info.name.to_string();

            let Some(&offset) = offsets.get(&name) else {
                panic!("Offset constant for function `{name}` not found in `{offsets_filename:?}`");
            };

            (offset, format!("    // {name}\n    word!(\"{}\"),", proc_info.digest))
        })
        .collect();

    let proc_count = generated_procs.len();
    let generated_procs: String = generated_procs.into_iter().enumerate().map(|(index, (offset, txt))| {
        if index != offset {
            panic!("Offset constants in the file `{offsets_filename:?}` are not contiguous (missing offset: {index})");
        }

        txt
    }).collect::<Vec<_>>().join("\n");

    fs::write(
        KERNEL_PROCEDURES_RS_FILE,
        format!(
            r#"// This file is generated by build.rs, do not modify

use crate::{{Word, word}};

// KERNEL PROCEDURES
// ================================================================================================

/// Hashes of all dynamically executed kernel procedures.
pub const KERNEL_PROCEDURES: [Word; {proc_count}] = [
{generated_procs}
];
"#,
        ),
    )
    .into_diagnostic()
}

fn parse_proc_offsets(filename: impl AsRef<Path>) -> Result<BTreeMap<String, usize>> {
    let regex: Regex = Regex::new(r"^const\s*(?P<name>\w+)_OFFSET\s*=\s*(?P<offset>\d+)").unwrap();
    let mut result = BTreeMap::new();
    for line in fs::read_to_string(filename).into_diagnostic()?.lines() {
        if let Some(captures) = regex.captures(line) {
            result.insert(
                captures["name"].to_string().to_lowercase(),
                captures["offset"].parse().into_diagnostic()?,
            );
        }
    }

    Ok(result)
}

// COMPILE PROTOCOL LIB
// ================================================================================================

/// Reads the MASM files from "{source_dir}/protocol" directory, compiles them into a Miden assembly
/// library, saves the library into "{target_dir}/protocol.masl", and returns the compiled library.
fn compile_protocol_lib(
    source_dir: &Path,
    target_dir: &Path,
    mut assembler: Assembler,
) -> Result<Library> {
    let source_dir = source_dir.join(ASM_PROTOCOL_DIR);
    let shared_path = Path::new(ASM_DIR).join(SHARED_UTILS_DIR);

    // add the shared modules to the protocol lib under the miden::protocol::util namespace
    // note that this module is not publicly exported, it is only available for linking the library
    // itself
    assembler.compile_and_statically_link_from_dir(&shared_path, PROTOCOL_LIB_NAMESPACE)?;

    let protocol_lib = assembler.assemble_library_from_dir(source_dir, PROTOCOL_LIB_NAMESPACE)?;

    let output_file = target_dir.join("protocol").with_extension(Library::LIBRARY_EXTENSION);
    protocol_lib.write_to_file(output_file).into_diagnostic()?;

    Ok(protocol_lib)
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a new [Assembler] loaded with miden-core-lib and the specified kernel, if provided.
fn build_assembler(kernel: Option<KernelLibrary>) -> Result<Assembler> {
    kernel
        .map(|kernel| Assembler::with_kernel(Arc::new(DefaultSourceManager::default()), kernel))
        .unwrap_or_default()
        .with_dynamic_library(miden_core_lib::CoreLibrary::default())
}

/// Copies the content of the build `shared_modules` folder to the `lib` and `protocol` build
/// folders. This is required to include the shared modules as APIs of the `kernel` and `protocol`
/// libraries.
///
/// This is done to make it possible to import the modules in the `shared_modules` folder directly,
/// i.e. "use $kernel::account_id".
fn copy_shared_modules<T: AsRef<Path>>(source_dir: T) -> Result<()> {
    // source is expected to be an `OUT_DIR/asm` folder
    let shared_modules_dir = source_dir.as_ref().join(SHARED_MODULES_DIR);

    for module_path in shared::get_masm_files(shared_modules_dir).unwrap() {
        let module_name = module_path.file_name().unwrap();

        // copy to kernel lib
        let kernel_lib_folder = source_dir.as_ref().join(ASM_TX_KERNEL_DIR).join("lib");
        fs::copy(&module_path, kernel_lib_folder.join(module_name)).into_diagnostic()?;

        // copy to protocol lib
        let protocol_lib_folder = source_dir.as_ref().join(ASM_PROTOCOL_DIR);
        fs::copy(&module_path, protocol_lib_folder.join(module_name)).into_diagnostic()?;
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
/// The function ensures that a constant is not defined twice, except if their error message is
/// the same. This can happen across multiple files.
///
/// Because the error files will be written to ./src/errors, this should be a no-op if ./src is
/// read-only. To enable writing to ./src, set the `BUILD_GENERATED_FILES_IN_SRC` environment
/// variable.
fn generate_error_constants(asm_source_dir: &Path) -> Result<()> {
    if !BUILD_GENERATED_FILES_IN_SRC {
        return Ok(());
    }

    // Transaction kernel errors
    // ------------------------------------------

    let tx_kernel_dir = asm_source_dir.join(ASM_TX_KERNEL_DIR);
    let errors = shared::extract_all_masm_errors(&tx_kernel_dir)
        .context("failed to extract all masm errors")?;
    validate_tx_kernel_category(&errors)?;

    shared::generate_error_file(
        shared::ErrorModule {
            file_name: TX_KERNEL_ERRORS_FILE,
            array_name: TX_KERNEL_ERRORS_ARRAY_NAME,
            is_crate_local: true,
        },
        errors,
    )?;

    // Miden protocol library errors
    // ------------------------------------------

    let protocol_dir = asm_source_dir.join(ASM_PROTOCOL_DIR);
    let errors = shared::extract_all_masm_errors(&protocol_dir)
        .context("failed to extract all masm errors")?;

    shared::generate_error_file(
        shared::ErrorModule {
            file_name: PROTOCOL_LIB_ERRORS_FILE,
            array_name: PROTOCOL_LIB_ERRORS_ARRAY_NAME,
            is_crate_local: true,
        },
        errors,
    )?;

    Ok(())
}

/// Validates that all error names in the provided slice start with a known tx kernel error
/// category.
fn validate_tx_kernel_category(errors: &[shared::NamedError]) -> Result<()> {
    for error in errors {
        if !TX_KERNEL_ERROR_CATEGORIES
            .iter()
            .any(|known_category| error.name.starts_with(known_category))
        {
            return Err(miette::miette!(
                "error `{}` does not start with a known tx kernel error category",
                error.name
            ));
        }
    }

    Ok(())
}

// EVENT CONSTANTS FILE GENERATION
// ================================================================================================

/// Reads all MASM files from the `asm_source_dir` and extracts event definitions,
/// then generates the transaction_events.rs file with constants.
fn generate_event_constants(asm_source_dir: &Path, target_dir: &Path) -> Result<()> {
    // Extract all event definitions from MASM files
    let events = extract_all_event_definitions(asm_source_dir)?;

    // Generate the events file in OUT_DIR
    let event_file_content = generate_event_file_content(&events).into_diagnostic()?;
    let event_file_path = target_dir.join("transaction_events.rs");
    fs::write(event_file_path, event_file_content).into_diagnostic()?;

    Ok(())
}

/// Extract all `const X=event("x")` definitions from all MASM files
fn extract_all_event_definitions(asm_source_dir: &Path) -> Result<BTreeMap<String, String>> {
    // collect mappings event path to const variable name, we want a unique mapping
    // which we use to generate the constants and enum variant names
    let mut events = BTreeMap::new();

    // Walk all MASM files
    for entry in WalkDir::new(asm_source_dir) {
        let entry = entry.into_diagnostic()?;
        if !shared::is_masm_file(entry.path()).into_diagnostic()? {
            continue;
        }
        let file_contents = fs::read_to_string(entry.path()).into_diagnostic()?;
        extract_event_definitions_from_file(&mut events, &file_contents, entry.path())?;
    }

    Ok(events)
}

/// Extract event definitions from a single MASM file in form of `const ${X} = event("${x::path}")`.
fn extract_event_definitions_from_file(
    events: &mut BTreeMap<String, String>,
    file_contents: &str,
    file_path: &Path,
) -> Result<()> {
    let regex = Regex::new(r#"const\s*(\w+)\s*=\s*event\("([^"]+)"\)"#).unwrap();

    for capture in regex.captures_iter(file_contents) {
        let const_name = capture.get(1).expect("const name should be captured");
        let event_path = capture.get(2).expect("event path should be captured");

        let event_path = event_path.as_str();
        let const_name = const_name.as_str();

        let const_name_wo_suffix =
            if let Some((const_name_wo_suffix, _)) = const_name.rsplit_once("_EVENT") {
                const_name_wo_suffix.to_string()
            } else {
                const_name.to_owned()
            };

        if !event_path.starts_with("miden::") {
            return Err(miette::miette!("unhandled `event_path={event_path}`"));
        }

        // Check for duplicates with different definitions
        if let Some(existing_const_name) = events.get(event_path) {
            if existing_const_name != &const_name_wo_suffix {
                println!(
                    "cargo:warning=Duplicate event definition found {event_path} with different definitions names:
                    '{existing_const_name}' vs '{const_name}' in {}",
                    file_path.display()
                );
            }
        } else {
            events.insert(event_path.to_owned(), const_name_wo_suffix.to_owned());
        }
    }

    Ok(())
}

/// Generate the content of the transaction_events.rs file
fn generate_event_file_content(
    events: &BTreeMap<String, String>,
) -> std::result::Result<String, std::fmt::Error> {
    use std::fmt::Write;

    let mut output = String::new();

    writeln!(&mut output, "// This file is generated by build.rs, do not modify")?;
    writeln!(&mut output)?;

    // Generate constants
    //
    // Note: If we ever encounter two constants `const X`, that are both named `X` we will error
    // when attempting to generate the rust code. Currently this is a side-effect, but we
    // want to error out as early as possible:
    // TODO: make the error out at build-time to be able to present better error hints
    for (event_path, event_name) in events {
        let value = miden_core::EventId::from_name(event_path).as_felt().as_int();
        debug_assert!(!event_name.is_empty());
        writeln!(&mut output, "const {}: u64 = {};", event_name, value)?;
    }

    {
        writeln!(&mut output)?;

        writeln!(&mut output)?;

        writeln!(
            &mut output,
            r###"
use alloc::collections::BTreeMap;

pub(crate) static EVENT_NAME_LUT: ::miden_utils_sync::LazyLock<BTreeMap<u64, &'static str>> =
    ::miden_utils_sync::LazyLock::new(|| {{
    BTreeMap::from_iter([
"###
        )?;

        for (event_path, const_name) in events {
            writeln!(&mut output, "        ({}, \"{}\"),", const_name, event_path)?;
        }

        writeln!(
            &mut output,
            r###"    ])
}});"###
        )?;
    }

    Ok(output)
}

/// This module should be kept in sync with the copy in miden-standards' build.rs.
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
