use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::Path;
use std::sync::Arc;

use fs_err as fs;
use miden_assembly::debuginfo::{DefaultSourceManager, SourceManager};
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr, miette};
use miden_assembly::{Assembler, KernelLibrary, Library, ProjectTargetSelector};
use miden_core::events::EventId;
use miden_mast_package::{Package, PackageId, TargetType, Version};
use miden_package_registry::{InMemoryPackageRegistry, PackageCache};
use regex::Regex;
use walkdir::WalkDir;

// CONSTANTS
// ================================================================================================

const ASSETS_DIR: &str = "assets";
const ASM_DIR: &str = "asm";
const ASM_PROTOCOL_DIR: &str = "protocol";

const ASM_PROTOCOL_UTILS_DIR: &str = "protocol_utils";
const ASM_TX_KERNEL_DIR: &str = "kernels/transaction";
const ASM_TX_KERNEL_CORE_DIR: &str = "kernels/transaction-core";
const ASM_BATCH_KERNEL_DIR: &str = "kernels/batch";

/// Name of the manifest file defining a Miden project.
const PROJECT_MANIFEST: &str = "miden-project.toml";

/// The build profile used when assembling the Miden projects.
const BUILD_PROFILE: &str = "release";

// Executable target names, as declared in the respective `miden-project.toml` files.
const TX_KERNEL_MAIN_TARGET: &str = "main";
const TX_SCRIPT_MAIN_TARGET: &str = "tx-script-main";
const BATCH_KERNEL_TARGET: &str = "miden-batch-kernel";

const KERNEL_PROCEDURES_RS_FILE: &str = "procedures.rs";
const TX_KERNEL_ERRORS_RS_FILE: &str = "tx_kernel_errors.rs";
const PROTOCOL_LIB_ERRORS_RS_FILE: &str = "protocol_errors.rs";

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
///
/// Assembles the Miden projects defined by the `miden-project.toml` files in the `asm` directory
/// into MAST packages (.masp files): the transaction kernel library and executables, the batch
/// kernel executable, and the user-facing protocol library.
fn main() -> Result<()> {
    // re-build when the MASM code changes
    println!("cargo::rerun-if-changed={ASM_DIR}/");

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

    // The miden-core library is provided through an in-memory registry
    let mut store = core_package_registry()?;

    // compile transaction kernel
    compile_tx_kernel(&source_dir, &target_dir.join("kernels"), &build_dir, &mut store)?;

    // compile protocol library
    compile_protocol_lib(&source_dir, &target_dir, &mut store)?;

    // compile batch kernel
    compile_batch_kernel(&source_dir, &target_dir.join("kernels"), &mut store)?;

    generate_error_constants(&source_dir, &build_dir)?;

    generate_event_constants(&source_dir, &target_dir)?;

    Ok(())
}

// COMPILE BATCH KERNEL
// ================================================================================================

/// Assembles the batch kernel project in `{source_dir}/kernels/batch` and saves the resulting
/// executable package to the `target_dir`.
fn compile_batch_kernel(
    source_dir: &Path,
    target_dir: &Path,
    store: &mut InMemoryPackageRegistry,
) -> Result<()> {
    let manifest_path = source_dir.join(ASM_BATCH_KERNEL_DIR).join(PROJECT_MANIFEST);
    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut project_assembler =
        build_assembler(source_manager).for_project_at_path(manifest_path, store)?;

    let batch_kernel_package = project_assembler
        .assemble(ProjectTargetSelector::Executable(BATCH_KERNEL_TARGET), BUILD_PROFILE)?;

    batch_kernel_package.write_masp_file(target_dir).into_diagnostic()
}

// COMPILE TRANSACTION KERNEL
// ================================================================================================

/// Assembles the transaction kernel project in `{source_dir}/kernels/transaction` and saves the
/// resulting packages to the `target_dir`.
///
/// The project is expected to have the following structure:
///
/// - {project_dir}/lib/api.masm           -> defines exported procedures from the transaction
///   kernel.
/// - {project_dir}/bin/main.masm          -> defines the executable program of the transaction
///   kernel.
/// - {project_dir}/bin/tx_script_main.masm -> defines the executable program of the arbitrary
///   transaction script.
///
/// The following are written to the `target_dir`:
///
/// - the kernel library package, compiled from lib/api.masm.
/// - the kernel executable package, compiled from bin/main.masm.
/// - the transaction script executor package, compiled from bin/tx_script_main.masm.
///
/// The kernel procedures table is written to `{build_dir}/procedures.rs`.
fn compile_tx_kernel(
    source_dir: &Path,
    target_dir: &Path,
    build_dir: &str,
    store: &mut InMemoryPackageRegistry,
) -> Result<()> {
    let project_dir = source_dir.join(ASM_TX_KERNEL_DIR);

    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let mut project_assembler = build_assembler(source_manager.clone())
        .for_project_at_path(project_dir.join(PROJECT_MANIFEST), store)?;

    // assemble the kernel library and write its package to the `target_dir`
    let kernel_package =
        project_assembler.assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;
    kernel_package.write_masp_file(target_dir).into_diagnostic()?;

    // generate kernel `procedures.rs` file
    generate_kernel_proc_hash_file(kernel_package.try_into_kernel_library()?, build_dir)?;

    // Assemble the executable targets and write their packages to the `target_dir`.
    //
    // The kernel internals live in the `miden-tx-kernel-core` library, which both programs
    // depend on, so the executables are assembled directly through the project manifest.
    for target_name in [TX_KERNEL_MAIN_TARGET, TX_SCRIPT_MAIN_TARGET] {
        let package = project_assembler
            .assemble(ProjectTargetSelector::Executable(target_name), BUILD_PROFILE)?;
        package.write_masp_file(target_dir).into_diagnostic()?;
    }

    // make sure the store is released before it is borrowed again below
    drop(project_assembler);

    // Assemble the kernel internals as a plain library and write its package to the `target_dir`.
    // This is needed in test assemblers to access individual internal procedures which are not
    // part of the kernel's public syscall API (api.masm).
    #[cfg(any(feature = "testing", test))]
    compile_kernel_testing_lib(source_dir, target_dir, store)?;

    Ok(())
}

/// Assembles the `miden-tx-kernel-core` library and saves the resulting package to the
/// `target_dir`.
#[cfg(any(feature = "testing", test))]
fn compile_kernel_testing_lib(
    source_dir: &Path,
    target_dir: &Path,
    store: &mut InMemoryPackageRegistry,
) -> Result<()> {
    let core_manifest = source_dir.join(ASM_TX_KERNEL_CORE_DIR).join(PROJECT_MANIFEST);
    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let mut assembler =
        build_assembler(source_manager).for_project_at_path(core_manifest, store)?;

    let package = assembler.assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;

    package.write_masp_file(target_dir).into_diagnostic()
}

/// Generates kernel `procedures.rs` file based on the kernel library.
///
/// The file is written to `{build_dir}/procedures.rs` and included via `include!` in the source.
fn generate_kernel_proc_hash_file(kernel: KernelLibrary, build_dir: &str) -> Result<()> {
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

    let output_path = Path::new(build_dir).join(KERNEL_PROCEDURES_RS_FILE);
    fs::write(
        output_path,
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
    let regex: Regex =
        Regex::new(r"^(?:pub\s+)?const\s*(?P<name>\w+)_OFFSET\s*=\s*(?P<offset>\d+)").unwrap();
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

/// Assembles the protocol library project in `{source_dir}/protocol` and saves the resulting
/// library package to `target_dir`.
fn compile_protocol_lib(
    source_dir: &Path,
    target_dir: &Path,
    store: &mut InMemoryPackageRegistry,
) -> Result<()> {
    let manifest_path = source_dir.join(ASM_PROTOCOL_DIR).join(PROJECT_MANIFEST);
    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut project_assembler =
        build_assembler(source_manager).for_project_at_path(manifest_path, store)?;

    let protocol_package =
        project_assembler.assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;

    protocol_package.write_masp_file(target_dir).into_diagnostic()
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a new [Assembler] using the provided source manager, with warnings treated as errors.
fn build_assembler(source_manager: Arc<dyn SourceManager>) -> Assembler {
    Assembler::new(source_manager).with_warnings_as_errors(true)
}

/// Builds an in-memory package registry loaded with the `miden-core` library, so the projects can
/// just declare it by version in the manifest.
fn core_package_registry() -> Result<InMemoryPackageRegistry> {
    // TODO: once miden_core_lib gets updated to v0.24, `CoreLibrary` will be a `Package` so we
    // won't need to add the metadata manually.
    //
    // This version must match the `miden-core` requirement declared in `asm/miden-project.toml`;
    // it's the version of the `miden-core-lib` crate that provides `CoreLibrary`.
    let library = Arc::new(Library::from(miden_core_lib::CoreLibrary::default()));
    let package = Package::from_library(
        PackageId::from("miden-core"),
        Version::new(0, 23, 4),
        TargetType::Library,
        library,
        core::iter::empty(),
    );

    let mut registry = InMemoryPackageRegistry::default();
    registry.cache_package(Arc::from(package)).into_diagnostic()?;
    Ok(registry)
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
/// The generated files are written to `build_dir` (i.e. `OUT_DIR`) and included via `include!`
/// in the source.
fn generate_error_constants(asm_source_dir: &Path, build_dir: &str) -> Result<()> {
    // Shared utils errors
    // For now these are duplicated in the tx kernel and protocol error module.
    // ------------------------------------------

    let shared_utils_dir = asm_source_dir.join(ASM_PROTOCOL_UTILS_DIR);
    let shared_utils_errors = shared::extract_all_masm_errors(&shared_utils_dir)
        .context("failed to extract all masm errors")?;

    // Transaction kernel errors
    // ------------------------------------------

    let tx_kernel_dir = asm_source_dir.join(ASM_TX_KERNEL_DIR);
    let mut errors = shared::extract_all_masm_errors(&tx_kernel_dir)
        .context("failed to extract all masm errors")?;
    // Most kernel error constants live in the tx kernel core library, which is a separate project.
    let kernel_core_dir = asm_source_dir.join(ASM_TX_KERNEL_CORE_DIR);
    errors.extend(
        shared::extract_all_masm_errors(&kernel_core_dir)
            .context("failed to extract all masm errors")?,
    );
    errors.extend_from_slice(&shared_utils_errors);
    validate_tx_kernel_category(&errors)?;

    shared::generate_error_file(
        shared::ErrorModule {
            file_path: Path::new(build_dir).join(TX_KERNEL_ERRORS_RS_FILE),
            array_name: TX_KERNEL_ERRORS_ARRAY_NAME,
            is_crate_local: true,
        },
        errors,
    )?;

    // Miden protocol library errors
    // ------------------------------------------

    let protocol_dir = asm_source_dir.join(ASM_PROTOCOL_DIR);
    let mut errors = shared::extract_all_masm_errors(&protocol_dir)
        .context("failed to extract all masm errors")?;
    errors.extend(shared_utils_errors);

    shared::generate_error_file(
        shared::ErrorModule {
            file_path: Path::new(build_dir).join(PROTOCOL_LIB_ERRORS_RS_FILE),
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
        let value = EventId::from_name(event_path).as_felt().as_canonical_u64();
        debug_assert!(!event_name.is_empty());
        writeln!(&mut output, "const {event_name}_ID: u64 = {value};")?;
        writeln!(
            &mut output,
            "static {event_name}_NAME: ::miden_core::events::EventName = ::miden_core::events::EventName::new(\"{event_path}\");"
        )?;
        writeln!(&mut output)?;
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
