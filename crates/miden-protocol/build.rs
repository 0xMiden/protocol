use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::Path;

use fs_err as fs;
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr, miette};
use miden_assembly::{Path as MasmPath, ProjectTargetSelector};
use miden_core::events::EventId;
use miden_core_lib::CoreLibrary;
use miden_mast_package::{Package, PackageExport};
use miden_package_registry::{InMemoryPackageRegistry, PackageCache};
use miden_protocol_build_utils::{
    ErrorModule,
    NamedError,
    PROJECT_MANIFEST,
    assemble_project,
    extract_all_masm_errors,
    generate_error_file,
    is_masm_file,
    write_release_package,
};
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

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_dir = env::var("OUT_DIR").unwrap();
    let source_dir = Path::new(&crate_dir).join(ASM_DIR);

    // set target directory to {OUT_DIR}/assets
    let target_dir = Path::new(&build_dir).join(ASSETS_DIR);

    // The miden-core library is provided through an in-memory registry
    let mut store = InMemoryPackageRegistry::default();
    store.cache_package(CoreLibrary::default().package()).into_diagnostic()?;

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
    assemble_project(
        manifest_path,
        ProjectTargetSelector::Executable(BATCH_KERNEL_TARGET),
        store,
        target_dir,
    )?;

    Ok(())
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
    let manifest_path = source_dir.join(ASM_TX_KERNEL_DIR).join(PROJECT_MANIFEST);

    // assemble the kernel library and write its package to the `target_dir`
    let kernel_package =
        assemble_project(&manifest_path, ProjectTargetSelector::Library, store, target_dir)?;

    write_release_package(&kernel_package)?;

    // generate kernel `procedures.rs` file
    generate_kernel_proc_hash_file(&kernel_package, build_dir)?;

    // Assemble the executable targets and write their packages to the `target_dir`.
    //
    // The kernel internals live in the `miden-tx-kernel-core` library, which both programs
    // depend on and which is resolved as a project dependency during assembly.
    for target_name in [TX_KERNEL_MAIN_TARGET, TX_SCRIPT_MAIN_TARGET] {
        assemble_project(
            &manifest_path,
            ProjectTargetSelector::Executable(target_name),
            store,
            target_dir,
        )?;
    }

    // Assemble the kernel internals as a plain library and write its package to the `target_dir`.
    // This is needed in test assemblers to access individual internal procedures which are not
    // part of the kernel's public syscall API (api.masm).
    #[cfg(any(feature = "testing", test))]
    {
        let core_manifest = source_dir.join(ASM_TX_KERNEL_CORE_DIR).join(PROJECT_MANIFEST);
        assemble_project(core_manifest, ProjectTargetSelector::Library, store, target_dir)?;
    }

    Ok(())
}

/// Generates kernel `procedures.rs` file based on the kernel library.
///
/// The file is written to `{build_dir}/procedures.rs` and included via `include!` in the source.
fn generate_kernel_proc_hash_file(kernel: &Package, build_dir: &str) -> Result<()> {
    let to_exclude = BTreeSet::from_iter(["exec_kernel_proc"]);
    let offsets_filename = Path::new(ASM_DIR)
        .join(ASM_PROTOCOL_DIR)
        .join("src")
        .join("kernel_proc_offsets.masm");
    let offsets = parse_proc_offsets(&offsets_filename)?;

    // Only direct `$kernel::<proc>` exports are dynamic kernel API procedures. Public support
    // modules also appear in package exports as `$kernel::<module>::<proc>`, but those are not
    // invoked through `exec_kernel_proc` and therefore do not belong in `KERNEL_PROCEDURES`.
    let kernel_api_exports: Vec<_> = kernel
        .manifest
        .exports()
        .filter_map(|export| match export {
            PackageExport::Procedure(proc_info) => Some(proc_info),
            _ => None,
        })
        .filter(|proc_info| is_dynamic_kernel_api_export(&proc_info.path))
        .collect();

    for proc_info in kernel_api_exports.iter() {
        let name = proc_info.path.last().unwrap();
        if to_exclude.contains::<str>(name) {
            continue;
        }

        if !offsets.contains_key(name) {
            return Err(miette::miette!(
                "Offset constant for kernel procedure `{}` not found in `{offsets_filename:?}`",
                proc_info.path,
            ));
        }
    }

    let generated_procs: BTreeMap<usize, String> = offsets
        .iter()
        .map(|(name, &offset)| {
            let mut matching_exports =
                kernel_api_exports.iter().filter(|proc_info| proc_info.path.last().unwrap() == name);
            let proc_info = matching_exports.next().ok_or_else(|| {
                miette::miette!(
                    "Kernel procedure offset `{name}` in `{offsets_filename:?}` does not match any exported procedure"
                )
            })?;

            if let Some(other_proc_info) = matching_exports.next() {
                return Err(miette::miette!(
                    "Kernel procedure offset `{name}` in `{offsets_filename:?}` matches multiple exported procedures: `{}` and `{}`",
                    proc_info.path,
                    other_proc_info.path,
                ));
            }

            Ok((offset, format!("    // {name}\n    word!(\"{}\"),", proc_info.digest)))
        })
        .collect::<Result<_>>()?;

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
    let protocol_package =
        assemble_project(manifest_path, ProjectTargetSelector::Library, store, target_dir)?;

    write_release_package(&protocol_package)
}

// HELPER FUNCTIONS
// ================================================================================================

fn is_dynamic_kernel_api_export(path: &MasmPath) -> bool {
    path.parent().is_some_and(|parent| parent.to_relative().as_str() == "$kernel")
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
    let shared_utils_errors =
        extract_all_masm_errors(&shared_utils_dir).context("failed to extract all masm errors")?;

    // Transaction kernel errors
    // ------------------------------------------

    let tx_kernel_dir = asm_source_dir.join(ASM_TX_KERNEL_DIR);
    let mut errors =
        extract_all_masm_errors(&tx_kernel_dir).context("failed to extract all masm errors")?;
    // Most kernel error constants live in the tx kernel core library, which is a separate project.
    let kernel_core_dir = asm_source_dir.join(ASM_TX_KERNEL_CORE_DIR);
    errors.extend(
        extract_all_masm_errors(&kernel_core_dir).context("failed to extract all masm errors")?,
    );
    errors.extend_from_slice(&shared_utils_errors);
    validate_tx_kernel_category(&errors)?;

    generate_error_file(
        ErrorModule {
            file_path: Path::new(build_dir).join(TX_KERNEL_ERRORS_RS_FILE),
            array_name: TX_KERNEL_ERRORS_ARRAY_NAME,
            is_crate_local: true,
        },
        errors,
    )?;

    // Miden protocol library errors
    // ------------------------------------------

    let protocol_dir = asm_source_dir.join(ASM_PROTOCOL_DIR);
    let mut errors =
        extract_all_masm_errors(&protocol_dir).context("failed to extract all masm errors")?;
    errors.extend(shared_utils_errors);

    generate_error_file(
        ErrorModule {
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
fn validate_tx_kernel_category(errors: &[NamedError]) -> Result<()> {
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
        if !is_masm_file(entry.path()).into_diagnostic()? {
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
    let regex = Regex::new(r#"const\s*(\w+)\s*=\s*event\(\s*"([^"]+)"\s*\)"#).unwrap();

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
