use std::collections::BTreeMap;
use std::env;
use std::path::Path;

use fs_err as fs;
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr, miette};
use miden_assembly::{Path as MasmPath, ProjectTargetSelector};
use miden_core_lib::CoreLibrary;
use miden_mast_package::{Package, PackageExport};
use miden_package_registry::{InMemoryPackageRegistry, PackageCache};
use miden_protocol_build_utils::{
    ErrorModule,
    NamedError,
    PROJECT_MANIFEST,
    assemble_project,
    extract_all_masm_errors,
    extract_all_masm_events,
    generate_error_file,
    generate_event_file,
};
use regex::Regex;

// CONSTANTS
// ================================================================================================

const ASSETS_DIR: &str = "assets";
const ASM_DIR: &str = "asm";
const ASM_PROTOCOL_DIR: &str = "protocol";

const ASM_PROTOCOL_UTILS_DIR: &str = "protocol_utils";
const ASM_TX_KERNEL_DIR: &str = "kernels/transaction";
const ASM_TX_KERNEL_CORE_DIR: &str = "kernels/transaction-core";
const ASM_BATCH_KERNEL_DIR: &str = "kernels/batch";
const ASM_BLOCK_KERNEL_DIR: &str = "kernels/block";

// Executable target names, as declared in the respective `miden-project.toml` files.
const TX_KERNEL_MAIN_TARGET: &str = "main";
const TX_SCRIPT_MAIN_TARGET: &str = "tx-script-main";
const BATCH_KERNEL_TARGET: &str = "miden-batch-kernel";
const BLOCK_KERNEL_TARGET: &str = "miden-block-kernel";

/// Module of the kernel package that holds the procedures which `exec_kernel_proc` invokes.
const KERNEL_API_MODULE_PATH: &str = "$kernel::api";

const KERNEL_PROCEDURES_RS_FILE: &str = "procedures.rs";
const TX_EVENTS_RS_FILE: &str = "transaction_events.rs";
const TX_KERNEL_ERRORS_RS_FILE: &str = "tx_kernel_errors.rs";
const PROTOCOL_LIB_ERRORS_RS_FILE: &str = "protocol_errors.rs";
const BATCH_KERNEL_ERRORS_RS_FILE: &str = "batch_kernel_errors.rs";

const TX_KERNEL_ERRORS_ARRAY_NAME: &str = "TX_KERNEL_ERRORS";
const PROTOCOL_LIB_ERRORS_ARRAY_NAME: &str = "PROTOCOL_LIB_ERRORS";
const BATCH_KERNEL_ERRORS_ARRAY_NAME: &str = "BATCH_KERNEL_ERRORS";

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
/// and block kernel executables, and the user-facing protocol library.
fn main() -> Result<()> {
    // re-build when the MASM code changes
    println!("cargo::rerun-if-changed={ASM_DIR}/");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_dir = env::var("OUT_DIR").unwrap();
    let source_dir = Path::new(&crate_dir).join(ASM_DIR);

    // set target directory to {OUT_DIR}/assets
    let target_dir = Path::new(&build_dir).join(ASSETS_DIR);

    // The miden-core library is provided through an in-memory registry.
    let mut store = InMemoryPackageRegistry::default();
    store.cache_package(CoreLibrary::default().package()).into_diagnostic()?;

    // compile transaction kernel
    compile_tx_kernel(&source_dir, &target_dir.join("kernels"), &build_dir, &mut store)?;

    // compile protocol library
    let manifest_path = source_dir.join(ASM_PROTOCOL_DIR).join(PROJECT_MANIFEST);
    assemble_project(manifest_path, ProjectTargetSelector::Library, &mut store, &target_dir)?;

    // compile batch kernel
    let manifest_path = source_dir.join(ASM_BATCH_KERNEL_DIR).join(PROJECT_MANIFEST);
    assemble_project(
        manifest_path,
        ProjectTargetSelector::Executable(BATCH_KERNEL_TARGET),
        &mut store,
        &target_dir.join("kernels"),
    )?;

    // compile block kernel
    let manifest_path = source_dir.join(ASM_BLOCK_KERNEL_DIR).join(PROJECT_MANIFEST);
    assemble_project(
        manifest_path,
        ProjectTargetSelector::Executable(BLOCK_KERNEL_TARGET),
        &mut store,
        &target_dir.join("kernels"),
    )?;

    generate_error_constants(&source_dir, &build_dir)?;

    // extract the event definitions from the MASM sources and generate their constants
    let events = extract_all_masm_events(&source_dir)?;
    generate_event_file(target_dir.join(TX_EVENTS_RS_FILE), &events)?;

    Ok(())
}

// COMPILE TRANSACTION KERNEL
// ================================================================================================

/// Assembles the transaction kernel project in `{source_dir}/kernels/transaction` and saves the
/// resulting packages to the `target_dir`.
///
/// The project is expected to have the following structure:
///
/// - {project_dir}/lib/dispatcher.masm    -> defines `exec_kernel_proc`, the only syscall entry
///   point of the transaction kernel.
/// - {project_dir}/lib/api.masm           -> defines the kernel API procedures, which are invoked
///   by `exec_kernel_proc` through `dynexec`.
/// - {project_dir}/bin/main.masm          -> defines the executable program of the transaction
///   kernel.
/// - {project_dir}/bin/tx_script_main.masm -> defines the executable program of the arbitrary
///   transaction script.
///
/// The following are written to the `target_dir`:
///
/// - the kernel library package, compiled from lib/dispatcher.masm.
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
    // part of the kernel API (api.masm).
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
    let offsets_filename = Path::new(ASM_DIR)
        .join(ASM_PROTOCOL_DIR)
        .join("src")
        .join("kernel_proc_offsets.masm");
    let offsets = parse_proc_offsets(&offsets_filename)?;

    // Only exports of the kernel API module are invoked through `exec_kernel_proc`. Other exports
    // of the kernel package, such as `exec_kernel_proc` itself, do not belong in
    // `KERNEL_PROCEDURES`.
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

// HELPER FUNCTIONS
// ================================================================================================

fn is_dynamic_kernel_api_export(path: &MasmPath) -> bool {
    path.parent()
        .is_some_and(|parent| parent.to_relative().as_str() == KERNEL_API_MODULE_PATH)
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

    // Batch kernel errors
    // ------------------------------------------

    let batch_kernel_dir = asm_source_dir.join(ASM_BATCH_KERNEL_DIR);
    let batch_kernel_errors =
        extract_all_masm_errors(&batch_kernel_dir).context("failed to extract all masm errors")?;

    generate_error_file(
        ErrorModule {
            file_path: Path::new(build_dir).join(BATCH_KERNEL_ERRORS_RS_FILE),
            array_name: BATCH_KERNEL_ERRORS_ARRAY_NAME,
            is_crate_local: true,
        },
        batch_kernel_errors,
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
