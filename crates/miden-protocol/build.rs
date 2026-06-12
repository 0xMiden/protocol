use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::Path;
use std::sync::Arc;

use fs_err as fs;
use miden_assembly::ast::{Module, ModuleKind};
use miden_assembly::debuginfo::{DefaultSourceManager, SourceManager};
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr, miette};
use miden_assembly::{
    Assembler,
    KernelLibrary,
    ModuleParser,
    ProjectSourceInputs,
    ProjectTargetSelector,
};
use miden_core::events::EventId;
use miden_mast_package::Package;
use miden_package_registry::NoPackageStore;
use regex::Regex;
use walkdir::WalkDir;

// CONSTANTS
// ================================================================================================

const ASSETS_DIR: &str = "assets";
const ASM_DIR: &str = "asm";
const ASM_PROTOCOL_DIR: &str = "protocol";

const UTILS_DIR: &str = "utils";
const SHARED_MODULES_DIR: &str = "shared_modules";
const ASM_TX_KERNEL_DIR: &str = "kernels/transaction";
const ASM_BATCH_KERNEL_DIR: &str = "kernels/batch";

/// Name of the manifest file defining a Miden project.
const PROJECT_MANIFEST: &str = "miden-project.toml";

/// The build profile used when assembling the Miden projects.
const BUILD_PROFILE: &str = "release";

/// Name of the directory containing the transaction kernel modules, relative to the transaction
/// kernel project root.
const TX_KERNEL_LIB_DIR: &str = "lib";

/// File name of the transaction kernel's root module, which defines the exported kernel API.
const TX_KERNEL_API_FILE: &str = "api.masm";

// Executable target names, as declared in the respective `miden-project.toml` files.
const TX_KERNEL_MAIN_TARGET: &str = "main";
const TX_SCRIPT_MAIN_TARGET: &str = "tx-script-main";
const BATCH_KERNEL_TARGET: &str = "batch-kernel";

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

    // copy the shared modules to the kernel and protocol library folders
    copy_shared_modules(&source_dir)?;

    // set target directory to {OUT_DIR}/assets
    let target_dir = Path::new(&build_dir).join(ASSETS_DIR);

    // all project dependencies are resolved from workspace sources, so no package store is needed
    let mut store = NoPackageStore;

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
/// executable package to `{target_dir}/batch_kernel.masp`.
fn compile_batch_kernel(
    source_dir: &Path,
    target_dir: &Path,
    store: &mut NoPackageStore,
) -> Result<()> {
    let manifest_path = source_dir.join(ASM_BATCH_KERNEL_DIR).join(PROJECT_MANIFEST);
    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut project_assembler =
        build_assembler(source_manager)?.for_project_at_path(manifest_path, store)?;

    let batch_kernel_package = project_assembler
        .assemble(ProjectTargetSelector::Executable(BATCH_KERNEL_TARGET), BUILD_PROFILE)?;

    write_package(&batch_kernel_package, target_dir, "batch_kernel")
}

// COMPILE TRANSACTION KERNEL
// ================================================================================================

/// Assembles the transaction kernel project in `{source_dir}/kernels/transaction` and saves the
/// resulting packages to the `target_dir`.
///
/// The project is expected to have the following structure:
///
/// - {project_dir}/lib/api.masm   -> defines exported procedures from the transaction kernel.
/// - {project_dir}/lib            -> contains the kernel modules, assembled under `$kernel`.
/// - {project_dir}/main.masm      -> defines the executable program of the transaction kernel.
/// - {project_dir}/tx_script_main -> defines the executable program of the arbitrary transaction
///   script.
///
/// The compiled files are written as follows:
///
/// - {target_dir}/tx_kernel.masp      -> contains the kernel library package compiled from
///   lib/api.masm.
/// - {target_dir}/tx_kernel_main.masp -> contains the executable package compiled from main.masm.
/// - {target_dir}/tx_script_main.masp -> contains the executable package compiled from
///   tx_script_main.masm.
/// - {build_dir}/procedures.rs        -> contains the kernel procedures table.
fn compile_tx_kernel(
    source_dir: &Path,
    target_dir: &Path,
    build_dir: &str,
    store: &mut NoPackageStore,
) -> Result<()> {
    let project_dir = source_dir.join(ASM_TX_KERNEL_DIR);

    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let mut project_assembler = build_assembler(source_manager.clone())?
        .for_project_at_path(project_dir.join(PROJECT_MANIFEST), store)?;

    // assemble the kernel library and write it to the "tx_kernel.masp" file
    let kernel_package =
        project_assembler.assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;
    write_package(&kernel_package, target_dir, "tx_kernel")?;

    // generate kernel `procedures.rs` file
    generate_kernel_proc_hash_file(kernel_package.try_into_kernel_library()?, build_dir)?;

    // Assemble the executable targets and write them to the "tx_kernel_main.masp" and
    // "tx_script_main.masp" files.
    //
    // Executable targets are assembled under the `$exec` namespace, but the kernel executables
    // `exec` kernel modules directly, expecting them under `$kernel`. To support this, the kernel
    // modules are parsed under the `$kernel` namespace and provided to the assembler explicitly.
    for (target_name, root_file, artifact_name) in [
        (TX_KERNEL_MAIN_TARGET, "main.masm", "tx_kernel_main"),
        (TX_SCRIPT_MAIN_TARGET, "tx_script_main.masm", "tx_script_main"),
    ] {
        let mut parser = ModuleParser::new(ModuleKind::Executable);
        parser.set_warnings_as_errors(true);
        let root = parser.parse_file(
            miden_assembly::Path::exec_path(),
            project_dir.join(root_file),
            source_manager.clone(),
        )?;
        let support = parse_kernel_modules(&project_dir, source_manager.clone())?;

        let package = project_assembler.assemble_with_sources(
            ProjectTargetSelector::Executable(target_name),
            BUILD_PROFILE,
            ProjectSourceInputs { root, support },
        )?;
        write_package(&package, target_dir, artifact_name)?;
    }

    // make sure the store is released before it is borrowed again below
    drop(project_assembler);

    // Build the kernel modules as a plain library and save it to the "kernel_library.masp" file.
    // This is needed in test assemblers to access individual procedures which would otherwise
    // be hidden when using KernelLibrary (api.masm)
    #[cfg(any(feature = "testing", test))]
    compile_kernel_testing_lib(source_dir, target_dir, store)?;

    Ok(())
}

/// Parses the transaction kernel modules in `{project_dir}/lib` under the `$kernel` namespace.
///
/// The kernel's root module (api.masm) is excluded: when assembling the kernel executables it is
/// provided by the kernel library package, which the project assembler links automatically.
// boxed modules are required by `ProjectSourceInputs`
#[allow(clippy::vec_box)]
fn parse_kernel_modules(
    project_dir: &Path,
    source_manager: Arc<dyn SourceManager>,
) -> Result<Vec<Box<Module>>> {
    let lib_dir = project_dir.join(TX_KERNEL_LIB_DIR);

    let mut modules = Vec::new();
    for module_file in shared::get_masm_files(&lib_dir)? {
        if module_file.file_name().is_some_and(|name| name == TX_KERNEL_API_FILE) {
            continue;
        }

        let module_name = module_file
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| miette::miette!("invalid module file name: {module_file:?}"))?;
        let module_path = miden_assembly::Path::kernel_path().join(module_name);

        let mut parser = ModuleParser::new(ModuleKind::Library);
        parser.set_warnings_as_errors(true);
        modules.push(parser.parse_file(&module_path, &module_file, source_manager.clone())?);
    }

    Ok(modules)
}

/// Assembles the transaction kernel modules as a plain library (i.e. not as a kernel) with the
/// utils library statically linked, and saves the resulting package to the
/// `{target_dir}/kernel_library.masp` file.
#[cfg(any(feature = "testing", test))]
fn compile_kernel_testing_lib(
    source_dir: &Path,
    target_dir: &Path,
    store: &mut NoPackageStore,
) -> Result<()> {
    use miden_mast_package::TargetType;
    use miden_project::Linkage;

    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());

    let utils_package = {
        let utils_manifest = source_dir.join(UTILS_DIR).join(PROJECT_MANIFEST);
        let mut utils_assembler =
            build_assembler(source_manager.clone())?.for_project_at_path(utils_manifest, store)?;
        utils_assembler.assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?
    };

    let mut assembler = build_assembler(source_manager.clone())?;
    assembler.link_package(utils_package, Linkage::Static)?;

    let modules = parse_kernel_modules(&source_dir.join(ASM_TX_KERNEL_DIR), source_manager)?;
    let library = assembler.assemble_library(modules)?;

    let package = Package::from_library(
        "tx-kernel-testing".into(),
        package_version()?,
        TargetType::Library,
        library,
        [],
    );

    write_package(&package, target_dir, "kernel_library")
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
/// library package to `{target_dir}/protocol.masp`.
fn compile_protocol_lib(
    source_dir: &Path,
    target_dir: &Path,
    store: &mut NoPackageStore,
) -> Result<()> {
    let manifest_path = source_dir.join(ASM_PROTOCOL_DIR).join(PROJECT_MANIFEST);
    let source_manager = Arc::new(DefaultSourceManager::default());
    let mut project_assembler =
        build_assembler(source_manager)?.for_project_at_path(manifest_path, store)?;

    let protocol_package =
        project_assembler.assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;

    write_package(&protocol_package, target_dir, "protocol")
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns a new [Assembler] using the provided source manager, loaded with miden-core-lib.
fn build_assembler(source_manager: Arc<dyn SourceManager>) -> Result<Assembler> {
    Assembler::new(source_manager)
        .with_warnings_as_errors(true)
        .with_dynamic_library(miden_core_lib::CoreLibrary::default())
}

/// Writes the package to the `{target_dir}/{name}.masp` file.
fn write_package(package: &Package, target_dir: &Path, name: &str) -> Result<()> {
    fs::create_dir_all(target_dir).into_diagnostic()?;
    let output_file = target_dir.join(name).with_extension(Package::EXTENSION);
    package.write_to_file(output_file).into_diagnostic()
}

/// Returns the version of this crate as the package version.
#[cfg(any(feature = "testing", test))]
fn package_version() -> Result<miden_mast_package::Version> {
    miden_mast_package::Version::parse(env!("CARGO_PKG_VERSION")).into_diagnostic()
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
/// The generated files are written to `build_dir` (i.e. `OUT_DIR`) and included via `include!`
/// in the source.
fn generate_error_constants(asm_source_dir: &Path, build_dir: &str) -> Result<()> {
    // Shared utils errors
    // For now these are duplicated in the tx kernel and protocol error module.
    // ------------------------------------------

    let shared_utils_dir = asm_source_dir.join(UTILS_DIR);
    let shared_utils_errors = shared::extract_all_masm_errors(&shared_utils_dir)
        .context("failed to extract all masm errors")?;

    // Transaction kernel errors
    // ------------------------------------------

    let tx_kernel_dir = asm_source_dir.join(ASM_TX_KERNEL_DIR);
    let mut errors = shared::extract_all_masm_errors(&tx_kernel_dir)
        .context("failed to extract all masm errors")?;
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
