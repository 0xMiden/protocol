//! Build-time helpers shared by the `build.rs` scripts of the Miden protocol crates.
//!
//! These utilities locate MASM sources, extract MASM error constants into generated Rust
//! files, and set up the registry and assembler used to build and write MAST packages.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::{env, io};

use fs_err as fs;
use miden_assembly::debuginfo::{DefaultSourceManager, SourceManager, SourceManagerExt};
use miden_assembly::diagnostics::{IntoDiagnostic, Result};
use miden_assembly::{Assembler, ProjectTargetSelector, Report};
use miden_core::events::EventId;
use miden_mast_package::Package;
use miden_package_registry::InMemoryPackageRegistry;
use miden_project::Workspace;
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

/// Assembles `selector` from the Miden project manifest at `manifest_path`, resolving
/// dependencies against `registry`, writes the assembled package to `target_dir` as a `.masp`
/// file, and returns it.
pub fn assemble_project(
    manifest_path: impl AsRef<Path>,
    selector: ProjectTargetSelector,
    registry: &mut InMemoryPackageRegistry,
    target_dir: &Path,
) -> Result<Arc<Package>> {
    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let package = Assembler::new(source_manager)
        .with_warnings_as_errors(true)
        .for_project_at_path(manifest_path.as_ref(), registry)?
        .assemble(selector, BUILD_PROFILE)?;
    package.write_masp_file(target_dir).into_diagnostic()?;
    Ok(package)
}

/// Assembles every member of the workspace whose manifest is at `manifest_path` that defines a
/// library target into a library package, writes each package to `target_dir` as a `.masp` file,
/// and returns the assembled packages. Members without a library target are skipped. Dependencies
/// are resolved against `registry`.
pub fn assemble_workspace(
    manifest_path: impl AsRef<Path>,
    registry: &mut InMemoryPackageRegistry,
    target_dir: &Path,
) -> Result<Vec<Arc<Package>>> {
    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let manifest = source_manager.load_file(manifest_path.as_ref()).into_diagnostic()?;
    let workspace = Workspace::load(manifest, source_manager.as_ref())?;

    let assembler = Assembler::new(source_manager).with_warnings_as_errors(true);

    let mut packages = Vec::with_capacity(workspace.members().len());
    for member in workspace.members() {
        // A workspace member is not required to define a library target (it may only define
        // executables), and assembling one from such a member would fail.
        if member.library_target().is_none() {
            continue;
        }

        let package = assembler
            .clone()
            .for_project(member.clone(), registry)?
            .assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;
        package.write_masp_file(target_dir).into_diagnostic()?;
        packages.push(package);
    }

    Ok(packages)
}

/// Writes the package to a fixed path: `<target>/<profile>/<name>.masp`.
pub fn write_release_package(package: &Package) -> Result<()> {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is always set for build scripts");
    let out_path = Path::new(&out_dir);
    let profile_dir = profile_dir(out_path)?;

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

/// Returns the cargo profile directory (e.g. `<target>/release`) that the current build script's
/// `OUT_DIR` lives under.
fn profile_dir(out_dir: &Path) -> Result<&Path> {
    // The profile directory is the parent of the `build` directory holding this build script's
    // output, located by name so the depth of `OUT_DIR` (a cargo implementation detail) doesn't
    // matter.
    let by_build_dir = out_dir
        .ancestors()
        .find(|dir| dir.file_name() == Some(OsStr::new("build")))
        .and_then(Path::parent);

    // Should cargo stop nesting build script outputs under a `build` directory, fall back to the
    // profile name. Note that `PROFILE` only ever holds `debug` or `release`, so this cannot find
    // the directory of a custom profile such as `test-dev`, whose `PROFILE` is `debug`.
    let by_profile_name = || {
        let profile = env::var("PROFILE").expect("PROFILE is always set for build scripts");
        out_dir.ancestors().find(|dir| dir.file_name() == Some(OsStr::new(&profile)))
    };

    by_build_dir.or_else(by_profile_name).ok_or_else(|| {
        Report::msg(format!(
            "failed to locate the profile directory containing OUT_DIR `{}`",
            out_dir.display()
        ))
    })
}

// ERROR CONSTANTS EXTRACTION
// ================================================================================================

/// Matches MASM error constant definitions of the form `const ERR_<NAME> = "<message>"`.
static MASM_ERROR_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"const\s*ERR_(?<name>.*)\s*=\s*"(?<message>.*)""#).unwrap());

#[derive(Debug, Clone)]
struct ExtractedError {
    message: String,
}

#[derive(Debug, Clone)]
pub struct NamedError {
    pub name: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ErrorModule {
    pub file_path: PathBuf,
    pub array_name: &'static str,
    pub is_crate_local: bool,
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
fn extract_masm_errors(
    errors: &mut BTreeMap<String, ExtractedError>,
    file_contents: &str,
) -> Result<()> {
    for capture in MASM_ERROR_REGEX.captures_iter(file_contents) {
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

fn is_new_error_category<'a>(last_error: &mut Option<&'a str>, current_error: &'a str) -> bool {
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

// EVENT CONSTANTS EXTRACTION
// ================================================================================================

/// Matches MASM event definitions of the form `const <NAME> = event("<path>")`.
static MASM_EVENT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"const\s*(\w+)\s*=\s*event\(\s*"([^"]+)"\s*\)"#).unwrap());

/// Extracts all `const X = event("x")` definitions from the masm files in the given path and
/// returns a map from event path to constant name.
pub fn extract_all_masm_events(asm_source_dir: &Path) -> Result<BTreeMap<String, String>> {
    // We collect a mapping from event path to const variable name, which we use to generate the
    // constants and enum variant names. The mapping must be unique, so we use a BTree to detect
    // events defined multiple times.
    let mut events = BTreeMap::new();

    // Walk all MASM files.
    for entry in WalkDir::new(asm_source_dir) {
        let entry = entry.into_diagnostic()?;
        if !is_masm_file(entry.path()).into_diagnostic()? {
            continue;
        }
        let file_contents = fs::read_to_string(entry.path()).into_diagnostic()?;
        extract_masm_events(&mut events, &file_contents, entry.path())?;
    }

    Ok(events)
}

/// Extracts the event definitions from a single masm file and inserts them into the provided map.
fn extract_masm_events(
    events: &mut BTreeMap<String, String>,
    file_contents: &str,
    file_path: &Path,
) -> Result<()> {
    for capture in MASM_EVENT_REGEX.captures_iter(file_contents) {
        let const_name = capture.get(1).expect("const name should be captured").as_str();
        let event_path = capture.get(2).expect("event path should be captured").as_str();

        let const_name_wo_suffix =
            if let Some((const_name_wo_suffix, _)) = const_name.rsplit_once("_EVENT") {
                const_name_wo_suffix.to_string()
            } else {
                const_name.to_owned()
            };

        if !event_path.starts_with("miden::") {
            return Err(Report::msg(format!("unhandled `event_path={event_path}`")));
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

/// Generates a Rust file defining the ID and name of each of the given events and writes it to the
/// file at `file_path`.
pub fn generate_event_file(
    file_path: impl AsRef<Path>,
    events: &BTreeMap<String, String>,
) -> Result<()> {
    let mut output = String::new();

    writeln!(output, "// This file is generated by build.rs, do not modify").into_diagnostic()?;
    writeln!(output).into_diagnostic()?;

    // Generate constants
    //
    // Note: If we ever encounter two constants `const X`, that are both named `X` we will error
    // when attempting to generate the rust code. Currently this is a side-effect, but we
    // want to error out as early as possible:
    // TODO: make the error out at build-time to be able to present better error hints
    for (event_path, event_name) in events {
        let value = EventId::from_name(event_path).as_felt().as_canonical_u64();
        debug_assert!(!event_name.is_empty());
        writeln!(output, "const {event_name}_ID: u64 = {value};").into_diagnostic()?;
        writeln!(
            output,
            "static {event_name}_NAME: ::miden_core::events::EventName = ::miden_core::events::EventName::new(\"{event_path}\");"
        )
        .into_diagnostic()?;
        writeln!(output).into_diagnostic()?;
    }

    fs::write(file_path.as_ref(), output).into_diagnostic()?;

    Ok(())
}
