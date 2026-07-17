use std::collections::{BTreeSet, HashSet};
use std::env;
use std::fmt::Write;
use std::path::Path;
use std::sync::Arc;

use fs_err as fs;
use miden_assembly::debuginfo::{DefaultSourceManager, SourceManager, SourceManagerExt};
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr};
use miden_assembly::{Assembler, ProjectTargetSelector, Report};
use miden_core::Word;
use miden_core_lib::CoreLibrary;
use miden_crypto::hash::keccak::{Keccak256, Keccak256Digest};
use miden_mast_package::Package;
use miden_package_registry::{InMemoryPackageRegistry, PackageCache};
use miden_project::Workspace;
use miden_protocol::ProtocolLib;
use miden_protocol::account::{AccountCode, AccountComponent, AccountComponentMetadata};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::TransactionKernel;
use miden_standards::StandardsLib;
use miden_standards::account::access::{AccessControl, Authority};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use regex::Regex;

// CONSTANTS
// ================================================================================================

const ASSETS_DIR: &str = "assets";
const ASM_DIR: &str = "asm";
const ASM_AGGLAYER_DIR: &str = "agglayer";
const ASM_COMPONENTS_DIR: &str = "components";
const ASM_NOTE_SCRIPTS_DIR: &str = "note_scripts";
const ASM_AGGLAYER_BRIDGE_DIR: &str = "agglayer/bridge";
const ASM_AGGLAYER_CONSTANTS_MASM: &str = "agglayer/common/constants.masm";

/// Name of the manifest file defining a Miden project.
const PROJECT_MANIFEST: &str = "miden-project.toml";

/// The build profile used when assembling the Miden projects.
///
/// Packages are assembled with the debug-info (`dev`) so published packages carry debug
/// information; consumers can strip it as needed.
const BUILD_PROFILE: &str = "dev";

const AGGLAYER_ERRORS_RS_FILE: &str = "agglayer_errors.rs";
const AGGLAYER_ERRORS_ARRAY_NAME: &str = "AGGLAYER_ERRORS";
const AGGLAYER_GLOBAL_CONSTANTS_FILE_NAME: &str = "agglayer_constants.rs";

// PRE-PROCESSING
// ================================================================================================

/// Read and parse the contents from `./asm`.
/// - Compiles the contents of the asm/agglayer directory into a single agglayer package. Note
///   scripts are included in this library.
/// - Compiles the contents of the asm/components directory into individual per-component packages.
fn main() -> Result<()> {
    // re-build when the MASM code changes
    println!("cargo::rerun-if-changed={ASM_DIR}/");
    println!("cargo::rerun-if-env-changed=REGENERATE_CANONICAL_ZEROS");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_dir = env::var("OUT_DIR").unwrap();
    let crate_path = Path::new(&crate_dir);

    // validate (or regenerate) canonical zeros in `asm/agglayer/bridge/canonical_zeros.masm`
    ensure_canonical_zeros(&crate_path.join(ASM_DIR).join(ASM_AGGLAYER_BRIDGE_DIR))?;

    // Read MASM sources directly from the crate's asm/ directory.
    // No copy to OUT_DIR is needed because this crate doesn't mutate the source tree.
    let source_dir = crate_path.join(ASM_DIR);

    // set target directory to {OUT_DIR}/assets
    let target_dir = Path::new(&build_dir).join(ASSETS_DIR);

    // The miden-core, miden-protocol and miden-standards libraries are provided through an
    // in-memory registry.
    let mut registry = build_registry()?;

    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
    let assembler = Assembler::new(source_manager.clone()).with_warnings_as_errors(true);

    // compile agglayer library (includes note scripts) and seed it into the registry
    compile_agglayer_lib(&source_dir, &target_dir, assembler.clone(), &mut registry)?;

    // compile account components (thin wrappers per component) and return their packages
    let component_packages = compile_account_components(
        &source_dir.join(ASM_COMPONENTS_DIR),
        &target_dir.join(ASM_COMPONENTS_DIR),
        &assembler,
        &mut registry,
        source_manager.clone(),
    )?;

    // compile note scripts (each statically links the agglayer library so it is self-contained)
    compile_note_scripts(
        &source_dir.join(ASM_NOTE_SCRIPTS_DIR),
        &target_dir.join(ASM_NOTE_SCRIPTS_DIR),
        &assembler,
        &mut registry,
        source_manager,
    )?;

    // generate agglayer specific constants
    let constants_out_path = Path::new(&build_dir).join(AGGLAYER_GLOBAL_CONSTANTS_FILE_NAME);
    let agglayer_constants_masm_path = crate_path.join(ASM_DIR).join(ASM_AGGLAYER_CONSTANTS_MASM);
    generate_agglayer_constants(
        constants_out_path,
        component_packages,
        &agglayer_constants_masm_path,
    )?;

    generate_error_constants(&source_dir, &build_dir)?;

    Ok(())
}

// ASSEMBLER & REGISTRY
// ================================================================================================

/// Builds a package registry seeded with the protocol library and its transitive `miden-tx-kernel`
/// and `miden-core` dependencies, plus the standards library, so that the dependencies declared by
/// the agglayer projects can be resolved during project assembly.
fn build_registry() -> Result<InMemoryPackageRegistry> {
    let mut registry = InMemoryPackageRegistry::default();

    // The protocol package declares dependencies on the kernel and core packages, and the agglayer
    // projects depend on the standards package, so all of these must be available in the registry
    // for project dependency resolution to succeed.
    for package in [
        CoreLibrary::default().package(),
        ProtocolLib::default().package(),
        TransactionKernel::package(),
        StandardsLib::default().package(),
    ] {
        registry.cache_package(package).into_diagnostic()?;
    }

    Ok(registry)
}

// COMPILE AGGLAYER LIB
// ================================================================================================

/// Assembles the agglayer library project in "{source_dir}/agglayer" into a package, saves it to
/// the `target_dir`, and seeds it into the `registry` so the account components can resolve it.
fn compile_agglayer_lib(
    source_dir: &Path,
    target_dir: &Path,
    assembler: Assembler,
    registry: &mut InMemoryPackageRegistry,
) -> Result<()> {
    let manifest_path = source_dir.join(ASM_AGGLAYER_DIR).join(PROJECT_MANIFEST);

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
/// `miden-agglayer-bridge.masp`), so the include path used by `lib.rs` is the package name.
///
/// Returns the assembled component packages so their code commitments can be computed.
fn compile_account_components(
    source_dir: &Path,
    target_dir: &Path,
    assembler: &Assembler,
    registry: &mut InMemoryPackageRegistry,
    source_manager: Arc<dyn SourceManager>,
) -> Result<Vec<Arc<Package>>> {
    let manifest =
        source_manager.load_file(&source_dir.join(PROJECT_MANIFEST)).into_diagnostic()?;
    let workspace = Workspace::load(manifest, source_manager.as_ref())?;

    let mut packages = Vec::new();
    for component in workspace.members() {
        let package = assembler
            .clone()
            .for_project(component.clone(), registry)?
            .assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;

        package.write_masp_file(target_dir).into_diagnostic()?;

        packages.push(package);
    }

    Ok(packages)
}

// COMPILE NOTE SCRIPTS
// ================================================================================================

/// Assembles each member of the note-scripts workspace in `source_dir` into a self-contained
/// package and saves it to `target_dir`.
///
/// Each note script statically links the agglayer library, so the agglayer procedures it uses are
/// inlined into the resulting package. This keeps note scripts portable: the standards and protocol
/// procedures they reference are resolved at execution time from the libraries loaded into the
/// transaction, but the agglayer-specific code travels with the note.
///
/// Each file is named after its package (e.g. `miden-agglayer-claim.masp`), so the include path
/// used by the note modules in `src/` is the package name.
fn compile_note_scripts(
    source_dir: &Path,
    target_dir: &Path,
    assembler: &Assembler,
    registry: &mut InMemoryPackageRegistry,
    source_manager: Arc<dyn SourceManager>,
) -> Result<()> {
    let manifest =
        source_manager.load_file(&source_dir.join(PROJECT_MANIFEST)).into_diagnostic()?;
    let workspace = Workspace::load(manifest, source_manager.as_ref())?;

    for note_script in workspace.members() {
        let package = assembler
            .clone()
            .for_project(note_script.clone(), registry)?
            .assemble(ProjectTargetSelector::Library, BUILD_PROFILE)?;

        package.write_masp_file(target_dir).into_diagnostic()?;
    }

    Ok(())
}

// GENERATE AGGLAYER CONSTANTS
// ================================================================================================

/// Parses every decimal `u32` constant from `asm/agglayer/common/constants.masm`.
///
/// Recognized lines (whitespace-flexible, one definition per line, `#` comments ignored by the
/// regex):
///
/// ```text
/// const SOME_NAME = 123
/// ```
///
/// Each match is emitted to `agglayer_constants.rs` as `pub const SOME_NAME: u32`.
/// Duplicate `const` names in the same file are a build error. Non-decimal values (e.g. `word(...)`
/// or array literals) are not parsed here; add support in this function when needed.
fn parse_numeric_constants_from_constants_masm(masm_path: &Path) -> Result<Vec<(String, u32)>> {
    // Read the full `constants.masm` text; parsing is line-based so we need the whole file.
    let contents = fs::read_to_string(masm_path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read {}", masm_path.display()))?;

    // One line per match: optional leading space, optional `pub` visibility, `const`, identifier
    // (no leading digit), `=`, decimal digits only. `(?m)^` makes `^` match after newlines so we
    // skip comment-only lines.
    let re = Regex::new(r"(?m)^\s*(?:pub\s+)?const\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d+)\s*$")
        .expect("constants.masm parse regex should compile");

    // `out` preserves declaration order; `seen` rejects duplicate const names in the same file.
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for caps in re.captures_iter(&contents) {
        let name = caps.get(1).expect("group 1").as_str();

        // Require each identifier at most once so generated Rust names are unique.
        if !seen.insert(name.to_string()) {
            return Err(Report::msg(format!(
                "duplicate `const {name}` in {}",
                masm_path.display()
            )));
        }

        // Right-hand side must fit `u32` (same range we emit in Rust).
        let raw = caps.get(2).expect("group 2").as_str();
        let value = raw.parse::<u32>().map_err(|_| {
            Report::msg(format!(
                "`const {name}` value `{raw}` is not a valid u32 in {}",
                masm_path.display()
            ))
        })?;

        out.push((name.to_string(), value));
    }

    // Empty match set is almost certainly a misconfigured or mistyped `constants.masm`.
    if out.is_empty() {
        return Err(Report::msg(format!(
            "{} does not contain any constants to parse",
            masm_path.display()
        )));
    }

    Ok(out)
}

/// Generates a Rust file containing AggLayer specific constants.
///
/// This file contains:
/// - All the constants listed in the `constants.masm` file.
/// - AggLayer Bridge code commitment.
/// - AggLayer Faucet code commitment.
fn generate_agglayer_constants(
    target_file: impl AsRef<Path>,
    component_packages: Vec<Arc<Package>>,
    constants_masm_path: &Path,
) -> Result<()> {
    let mut file_contents = String::new();

    writeln!(
        file_contents,
        "// This file is generated by build.rs, do not modify manually.\n"
    )
    .unwrap();

    writeln!(
        file_contents,
        "// AGGLAYER CONSTANTS
// ================================================================================================
"
    )
    .unwrap();

    let masm_constants = parse_numeric_constants_from_constants_masm(constants_masm_path)?;
    for (name, value) in &masm_constants {
        writeln!(file_contents, "pub const {name}: u32 = {value};\n").unwrap();
    }

    // Create a dummy metadata to be able to create components. We only interested in the resulting
    // code commitment, so it doesn't matter what does this metadata holds.
    let dummy_metadata = AccountComponentMetadata::new("dummy");

    // iterate over the AggLayer Bridge and AggLayer Faucet packages
    for package in component_packages {
        // Derive the short component name (e.g. "bridge" / "faucet") from the package name
        // (e.g. "miden-agglayer-bridge").
        let component_name = package
            .name
            .rsplit('-')
            .next()
            .expect("component package name should be non-empty")
            .to_owned();

        let agglayer_component =
            AccountComponent::new(Arc::unwrap_or_clone(package), vec![], dummy_metadata.clone())
                .unwrap();

        // The faucet account includes Ownable2Step and OwnerControlled components for mint and burn
        // policies alongside the agglayer faucet component, since
        // fungible::mint_and_send requires these for access control.
        //
        // The allowlist lives in storage, not code, and here we only care about the code commitment
        // of the accounts, so we can init the allowlists with dummy values.
        let placeholder_allowlist = BTreeSet::from([NoteScriptRoot::from_raw(Word::default())]);
        let auth_component = AuthNetworkAccount::with_allowed_notes(placeholder_allowlist)
            .expect("placeholder allowlist is non-empty");
        // Use a dummy owner for commitment computation - the actual owner is set at runtime. Only
        // the component code (not storage) contributes to the code commitment.
        let dummy_owner = miden_protocol::account::AccountId::try_from(
            miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        )
        .unwrap();

        let mut components: Vec<AccountComponent> =
            vec![AccountComponent::from(auth_component), agglayer_component];
        if component_name == "bridge" {
            // The bridge installs the RBAC access-control stack (RoleBasedAccessControl +
            // Authority::RbacControlled), matching `create_bridge_account_builder` in lib.rs. An
            // empty admin / role config suffices here since only component code affects the
            // commitment.
            components.extend(AccessControl::Rbac {
                admin: dummy_owner,
                procedure_roles: std::collections::BTreeMap::new(),
            });
        } else if component_name == "faucet" {
            components.push(AccountComponent::from(
                miden_standards::account::access::Ownable2Step::new(dummy_owner),
            ));
            components.push(AccountComponent::from(Authority::OwnerControlled));
            // Mirror the component order used by `create_agglayer_faucet_builder` in lib.rs so
            // the compile-time code commitment matches the one computed at runtime.
            //
            // Burn policy manager: active = `owner_only` (burns locked by default), `allow_all`
            // is registered as Reserved so the owner can open burns at runtime via
            // `set_burn_policy`.
            let token_policy_manager = TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::owner_only())
                .active_burn_policy(BurnPolicy::owner_only())
                .allowed_burn_policy(BurnPolicy::allow_all())
                .active_send_policy(TransferPolicy::allow_all())
                .active_receive_policy(TransferPolicy::allow_all())
                .build();

            components.extend(token_policy_manager);
        }

        // use `AccountCode` to merge codes of agglayer and authentication components
        let account_code =
            AccountCode::from_components(&components).expect("account code creation failed");

        let code_commitment = account_code.commitment();

        writeln!(
            file_contents,
            "pub const {}_CODE_COMMITMENT: Word = miden_protocol::word!(\"{code_commitment}\");",
            component_name.to_uppercase(),
        )
        .unwrap();
    }

    // write the resulting constants to the target directory
    shared::write_if_changed(target_file, file_contents.as_bytes())?;

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
fn generate_error_constants(asm_source_dir: &Path, build_dir: &str) -> Result<()> {
    // Miden agglayer errors
    // ------------------------------------------

    let errors = shared::extract_all_masm_errors(asm_source_dir)
        .context("failed to extract all masm errors")?;
    shared::generate_error_file(
        shared::ErrorModule {
            file_path: Path::new(build_dir).join(AGGLAYER_ERRORS_RS_FILE),
            array_name: AGGLAYER_ERRORS_ARRAY_NAME,
            is_crate_local: false,
        },
        errors,
    )?;

    Ok(())
}

// CANONICAL ZEROS VALIDATION
// ================================================================================================

/// Validates that the committed `canonical_zeros.masm` matches the expected content computed from
/// Keccak256 canonical zeros. If the `REGENERATE_CANONICAL_ZEROS` environment variable is set,
/// the file is regenerated instead.
fn ensure_canonical_zeros(target_dir: &Path) -> Result<()> {
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
        "# This file contains deterministic values. Do not modify manually.\n
# This file contains the canonical zeros for the Keccak hash function.
# Zero of height `n` (ZERO_N) is the root of the binary tree of height `n` with leaves equal zero.
#
# Since the Keccak hash is represented by eight u32 values, each constant consists of two Words.\n",
    );

    for (height, zero) in zeros_by_height.iter().enumerate() {
        let zero_as_u32_vec = zero
            .chunks(4)
            .map(|chunk_u32| u32::from_le_bytes(chunk_u32.try_into().unwrap()).to_string())
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
use {mem_store_double_word} from agglayer::common::utils


#! Inputs:  [zeros_ptr]
#! Outputs: []
pub proc load_zeros_to_memory\n",
    );

    for zero_index in 0..32 {
        zero_constants.push_str(&format!("\tpush.ZERO_{zero_index}_R.ZERO_{zero_index}_L exec.mem_store_double_word dropw dropw add.8\n"));
    }

    zero_constants.push_str("\tdrop\nend\n");

    let file_path = target_dir.join("canonical_zeros.masm");

    if option_env!("REGENERATE_CANONICAL_ZEROS").is_some() {
        // Regeneration mode: write the file
        shared::write_if_changed(&file_path, &zero_constants)?;
    } else {
        // Validation mode: ensure the committed file matches
        let committed = fs::read_to_string(&file_path)
            .into_diagnostic()
            .wrap_err("canonical_zeros.masm not found - it should be committed in the repo")?;
        if committed != zero_constants {
            return Err(Report::msg(
                "canonical_zeros.masm is out of date. \
                 Run with REGENERATE_CANONICAL_ZEROS=1 to regenerate and commit the result.",
            ));
        }
    }

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

        fs::write(module.file_path, output).into_diagnostic()?;

        Ok(())
    }

    /// Writes `contents` to `path` only if the file doesn't exist or its current contents
    /// differ. This avoids updating the file's mtime when nothing changed, which prevents
    /// cargo from treating the crate as dirty on the next build.
    pub fn write_if_changed(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<()> {
        let path = path.as_ref();
        let new_contents = contents.as_ref();
        if path.exists() {
            let existing = std::fs::read(path).into_diagnostic()?;
            if existing == new_contents {
                return Ok(());
            }
        }
        std::fs::write(path, new_contents).into_diagnostic()
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
