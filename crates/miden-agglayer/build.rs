use std::collections::{BTreeSet, HashSet};
use std::env;
use std::fmt::Write;
use std::path::Path;
use std::sync::Arc;

use fs_err as fs;
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr};
use miden_assembly::{ProjectTargetSelector, Report};
use miden_build_utils::{
    ErrorModule,
    PROJECT_MANIFEST,
    assemble_project,
    assemble_workspace,
    extract_all_masm_errors,
    generate_error_file,
};
use miden_core::Word;
use miden_core_lib::CoreLibrary;
use miden_crypto::hash::keccak::{Keccak256, Keccak256Digest};
use miden_mast_package::Package;
use miden_package_registry::{InMemoryPackageRegistry, PackageCache};
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

    // compile agglayer library (includes note scripts) and seed it into the registry
    compile_agglayer_lib(&source_dir, &target_dir, &mut registry)?;

    // compile account components (thin wrappers per component); their packages are returned so
    // their code commitments can be computed below
    let component_packages = assemble_workspace(
        source_dir.join(ASM_COMPONENTS_DIR).join(PROJECT_MANIFEST),
        &mut registry,
        &target_dir.join(ASM_COMPONENTS_DIR),
    )?;

    // compile note scripts (each statically links the agglayer library so it is self-contained)
    assemble_workspace(
        source_dir.join(ASM_NOTE_SCRIPTS_DIR).join(PROJECT_MANIFEST),
        &mut registry,
        &target_dir.join(ASM_NOTE_SCRIPTS_DIR),
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
        Arc::new(Package::from(ProtocolLib::default())),
        TransactionKernel::package(),
        Arc::new(Package::from(StandardsLib::default())),
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
    registry: &mut InMemoryPackageRegistry,
) -> Result<()> {
    let manifest_path = source_dir.join(ASM_AGGLAYER_DIR).join(PROJECT_MANIFEST);

    let package =
        assemble_project(manifest_path, ProjectTargetSelector::Library, registry, target_dir)?;

    registry.cache_package(package).into_diagnostic()?;

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
    write_if_changed(target_file, file_contents.as_bytes())?;

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

    let errors =
        extract_all_masm_errors(asm_source_dir).context("failed to extract all masm errors")?;
    generate_error_file(
        ErrorModule {
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
        write_if_changed(&file_path, &zero_constants)?;
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
