use std::collections::BTreeSet;
use std::env;
use std::fmt::Write;
use std::path::Path;
use std::sync::Arc;

use fs_err as fs;
use miden_assembly::diagnostics::{IntoDiagnostic, Result, WrapErr};
use miden_assembly::{ProjectTargetSelector, Report};
use miden_core::Word;
use miden_core_lib::CoreLibrary;
use miden_crypto::hash::keccak::{Keccak256, Keccak256Digest};
use miden_mast_package::Package;
use miden_package_registry::{InMemoryPackageRegistry, PackageCache};
use miden_protocol::ProtocolLib;
use miden_protocol::account::{AccountCode, AccountComponent, AccountComponentMetadata};
use miden_protocol::note::NoteScriptRoot;
use miden_protocol::transaction::TransactionKernel;
use miden_protocol_build_utils::{
    ErrorModule,
    PROJECT_MANIFEST,
    assemble_project,
    assemble_workspace,
    extract_all_masm_errors,
    generate_error_file,
};
use miden_standards::StandardsLib;
use miden_standards::account::access::{AccessControl, Pausable, PausableManager};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::fees::{
    BasicConstantFeePolicy,
    ConstantFeeManager,
    FeePolicyManager,
};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};

// CONSTANTS
// ================================================================================================

const ASSETS_DIR: &str = "assets";
const ASM_DIR: &str = "asm";
const ASM_AGGLAYER_DIR: &str = "agglayer";
const ASM_COMPONENTS_DIR: &str = "components";
const ASM_AGGLAYER_BRIDGE_DIR: &str = "agglayer/bridge";

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
    compile_agglayer_package(&source_dir, &target_dir, &mut registry)?;

    // compile account components (thin wrappers per component); their packages are returned so
    // their code commitments can be computed below
    let component_packages = assemble_workspace(
        source_dir.join(ASM_COMPONENTS_DIR).join(PROJECT_MANIFEST),
        &mut registry,
        &target_dir.join(ASM_COMPONENTS_DIR),
    )?;

    // generate agglayer specific constants
    let constants_out_path = Path::new(&build_dir).join(AGGLAYER_GLOBAL_CONSTANTS_FILE_NAME);
    generate_agglayer_constants(constants_out_path, component_packages)?;

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
    for package in CoreLibrary::default().packages().into_iter().chain([
        ProtocolLib::default().package(),
        TransactionKernel::package(),
        StandardsLib::default().package(),
    ]) {
        registry.cache_package(package).into_diagnostic()?;
    }

    Ok(registry)
}

// COMPILE AGGLAYER LIB
// ================================================================================================

/// Assembles the agglayer library project in "{source_dir}/agglayer" into a package, saves it to
/// the `target_dir`, and seeds it into the `registry` so the account components can resolve it.
fn compile_agglayer_package(
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

/// Generates a Rust file containing AggLayer specific constants.
///
/// This file contains:
/// - AggLayer Bridge code commitment.
/// - AggLayer Faucet code commitment.
fn generate_agglayer_constants(
    target_file: impl AsRef<Path>,
    component_packages: Vec<Arc<Package>>,
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

        let dummy_account_id = miden_protocol::account::AccountId::try_from(
            miden_protocol::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
        )
        .unwrap();

        let fee_policy_manager = FeePolicyManager::builder()
            .active_fee_policy(BasicConstantFeePolicy::new().into())
            .fee_faucet_id(dummy_account_id)
            .build();

        let placeholder_allowlist = BTreeSet::from([NoteScriptRoot::from_raw(Word::default())]);
        let auth_component = AuthNetworkAccount::new(placeholder_allowlist, fee_policy_manager)
            .expect("placeholder allowlist is non-empty");

        let mut components: Vec<AccountComponent> = auth_component.into_iter().collect();
        components.push(agglayer_component);
        if component_name == "bridge" {
            components.extend(AccessControl::Rbac {
                admin: dummy_account_id,
                procedure_roles: std::collections::BTreeMap::new(),
            });
            components.push(AccountComponent::from(Pausable::unpaused()));
            components.push(AccountComponent::from(PausableManager));
            components
                .push(AccountComponent::from(ConstantFeeManager::for_basic_constant_fee_policy()));
        } else if component_name == "faucet" {
            components.push(AccountComponent::from(
                miden_standards::account::access::Ownable2Step::new(dummy_account_id),
            ));
            components.extend(AccessControl::Rbac {
                admin: dummy_account_id,
                procedure_roles: std::collections::BTreeMap::new(),
            });
            let token_policy_manager = TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::owner_only())
                .active_burn_policy(BurnPolicy::owner_only())
                .active_send_policy(TransferPolicy::allow_all())
                .active_receive_policy(TransferPolicy::allow_all())
                .build();

            components.extend(token_policy_manager);
            components
                .push(AccountComponent::from(ConstantFeeManager::for_basic_constant_fee_policy()));
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
use {mem_store_double_word} from miden::standards::utils


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
