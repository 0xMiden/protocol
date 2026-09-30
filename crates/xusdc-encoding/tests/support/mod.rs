//! Shared test-support for the faucet mint-precondition shell suite.
//!
//! OWNERSHIP NOTE: the `ERR_XRESERVE_*` constants and the config-slot labels below are
//! faucet-owned TEST-SIDE mirrors — the encoding library crate owns none of them (the shared
//! parser is encoding-owned;
//! the faucet owns only mint-specific assertions). They are the single Rust source for both the
//! fixture slot bindings and the generated-driver interpolation; the shell modules declare
//! byte-identical production `word("…")` slot consts, and the constant-parity suite pins the
//! production labels against these.
//!
//! Harness mechanics mirror `tests/masm_dual.rs` (assemble → bind → MockChain →
//! execute), extended so that the shell reads config slots via
//! `active_account::get_item`, which the kernel authenticates as account-origin, so the
//! driver is a CALL-entered account component proc that stages the preimage in its own
//! (account-context) memory and `exec`s the shell — exactly the production
//! `xreserve_mint` calling shape.

#![allow(dead_code)]

pub mod mint_transport;
pub mod w2admin;

// The standard pause / blocklist admin-note factories live with the rest of the standard-admin
// fixtures; re-exported here so every suite reaches them through `support::*` as before.
// Each test binary compiles this module separately and pulls in only the helpers it uses, so the
// re-export is legitimately unused in most of them.
#[allow(unused_imports)]
pub use w2admin::{
    stock_block_note, stock_min_burn_note, stock_pause_action_note, stock_pause_note,
    stock_set_max_supply_note, stock_unblock_note, stock_unpause_note,
};

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use miden_processor::advice::AdviceInputs;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::component::{AccountComponentCode, AccountComponentMetadata};
use miden_protocol::account::{
    Account, AccountComponent, AccountId, AccountIdVersion, AccountProcedureRoot, AccountType,
    AssetCallbackFlag, RoleSymbol, StorageMap, StorageMapKey, StorageSlot,
};
use miden_protocol::assembly::Package;
use miden_protocol::asset::{Asset, AssetAmount, AssetId, FungibleAsset, TokenSymbol};
use miden_protocol::block::FeeParameters;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteScript, NoteType};
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote};
use miden_protocol::utils::bytes_to_packed_u32_elements;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::{
    Pausable, PausableManager, PausableStorage, RoleBasedAccessControl, RoleConfig,
};
use miden_standards::account::auth::AuthNetworkAccount;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::fees::{BasicConstantFeePolicy, FeePolicyManager};
use miden_standards::account::policies::{
    BurnPolicy, MinBurnAmount, MintPolicy, TokenPolicyManager,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::config::{
    BlocklistConfigNote, ConstantFeePolicyConfigNote, FaucetMetadataConfigNote, PauseConfigNote,
    RbacConfigNote,
};
use miden_standards::note::{BurnNote, FeeSponsorshipNote, MintNote};
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_testing::{AccountState, Auth, MockChain, MockChainBuilder};
use miden_tx::TransactionExecutorError;
use xusdc_encoding::account::xreserve::builder::XRESERVE_BURN_POLICY_PROC_PATH;
use xusdc_encoding::account::xreserve::{
    XReserveAdminAuthority, XReserveFaucetExtension, XReserveStablecoinBuilder,
    XReserveStablecoinBuilderError, ATTEST_ADMIN_ROLE, BLK_MANAGER_ROLE, DOM_PAUSER_ROLE,
    DOM_UNPAUSER_ROLE,
};
use xusdc_encoding::errors;
use xusdc_encoding::note::xreserve_admin::{XReserveMinBurnAmountNote, XReserveSetAttesterNote};
use xusdc_encoding::note::xreserve_burn::XReserveBurnNote;
use xusdc_encoding::note::xreserve_mint::{DepositAttestation, XUsdcMintNote};
use xusdc_encoding::xreserve::encoding::{
    CircleDomain, DepositIntent, ForeignChainAddress, XReserveBurnItems,
};
use xusdc_encoding::xreserve_lib::XReserveLibrary;

// Attestation fixtures — deterministic secp256k1 keys and signatures generated IN-TEST (the
// canonical vector artifact is untouched), mirroring the `gen_vectors` att_* helpers: k256 the
// keypair+signature, sha3 the keccak digest, miden-crypto `PublicKey::to_commitment` the
// allowlist-key oracle, miden_protocol `bytes_to_packed_u32_elements` the advice felt packing.
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey};
use miden_crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_crypto::utils::Deserializable;
use miden_crypto::SequentialCommit;
use miden_standards::interop::eth::EthEmbeddedAccountId;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha3::{Digest, Keccak256};

// TEST-ONLY FAUCET CONFIG (the domain id and the identifier encoding are Circle-owned and OPEN)
// ================================================================================================
// The real Miden domain id is Circle-assigned and OPEN — `TEST_DOMAIN` exists
// solely to match the canonical accept vectors' `remote_domain` (= 7) and must never
// be presented as the real value. The AccountId↔bytes32 encoding the faucet derives its
// identifier with is likewise Circle-OPEN.

/// Matches `di-pos-hookdata` / `di-pos-empty-hookdata` `fields.remote_domain`.
pub const TEST_DOMAIN: CircleDomain = CircleDomain::new(7);
/// Any value != the vectors' remote_domain, for the wrong-domain reject.
pub const TEST_WRONG_DOMAIN: CircleDomain = CircleDomain::new(8);
/// Test destination domain for burn fixtures.
pub const TEST_SOURCE_DOMAIN: CircleDomain = CircleDomain::new(3);

/// The production mint note over a RAW Circle payload, built exactly the way the relayer builds
/// one: decode the payload, then drive the typed [`XUsdcMintNote`] builder at [`TEST_DOMAIN`].
///
/// The suites carry raw payloads because that is what the golden vectors hold, so this is the one
/// place the decode step lives.
pub fn mint_note_from_payload(
    sender: AccountId,
    faucet_id: AccountId,
    payload: &[u8],
    attestation: DepositAttestation,
    rng: &mut impl FeltRng,
) -> Result<Note> {
    mint_note_from_payload_at_domain(sender, faucet_id, TEST_DOMAIN, payload, attestation, rng)
}

/// [`mint_note_from_payload`] against a named faucet domain — for the suites that drive a faucet
/// configured to something other than [`TEST_DOMAIN`].
pub fn mint_note_from_payload_at_domain(
    sender: AccountId,
    faucet_id: AccountId,
    remote_domain: CircleDomain,
    payload: &[u8],
    attestation: DepositAttestation,
    rng: &mut impl FeltRng,
) -> Result<Note> {
    let deposit_intent = DepositIntent::try_from(payload)
        .map_err(|e| anyhow::anyhow!("decoding the deposit intent payload: {e}"))?;
    let note = XUsdcMintNote::builder()
        .sender(sender)
        .target(faucet_id)
        .remote_domain(remote_domain)
        .deposit_intent(deposit_intent)
        .attestation(attestation)
        .generate_serial_number(rng)
        .build()
        .map_err(|e| anyhow::anyhow!("building the attested stock mint note: {e}"))?;
    Ok(Note::from(note))
}

// NOTE: the tests do not bind slot names of their own. The three xreserve slots come from
// `XReserveFaucetExtension::*_slot()` and the stock ones from their owning standards component
// (`FungibleFaucet::token_config_slot()`, `MinBurnAmount::slot_name()` — the latter read via
// [`read_min_burn_size`]), so a test and the shipped faucet can never key different slots.

// FAUCET ERROR MIRRORS (frozen names)
// ================================================================================================

/// Name → constant table for the faucet-owned shell errors, so a behaviour test can name the EXACT
/// error it expects. The messages are NOT written here: each row points at the constant `build.rs`
/// generated from the MASM that raises it, so a message can only be changed in the MASM. What this
/// table still carries is the NAME set — an error the faucet raises but no test names fails the
/// bidirectional constant sweep until it gets a row.
pub static SHELL_ERR_TABLE: [(&str, MasmError); 23] = [
    (
        "ERR_XRESERVE_BURN_NOTE_WITHDRAWAL_MISSING",
        errors::ERR_XRESERVE_BURN_NOTE_WITHDRAWAL_MISSING,
    ),
    (
        "ERR_XRESERVE_BURN_NOTE_TARGET_MISSING",
        errors::ERR_XRESERVE_BURN_NOTE_TARGET_MISSING,
    ),
    (
        "ERR_XRESERVE_BURN_NOTE_ATTACHMENT_COUNT",
        errors::ERR_XRESERVE_BURN_NOTE_ATTACHMENT_COUNT,
    ),
    (
        "ERR_XRESERVE_BURN_NOTE_WITHDRAWAL_WORDS",
        errors::ERR_XRESERVE_BURN_NOTE_WITHDRAWAL_WORDS,
    ),
    (
        "ERR_XRESERVE_BURN_AMOUNT_BELOW_MIN",
        errors::ERR_XRESERVE_BURN_AMOUNT_BELOW_MIN,
    ),
    (
        "ERR_XRESERVE_MINT_INTENT_LIMB",
        errors::ERR_XRESERVE_MINT_INTENT_LIMB,
    ),
    (
        "ERR_XRESERVE_DOMAIN_NOT_U32",
        errors::ERR_XRESERVE_DOMAIN_NOT_U32,
    ),
    (
        "ERR_XRESERVE_MINT_ZERO_AMOUNT",
        errors::ERR_XRESERVE_MINT_ZERO_AMOUNT,
    ),
    (
        "ERR_XRESERVE_MINT_AMOUNT_OVER_MAX",
        errors::ERR_XRESERVE_MINT_AMOUNT_OVER_MAX,
    ),
    (
        "ERR_XRESERVE_AMOUNT_BELOW_FEE",
        errors::ERR_XRESERVE_AMOUNT_BELOW_FEE,
    ),
    (
        "ERR_XRESERVE_NONCE_REPLAY",
        errors::ERR_XRESERVE_NONCE_REPLAY,
    ),
    (
        "ERR_XRESERVE_DISALLOWED_PUB_KEY",
        errors::ERR_XRESERVE_DISALLOWED_PUB_KEY,
    ),
    ("ERR_XRESERVE_SIG_LIMB", errors::ERR_XRESERVE_SIG_LIMB),
    (
        "ERR_XRESERVE_MINT_NOTE_TRANSPORT_MISSING",
        errors::ERR_XRESERVE_MINT_NOTE_TRANSPORT_MISSING,
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_TARGET_MISSING",
        errors::ERR_XRESERVE_MINT_NOTE_TARGET_MISSING,
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_ATTACHMENT_COUNT",
        errors::ERR_XRESERVE_MINT_NOTE_ATTACHMENT_COUNT,
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_TRANSPORT_TOO_SHORT",
        errors::ERR_XRESERVE_MINT_NOTE_TRANSPORT_TOO_SHORT,
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_HOOK_LEN_LIMB",
        errors::ERR_XRESERVE_MINT_NOTE_HOOK_LEN_LIMB,
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_INTENT_WORDS",
        errors::ERR_XRESERVE_MINT_NOTE_INTENT_WORDS,
    ),
    (
        "ERR_XRESERVE_MINT_RECIPIENT_MISMATCH",
        errors::ERR_XRESERVE_MINT_RECIPIENT_MISMATCH,
    ),
    (
        "ERR_XRESERVE_MINT_AMOUNT_MISMATCH",
        errors::ERR_XRESERVE_MINT_AMOUNT_MISMATCH,
    ),
    (
        "ERR_XRESERVE_MINT_TAG_MISMATCH",
        errors::ERR_XRESERVE_MINT_TAG_MISMATCH,
    ),
    (
        "ERR_XRESERVE_MINT_NOTE_TYPE_NOT_PUBLIC",
        errors::ERR_XRESERVE_MINT_NOTE_TYPE_NOT_PUBLIC,
    ),
];

/// The stock minimum-burn error, preserved by the custom burn policy.
pub fn err_burn_below_min_burn_amount() -> MasmError {
    MasmError::from_static_str(
        "amount to be burned must meet or exceed specified minimum burn amount",
    )
}

/// The rendering of the core library's own ECDSA reject (`miden::core::crypto::dsa::
/// ecdsa_k256_keccak`) — a signature that is well-formed but does not verify for the presented
/// key and message.
///
/// This identity is upstream's, not the faucet's, and that is forced rather than chosen: the
/// verifier the faucet calls traps on a failed verification instead of returning a flag, so no
/// faucet-owned assert ever runs. The secp256k1 arithmetic settles through the `uint256`
/// precompile, so the trap surfaces as that precompile's deferred assertion failure.
pub const ECDSA_VERIFY_REJECT_RENDERING: &str =
    "precompile `uint256`: deferred assertion failed: values disagree";

/// Asserts `result` is the trap a failed ECDSA verification produces, by its rendered identity
/// ([`ECDSA_VERIFY_REJECT_RENDERING`]).
pub fn assert_ecdsa_verify_reject<T>(result: Result<T, TransactionExecutorError>) {
    let Err(err) = result else {
        panic!("a failed ECDSA verification must trap the transaction")
    };
    let rendered = format!("{:#}", anyhow::Error::new(err));
    assert!(
        rendered.contains(ECDSA_VERIFY_REJECT_RENDERING),
        "expected the ECDSA verification reject, got: {rendered}"
    );
}

/// Looks up an expected faucet-owned MASM error by name. Errors raised inside the LINKED protocol
/// and standards libraries are not here — a test that expects one names that library's own
/// constant, so there is no local copy to drift.
pub fn shell_error_by_name(name: &str) -> &'static MasmError {
    SHELL_ERR_TABLE
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, e)| e)
        .unwrap_or_else(|| panic!("test names unknown MASM error constant {name}"))
}

// TRIPWIRE SERIALIZATION
// ================================================================================================

/// Serializes the security-tripwire tests: they flake under parallel `cargo test`, so every
/// tripwire holds this lock for its whole body — the in-tree equivalent of `serial_test`'s
/// `#[serial]` (that crate is not in the pinned offline `Cargo.lock`, so the guard lives here
/// instead of a new dependency; cargo runs test BINARIES sequentially, so a per-binary process
/// lock is exactly the scope `serial_test` would give). The async-aware `tokio::sync::Mutex`
/// is deliberate: an async tripwire holds its guard across `.await` points
/// (`clippy::await_holding_lock` forbids a `std` guard there), and tokio's mutex has no
/// poisoning, so a panicking holder cannot cascade spurious failures into later tripwires.
static TRIPWIRE_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The async-test guard: `let _serial = tripwire_serial_guard().await;`.
pub async fn tripwire_serial_guard() -> tokio::sync::MutexGuard<'static, ()> {
    TRIPWIRE_SERIAL.lock().await
}

/// The sync-test guard (blocks the test thread; sync tests run outside any tokio runtime, which
/// `blocking_lock` requires): `let _serial = tripwire_serial_guard_blocking();`.
pub fn tripwire_serial_guard_blocking() -> tokio::sync::MutexGuard<'static, ()> {
    TRIPWIRE_SERIAL.blocking_lock()
}

// HARNESS (assemble → bind components+slots → MockChain account)
// ================================================================================================

/// Memory base for preimages staged by the driver proc in ITS OWN call context
/// (word-aligned; same base convention as `masm_dual.rs`). Test-fixture-only global
/// staging: the driver owns the entire fresh call context, so the
/// `masm-locals-over-globals` scratch rule is deliberately not applied here (recorded
/// deviation; the shell itself uses no memory at all).
pub const INTENT_PTR: u64 = 1024;

fn collect_masm_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("asm directory must be readable") {
        let path = entry.expect("directory entry must be readable").path();
        if path.is_dir() {
            collect_masm_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "masm") {
            out.push(path);
        }
    }
}

/// Memory bases for the attestation operands the drivers stage alongside the preimage, mirroring
/// how the production policy hands `validate` and `verify_attestation` pointers into
/// the hash-verified attestation attachment. All word-aligned and clear of `INTENT_PTR`.
pub const FEE_AMOUNT_PTR: u64 = 0;
pub const PUBKEY_PTR: u64 = 8;
pub const SIGNATURE_PTR: u64 = 24;

/// Module path of the generated per-case shell driver component.
pub const SHELL_DRIVER_PATH: &str = "xusdc::test_fixtures::shell_driver";
/// Module path of the slot-binding probe component.
pub const SLOT_PROBE_PATH: &str = "xusdc::test_fixtures::slot_probe";

/// A deterministic dummy `AccountId` for the builder's `owner` / DOM role-holder inputs and for the
/// role-holder / non-holder note senders in the `set_attester` suite. Mirrors
/// `miden-testing/tests/scripts/rbac.rs:49-51`.
pub fn test_account_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Private,
        AssetCallbackFlag::Disabled,
    )
}

/// A deterministic PUBLIC dummy account id representing THIS (policed) faucet — usable as a faucet
/// target for the scheme-2 `NetworkAccountTarget` routing attachment (mint/burn/admin notes require
/// a PUBLIC faucet id) and as a fungible-asset issuer in note-construction unit tests. Carries
/// `AssetCallbackFlag::Enabled`: the deployed faucet is Enabled (policed), so a dummy standing in
/// for it must not misrepresent it as a basic (callback-disabled) asset issuer.
pub fn test_faucet_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Enabled,
    )
}

/// The faucet issuing the test-only fee asset.
pub fn test_fee_faucet_id() -> AccountId {
    test_faucet_id(250)
}

/// Returns fee parameters with a zero base fee for behavior tests unrelated to fee collection.
pub fn test_fee_parameters() -> FeeParameters {
    FeeParameters::new(0)
}

/// Returns the test fee asset, issued by [`test_fee_faucet_id`].
pub fn test_fee_asset_id() -> AssetId {
    AssetId::new_fungible(test_fee_faucet_id())
}

/// Returns the default fee policy used by tests.
pub fn test_fee_policy() -> BasicConstantFeePolicy {
    BasicConstantFeePolicy::new()
        .with_fees(
            XReserveStablecoinBuilder::allowed_note_scripts()
                .into_iter()
                .map(|root| (root, AssetAmount::ZERO)),
        )
        .with_fee(
            ConstantFeePolicyConfigNote::script_root(),
            AssetAmount::new(1).expect("one is a valid fee"),
        )
}

/// Returns a fee manager for tests that instantiate `AuthNetworkAccount` directly.
pub fn test_fee_policy_manager() -> FeePolicyManager {
    FeePolicyManager::builder()
        .fee_faucet_id(test_fee_faucet_id())
        .active_fee_policy(test_fee_policy().into())
        .build()
}

/// Adds a faucet account to the mock chain from its composed `components`. The immutable
/// `AssetCallbackFlag` is derived by the `AccountBuilder` from the installed callback slots, so a
/// policed faucet's transfer-policy callbacks fire without any per-fixture flag plumbing.
pub fn add_faucet_account(
    builder: &mut MockChainBuilder,
    auth: Auth,
    components: Vec<AccountComponent>,
) -> Result<Account> {
    let mut account_builder = Account::builder(rand::random()).account_type(AccountType::Public);
    for component in components {
        account_builder = account_builder.with_component(component);
    }
    builder
        .add_account_from_builder(auth, account_builder, AccountState::Exists)
        .context("adding a faucet account from its composed components (callback-flag derived)")
}

/// Adds the production network faucet using `XReserveStablecoinBuilder::auth_component()`.
pub fn add_network_faucet_account(
    builder: &mut MockChainBuilder,
    components: Vec<AccountComponent>,
) -> Result<Account> {
    let account =
        build_network_faucet_account(components, test_fee_parameters(), test_fee_asset_id())?;
    builder
        .add_account(account.clone())
        .context("registering the production network faucet account")?;
    Ok(account)
}

/// Builds the production network faucet with the xUSDC fee policy derived from `fee_parameters`.
pub fn build_network_faucet_account(
    components: Vec<AccountComponent>,
    fee_parameters: FeeParameters,
    fee_asset_id: AssetId,
) -> Result<Account> {
    build_network_faucet_account_with_assets(components, fee_parameters, fee_asset_id, [])
}

/// Builds the production network faucet with initial assets and the xUSDC fee policy.
pub fn build_network_faucet_account_with_assets(
    components: Vec<AccountComponent>,
    fee_parameters: FeeParameters,
    fee_asset_id: AssetId,
    assets: impl IntoIterator<Item = Asset>,
) -> Result<Account> {
    let auth = XReserveStablecoinBuilder::auth_component(fee_parameters, fee_asset_id)
        .map_err(|e| anyhow::anyhow!("the production auth component must build: {e}"))?;
    build_network_faucet_account_with_auth(components, auth, assets)
}

/// Builds the network faucet with an explicit policy for fee-pricing benchmark fixtures.
pub fn build_network_faucet_account_with_fee_policy_and_assets(
    components: Vec<AccountComponent>,
    fee_faucet_id: AccountId,
    fee_policy: BasicConstantFeePolicy,
    assets: impl IntoIterator<Item = Asset>,
) -> Result<Account> {
    let fee_policy_manager = FeePolicyManager::builder()
        .fee_faucet_id(fee_faucet_id)
        .active_fee_policy(fee_policy.into())
        .build();
    let auth = AuthNetworkAccount::custom(
        XReserveStablecoinBuilder::allowed_note_scripts(),
        fee_policy_manager,
    )?
    .with_allowed_tx_scripts(BTreeSet::from([ExpirationTransactionScript::script_root()]));
    build_network_faucet_account_with_auth(components, auth, assets)
}

fn build_network_faucet_account_with_auth(
    components: Vec<AccountComponent>,
    auth: AuthNetworkAccount,
    assets: impl IntoIterator<Item = Asset>,
) -> Result<Account> {
    let mut account_builder = Account::builder(rand::random())
        .account_type(AccountType::Public)
        .with_assets(assets);
    for component in components {
        account_builder = account_builder.with_component(component);
    }
    account_builder = account_builder.with_components(auth);
    account_builder
        .build_existing()
        .context("building the production network faucet account")
}

/// The shipped xreserve library, as the build script assembled it.
///
/// Assembly moved to build time, so there is nothing left here that can fail; the `Result` is kept
/// because this fixture has many callers and none of them care.
pub fn assemble_xreserve_lib() -> Result<Package> {
    Ok(XReserveLibrary::default().into())
}

/// Where the attestation mint policy answers inside the LIBRARY, as opposed to
/// [`ATTESTATION_MINT_POLICY_PROC_PATH`], which is where the shipped faucet component re-exports it.
/// Both resolve to the same root; the harnesses below install the library directly, so they have to
/// ask for it by this path.
const LIBRARY_ATTESTATION_MINT_POLICY_PROC_PATH: &str = "xreserve::mint_policy::check_policy";

/// Resolves the attestation mint policy's root from a component carrying the xreserve library.
fn library_attestation_mint_policy_root(component: &AccountComponent) -> Result<Word> {
    component
        .get_procedure_root_by_path(LIBRARY_ATTESTATION_MINT_POLICY_PROC_PATH)
        .map(Word::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the harness component does not export \
                 '{LIBRARY_ATTESTATION_MINT_POLICY_PROC_PATH}'"
            )
        })
}

/// THE production-shape [`XReserveStablecoinBuilder`] construction — the ONE definition of the
/// constructor argument shape that every production fixture AND every production PIN is measured
/// through. A second copy of this shape anywhere would keep measuring
/// the OLD arguments after the production ones changed, leaving a root/slot pin green while the
/// shipped account moved; so there is exactly one, and callers differ only in `domain`, the
/// optional `min_burn_amount` and the build-seeded `attesters`. Returns the constructor's typed
/// verdict; the outer `Result` carries fixture setup failures only.
pub fn production_builder_verdict_with_attesters(
    token_supply: u64,
    domain: CircleDomain,
    min_burn_amount: Option<AssetAmount>,
    attesters: Vec<PublicKey>,
) -> Result<std::result::Result<XReserveStablecoinBuilder, XReserveStablecoinBuilderError>> {
    Ok(XReserveStablecoinBuilder::builder()
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        .owner(test_account_id(1))
        .attest_admin_holders(vec![test_account_id(1)])
        .pauser_holders(vec![test_account_id(2)])
        .unpauser_holders(vec![test_account_id(3)])
        .blocklist_manager_holders(vec![test_account_id(4)])
        .fee_parameters(test_fee_parameters())
        .fee_asset_id(test_fee_asset_id())
        .domain(domain)
        .attesters(attesters)
        .maybe_min_burn_amount(min_burn_amount)
        .build())
}

/// [`production_builder_verdict_with_attesters`] with an empty allowlist.
pub fn production_builder_verdict(
    token_supply: u64,
    domain: CircleDomain,
    min_burn_amount: Option<AssetAmount>,
) -> Result<std::result::Result<XReserveStablecoinBuilder, XReserveStablecoinBuilderError>> {
    production_builder_verdict_with_attesters(token_supply, domain, min_burn_amount, Vec::new())
}

pub fn production_builder(
    token_supply: u64,
    domain: CircleDomain,
) -> Result<XReserveStablecoinBuilder> {
    production_builder_verdict(token_supply, domain, None)?
        .map_err(|e| anyhow::anyhow!("building the production faucet: {e}"))
}

pub fn production_component_set(token_supply: u64) -> Result<Vec<AccountComponent>> {
    production_builder_outcome(token_supply, None)?
        .map_err(|e| anyhow::anyhow!("composing the production faucet components: {e}"))
}

/// The ten allowlisted note scripts as labelled `(name, script)` pairs: two supply notes, six
/// administration and configuration notes (one faucet-owned, five standard), the constant-fee
/// configuration note, and the sponsorship note.
pub fn allowlisted_note_scripts() -> Vec<(&'static str, NoteScript)> {
    vec![
        ("stock_mint_note", MintNote::script()),
        ("stock_burn_note", BurnNote::script()),
        ("set_attester", XReserveSetAttesterNote::script()),
        (
            "stock_min_burn_amount_config_note",
            XReserveMinBurnAmountNote::script(),
        ),
        ("stock_pause_action_note", PauseConfigNote::script()),
        (
            "stock_faucet_metadata_config_note",
            FaucetMetadataConfigNote::script(),
        ),
        ("stock_blocklist_config_note", BlocklistConfigNote::script()),
        ("stock_rbac_action_note", RbacConfigNote::script()),
        (
            "stock_constant_fee_policy_config_note",
            ConstantFeePolicyConfigNote::script(),
        ),
        ("stock_fee_sponsorship_note", FeeSponsorshipNote::script()),
    ]
}

/// The PRODUCTION builder verdict with the fixture SETUP errors separated from the builder's own
/// typed outcome: the outer `Result` carries test-fixture setup failures (library assembly, slot
/// binding, faucet construction), the inner `Result` is `build_components`' typed
/// [`XReserveStablecoinBuilderError`] verdict — so the builder-reject tripwires can
/// `assert_matches!` the CONCRETE variant (the specific error, never a stringified word
/// search). `min_burn_size = None` keeps the builder default. The mint policy is not a builder
/// input — it is hard-wired to the attestation policy, the production shape.
pub fn production_builder_outcome(
    token_supply: u64,
    min_burn_size: Option<u64>,
) -> Result<std::result::Result<Vec<AccountComponent>, XReserveStablecoinBuilderError>> {
    let min_burn_amount = min_burn_size
        .map(AssetAmount::new)
        .transpose()
        .context("invalid min_burn_size")?;
    Ok(
        production_builder_verdict(token_supply, TEST_DOMAIN, min_burn_amount)?
            .and_then(|builder| builder.build_components()),
    )
}

pub struct ShellHarness {
    pub mock_chain: MockChain,
    pub account_id: AccountId,
    pub driver_code: AccountComponentCode,
    pub driver_path: &'static str,
}

/// Builds the MockChain account carrying [the xreserve component WITH the named domain value
/// slot + the `usedNonces` map slot] + [the generated driver component], per the
/// proven binding (`StorageSlotName::new(label)` ↔ MASM `word("label")`) and the
/// proven `StorageSlot::with_map` map-slot path. The `usedNonces` map starts EMPTY
/// (unused nonces read `EMPTY_WORD`); use `setup_shell_account_with_nonce_seed` to
/// pre-populate it so the replay guard sees a spent nonce.
pub fn setup_shell_account(
    domain: Word,
    driver_src: &str,
    driver_path: &'static str,
) -> Result<ShellHarness> {
    setup_shell_account_with_nonce_seed(domain, None, driver_src, driver_path)
}

/// Like `setup_shell_account`, but optionally seeds the `usedNonces` map with a single
/// `key -> marker` entry (the replay fixture): `Some((key, marker))` pre-populates the
/// map so a real `active_account::get_map_item` read returns the non-empty marker; `None`
/// leaves it empty. The guard only READS the map — this seeding is a test fixture standing in for
/// the marker the mint tail would have written.
pub fn setup_shell_account_with_nonce_seed(
    domain: Word,
    nonce_seed: Option<(Word, Word)>,
    driver_src: &str,
    driver_path: &'static str,
) -> Result<ShellHarness> {
    setup_shell_account_with_lib(
        assemble_xreserve_lib()?,
        domain,
        nonce_seed,
        driver_src,
        driver_path,
    )
}

fn setup_shell_account_with_lib(
    library: Package,
    domain: Word,
    nonce_seed: Option<(Word, Word)>,
    driver_src: &str,
    driver_path: &'static str,
) -> Result<ShellHarness> {
    let nonce_map = match nonce_seed {
        Some((key, marker)) => StorageMap::with_entries([(StorageMapKey::new(key), marker)])
            .map_err(|e| anyhow::anyhow!("seeding the usedNonces map fixture: {e}"))?,
        None => StorageMap::new(),
    };

    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![
            StorageSlot::with_value(
                XReserveFaucetExtension::domain_config_slot().clone(),
                domain,
            ),
            StorageSlot::with_map(
                XReserveFaucetExtension::used_nonces_slot().clone(),
                nonce_map,
            ),
        ],
        AccountComponentMetadata::new("xusdc-mint-shell-harness"),
    )
    .context("binding the xreserve library + config slots as a component")?;

    let driver_code = CodeBuilder::new()
        .with_dynamically_linked_package(&library)
        .context("linking the xreserve library into the driver component")?
        .compile_component_code(driver_path, driver_src)
        .with_context(|| {
            format!("driver component failed to compile\n--- driver ---\n{driver_src}")
        })?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-shell-driver"),
    )
    .context("binding the driver component")?;

    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(
            Auth::IncrNonce,
            [xreserve_component, driver_component],
        )
        .context("adding the shell harness account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(ShellHarness {
        mock_chain,
        account_id: account.id(),
        driver_code,
        driver_path,
    })
}

/// Executes `call.driver::<proc>` from a trivial tx script (alias-import pattern)
/// — the call enters the driver component proc in the ACCOUNT context.
pub async fn run_call_driver(
    h: &ShellHarness,
    proc_name: &str,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src = format!(
        "use {path} as driver\n@transaction_script\npub proc main\n    call.driver::{proc_name}\nend\n",
        path = h.driver_path
    );
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_package(&h.driver_code)
        .expect("linking the driver component into the tx script")
        .compile_tx_script(&src)
        .unwrap_or_else(|e| {
            panic!("driver call script failed to compile: {e}\n--- script ---\n{src}")
        });
    h.mock_chain
        .build_transaction(h.account_id)
        .tx_script(tx_script)
        .build()
        .expect("building the transaction")
        .execute()
        .await
}

// GENERATED DRIVER SOURCES
// ================================================================================================

fn word_of(felts: &[Felt]) -> Word {
    Word::new([felts[0], felts[1], felts[2], felts[3]])
}

/// Emits the `push.[..] mem_storew_le.{addr} dropw` staging sequence for a felt slice
/// (zero-padding the trailing word) at `base_ptr`, inside the driver proc's own call context.
/// `base_ptr` must be word-aligned.
fn stage_felts(src: &mut String, felts: &[Felt], base_ptr: u64) {
    for (i, chunk) in felts.chunks(4).enumerate() {
        let mut w = [miden_protocol::ZERO; 4];
        w[..chunk.len()].copy_from_slice(chunk);
        let addr = base_ptr + 4 * i as u64;
        writeln!(src, "    push.{} mem_storew_le.{addr} dropw", word_of(&w)).unwrap();
    }
}

/// Stages the DepositIntent preimage at `INTENT_PTR` — the `masm_dual.rs` staging convention.
fn stage_preimage(src: &mut String, felts: &[Felt]) {
    stage_felts(src, felts, INTENT_PTR);
}

/// Generates the per-case shell-driver component source: a CALL-entered account proc that stages
/// the case's preimage and `feeAmount`, pushes the `validate` inputs `[intent_ptr,
/// intent_num_words, fee_amount_ptr, scale_exp, amount_y]`, `exec`s the shell, and (happy path)
/// asserts the returned `intent_num_bytes`.
///
/// `validate` is the parser's single entry, so one driver serves every mint-precondition stage: a
/// case reaches the stage it targets by being valid for the stages that run before it.
pub fn validate_driver_src(
    preimage: &[Felt],
    intent_num_words: u64,
    fee_amount: &[Felt],
    amount_y: u64,
    expected_intent_num_bytes: Option<u32>,
) -> String {
    validate_driver_src_inner(
        preimage,
        intent_num_words,
        fee_amount,
        amount_y,
        expected_intent_num_bytes,
        false,
    )
}

/// Like [`validate_driver_src`], but overwrites the staged intent's `remoteToken` with eight felts
/// taken from the advice stack before entering `validate`.
///
/// The faucet compares `remoteToken` against its OWN account id, and an account id is a hash over
/// the account's code — which includes this very driver. A driver that baked the bound token into
/// its source would therefore change the id it is trying to match. Taking the eight limbs as
/// transaction inputs breaks that circularity: the account is built first, and the Rust encoder
/// then produces the bytes for the id it actually got ([`own_token_advice`]).
pub fn validate_driver_src_own_token(
    preimage: &[Felt],
    intent_num_words: u64,
    fee_amount: &[Felt],
    amount_y: u64,
    expected_intent_num_bytes: Option<u32>,
) -> String {
    validate_driver_src_inner(
        preimage,
        intent_num_words,
        fee_amount,
        amount_y,
        expected_intent_num_bytes,
        true,
    )
}

fn validate_driver_src_inner(
    preimage: &[Felt],
    intent_num_words: u64,
    fee_amount: &[Felt],
    amount_y: u64,
    expected_intent_num_bytes: Option<u32>,
    splice_own_token: bool,
) -> String {
    let mut src = String::from(
        "use xreserve::deposit_intent\n\n\
         #! Test driver: stages a DepositIntent preimage and a feeAmount in the account context\n\
         #! and execs the faucet mint-precondition shell.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         @account_procedure\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    if splice_own_token {
        for i in 0..8 {
            let addr = INTENT_PTR + REMOTE_TOKEN_FELT_OFF + i;
            writeln!(src, "    adv_push mem_store.{addr}").unwrap();
        }
    }
    stage_felts(&mut src, fee_amount, FEE_AMOUNT_PTR);
    writeln!(src, "    push.{amount_y}").unwrap();
    writeln!(src, "    push.{FEE_AMOUNT_PTR}").unwrap();
    writeln!(src, "    push.{intent_num_words}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.deposit_intent_parser::validate\n");
    match expected_intent_num_bytes {
        // happy path: pin the shell's output, restoring the 16-depth call boundary
        Some(expected) => {
            writeln!(
                src,
                "    push.{expected} assert_eq.err=\"driver: intent_num_bytes mismatch\""
            )
            .unwrap();
        }
        // reject path: balance the would-be output so an unexpected non-trapping run
        // returns cleanly and the test's exact-error assertion reports the mismatch
        None => src.push_str("    drop\n"),
    }
    src.push_str("end\n");
    src
}

/// Generates the nonce-guard driver: push a `usedNonces` key and run the replay guard.
///
/// Under DC-14 the guard takes the key the caller already derived — the policy needs the same Word
/// for the output note's serial — so the driver no longer has to stage a whole intent to reach it.
pub fn nonce_guard_driver_src(key: Word) -> String {
    format!(
        "use xreserve::mint_intent\n\n         #! Test driver: runs the faucet's nonce replay guard over a caller-derived key.\n         #!\n         #! Inputs:  [pad(16)]\n         #! Outputs: [pad(16)]\n         #!\n         #! Invocation: call\n         @account_procedure\n         pub proc drive\n         \x20   push.{key}\n         \x20   exec.mint_intent::assert_nonce_unused\n         end\n"
    )
}

// DC-14 PREIMAGE-WRITER DRIVER
// ================================================================================================

/// Staging addresses for the `rebuild` driver. Both word-aligned and clear of the other drivers'
/// regions. The deposit-intent region is GLOBAL memory, mirroring the policy: `rebuild` writes only
/// the fields the message carries and relies on the rest reading zero.
pub const MINT_INTENT_PTR: u64 = 2048;
pub const DEPOSIT_INTENT_PTR: u64 = 3072;

/// Generates the DC-14 writer driver: stage the mint intent, run `deposit_intent::rebuild`, then
/// compare every felt of the message it built against the Rust mirror's.
///
/// The expected felts arrive on the ADVICE STACK rather than baked into this source, because the
/// message embeds the account's own id and an account id is a hash over the account's code — which
/// is this driver. Baking them would change the id they are trying to describe.
pub fn rebuild_driver_src(
    mint_intent_felts: &[Felt],
    mint_intent_num_words: u64,
    amount: u64,
    num_expected_felts: usize,
) -> String {
    let mut src = String::from(
        "use xreserve::deposit_intent\n\n         #! Test driver: stages the mint intent in the account context, rebuilds the DepositIntent\n         #! from it, and pins every felt against the Rust mirror.\n         #!\n         #! Inputs:  [pad(16)]\n         #! Outputs: [pad(16)]\n         #!\n         #! Invocation: call\n         @account_procedure\n         pub proc drive\n",
    );
    stage_felts(&mut src, mint_intent_felts, MINT_INTENT_PTR);
    writeln!(src, "    push.{amount}").unwrap();
    writeln!(src, "    push.{mint_intent_num_words}").unwrap();
    writeln!(src, "    push.{MINT_INTENT_PTR}").unwrap();
    writeln!(src, "    push.{DEPOSIT_INTENT_PTR}").unwrap();
    src.push_str("    exec.deposit_intent::rebuild\n");
    // => [intent_num_bytes]; the message itself is what this driver checks
    src.push_str("    drop\n");
    for i in 0..num_expected_felts {
        let addr = DEPOSIT_INTENT_PTR + i as u64;
        writeln!(
            src,
            "    adv_push mem_load.{addr} assert_eq.err=\"driver: deposit intent felt {i} mismatch\""
        )
        .unwrap();
    }
    src.push_str("end\n");
    src
}

/// The first felt of the DepositIntent `remoteToken` field in a staged preimage (wire bytes
/// 44..76, four wire bytes per felt).
const REMOTE_TOKEN_FELT_OFF: u64 = 11;

/// The eight advice felts [`validate_driver_src_own_token`] splices into a staged intent: the packed
/// limbs of `EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()`, produced by the RUST encoder.
pub fn own_token_advice(faucet_id: AccountId) -> Vec<Felt> {
    xusdc_encoding::xreserve::encoding::bytes32_to_packed_felts(
        &EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32(),
    )
    .to_vec()
}

/// Generates the P2 slot-binding probe component: reads the domain config slot via
/// `word("label")[0..2]` + `active_account::get_item` and pins the fixture word —
/// proving the `StorageSlotName` ↔ `word("…")` linkage and the call-context `get_item`
/// pipeline on the pinned 0.23.3 stack, independent of the shell implementation.
pub fn slot_probe_src(domain: Word) -> String {
    format!(
        "use miden::protocol::active_account\n\n\
         # the slot id derives from the SAME name the Rust fixture binds (single source:\n\
         # the XReserveFaucetExtension slot accessors)\n\
         const PROBE_DOMAIN_SLOT = word(\"{domain_label}\")\n\n\
         #! Probe: asserts the domain config slot holds the fixture word.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         @account_procedure\n\
         pub proc read_slots\n\
             push.PROBE_DOMAIN_SLOT[0..2]\n\
             exec.active_account::get_item\n\
             push.{domain}\n\
             assert_eqw.err=\"probe: domain slot mismatch\"\n\
         end\n",
        domain_label = XReserveFaucetExtension::domain_config_slot(),
    )
}

// AMOUNT / FEE HELPERS
// ================================================================================================

/// Felt offsets in a staged DepositIntent preimage: the two uint256 money fields (`amount` at
/// felts 2..9, `maxFee` at felts 43..50) and the `hookDataLen` limb at felt 59.
///
/// Each is the field's byte offset in the wire format divided by four, since one felt packs four
/// bytes. They mirror the MASM layout constants of the same names, and the two definitions are
/// held together by `constant_parity.rs`.
pub const AMOUNT_FELT_OFF: usize = 2;
pub const MAX_FEE_FELT_OFF: usize = 43;
pub const HOOK_DATA_LEN_FELT_OFF: usize = 59;

/// Clones a base accept preimage and overwrites the `amount` and `maxFee` fields with the
/// 8 u32-LE limbs of the chosen canonical `amt-*` vectors (read from the shared artifact — no
/// copied vector tables). The rest of the DepositIntent envelope (magic / version /
/// nonzero fields / length) is unchanged, so the shared-encoding structural parse stays valid and
/// execution reaches the amount reduction and its compares.
pub fn splice_amounts(base: &[Felt], amount_limbs: [u32; 8], maxfee_limbs: [u32; 8]) -> Vec<Felt> {
    let mut preimage = base.to_vec();
    for (i, limb) in amount_limbs.iter().enumerate() {
        preimage[AMOUNT_FELT_OFF + i] = Felt::from(*limb);
    }
    for (i, limb) in maxfee_limbs.iter().enumerate() {
        preimage[MAX_FEE_FELT_OFF + i] = Felt::from(*limb);
    }
    preimage
}

/// The 8 u32-LE `feeAmount` limbs as felts (`Felt::from(u32)`, infallible —
/// `felt-construction`), in the order the reducer reads them out of memory.
pub fn fee_amount_felts(limbs: [u32; 8]) -> Vec<Felt> {
    limbs.iter().map(|l| Felt::from(*l)).collect()
}

/// Like `run_call_driver`, but stages an optional `feeAmount` advice stack into the tx
/// context (`extend_advice_inputs`). `None` ⇒ no advice staged (the missing-advice case,
/// which must error). `AdviceInputs::with_advice_stack` preserves order:
/// the first felt is the first one `adv_push` returns.
pub async fn run_call_driver_with_advice(
    h: &ShellHarness,
    proc_name: &str,
    advice_stack: Option<Vec<Felt>>,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let src = format!(
        "use {path} as driver\n@transaction_script\npub proc main\n    call.driver::{proc_name}\nend\n",
        path = h.driver_path
    );
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_package(&h.driver_code)
        .expect("linking the driver component into the tx script")
        .compile_tx_script(&src)
        .unwrap_or_else(|e| {
            panic!("driver call script failed to compile: {e}\n--- script ---\n{src}")
        });
    let mut ctx = h
        .mock_chain
        .build_transaction(h.account_id)
        .tx_script(tx_script);
    if let Some(stack) = advice_stack {
        ctx = ctx.extend_advice_inputs(AdviceInputs::default().with_stack(stack.into()));
    }
    ctx.build()
        .expect("building the transaction")
        .execute()
        .await
}

// D5D ATTESTATION VERIFY HELPERS
// ================================================================================================

/// A deterministically-generated attester: its 16-felt affine pubkey + 17-felt
/// signature (as advice felts) over a payload's keccak digest, and its `xReserveAttesters`
/// allowlist commitment (the miden-crypto `PublicKey::to_commitment` oracle == the on-chain MASM
/// `pubkey_commitment`).
pub struct AttesterVector {
    /// 16-felt affine pubkey coordinates `qx_le_u32[8] || qy_le_u32[8]` (the candidate pubkey the
    /// driver stages in memory; the Circle wire form stays the 33-byte compressed key below).
    pub pubkey_felts: Vec<Felt>,
    /// 17-felt u32-LE-packed r||s||v signature over keccak256(payload).
    pub sig_felts: Vec<Felt>,
    /// Poseidon2 commitment Word = the `xReserveAttesters` allowlist key for this pubkey.
    pub commitment: Word,
    /// The decoded key itself (what the relayer hands `XUsdcMintNote::create`); the 33-byte
    /// compressed SEC1 wire form it was read from is recovered with `Serializable::to_bytes`.
    pub pubkey: PublicKey,
    /// Raw 65-byte `r||s||v` signature (what the relayer hands `XUsdcMintNote::create`).
    pub sig_bytes: [u8; 65],
}

/// The 32 advice elements the core library's ECDSA verifier consumes for this attester:
/// `QX[8] || QY[8] || SIG_R[8] || SIG_S[8]`, every value a little-endian numeric u32 limb.
///
/// This is the verifier's own witness encoding (`miden_core_lib::dsa::ecdsa_k256_keccak::
/// encode_signature`), rebuilt here rather than imported because the core library is not a
/// dependency of this crate. It exists for ONE purpose: to let a test play the malicious host and
/// stage a witness that WOULD verify, proving the faucet consumes its own hash-verified material
/// instead. Note the limb order — the attestation wire carries a scalar as packed BYTES, most
/// significant limb first, while the verifier reads numeric limbs least significant first, which is
/// exactly the rewrite `attestation_verify::store_native_scalar` performs on-chain.
pub fn ecdsa_advice_witness(attester: &AttesterVector) -> Vec<Felt> {
    let mut witness = attester.pubkey_felts.clone();
    witness.extend(native_scalar_limbs(&attester.sig_bytes[..32]));
    witness.extend(native_scalar_limbs(&attester.sig_bytes[32..64]));
    witness
}

/// One 32-byte big-endian scalar as eight little-endian numeric u32 limbs.
fn native_scalar_limbs(be: &[u8]) -> [Felt; 8] {
    core::array::from_fn(|i| {
        let start = be.len() - 4 * (i + 1);
        Felt::from(u32::from_be_bytes(
            be[start..start + 4].try_into().expect("a 4-byte limb"),
        ))
    })
}

/// Deterministically generates an attester keypair (k256 + seeded StdRng) and signs
/// `keccak256(payload)` (sha3) with it — the SAME independent path
/// `gen_vectors` uses. Two distinct seeds over the SAME payload give the seam's key A / key B.
pub fn gen_attester(seed: u64, payload: &[u8]) -> AttesterVector {
    let mut key_bytes = [0u8; 32];
    StdRng::seed_from_u64(seed).fill_bytes(&mut key_bytes);
    let sk = SigningKey::from_slice(&key_bytes).expect("the seed yields a valid non-zero scalar");
    let pk33: [u8; 33] = sk
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 pubkey is 33 bytes");

    let mut hasher = Keccak256::new();
    hasher.update(payload);
    let digest: [u8; 32] = hasher.finalize().into();

    let (sig, recid): (K256Signature, RecoveryId) = sk
        .sign_prehash_recoverable(&digest)
        .expect("k256 prehash sign");
    let mut sig65 = [0u8; 65];
    sig65[..64].copy_from_slice(sig.to_bytes().as_ref());
    sig65[64] = recid.to_byte();

    let pubkey =
        PublicKey::read_from_bytes(&pk33).expect("the deterministic attester key is a curve point");
    let pubkey_felts = pubkey.to_elements();
    let commitment = pubkey.to_commitment();

    AttesterVector {
        pubkey_felts,
        commitment,
        sig_felts: bytes_to_packed_u32_elements(&sig65),
        pubkey,
        sig_bytes: sig65,
    }
}

/// Builds the MockChain account carrying [the xreserve component WITH the `xReserveAttesters` map
/// slot] + [the generated driver]. `attesters_seed = Some((commitment, marker))` pre-populates the
/// allowlist (an enabled attester); `None` leaves it empty (no attester allowlisted). The seeding
/// is a TEST fixture — the real `set_attester` admin setter is a separate path.
pub fn setup_attestation_account(
    attesters_seed: Option<(Word, Word)>,
    driver_src: &str,
    driver_path: &'static str,
) -> Result<ShellHarness> {
    let library = assemble_xreserve_lib()?;

    let attesters_map = match attesters_seed {
        Some((key, marker)) => StorageMap::with_entries([(StorageMapKey::new(key), marker)])
            .map_err(|e| anyhow::anyhow!("seeding the xReserveAttesters map fixture: {e}"))?,
        None => StorageMap::new(),
    };

    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![StorageSlot::with_map(
            XReserveFaucetExtension::xreserve_attesters_slot().clone(),
            attesters_map,
        )],
        AccountComponentMetadata::new("xusdc-attestation-harness"),
    )
    .context("binding the xreserve library + attester allowlist slot as a component")?;

    let driver_code = CodeBuilder::new()
        .with_dynamically_linked_package(&library)
        .context("linking the xreserve library into the driver component")?
        .compile_component_code(driver_path, driver_src)
        .with_context(|| {
            format!("driver component failed to compile\n--- driver ---\n{driver_src}")
        })?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-attestation-driver"),
    )
    .context("binding the driver component")?;

    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(
            Auth::IncrNonce,
            [xreserve_component, driver_component],
        )
        .context("adding the attestation harness account")?;
    let mock_chain = builder.build().context("building the MockChain")?;
    Ok(ShellHarness {
        mock_chain,
        account_id: account.id(),
        driver_code,
        driver_path,
    })
}

/// Generates the per-case attestation driver: stages the DepositIntent payload preimage, the
/// candidate pubkey and the signature in the account context, pushes
/// `[intent_ptr, intent_num_bytes, pubkey_ptr, signature_ptr]`, and `exec`s the faucet
/// `verify_attestation` shell. The shell returns `[]` (assert-only gate), so the
/// staged-then-consumed stack restores the 16-depth `call` boundary.
///
/// Taking the pubkey and signature separately is what lets the seam cases pair one attester's
/// pubkey with another's signature.
pub fn attestation_driver_src(
    preimage: &[Felt],
    len_bytes: u64,
    pubkey_felts: &[Felt],
    sig_felts: &[Felt],
) -> String {
    let mut src = String::from(
        "use xreserve::attestation_verify\n\n\
         #! Test driver: stages a DepositIntent payload, a candidate pubkey and a signature in\n\
         #! the account context and execs the attestation verify shell.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         @account_procedure\n\
         pub proc drive\n",
    );
    stage_preimage(&mut src, preimage);
    stage_felts(&mut src, pubkey_felts, PUBKEY_PTR);
    stage_felts(&mut src, sig_felts, SIGNATURE_PTR);
    writeln!(src, "    push.{SIGNATURE_PTR}").unwrap();
    writeln!(src, "    push.{PUBKEY_PTR}").unwrap();
    writeln!(src, "    push.{len_bytes}").unwrap();
    writeln!(src, "    push.{INTENT_PTR}").unwrap();
    src.push_str("    exec.attestation_verify::verify_attestation\n");
    src.push_str("end\n");
    src
}

// FIXTURE COMPONENT PATHS + FIELD OFFSETS
// ================================================================================================

/// Module path of the guarded fixture's caller-supplied probe component.
pub const MINT_PROBE_PATH: &str = "xusdc::test_fixtures::mint_probe";

/// Module path of the guarded fixture's caller-supplied driver component (compile-only in the
/// recomposed suites: the fixtures drive behavior through REAL notes; the slot remains for
/// probes that want a call-entered account proc).
pub const GUARDED_DRIVER_PATH: &str = "xusdc::test_fixtures::guarded_driver";

pub const REMOTE_RECIPIENT_FELT_OFF: usize = 19;

pub const AMOUNT_BYTE_OFF: usize = AMOUNT_FELT_OFF * 4;
pub const MAX_FEE_BYTE_OFF: usize = MAX_FEE_FELT_OFF * 4;
pub const REMOTE_RECIPIENT_BYTE_OFF: usize = REMOTE_RECIPIENT_FELT_OFF * 4;

/// A `uint256` big-endian 32-byte encoding of a u64 value (24 zero bytes + 8-byte BE) — for splicing
/// `amount` / `maxFee` into a payload's byte image.
pub fn uint256_be(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&value.to_be_bytes());
    out
}

pub struct CompositionHarness {
    pub mock_chain: MockChain,
    pub account_id: AccountId,
    pub driver_code: AccountComponentCode,
    pub probe_code: AccountComponentCode,
}

pub fn setup_bare_immutable_faucet(
    token_supply: u64,
    max_supply: u64,
) -> Result<CompositionHarness> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        // is_max_supply_mutable defaults to false (immutable) — the control fixture.
        .build()
        .context("failed to build the bare immutable FungibleFaucet")?;
    let placeholder = FungibleFaucet::code().clone();

    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(Auth::IncrNonce, [faucet.into()])
        .context("adding the bare immutable faucet account")?;
    let mock_chain = builder
        .build()
        .context("building the bare-faucet MockChain")?;
    Ok(CompositionHarness {
        mock_chain,
        account_id: account.id(),
        driver_code: placeholder.clone(),
        probe_code: placeholder,
    })
}

pub fn composition_supply_probe_src(expected_token_supply: u64) -> String {
    format!(
        "use miden::protocol::active_account\n\n\
         const PROBE_TOKEN_CONFIG_SLOT = word(\"{cfg}\")\n\n\
         #! No-effects readback: token_config.token_supply == expected.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         @account_procedure\n\
         pub proc check\n\
         \x20\x20\x20\x20push.PROBE_TOKEN_CONFIG_SLOT[0..2] exec.active_account::get_item\n\
         \x20\x20\x20\x20push.{expected} assert_eq.err=\"no-effect: token_supply changed\"\n\
         \x20\x20\x20\x20dropw\n\
         end\n",
        cfg = FungibleFaucet::token_config_slot(),
        expected = expected_token_supply,
    )
}

pub fn set_attester_note(
    sender: AccountId,
    commitment: Word,
    enabled: u8,
    seed: u64,
) -> Result<Note> {
    let lib = assemble_xreserve_lib()?;
    // Stack contract: [PK_COMMITMENT, enabled, pad(11)] (PK_COMMITMENT element-0 on top). Push the
    // 11 pad felts (deepest), then enabled, then the commitment so c0 ends on top: 11 + 1 + 4 = 16.
    let src = format!(
        "use xreserve::attester_admin\n\
         @note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.11 push.0 end\n\
         \x20\x20\x20\x20push.{enabled}\n\
         \x20\x20\x20\x20push.{c3}.{c2}.{c1}.{c0}\n\
         \x20\x20\x20\x20call.attester_admin::set_attester\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
        c0 = commitment[0],
        c1 = commitment[1],
        c2 = commitment[2],
        c3 = commitment[3],
    );
    let script = CodeBuilder::new()
        .with_dynamically_linked_package(&lib)
        .context("linking xreserve into the set_attester note script")?
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("set_attester note script failed to compile: {e}\n{src}"))?;
    // Deterministic note rng (RandomCoin satisfies NoteBuilder's `Rng` bound; StdRng's `rand`
    // version does not). The seed only affects the note serial, never the gate.
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(1u32),
        Felt::from(2u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a `set_attester` note (sent by `sender`) against the faucet `account`, returning the raw
/// execution result so callers can assert success or the exact trap. Note building (assemble/compile)
/// is a test-setup invariant (panics on failure); only the on-chain execution is returned.
pub async fn run_set_attester_tx(
    h: &CompositionHarness,
    account: &Account,
    sender: AccountId,
    commitment: Word,
    enabled: u8,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = set_attester_note(sender, commitment, enabled, seed)
        .expect("building the set_attester note (test-setup invariant)");
    h.mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the set_attester transaction")
        .execute()
        .await
}

/// The faucet account's CURRENT committed state — the starting point for the seam's first tx.
pub fn faucet_account(h: &CompositionHarness) -> Account {
    h.mock_chain
        .committed_account(h.account_id)
        .expect("faucet account is committed in the mock chain")
        .clone()
}

/// Builds a note SENT BY `sender` whose script calls the stock `PausableManager::pause`. The
/// procedure IS installed, so this note is the probe for WHO may use it: sent by the Domain pauser
/// it pauses the faucet, and sent by anyone else — including the administrator — it traps the role error,
/// which is what `administrator_has_no_pause_path` pins. It assembles without an xreserve link, since
/// StandardsLib is pre-linked.
pub fn manager_pause_call_note(sender: AccountId, seed: u64) -> Result<Note> {
    let src = "use miden::standards::access::pausable::manager\n\
               @note_script\n\
               pub proc main\n\
               \x20\x20\x20\x20repeat.16 push.0 end\n\
               \x20\x20\x20\x20call.manager::pause\n\
               \x20\x20\x20\x20dropw dropw dropw dropw\n\
               end\n";
    let script = CodeBuilder::new()
        .compile_note_script(src)
        .map_err(|e| anyhow::anyhow!("pause note script failed to compile: {e}"))?;
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(3u32),
        Felt::from(4u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a stock `PausableManager::pause` note (sent by `sender`) against the faucet `account` —
/// the CompositionHarness-shaped twin of [`run_pause_against`]. The procedure IS installed, so the
/// verdict is the role gate's: the Domain pauser succeeds and anyone else traps the role error.
pub async fn run_pause_tx(
    h: &CompositionHarness,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = manager_pause_call_note(sender, seed)
        .expect("building the manager pause-call note (test-setup invariant)");
    h.mock_chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the pause transaction")
        .execute()
        .await
}

// AUTHORITY-GATE ERROR MIRROR
// ================================================================================================

/// The exact stock error the RBAC role assertion traps (`rbac.masm` ERR_SENDER_LACKS_ROLE). Under
/// the account's role-based authority this is what an unauthorized sender gets from EVERY
/// authority-gated procedure: the ones with a role assigned (the pause and blocklist managers) and
/// the ones without, which fall back to the administrator role (`set_attester`,
/// the supply cap, the burn floor, the policy setters). No procedure gates on an administrator slot any
/// more — the faucet installs no ownership component, so there is no owner error to raise.
pub fn err_sender_lacks_role() -> MasmError {
    MasmError::from_static_str("note sender does not hold the required role")
}

// Minimum-burn configuration note and slot read-back
// ================================================================================================

/// Executes a standard minimum-burn configuration note sent by `sender` against `account` on a bare
/// `&MockChain` (the burn-policy harness is a `BurnPolicyHarness`, not a `CompositionHarness`). Returns
/// the raw execution result so callers assert success or the exact trap. Mirrors [`run_pause_against`].
pub async fn run_set_min_burn_amount_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    new_min: u64,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = stock_min_burn_note(sender, account.id(), new_min, seed)
        .expect("building the minimum-burn configuration note (test-setup invariant)");
    chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the minimum-burn configuration transaction")
        .execute()
        .await
}

/// Reads the STOCK `MinBurnAmount` floor slot word `[min_burn_amount, 0, 0, 0]` from a
/// committed/evolved account — the full-word read-back the write-integrity + no-state-change
/// tests use (the slot the stock `check_policy` reads and the stock `set_min_burn_amount`
/// writes; there is no custom `min_burn_size` slot). Mirrors
/// [`read_token_config`].
pub fn read_min_burn_size(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(MinBurnAmount::slot_name())
        .map_err(|e| anyhow::anyhow!("reading the stock MinBurnAmount floor slot: {e}"))
}

// set_max_supply — stock admin setter note + token_config read-back
// ================================================================================================

/// The exact stock error `set_max_supply` traps when the faucet's max_supply is immutable
/// (`fungible.masm:40` ERR_MAX_SUPPLY_NOT_MUTABLE). Constructed inline (a stock protocol error, not an
/// xusdc shell error, so it is not in `SHELL_ERR_TABLE`).
pub fn err_max_supply_not_mutable() -> MasmError {
    MasmError::from_static_str("max supply is not mutable")
}

/// The exact stock error `set_max_supply` traps when `new_max_supply < token_supply`
/// (`fungible.masm:41` ERR_NEW_MAX_SUPPLY_BELOW_TOKEN_SUPPLY).
pub fn err_new_max_supply_below_token_supply() -> MasmError {
    MasmError::from_static_str("new max supply is less than current token supply")
}

/// Reads the faucet `token_config` value word `[token_supply, max_supply, decimals, token_symbol]`
/// from a committed/evolved account — the full-word read-back the set_max_supply write-integrity test
/// uses to prove `set_max_supply` changed ONLY word[1] (max_supply).
pub fn read_token_config(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(FungibleFaucet::token_config_slot())
        .map_err(|e| anyhow::anyhow!("reading the token_config value slot: {e}"))
}

pub enum GuardSelection {
    /// PRODUCTION `XReserveStablecoinBuilder::build_components` (the attestation mint policy ONLY,
    /// no reserved alternates — the sole-supply-surface invariant).
    ProductionAttestation,
    /// TEST-ONLY oracle (test-harness [`oracle_components`]): allow-all mint + allow-all burn
    /// ACTIVE — the builder-bypassing contrast fixture for non-vacuity controls.
    OracleAllowAll,
}

/// A guarded mint harness: the composition account WITH the `TokenPolicyManager` (the attestation
/// policy or allow-all per the [`GuardSelection`]), plus the resolved ACTIVE mint-policy proc
/// root. The production path is composed by `XReserveStablecoinBuilder::build_components`; the
/// allow-all oracle by the test-only [`oracle_components`] helper. Pause is the stock
/// `PausableManager` gated on the Domain pauser role by the account's procedure-role map; the
/// `is_paused` slot it writes is installed by the base `Pausable` component (v0.16 #2944 moved it
/// out of `FungibleFaucet`).
pub struct GuardedMint {
    pub harness: CompositionHarness,
    pub policy_root: Word,
}

/// Like [`setup_mint_composition_account`] but ALSO installs the `TokenPolicyManager` (the
/// attestation policy or allow-all per `selection`) via [`XReserveStablecoinBuilder`]. The
/// attestation policy rides the same `xreserve` library component (its
/// `mint_policy::check_policy` proc). The production arm build-seeds the caller's `domain` word
/// (element 0) through the generated `XReserveStablecoinBuilder::builder()`.
///
/// `is_max_supply_mutable` configures the built faucet's stock max-supply mutability flag (threaded
/// into the `FungibleFaucet::builder()` chain). The production builder REJECTS an immutable
/// max_supply at build time, so every `ProductionAttestation` caller must pass `true`; the
/// `OracleAllowAll` path bypasses the builder and is unaffected. The immutable control
/// (`set_max_supply_immutable_traps`) builds its immutable fixture via the builder-bypassing
/// [`setup_bare_immutable_faucet`] instead of this helper.
pub fn setup_guarded_mint_account(
    selection: GuardSelection,
    max_supply: u64,
    token_supply: u64,
    domain: Word,
    nonce_seed: Option<(Word, Word)>,
    attesters_seed: Option<(Word, Word)>,
    driver_src: &str,
    probe_src: &str,
    is_max_supply_mutable: bool,
) -> Result<GuardedMint> {
    let library = assemble_xreserve_lib()?;

    let map_of = |seed: Option<(Word, Word)>, what: &str| -> Result<StorageMap> {
        match seed {
            Some((key, marker)) => StorageMap::with_entries([(StorageMapKey::new(key), marker)])
                .map_err(|e| anyhow::anyhow!("seeding the {what} map fixture: {e}")),
            None => Ok(StorageMap::new()),
        }
    };

    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![
            StorageSlot::with_value(
                XReserveFaucetExtension::domain_config_slot().clone(),
                domain,
            ),
            StorageSlot::with_map(
                XReserveFaucetExtension::used_nonces_slot().clone(),
                map_of(nonce_seed, "usedNonces")?,
            ),
            StorageSlot::with_map(
                XReserveFaucetExtension::xreserve_attesters_slot().clone(),
                map_of(attesters_seed, "xReserveAttesters")?,
            ),
        ],
        AccountComponentMetadata::new("xusdc-mint-composition-harness"),
    )
    .context("binding the xreserve library + all composition slots as a component")?;

    let link = |path: &'static str, src: &str, what: &str| -> Result<AccountComponentCode> {
        CodeBuilder::new()
            .with_dynamically_linked_package(&library)
            .with_context(|| format!("linking the xreserve library into the {what}"))?
            .compile_component_code(path, src)
            .with_context(|| format!("{what} failed to compile\n--- src ---\n{src}"))
    };
    let driver_code = link(GUARDED_DRIVER_PATH, driver_src, "guarded fixture driver")?;
    let probe_code = link(MINT_PROBE_PATH, probe_src, "no-effects probe")?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-mint-composition-driver"),
    )
    .context("binding the mint composition driver component")?;
    let probe_component = AccountComponent::new(
        probe_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-mint-composition-probe"),
    )
    .context("binding the no-effects probe component")?;

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        .is_max_supply_mutable(is_max_supply_mutable)
        .build()
        .context("failed to build FungibleFaucet")?;

    // Resolve the attestation-policy root from the harness component. It carries the whole library,
    // so the procedure answers to its LIBRARY path here; the shipped faucet component re-exports the
    // same procedure, and therefore the same root, under its own path.
    let attestation_root: Word = library_attestation_mint_policy_root(&xreserve_component)?;
    let (mut components, policy_root) = match selection {
        // PRODUCTION path: the real builder — attestation policy ONLY (no reserved alternates).
        // The caller's `domain` word (element 0) is build-seeded.
        GuardSelection::ProductionAttestation => {
            let domain = u32::try_from(domain[0].as_canonical_u64())
                .map(CircleDomain::new)
                .context("the fixture domain word element 0 must be a u32")?;
            let components = production_builder(token_supply, domain)
                .context("building the production attestation faucet")?
                .build_components()
                .map_err(|e| anyhow::anyhow!("composing the production attestation faucet: {e}"))?;
            (components, attestation_root)
        }
        // TEST-ONLY oracle: allow-all mint + allow-all burn ACTIVE (builder-bypassing contrast).
        GuardSelection::OracleAllowAll => {
            let components = oracle_components(faucet, xreserve_component)
                .context("composing the oracle allow-all faucet")?;
            (components, Word::from(MintPolicy::allow_all().root()))
        }
    };
    components.push(driver_component);
    components.push(probe_component);

    let mut mc = MockChain::builder();
    let account = add_faucet_account(&mut mc, Auth::IncrNonce, components)
        .context("adding guarded faucet")?;
    let mock_chain = mc.build().context("building MockChain")?;
    Ok(GuardedMint {
        harness: CompositionHarness {
            mock_chain,
            account_id: account.id(),
            driver_code,
            probe_code,
        },
        policy_root,
    })
}

/// TEST-ONLY allow-all oracle composition: the stock `MintAllowAll` + `BurnAllowAll` ACTIVE — the
/// builder-bypassing contrast fixture for non-vacuity controls (the production builder REJECTS
/// any active mint policy that is not the attestation policy, so this shape is constructible only
/// here, in the test harness).
fn oracle_components(
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
) -> Result<Vec<AccountComponent>> {
    let manager = TokenPolicyManager::builder()
        .active_mint_policy(MintPolicy::allow_all())
        .active_burn_policy(BurnPolicy::allow_all())
        .build();
    // No PausableManager (the Domain-Pauser-only model); the base Pausable component installs the
    // is_paused slot execute_mint_policy's assert_not_paused reads (v16 — #2944 moved it out of
    // FungibleFaucet). The manager iterator yields [manager, then one companion per distinct
    // policy root] — here the two stock allow-all companions, both kept.
    let mut parts = manager.into_iter();
    let manager_component = parts.next().expect("manager component first");
    let companions: Vec<AccountComponent> = parts.collect();
    anyhow::ensure!(
        companions.len() == 2,
        "allow-all-oracle seam: expected the 2 stock allow-all companions, got {}",
        companions.len()
    );
    let mut components = vec![
        faucet.into(),
        Pausable::unpaused().into(),
        xreserve_component,
    ];
    components.push(manager_component);
    components.extend(companions); // [MintAllowAll, BurnAllowAll]
    Ok(components)
}

fn felt_from_u64(value: u64) -> Felt {
    Felt::new(value).expect("a burn magnitude (< 2^63) is a valid field element")
}

pub enum BurnGuardSelection {
    /// TEST-ONLY oracle: the real `burn_policy::check_policy` (`Custom(burn_root)`) ACTIVE, allow-all
    /// RESERVED. The arm the zero-burn/below-minimum rejects + the valid-burn positive run against.
    OracleBurnReal,
    /// TEST-ONLY oracle: stock `BurnAllowAll` ACTIVE, the real burn policy RESERVED. The non-vacuity
    /// control: the SAME below-min burn succeeds + decrements here, proving the real arm's trap is
    /// policy-caused.
    OracleBurnAllowAll,
}

/// A burn-policy harness: a built [`MockChain`] holding the composed faucet (real burn policy active or
/// allow-all per [`BurnGuardSelection`]) + a user wallet seeded with the burn asset + the canonical
/// asset-bearing [`BurnNote`] the tests reproduce in-block and consume via the 2-block
/// lifecycle.
pub struct BurnPolicyHarness {
    pub chain: MockChain,
    pub faucet_id: AccountId,
    pub user_id: AccountId,
    /// The canonical burn note (random serial) the user emits in-block, then the faucet consumes.
    pub burn_note: Note,
    /// The single fungible burn asset (`FungibleAsset::new(faucet_id, burn_amount)`).
    pub asset: FungibleAsset,
    pub burn_root: Word,
    pub min_burn_size: u64,
    pub burn_amount: u64,
}

/// Seeds the burn oracle through the stock RBAC builder with the same five roles as production.
/// `support_replica_matches_the_production_role_seed` pins both maps to the production seed.
fn seeded_dom_roles_rbac_component(
    owner: AccountId,
    attest_admin_holder: AccountId,
    pauser_holder: AccountId,
    unpauser_holder: AccountId,
    blocklist_manager_holder: AccountId,
) -> AccountComponent {
    let pauser = RoleSymbol::new(DOM_PAUSER_ROLE).expect("DOM_PAUSER is a fixed valid role symbol");
    let attest_admin =
        RoleSymbol::new(ATTEST_ADMIN_ROLE).expect("ATTEST_ADMIN is a fixed valid role symbol");
    let unpauser =
        RoleSymbol::new(DOM_UNPAUSER_ROLE).expect("DOM_UNPAUSER is a fixed valid role symbol");
    let blk_manager =
        RoleSymbol::new(BLK_MANAGER_ROLE).expect("BLK_MANAGER is a fixed valid role symbol");
    let admin = RoleBasedAccessControl::admin_role();

    RoleBasedAccessControl::builder()
        .role(RoleConfig::new(pauser).with_member(pauser_holder))
        .role(RoleConfig::new(attest_admin).with_member(attest_admin_holder))
        .role(RoleConfig::new(unpauser).with_member(unpauser_holder))
        .role(RoleConfig::new(admin).with_member(owner))
        .role(RoleConfig::new(blk_manager).with_member(blocklist_manager_holder))
        .build()
        .expect("the seeded RBAC component mirrors production and is valid")
        .into()
}

/// Builds test components with either the custom burn policy or `BurnAllowAll` active.
/// Both versions use the same components and minimum burn amount so tests can compare the policies.
/// Production allows only the custom burn policy.
fn oracle_burn_components(
    faucet: FungibleFaucet,
    xreserve_component: AccountComponent,
    min_burn_size: u64,
    burn_real_active: bool,
    administrator: AccountId,
    attest_admin_holder: AccountId,
    pauser_holder: AccountId,
    unpauser_holder: AccountId,
    blocklist_manager_holder: AccountId,
) -> Result<Vec<AccountComponent>> {
    let min_burn =
        AssetAmount::new(min_burn_size).map_err(|e| anyhow::anyhow!("oracle floor: {e}"))?;
    let burn_policy_component = XReserveStablecoinBuilder::burn_policy_component();
    let burn_root = burn_policy_component
        .get_procedure_root_by_path(XRESERVE_BURN_POLICY_PROC_PATH)
        .context("burn-policy component exports its check procedure")?;
    let real_burn = BurnPolicy::custom(
        burn_root,
        [burn_policy_component, MinBurnAmount::new(min_burn).into()],
    )?;
    let allow_burn = BurnPolicy::allow_all();
    let (active_burn, reserved_burn) = if burn_real_active {
        (real_burn, allow_burn)
    } else {
        (allow_burn, real_burn)
    };
    let attestation_root: Word = library_attestation_mint_policy_root(&xreserve_component)?;
    let manager = TokenPolicyManager::builder()
        .active_mint_policy(
            MintPolicy::custom(
                AccountProcedureRoot::from_raw(attestation_root),
                [xreserve_component.clone()],
            )
            .map_err(|e| anyhow::anyhow!("oracle attestation mint policy: {e}"))?,
        )
        .active_burn_policy(active_burn)
        .allowed_burn_policy(reserved_burn)
        .build();

    // Production build_components extends the manager iterator (the mint policy already
    // carries the seeded xreserve). This oracle keeps the custom burn policy, MinBurnAmount,
    // and BurnAllowAll companions, and drops the xreserve copy because
    // it also installs `xreserve_component` separately below. The base Pausable component
    // installs the is_paused slot (v16 — #2944 moved it out of FungibleFaucet) and the stock
    // PausableManager writes it, gated on the Domain pauser role by the procedure-role map.
    let xreserve_code = xreserve_component.component_code().clone();
    let mut parts = manager.into_iter();
    let manager_component = parts.next().expect("manager component first");
    let companions: Vec<AccountComponent> = parts.collect();
    let (dup, keep): (Vec<_>, Vec<_>) = companions
        .into_iter()
        .partition(|c| c.component_code().as_package() == xreserve_code.as_package());
    anyhow::ensure!(
        dup.len() == 1 && keep.len() == 3,
        "burn-oracle seam: expected 1 xreserve companion copy + 3 burn companions, got \
         {} + {}",
        dup.len(),
        keep.len()
    );
    let mut components = vec![
        faucet.into(),
        Pausable::unpaused().into(),
        xreserve_component,
    ];
    components.push(manager_component);
    components.extend(keep); // custom burn policy, MinBurnAmount, BurnAllowAll
    components.push(PausableManager.into());
    components.push(seeded_dom_roles_rbac_component(
        administrator,
        attest_admin_holder,
        pauser_holder,
        unpauser_holder,
        blocklist_manager_holder,
    ));
    components.push(XReserveAdminAuthority::new().into());
    Ok(components)
}

/// Builds the burn-policy harness: assembles the `xreserve` component with the full production slot set
/// (the domain-config value slots, usedNonces/xReserveAttesters map slots, AND the NET-NEW minBurnSize
/// value slot seeded `[min_burn_size, 0, 0, 0]`), composes the faucet via [`oracle_burn_components`]
/// (`ADMIN` = `ATTEST_ADMIN` = id(1), `DOM_PAUSER` = id(2), `DOM_UNPAUSER` = id(3),
/// `BLK_MANAGER` = id(4)), adds a user wallet seeded with the single burn asset, and
/// creates the canonical [`XReserveBurnNote`]. The faucet is built with `is_max_supply_mutable(true)` + decimals
/// 6, mirroring the mint composition fixtures.
pub fn setup_burn_policy_account(
    selection: BurnGuardSelection,
    max_supply: u64,
    token_supply: u64,
    min_burn_size: u64,
    burn_amount: u64,
) -> Result<BurnPolicyHarness> {
    let library = assemble_xreserve_lib()?;

    let xreserve_component = AccountComponent::new(
        library.clone(),
        vec![
            StorageSlot::with_value(
                XReserveFaucetExtension::domain_config_slot().clone(),
                Word::from([TEST_DOMAIN.as_u32(), 0, 0, 0]),
            ),
            StorageSlot::with_empty_map(XReserveFaucetExtension::used_nonces_slot().clone()),
            StorageSlot::with_empty_map(XReserveFaucetExtension::xreserve_attesters_slot().clone()),
            // oracle_burn_components stores the minimum burn amount in the MinBurnAmount component.
        ],
        AccountComponentMetadata::new("xusdc-burn-policy-harness"),
    )
    .context("binding the xreserve library + all composition slots as a component")?;

    let burn_root = Word::from(
        XReserveStablecoinBuilder::burn_policy_component()
            .get_procedure_root_by_path(XRESERVE_BURN_POLICY_PROC_PATH)
            .context("burn-policy component exports its check procedure")?,
    );

    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("USDCx")?)
        .symbol(TokenSymbol::new("USDCX")?)
        .decimals(6)
        .max_supply(AssetAmount::new(max_supply).context("invalid max_supply")?)
        .token_supply(AssetAmount::new(token_supply).context("invalid token_supply")?)
        .is_max_supply_mutable(true)
        .build()
        .context("failed to build FungibleFaucet")?;

    let burn_real_active = matches!(selection, BurnGuardSelection::OracleBurnReal);
    let components = oracle_burn_components(
        faucet,
        xreserve_component,
        min_burn_size,
        burn_real_active,
        test_account_id(1),
        test_account_id(1),
        test_account_id(2),
        test_account_id(3),
        test_account_id(4),
    )?;

    let mut builder = MockChain::builder();
    let faucet_account = builder
        .add_existing_account_from_components(Auth::IncrNonce, components)
        .context("adding the burn-policy faucet account")?;
    let faucet_id = faucet_account.id();

    // The user wallet seeded with exactly the burn asset (faucet_id known only now).
    let asset = FungibleAsset::new(faucet_id, burn_amount).context("invalid burn asset")?;
    let user = add_emitting_wallet(&mut builder, Auth::IncrNonce, [asset.into()])
        .context("adding the burn user wallet")?;
    let user_id = user.id();

    // The burn note carries the withdrawal attachment required by the production policy.
    let burn_note = XReserveBurnNote::create(
        user_id,
        faucet_id,
        asset.amount(),
        XReserveBurnItems {
            dest_domain: TEST_SOURCE_DOMAIN,
            dest_recipient: ForeignChainAddress::new([0xAB; 32]),
        },
        builder.rng_mut(),
    )
    .context("creating the canonical burn note")?;

    let chain = builder
        .build()
        .context("building the burn-policy MockChain")?;
    Ok(BurnPolicyHarness {
        chain,
        faucet_id,
        user_id,
        burn_note,
        asset,
        burn_root,
        min_burn_size,
        burn_amount,
    })
}

/// The user send tx-script that emits `burn_note` exactly (ported from the grounding test
/// `burn_canary.rs:57-91`): pushes `burn_note`'s recipient digest + the note's OWN metadata
/// (`note_type` + `tag`, read from `burn_note.metadata()`) into `output_note::create`, then `call`s
/// the BasicWallet `move_asset_to_note` to draw `fungible_asset` from the executing user's vault into
/// that note. Reading the note's own metadata keeps the emitted note's id == `burn_note.id()` for BOTH
/// the stock `BurnNote` (Public + `with_account_target`) and the `XReserveBurnNote` (Public + the fixed
/// xUSDC burn tag) — NoteId commits to metadata, so a recomputed tag would break id parity.
pub fn send_burn_note_script(
    burn_note: &Note,
    fungible_asset: &FungibleAsset,
    _faucet_id: AccountId,
) -> String {
    let recipient = burn_note.recipient().digest();
    let note_type = Felt::from(burn_note.metadata().note_type());
    let tag = Felt::from(burn_note.metadata().tag());
    let asset_id = fungible_asset.id().to_word();
    let asset_value = fungible_asset.to_value_word();
    // v0.16 #3204: output_note::create / add_attachment execute only from the active account's own
    // procedures, so note creation runs in ACCOUNT context — the STOCK wallet's `create_note`
    // (defined in `miden::standards::note::note_creator` and re-exported by the BasicWallet
    // component, so the account exposes its root) for the attachment-less stock BurnNote, and the
    // user-installed emit helper for the attachment-bearing XReserveBurnNote (whose scheme-2 routing
    // target AND scheme-tagged withdrawal payload must both be reproduced so the emitted note's id ==
    // burn_note.id(); NoteId commits to attachments). Every attachment's content is supplied via the
    // advice map keyed by its commitment (`attachment_advice`, extended in `try_emit_burn_note`). The
    // first attachment rides the create-plus-one call; each further attachment gets its own
    // `add_note_attachment` leg. The producer tx creates exactly ONE output note, so its index is 0 —
    // which feeds move_asset_to_note (re-established after the add legs, which consume it).
    let attachments: Vec<_> = burn_note.attachments().iter().collect();
    let create_src = if attachments.is_empty() {
        "    repeat.10 push.0 end\n\
         \x20\x20\x20\x20push.{recipient}\n\
         \x20\x20\x20\x20push.{note_type}\n\
         \x20\x20\x20\x20push.{tag}\n\
         \x20\x20\x20\x20call.note_creator::create_note\n"
            .to_string()
    } else {
        let first = attachments[0];
        let mut src = format!(
            "    repeat.5 push.0 end\n\
             \x20\x20\x20\x20push.{commitment}\n\
             \x20\x20\x20\x20push.{scheme}\n\
             \x20\x20\x20\x20push.{{recipient}}\n\
             \x20\x20\x20\x20push.{{note_type}}\n\
             \x20\x20\x20\x20push.{{tag}}\n\
             \x20\x20\x20\x20call.emit_helper::emit_note_with_attachment\n",
            commitment = first.content().to_commitment(),
            scheme = first.attachment_scheme().as_u16(),
        );
        for attachment in attachments.iter().skip(1) {
            src.push_str(&format!(
                "\x20\x20\x20\x20push.0\n\
                 \x20\x20\x20\x20push.{commitment}\n\
                 \x20\x20\x20\x20push.{scheme}\n\
                 \x20\x20\x20\x20call.emit_helper::add_note_attachment\n",
                commitment = attachment.content().to_commitment(),
                scheme = attachment.attachment_scheme().as_u16(),
            ));
        }
        if attachments.len() > 1 {
            // the create-plus-one leg left note index 0 on the stack, but each add leg consumes it;
            // re-establish it for the asset move.
            src.push_str("\x20\x20\x20\x20push.0\n");
        }
        src
    };
    let create_src = create_src
        .replace("{recipient}", &recipient.to_string())
        .replace("{note_type}", &note_type.to_string())
        .replace("{tag}", &tag.to_string());
    format!(
        r#"
use miden::standards::note::note_creator
use miden::standards::wallets::basic as wallet
use xusdc::test_fixtures::emit_helper

@transaction_script
pub proc main
    # create the burn note (empty) carrying burn_note's recipient + metadata (+ routing target).
{create_src}
    # => [note_idx, pad(15)]

    # move the user's single fungible asset from the vault into the note.
    push.{asset_value}
    push.{asset_id}
    # => [ASSET_ID, ASSET_VALUE, note_idx, pad(15)]
    call.wallet::move_asset_to_note
    # => [pad(16)]

    exec.::miden::core::sys::truncate_stack
end
"#
    )
}

/// The advice-map inputs carrying each of `note`'s attachment contents keyed by its commitment — the
/// witness the `output_note::add_attachment` emit path resolves (the scheme-2 routing target).
pub fn attachment_advice(note: &Note) -> AdviceInputs {
    let mut advice = AdviceInputs::default();
    for attachment in note.attachments().iter() {
        advice = advice.with_map([(
            attachment.content().to_commitment(),
            attachment.content().to_elements(),
        )]);
    }
    advice
}

/// Reads the faucet's committed `token_supply` from its `token_config` slot post-block (ported from
/// the grounding test `burn_canary.rs:94-97`).
pub fn committed_token_supply(chain: &MockChain, faucet_id: AccountId) -> Result<AssetAmount> {
    let storage = chain.committed_account(faucet_id)?.storage();
    Ok(FungibleFaucet::try_from(storage)?.token_supply())
}

/// Reads the ACTIVE burn-policy procedure root committed in the faucet account's
/// `TokenPolicyManager` storage slot (the burn-slot twin of the mint-policy slot). Asserting this
/// stored root equals the expected `burn_policy_root()` is the storage-COMMITMENT proof that the sole
/// supply-decrement path (stock `receive_and_burn`) is burn-policy-gated — stronger than resolving
/// the merely-EXPORTED proc root via `get_procedure_root_by_path`.
pub fn read_active_burn_policy_root(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(TokenPolicyManager::active_burn_policy_slot())
        .map_err(|e| anyhow::anyhow!("reading the active burn policy root slot: {e}"))
}

/// tx0 ONLY (non-panicking): the user emits `burn_note` in-block (a send tx-script that draws the asset
/// from the user vault into the note). Returns the raw execution result so callers can observe an
/// upstream rejection (the zero-amount reachability probe) without the strict-path panic. Used as the
/// first half of [`run_burn_consume`].
pub async fn try_emit_burn_note(
    chain: &MockChain,
    burn_note: &Note,
    asset: &FungibleAsset,
    faucet_id: AccountId,
    user_id: AccountId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_package(
            emit_helper_component()
                .expect("the emit helper compiles")
                .component_code()
                .clone(),
        )
        .expect("linking the emit helper into the burn emit script")
        .compile_tx_script(send_burn_note_script(burn_note, asset, faucet_id))
        .expect("the user send-burn-note script compiles");
    let mut ctx = chain
        .build_transaction(user_id)
        .tx_script(tx_script)
        // The attachment contents (routing target) keyed by commitment for `add_attachment`.
        .extend_advice_inputs(attachment_advice(burn_note))
        // Register the full note details so the kernel's `before_created` event can resolve the PUBLIC
        // note's details when tx0 creates it.
        .expected_output_note(RawOutputNote::Full(burn_note.clone()));
    // A POLICED (callback-Enabled) faucet's asset fires the SEND callback when the holder
    // emits a note moving it out of their vault (native = the holder), so the kernel dyncalls the
    // issuing faucet to run `basic_blocklist::check_policy` — attach it as a foreign account. A basic
    // (Disabled) faucet — e.g. the burn oracle fixtures — fires no callback, so it is skipped.
    if faucet_id.asset_callback_flag() == AssetCallbackFlag::Enabled {
        let foreign = chain
            .get_foreign_account_inputs(faucet_id)
            .expect("faucet foreign-account inputs (committed)");
        ctx = ctx.foreign_accounts([foreign]);
    }
    ctx.build()
        .expect("building the user emit tx")
        .execute()
        .await
}

/// Runs the 2-block burn lifecycle against `chain`: the user emits `burn_note` at block N (tx0,
/// a test-setup invariant — panics on failure), the block is proven, then the FAUCET consumes the
/// now-committed note at block N+1 via stock `receive_and_burn`. Returns the faucet-consume RESULT so
/// the caller asserts the policy trap (`assert_transaction_executor_error!`) or the success+decrement
/// (`committed_token_supply` after committing the returned tx).
pub async fn run_burn_consume(
    chain: &mut MockChain,
    burn_note: &Note,
    asset: &FungibleAsset,
    faucet_id: AccountId,
    user_id: AccountId,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let tx0 = try_emit_burn_note(chain, burn_note, asset, faucet_id, user_id)
        .await
        .expect("the user emit tx0 succeeds (test-setup invariant)");
    chain
        .add_pending_executed_transaction(&tx0)
        .expect("queuing tx0 into block N");
    chain.prove_next_block().expect("proving block N");

    // tx1: the faucet consumes the committed burn note (runs receive_and_burn -> execute_burn_policy ->
    // the active burn policy).
    chain
        .build_transaction(faucet_id)
        .authenticated_input_note(burn_note.id())
        .build()
        .expect("building the faucet consume tx")
        .execute()
        .await
}

/// Executes a stock `PausableManager::pause` note SENT BY `sender` against the faucet `account` on a
/// bare `&MockChain` (the note is provided unauthenticated). Under the Domain-Pauser-only model the
/// stock proc is NOT installed — this is the NEGATIVE PROBE `administrator_has_no_pause_path` drives: the tx
/// must trap `UnknownAccountProcedure` and never flip `is_paused`. To actually pause, use
/// [`run_dom_pauser_pause`] (the DOM_PAUSER custom proc — the only pause surface).
pub async fn run_pause_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = manager_pause_call_note(sender, seed)
        .expect("building the manager pause-call note (test-setup invariant)");
    chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the pause transaction")
        .execute()
        .await
}

/// Builds a note SENT BY `sender` whose script calls the stock `PausableManager::unpause` — the
/// unpause twin of [`manager_pause_call_note`]. Serial tail [25, 26] keeps note serials disjoint
/// from the other admin-note families.
pub fn manager_unpause_call_note(sender: AccountId, seed: u64) -> Result<Note> {
    let src = "use miden::standards::access::pausable::manager\n\
               @note_script\n\
               pub proc main\n\
               \x20\x20\x20\x20repeat.16 push.0 end\n\
               \x20\x20\x20\x20call.manager::unpause\n\
               \x20\x20\x20\x20dropw dropw dropw dropw\n\
               end\n";
    let script = CodeBuilder::new()
        .compile_note_script(src)
        .map_err(|e| anyhow::anyhow!("stock unpause note script failed to compile: {e}"))?;
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(25u32),
        Felt::from(26u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a stock `PausableManager::unpause` note (sent by `sender`) against the faucet `account`
/// on a bare `&MockChain` — the unpause twin of [`run_pause_against`].
pub async fn run_stock_unpause_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = manager_unpause_call_note(sender, seed)
        .expect("building the manager unpause-call note (test-setup invariant)");
    chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the stock unpause transaction")
        .execute()
        .await
}

/// Asserts an executor error carries the EXACT `UnknownAccountProcedure` failure — the pinned
/// surface when a note `call`s a procedure whose MAST root is NOT in the account code: the kernel's
/// `authenticate_and_track_procedure` first emits `ACCOUNT_PUSH_PROCEDURE_INDEX_EVENT`, whose host
/// handler fails with `TransactionKernelError::UnknownAccountProcedure` ("account procedure with
/// procedure root .. is not in the account procedure index map"), surfacing as
/// `ExecutionError::EventError` — a HOST event error, NOT a MASM assert (so `MasmError` matching
/// can never see it). Walks the full error chain and asserts the exact static message
/// (assert-specific-error-in-tests; no bare `is_err()`).
pub fn assert_unknown_account_procedure(err: &TransactionExecutorError) {
    let mut messages = vec![err.to_string()];
    let mut source: Option<&dyn std::error::Error> = std::error::Error::source(err);
    while let Some(inner) = source {
        messages.push(inner.to_string());
        source = inner.source();
    }
    assert!(
        messages
            .iter()
            .any(|m| m.contains("is not in the account procedure index map")),
        "expected the exact UnknownAccountProcedure failure (the called proc root is not part of \
         the account code); actual error chain: {messages:?}"
    );
}

// DOM_PAUSER PAUSE — notes + runners for the stock PausableManager procs
// ================================================================================================

/// Builds a note SENT BY `sender` whose script `call`s the stock `PausableManager::{proc}`, which
/// the account's procedure-role map gates on the Domain pauser role.
///
/// This is the same underlying procedure [`manager_pause_call_note`] targets — the pause surface is
/// the stock manager for every caller now, and who may use it is decided by the role map, not by
/// which procedure the note calls. The two helpers differ only in their serial tails, which keeps
/// note ids from colliding across the admin-note families.
fn dom_pauser_manager_note(
    sender: AccountId,
    seed: u64,
    proc: &str,
    tail0: u32,
    tail1: u32,
) -> Result<Note> {
    let src = format!(
        "use miden::standards::access::pausable::manager\n\
         @note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.16 push.0 end\n\
         \x20\x20\x20\x20call.manager::{proc}\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| {
            anyhow::anyhow!("dom_pauser {proc} note script failed to compile: {e}\n{src}")
        })?;
    // Deterministic note rng (serial only; never affects the gate). Distinct tails ([21,22] pause /
    // [23,24] unpause) keep serials disjoint from set_attester [1,2] / pause [3,4] / set_max_supply
    // [5,6] / set_min_burn [7,8] / domain_init [9,10].
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(tail0),
        Felt::from(tail1),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// A `PausableManager::pause` note sent by `sender` (the Domain pauser, for success).
pub fn dom_pauser_pause_note(sender: AccountId, seed: u64) -> Result<Note> {
    dom_pauser_manager_note(sender, seed, "pause", 21, 22)
}

/// A `PausableManager::unpause` note sent by `sender` (the Domain unpauser, for success).
pub fn dom_pauser_unpause_note(sender: AccountId, seed: u64) -> Result<Note> {
    dom_pauser_manager_note(sender, seed, "unpause", 23, 24)
}

/// Executes a `PausableManager::pause` note (sent by `sender`) against the faucet `account` on a
/// bare `&MockChain`; the caller applies the returned delta (the unauthenticated note is not
/// block-proven).
pub async fn run_dom_pauser_pause(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = dom_pauser_pause_note(sender, seed)
        .expect("building the dom_pauser pause note (test-setup invariant)");
    chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the dom_pauser pause transaction")
        .execute()
        .await
}

/// The `unpause` twin of [`run_dom_pauser_pause`].
pub async fn run_dom_pauser_unpause(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = dom_pauser_unpause_note(sender, seed)
        .expect("building the dom_pauser unpause note (test-setup invariant)");
    chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .expect("building the dom_pauser unpause transaction")
        .execute()
        .await
}

/// Reads the `Pausable`-installed `is_paused` value slot (v0.16 #2944 moved it out of
/// `FungibleFaucet`; `[0,0,0,0]` unpaused, `[1,0,0,0]` paused)
/// from a committed/evolved account — the `GetAccount` pause-state observability read (Circle
/// requires the pause state be publicly observable). Mirrors
/// [`read_min_burn_size`] / [`read_token_config`]; the slot is installed by the base `Pausable` component, so it is
/// present on every production faucet (never a missing-slot artifact).
pub fn read_is_paused(account: &Account) -> Result<Word> {
    account
        .storage()
        .get_item(PausableStorage::is_paused_slot())
        .map_err(|e| anyhow::anyhow!("reading the is_paused value slot: {e}"))
}

// RBAC ROLE ADMINISTRATION — grant/revoke/set_role_admin notes + runners + role read-backs
// ================================================================================================

/// Builds a note SENT BY `sender` whose script `call`s a stock rbac member-administration proc
/// (`grant_role` / `revoke_role`, rbac.masm:197/:228) for (`role`, `member`). Stack contract:
/// `[role_symbol, account_suffix, account_prefix, pad(13)]` (role on top). Like `set_max_supply_note`,
/// the stock rbac procs are pure standards procs (CodeBuilder pre-links StandardsLib), so the
/// absolute-path `call` resolves to the SAME proc root the production account exposes via the RBAC
/// component re-exports (`account_components/access/rbac.masm`) — no xreserve link is needed. The
/// role/member felts are injected from the Rust-side `RoleSymbol`/`AccountId` (single source; no new
/// MASM constants, no new parity surface).
fn rbac_member_note(
    sender: AccountId,
    proc_name: &str,
    role: &RoleSymbol,
    member: AccountId,
    seed: u64,
    tail0: u32,
    tail1: u32,
) -> Result<Note> {
    // Push 13 pads (deepest), then prefix, suffix, role so the triple ends role-on-top: 13 + 3 = 16.
    let role_felt = Felt::from(role).as_canonical_u64();
    let member_suffix = member.suffix().as_canonical_u64();
    let member_prefix = member.prefix().as_felt().as_canonical_u64();
    let src = format!(
        "@note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.13 push.0 end\n\
         \x20\x20\x20\x20push.{member_prefix}\n\
         \x20\x20\x20\x20push.{member_suffix}\n\
         \x20\x20\x20\x20push.{role_felt}\n\
         \x20\x20\x20\x20call.::miden::standards::access::rbac::{proc_name}\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| {
            anyhow::anyhow!("rbac {proc_name} note script failed to compile: {e}\n{src}")
        })?;
    // Deterministic note rng (serial only; never affects the gate). Distinct tails ([11,12] grant /
    // [13,14] revoke / [15,16] set_role_admin) keep serials disjoint from set_attester [1,2] / pause
    // [3,4] / set_max_supply [5,6] / set_min_burn [7,8] / domain_init [9,10] / dom pause [21,22] /
    // dom unpause [23,24].
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(tail0),
        Felt::from(tail1),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// A `grant_role(role, member)` note sent by `sender` (stock gate at v0.16: the granted role's
/// EFFECTIVE admin).
pub fn grant_role_note(
    sender: AccountId,
    role: &RoleSymbol,
    member: AccountId,
    seed: u64,
) -> Result<Note> {
    rbac_member_note(sender, "grant_role", role, member, seed, 11, 12)
}

/// A `revoke_role(role, member)` note sent by `sender` (same role-admin gate: the revoked role's
/// effective admin).
pub fn revoke_role_note(
    sender: AccountId,
    role: &RoleSymbol,
    member: AccountId,
    seed: u64,
) -> Result<Note> {
    rbac_member_note(sender, "revoke_role", role, member, seed, 13, 14)
}

/// A `set_role_admin(role, admin_role)` note sent by `sender`. Stock gate at v0.16: the MANAGED
/// role's EFFECTIVE admin — its delegated admin, else the built-in `ADMIN` role
/// (`assert_sender_is_role_admin`, rbac.masm:200).
/// `admin_role = None` pushes 0 — the stock "clear the delegation" sentinel, after which the role
/// is `ADMIN`-administered. PROC-LEVEL CHARACTERIZATION ONLY (permissive-auth fixtures): in
/// production the `set_role_admin` capability is structurally unreachable — its note is not in
/// the allowlist, so the deployed role-admin graph is
/// frozen at the build seed.
/// Stack contract: `[role_symbol, admin_role_symbol, pad(14)]` (role on top).
pub fn set_role_admin_note(
    sender: AccountId,
    role: &RoleSymbol,
    admin_role: Option<&RoleSymbol>,
    seed: u64,
) -> Result<Note> {
    let role_felt = Felt::from(role).as_canonical_u64();
    let admin_felt = admin_role
        .map(|r| Felt::from(r).as_canonical_u64())
        .unwrap_or(0);
    let src = format!(
        "@note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.14 push.0 end\n\
         \x20\x20\x20\x20push.{admin_felt}\n\
         \x20\x20\x20\x20push.{role_felt}\n\
         \x20\x20\x20\x20call.::miden::standards::access::rbac::set_role_admin\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("set_role_admin note script failed to compile: {e}\n{src}"))?;
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(15u32),
        Felt::from(16u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a role-administration `note` against the faucet `account` on a bare `&MockChain` —
/// the shared body of the grant/revoke/set_role_admin runners. Mirrors [`run_dom_pauser_pause`];
/// the caller applies the returned delta (the unauthenticated note is not block-proven).
async fn run_rbac_note_against(
    chain: &MockChain,
    account: &Account,
    note: Note,
    what: &str,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note.clone())
        .build()
        .unwrap_or_else(|e| panic!("building the {what} transaction: {e}"))
        .execute()
        .await
}

/// Executes a `grant_role` note (sent by `sender`) against the faucet `account`.
pub async fn run_grant_role_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    role: &RoleSymbol,
    member: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = grant_role_note(sender, role, member, seed)
        .expect("building the grant_role note (test-setup invariant)");
    run_rbac_note_against(chain, account, note, "grant_role").await
}

/// Executes a `revoke_role` note (sent by `sender`) against the faucet `account`.
pub async fn run_revoke_role_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    role: &RoleSymbol,
    member: AccountId,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = revoke_role_note(sender, role, member, seed)
        .expect("building the revoke_role note (test-setup invariant)");
    run_rbac_note_against(chain, account, note, "revoke_role").await
}

/// Executes a `set_role_admin` note (sent by `sender`) against the faucet `account`.
pub async fn run_set_role_admin_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    role: &RoleSymbol,
    admin_role: Option<&RoleSymbol>,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = set_role_admin_note(sender, role, admin_role, seed)
        .expect("building the set_role_admin note (test-setup invariant)");
    run_rbac_note_against(chain, account, note, "set_role_admin").await
}

/// A `renounce_role(role)` note sent by `sender` (stock gate: SELF-only by construction —
/// `rbac::renounce_role` reads the note sender and revokes that account's own membership;
/// re-exported on the account interface, `account_components/access/rbac.masm:12`). Stack
/// contract: `[role_symbol, pad(15)]`.
pub fn renounce_role_note(sender: AccountId, role: &RoleSymbol, seed: u64) -> Result<Note> {
    let role_felt = Felt::from(role).as_canonical_u64();
    let src = format!(
        "@note_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.15 push.0 end\n\
         \x20\x20\x20\x20push.{role_felt}\n\
         \x20\x20\x20\x20call.::miden::standards::access::rbac::renounce_role\n\
         \x20\x20\x20\x20dropw dropw dropw dropw\n\
         end\n",
    );
    let script = CodeBuilder::new()
        .compile_note_script(src.clone())
        .map_err(|e| anyhow::anyhow!("renounce_role note script failed to compile: {e}\n{src}"))?;
    // Fresh serial tail [31,32] — disjoint from every other admin-note family.
    let mut rng = RandomCoin::new(Word::from([
        Felt::from(seed as u32),
        Felt::from((seed >> 32) as u32),
        Felt::from(31u32),
        Felt::from(32u32),
    ]));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .build()?)
}

/// Executes a `renounce_role` note (sent by `sender`, self-targeting) against the faucet `account`.
pub async fn run_renounce_role_against(
    chain: &MockChain,
    account: &Account,
    sender: AccountId,
    role: &RoleSymbol,
    seed: u64,
) -> std::result::Result<ExecutedTransaction, TransactionExecutorError> {
    let note = renounce_role_note(sender, role, seed)
        .expect("building the renounce_role note (test-setup invariant)");
    run_rbac_note_against(chain, account, note, "renounce_role").await
}

/// Reads a role's `role_config` word `[member_count, admin_role_symbol, 0, 0]` from a
/// committed/evolved account (stock key encoding `[0,0,0,role_symbol]`, rbac.masm:12).
pub fn read_role_config(account: &Account, role: &RoleSymbol) -> Result<Word> {
    let key = Word::from([Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::from(role)]);
    account
        .storage()
        .get_map_item(
            RoleBasedAccessControl::role_config_slot(),
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading the role_config entry: {e}"))
}

/// Reads a member's `role_membership` word `[is_member, 0, 0, 0]` from a committed/evolved account
/// (stock key encoding `[0, role_symbol, account_suffix, account_prefix]`, rbac.masm:15).
pub fn read_role_membership(
    account: &Account,
    role: &RoleSymbol,
    member: AccountId,
) -> Result<Word> {
    let key = Word::from([
        Felt::ZERO,
        Felt::from(role),
        member.suffix(),
        member.prefix().as_felt(),
    ]);
    account
        .storage()
        .get_map_item(
            RoleBasedAccessControl::role_membership_slot(),
            StorageMapKey::new(key),
        )
        .map_err(|e| anyhow::anyhow!("reading the role_membership entry: {e}"))
}

// STOCK MinBurnAmount DIRECT-POLICY DRIVER — exec check_policy with a crafted [ASSET_ID, ASSET_VALUE]
// ================================================================================================

/// Module path of the generated direct burn-policy driver component.
pub const BURN_POLICY_DRIVER_PATH: &str = "xusdc::test_fixtures::burn_policy_driver";

/// Generates a direct-policy driver: a CALL-entered account proc that pushes a crafted
/// `[ASSET_ID, ASSET_VALUE]` burn-policy stack (`ASSET_VALUE = [amount, 0, 0, 0]`) and `exec`s
/// the STOCK `min_burn_amount::check_policy` (the floor comparison the custom policy preserves). The policy
/// consumes the 8 cells and returns `[]`, restoring the 16-depth `call` boundary. Drives the
/// floor boundary DIRECTLY as a SUPPLEMENTARY, belt-and-suspenders proof beside the
/// note-reachable rejects.
pub fn burn_policy_direct_driver_src(asset_key: Word, amount: u64) -> String {
    let asset_value = Word::from([felt_from_u64(amount), Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    format!(
        "use miden::standards::faucets::policies::burn::min_burn_amount\n\n\
         #! Test driver: pushes [ASSET_ID, ASSET_VALUE] and execs the stock burn policy directly.\n\
         #!\n\
         #! Inputs:  [pad(16)]\n\
         #! Outputs: [pad(16)]\n\
         #!\n\
         #! Invocation: call\n\
         @account_procedure\n\
         pub proc drive\n\
         \x20\x20\x20\x20push.{asset_value}\n\
         \x20\x20\x20\x20push.{asset_key}\n\
         \x20\x20\x20\x20exec.min_burn_amount::check_policy\n\
         end\n",
    )
}

/// Builds a MockChain account carrying [the STOCK `MinBurnAmount` component with its floor slot
/// seeded] + [the generated direct burn-policy driver], reusing [`ShellHarness`] +
/// [`run_call_driver`]. Used by the direct floor-boundary proofs: the stock `check_policy` reads
/// only `amount` + its own floor slot.
pub fn setup_burn_policy_direct_account(
    min_burn_size: u64,
    driver_src: &str,
) -> Result<ShellHarness> {
    let min_burn =
        MinBurnAmount::new(AssetAmount::new(min_burn_size).context("invalid min_burn_size")?);

    let driver_code = CodeBuilder::new()
        .compile_component_code(BURN_POLICY_DRIVER_PATH, driver_src)
        .with_context(|| {
            format!("direct driver failed to compile\n--- driver ---\n{driver_src}")
        })?;
    let driver_component = AccountComponent::new(
        driver_code.clone(),
        vec![],
        AccountComponentMetadata::new("xusdc-burn-policy-direct-driver"),
    )
    .context("binding the direct driver component")?;

    let mut builder = MockChain::builder();
    let account = builder
        .add_existing_account_from_components(Auth::IncrNonce, [min_burn.into(), driver_component])
        .context("adding the direct burn-policy account")?;
    let mock_chain = builder
        .build()
        .context("building the direct-policy MockChain")?;
    Ok(ShellHarness {
        mock_chain,
        account_id: account.id(),
        driver_code,
        driver_path: BURN_POLICY_DRIVER_PATH,
    })
}

// FULL-ASSEMBLY E2E HARNESS — the production-assembled faucet with
// EMPTY domain config + a real recipient wallet, run sequentially through the whole lifecycle.
// ================================================================================================

pub struct ProductionFaucet {
    pub mock_chain: MockChain,
    pub faucet_id: AccountId,
    pub recipient_id: AccountId,
    pub producer_id: AccountId,
    pub seeded_notes: Vec<Note>,
    /// The build-time token supply, the fail-closure baseline a rejected mint must not move.
    pub build_token_supply: u64,
}

/// Builds the production-component-set faucet fixture. `seed_notes_for` receives the recipient
/// wallet's `AccountId` (payloads embed `remoteRecipient = EthEmbeddedAccountId::from_account_id(recipient).to_bytes32()`) and
/// returns the admin notes to seed at genesis. The faucet account carries EXACTLY the components
/// `XReserveStablecoinBuilder::build_components` returns — proving the real-note mint needs no
/// test-only component.
pub fn setup_production_faucet(
    token_supply: u64,
    seed_notes_for: impl FnOnce(AccountId, AccountId) -> Vec<Note>,
) -> Result<ProductionFaucet> {
    setup_production_faucet_with_attesters(token_supply, Vec::new(), seed_notes_for)
}

/// [`setup_production_faucet`] with `attesters` allowlisted at build time.
pub fn setup_production_faucet_with_attesters(
    token_supply: u64,
    attesters: Vec<PublicKey>,
    seed_notes_for: impl FnOnce(AccountId, AccountId) -> Vec<Note>,
) -> Result<ProductionFaucet> {
    let mut mc = MockChain::builder();
    let recipient = mc
        .add_existing_wallet(Auth::IncrNonce)
        .context("adding recipient wallet")?;
    let producer =
        add_emitting_wallet(&mut mc, Auth::IncrNonce, []).context("adding producer wallet")?;

    // The builder builds the fixed-identity USDCx faucet and assembles the one valid xreserve
    // component internally, so the fixture supplies only the supply parameters and the attesters.
    let components =
        production_builder_verdict_with_attesters(token_supply, TEST_DOMAIN, None, attesters)?
            .map_err(|e| anyhow::anyhow!("building the production faucet: {e}"))?
            .build_components()
            .map_err(|e| anyhow::anyhow!("composing the production faucet: {e}"))?;

    // Build the keyless network account with the production allowlists and test fee policy.
    let account = add_network_faucet_account(&mut mc, components)
        .context("adding the production faucet account")?;
    // The faucet id is now known, so the seed-notes closure binds its notes and its mint payloads
    // (`remoteToken = EthEmbeddedAccountId::from_account_id(faucet_id).to_bytes32()`) to the REAL faucet identity. Seeded AFTER the account is built; order relative to `mc.build()` is all that
    // matters for genesis notes.
    let seeded_notes = seed_notes_for(recipient.id(), account.id());
    for note in &seeded_notes {
        mc.add_output_note(RawOutputNote::Full(note.clone()));
    }
    let mock_chain = mc.build().context("building the production MockChain")?;
    Ok(ProductionFaucet {
        mock_chain,
        faucet_id: account.id(),
        recipient_id: recipient.id(),
        producer_id: producer.id(),
        seeded_notes,
        build_token_supply: token_supply,
    })
}

/// Emits `note` (with any attachments) from `producer` in a REAL in-block tx and commits block N:
/// `output_note::create` from the recipient digest + metadata, then `output_note::add_attachment`
/// per attachment with the elements in the PRODUCER tx's advice map (the upstream
/// `note_script_that_creates_notes` pattern, miden-testing/src/utils.rs:245-315 — producer-side
/// advice is legitimate: the producer knows the data it is publishing). The full note details are
/// registered via `RawOutputNote::Full` so the kernel resolves the PUBLIC note, mirroring
/// `try_emit_burn_note`. No asset is attached (the mint-note shape: the amount travels in the
/// note's storage).
/// Module path of the note-emission helper component (v0.16 #3204: `output_note::create` /
/// `add_attachment` execute only from the active account's own procedures, so the emit tx
/// scripts route through these call-exposed wrappers instead of exec'ing the kernel API
/// directly — the same pattern as the stock `note_creator::create_note`).
pub const EMIT_HELPER_PATH: &str = "xusdc::test_fixtures::emit_helper";

/// The FIXED emit-helper component source: create-plus-one-attachment returning the note index
/// (the burn note's shape, where the index feeds the subsequent `move_asset_to_note`, and the
/// first leg of every multi-attachment emit) plus the appender that adds each further attachment
/// to the note the first leg created.
fn emit_helper_src() -> String {
    "use miden::protocol::output_note\n\
     \n\
     #! Creates an output note, adds its single attachment, and returns the note index.\n\
     #!\n\
     #! Inputs:  [tag, note_type, RECIPIENT, scheme, COMM, pad(5)]\n\
     #! Outputs: [note_idx, pad(15)]\n\
     #!\n\
     #! Invocation: call\n\
     @account_procedure\n\
     pub proc emit_note_with_attachment\n\
     \x20\x20\x20\x20exec.output_note::create\n\
     \x20\x20\x20\x20# => [note_idx, scheme, COMM, pad(5)]\n\
     \x20\x20\x20\x20dup movdn.6\n\
     \x20\x20\x20\x20# => [note_idx, scheme, COMM, note_idx, pad(5)]\n\
     \x20\x20\x20\x20movdn.5\n\
     \x20\x20\x20\x20# => [scheme, COMM, note_idx, note_idx, pad(5)]\n\
     \x20\x20\x20\x20exec.output_note::add_attachment\n\
     \x20\x20\x20\x20# => [note_idx, pad(5)]\n\
     end\n\
     \n\
     #! Adds one attachment to an already-created output note (the extra-attachment leg of a\n\
     #! multi-attachment emit: create-plus-one leaves the note index on the caller stack, this\n\
     #! appends one more attachment to that note).\n\
     #!\n\
     #! Inputs:  [scheme, COMM, note_idx, pad(10)]\n\
     #! Outputs: [pad(16)]\n\
     #!\n\
     #! Invocation: call\n\
     @account_procedure\n\
     pub proc add_note_attachment\n\
     \x20\x20\x20\x20exec.output_note::add_attachment\n\
     \x20\x20\x20\x20# => [pad(10)]\n\
     end\n"
        .to_string()
}

/// The compiled zero-storage emit-helper `AccountComponent`.
pub fn emit_helper_component() -> Result<AccountComponent> {
    let code = CodeBuilder::new()
        .compile_component_code(EMIT_HELPER_PATH, emit_helper_src())
        .context("emit helper component failed to compile")?;
    AccountComponent::new(
        code,
        vec![],
        AccountComponentMetadata::new("xusdc-emit-helper"),
    )
    .context("binding the emit helper component")
}

/// Adds an existing BasicWallet account CARRYING the emit helper (assets optional) — the
/// note-emitting producer/user accounts the emit-realness paths drive.
pub fn add_emitting_wallet(
    builder: &mut miden_testing::MockChainBuilder,
    auth: Auth,
    assets: impl IntoIterator<Item = miden_protocol::asset::Asset>,
) -> Result<Account> {
    let account_builder = Account::builder(rand::random())
        .account_type(AccountType::Public)
        .with_component(BasicWallet)
        .with_component(emit_helper_component()?)
        .with_assets(assets);
    builder
        .add_account_from_builder(auth, account_builder, AccountState::Exists)
        .context("adding an emitting wallet")
}

pub async fn emit_note_with_attachments(
    chain: &mut MockChain,
    producer: AccountId,
    note: &Note,
) -> Result<()> {
    let recipient = note.recipient().digest();
    let note_type = Felt::from(note.metadata().note_type());
    let tag = Felt::from(note.metadata().tag());

    // v0.16 #3204: output_note::create/add_attachment execute only from account procedures —
    // the script calls the producer-installed emit helper. The FIRST attachment rides the
    // create-plus-one call (16 call-window felts with five pads); every further attachment gets
    // its own `add_note_attachment` leg. The shape negatives emit one-attachment notes and the
    // production shape two, so the leg count is driven by the note, never assumed.
    let attachments: Vec<_> = note.attachments().iter().collect();
    anyhow::ensure!(
        (1..=4).contains(&attachments.len()),
        "emit_note_with_attachments emits the one- to four-attachment mint-note shapes, got {}",
        attachments.len()
    );
    let (scheme_a, comm_a) = (
        attachments[0].attachment_scheme().as_u16(),
        attachments[0].content().to_commitment(),
    );
    let mut advice = AdviceInputs::default();
    for attachment in &attachments {
        advice = advice.with_map([(
            attachment.content().to_commitment(),
            attachment.content().to_elements(),
        )]);
    }
    // each extra-attachment leg re-supplies the note index explicitly — the producer tx creates
    // exactly ONE output note, so its index is deterministically 0 — and calls the appender
    // (insertion order preserved).
    let mut extra_legs = String::new();
    for attachment in attachments.iter().skip(1) {
        let scheme_n = attachment.attachment_scheme().as_u16();
        let comm_n = attachment.content().to_commitment();
        extra_legs.push_str(&format!(
            "\x20\x20\x20\x20push.0\n\
             \x20\x20\x20\x20push.{comm_n}\n\
             \x20\x20\x20\x20push.{scheme_n}\n\
             \x20\x20\x20\x20call.emit_helper::add_note_attachment\n"
        ));
    }
    let src = format!(
        "use xusdc::test_fixtures::emit_helper\n\
         \n\
         @transaction_script\n\
         pub proc main\n\
         \x20\x20\x20\x20repeat.5 push.0 end\n\
         \x20\x20\x20\x20push.{comm_a}\n\
         \x20\x20\x20\x20push.{scheme_a}\n\
         \x20\x20\x20\x20push.{recipient}\n\
         \x20\x20\x20\x20push.{note_type}\n\
         \x20\x20\x20\x20push.{tag}\n\
         \x20\x20\x20\x20call.emit_helper::emit_note_with_attachment\n\
         {extra_legs}\
         \x20\x20\x20\x20exec.::miden::core::sys::truncate_stack\n\
         end\n"
    );

    let tx_script = CodeBuilder::new()
        .with_dynamically_linked_package(emit_helper_component()?.component_code().clone())?
        .compile_tx_script(src)?;
    let tx = chain
        .build_transaction(producer)
        .tx_script(tx_script)
        .extend_advice_inputs(advice)
        .expected_output_note(RawOutputNote::Full(note.clone()))
        .build()?
        .execute()
        .await?;
    anyhow::ensure!(
        tx.output_notes().num_notes() == 1 && tx.output_notes().get_note(0).id() == note.id(),
        "the producer tx must emit exactly the constructed note (id parity)"
    );
    chain.add_pending_executed_transaction(&tx)?;
    chain.prove_next_block()?;
    anyhow::ensure!(
        chain.is_note_committed(&note.id()),
        "the emitted note must be committed"
    );
    Ok(())
}
