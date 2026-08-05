extern crate alloc;

pub use miden_agglayer::testing::{
    ClaimDataSource,
    LEAF_VALUE_VECTORS_JSON,
    LeafValueVector,
    MerkleProofVerificationFile,
    MtfVectorsFile,
    SOLIDITY_CANONICAL_ZEROS,
    SOLIDITY_MERKLE_PROOF_VECTORS,
    bridge_admin_account_id,
    create_existing_bridge_account_with_roles,
};
use miden_agglayer::{
    AggLayerBridge,
    AggLayerFaucet,
    AggLayerFaucetAccountBuilder,
    BridgeRoles,
    agglayer_package,
};
use miden_core_lib::CoreLibrary;
use miden_processor::advice::AdviceInputs;
use miden_processor::{
    DefaultHost,
    ExecutionError,
    ExecutionOutput,
    FastProcessor,
    Program,
    StackInputs,
};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::FeeParameters;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::ACCOUNT_ID_FEE_FAUCET;
use miden_protocol::transaction::{ExecutedTransaction, RawOutputNote, TransactionKernel};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, ProtocolLib, Word};
use miden_standards::StandardsLib;
use miden_standards::account::access::PausableStorage;
use miden_standards::note::{FeeSponsorshipNote, StandardNote};
use miden_testing::{Auth, MockChain, MockChainBuilder};
use miden_tx::NetworkNotePricer;

// TEST NETWORK ID
// ================================================================================================

/// The AggLayer network ID encoded as `destination_network` in the bundled Solidity-generated claim
/// test vectors.
pub const MIDEN_NETWORK_ID: u32 = 77;

/// Non-zero base fee used by the AggLayer fee-enabled end-to-end cases.
pub const VERIFICATION_BASE_FEE: u32 = 500;

// PAUSE STATE
// ================================================================================================

/// Reads the pause state from the committed bridge account.
pub fn is_bridge_paused(mock_chain: &MockChain, bridge_id: AccountId) -> anyhow::Result<bool> {
    let word = mock_chain
        .committed_account(bridge_id)?
        .storage()
        .get_item(PausableStorage::is_paused_slot())?;
    Ok(word != Word::default())
}

// EMBEDDED TEST VECTOR JSON FILES
// ================================================================================================

/// Merkle Tree Frontier (MTF) vectors JSON from the Foundry-generated file.
pub const MTF_VECTORS_JSON: &str = include_str!(
    "../../../miden-agglayer/solidity-compat/test-vectors/merkle_tree_frontier_vectors.json"
);

// LAZY-PARSED TEST VECTORS
// ================================================================================================

/// Lazily parsed Merkle Tree frontier (MTF) vectors from the JSON file.
pub static SOLIDITY_MTF_VECTORS: LazyLock<MtfVectorsFile> = LazyLock::new(|| {
    serde_json::from_str(MTF_VECTORS_JSON).expect("failed to parse MTF vectors JSON")
});

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the native fee faucet used by [`MockChainBuilder`] by default.
pub fn fee_faucet_id() -> AccountId {
    ACCOUNT_ID_FEE_FAUCET
        .try_into()
        .expect("mock-chain fee faucet ID should be valid")
}

/// Returns the production note pricer configured for the fee-enabled AggLayer test chain.
pub fn network_note_pricer(verification_base_fee: u32) -> NetworkNotePricer {
    NetworkNotePricer::builder()
        .fee_parameters(FeeParameters::new(fee_faucet_id(), verification_base_fee))
        .build()
}

/// Adds the sponsorship paired with `feature_note`, using the production price of its script.
pub fn add_fee_sponsorship(
    builder: &mut MockChainBuilder,
    feature_note: &Note,
    target: AccountId,
    verification_base_fee: u32,
) -> anyhow::Result<Note> {
    let fee = network_note_pricer(verification_base_fee).price(feature_note.script().root())?;
    let sponsorship: Note = FeeSponsorshipNote::builder()
        .sender(feature_note.metadata().sender())
        .target_account(target)
        .feature_note_id(feature_note.id())
        .asset(FungibleAsset::new(fee_faucet_id(), fee.as_u64())?)
        .generate_serial_number(builder.rng_mut())
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(sponsorship.clone()));
    Ok(sponsorship)
}

/// Asserts that a fee-enabled transaction charged a non-zero fee and emitted its TX_FEE note.
pub fn assert_transaction_paid_fee(executed: &ExecutedTransaction) {
    assert!(executed.compute_fee().as_u64() > 0, "transaction fee should be non-zero");
    assert!(
        executed.output_notes().iter().any(|note| {
            note.recipient().map(|recipient| recipient.script().root())
                == Some(StandardNote::TX_FEE.script_root())
        }),
        "fee-enabled transaction should emit a TX_FEE note"
    );
}

/// Builds an existing AggLayer bridge with its production-priced fee policy.
pub fn create_existing_priced_bridge(
    seed: Word,
    admin: AccountId,
    faucet_manager: AccountId,
    ger_injector: AccountId,
    ger_remover: AccountId,
    verification_base_fee: u32,
) -> anyhow::Result<Account> {
    let roles =
        BridgeRoles::new([faucet_manager].into(), [ger_injector].into(), [ger_remover].into())?;
    let fee_policy_manager =
        network_note_pricer(verification_base_fee).agglayer_bridge_fee_policy_manager()?;
    Ok(
        AggLayerBridge::account_builder(seed, admin, roles, MIDEN_NETWORK_ID, fee_policy_manager)
            .build_existing(),
    )
}

/// Returns a builder for an existing AggLayer faucet with its production-priced fee policy,
/// administered by [`bridge_admin_account_id`].
///
/// Callers finish with `build_existing`, after opting into any account settings the scenario
/// needs (e.g. asset callbacks).
pub fn priced_faucet_builder(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    initial_supply: Felt,
    bridge_account_id: AccountId,
    verification_base_fee: u32,
) -> anyhow::Result<AggLayerFaucetAccountBuilder> {
    let fee_policy_manager =
        network_note_pricer(verification_base_fee).agglayer_faucet_fee_policy_manager()?;
    Ok(AggLayerFaucet::account_builder(
        seed,
        token_symbol,
        decimals,
        max_supply,
        bridge_admin_account_id(),
        bridge_account_id,
        fee_policy_manager,
    )
    .with_initial_supply(initial_supply))
}

/// Execute a program with a default host and optional advice inputs.
pub async fn execute_program_with_default_host(
    program: Program,
    advice_inputs: Option<AdviceInputs>,
) -> Result<ExecutionOutput, ExecutionError> {
    let mut host = DefaultHost::default();

    let kernel_core_package = TransactionKernel::core_package();
    host.load_library(kernel_core_package.mast_forest()).unwrap();

    let std_lib = CoreLibrary::default();
    host.load_library(std_lib.mast_forest()).unwrap();

    for (event_name, handler) in std_lib.handlers() {
        host.register_handler(event_name, handler)?;
    }

    let protocol_lib = ProtocolLib::default();
    host.load_library(protocol_lib.mast_forest()).unwrap();

    let standards_lib = StandardsLib::default();
    host.load_library(standards_lib.mast_forest()).unwrap();

    let agglayer_package = agglayer_package();
    host.load_library(agglayer_package.mast_forest()).unwrap();

    let stack_inputs = StackInputs::new(&[]).unwrap();
    let advice_inputs = advice_inputs.unwrap_or_default();

    let processor = FastProcessor::new(stack_inputs)
        .with_advice(advice_inputs)
        .map_err(ExecutionError::advice_error_no_context)?;
    processor.execute(&program, &mut host).await
}

// BRIDGE SETUP
// ================================================================================================

/// The bridge account together with the wallets holding each of its operational roles.
pub struct BridgeSetup {
    pub bridge: Account,
    pub faucet_manager: Account,
    pub ger_injector: Account,
    pub ger_remover: Account,
}

/// Creates the faucet manager, GER injector, and GER remover wallets, builds the bridge account
/// wired to those roles (with the fixed [`bridge_admin_account_id`] as the `ADMIN` member), and
/// registers the bridge account with the builder.
pub fn setup_bridge(builder: &mut MockChainBuilder) -> anyhow::Result<BridgeSetup> {
    let faucet_manager = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_injector = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;
    let ger_remover = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge = create_existing_bridge_account_with_roles(
        builder.rng_mut().draw_word(),
        bridge_admin_account_id(),
        faucet_manager.id(),
        ger_injector.id(),
        ger_remover.id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge.clone())?;

    Ok(BridgeSetup {
        bridge,
        faucet_manager,
        ger_injector,
        ger_remover,
    })
}
