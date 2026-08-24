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
use miden_agglayer::{AggLayerBridge, AggLayerFaucet, BridgeRoles, agglayer_package};
use miden_core_lib::CoreLibrary;
use miden_crypto::hash::keccak::Keccak256;
use miden_processor::advice::AdviceInputs;
use miden_processor::utils::bytes_to_packed_u32_elements;
use miden_processor::{
    DefaultHost,
    ExecutionError,
    ExecutionOutput,
    FastProcessor,
    Program,
    StackInputs,
};
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountBuilder, AccountId};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::FeeParameters;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{Note, NoteScriptRoot};
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

pub const VERIFICATION_BASE_FEE: u32 = 500;

// KECCAK-256
// ================================================================================================

/// Returns the Keccak-256 digest of `data` as the eight packed u32 field elements the
/// AggLayer MASM code works with.
pub fn hash_with_keccak256_to_elements(data: &[u8]) -> Vec<Felt> {
    let digest = <[u8; 32]>::from(Keccak256::hash(data));
    bytes_to_packed_u32_elements(&digest)
}

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

pub fn fee_faucet_id() -> AccountId {
    ACCOUNT_ID_FEE_FAUCET
        .try_into()
        .expect("mock-chain fee faucet ID should be valid")
}

pub fn network_note_pricer(verification_base_fee: u32) -> NetworkNotePricer {
    NetworkNotePricer::builder()
        .fee_parameters(FeeParameters::new(fee_faucet_id(), verification_base_fee))
        .build()
}

pub fn find_output_note(
    executed: &ExecutedTransaction,
    script_root: NoteScriptRoot,
) -> Option<&RawOutputNote> {
    executed.output_notes().iter().find(|note| {
        note.recipient().map(|recipient| recipient.script().root()) == Some(script_root)
    })
}

pub fn add_fee_sponsorship(
    builder: &mut MockChainBuilder,
    feature_note: &Note,
    target: AccountId,
    verification_base_fee: u32,
) -> anyhow::Result<Option<Note>> {
    if verification_base_fee == 0 {
        return Ok(None);
    }

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
    Ok(Some(sponsorship))
}

pub fn assert_transaction_paid_fee(executed: &ExecutedTransaction) {
    assert!(executed.compute_fee().as_u64() > 0, "transaction fee should be non-zero");
    assert!(
        find_output_note(executed, StandardNote::TX_FEE.script_root()).is_some(),
        "fee-enabled transaction should emit a TX_FEE note"
    );
}

pub fn create_existing_priced_bridge(
    seed: Word,
    bridge_admin: AccountId,
    faucet_manager: AccountId,
    ger_injector: AccountId,
    ger_remover: AccountId,
    verification_base_fee: u32,
) -> anyhow::Result<Account> {
    let roles = BridgeRoles::new(
        [faucet_manager].into(),
        [ger_injector].into(),
        [ger_remover].into(),
        [bridge_admin].into(),
        [bridge_admin].into(),
    )?;
    let pricer = network_note_pricer(verification_base_fee);
    let fee_policy = pricer.basic_constant_fee_policy(AggLayerBridge::allowed_notes())?;
    Ok(AggLayerBridge::account_builder(
        seed,
        bridge_admin,
        roles,
        MIDEN_NETWORK_ID,
        pricer.fee_parameters().fee_faucet_id(),
        fee_policy,
    )
    .build_existing()?)
}

pub fn priced_faucet_builder(
    seed: Word,
    token_symbol: &str,
    decimals: u8,
    max_supply: Felt,
    initial_supply: Felt,
    bridge_account_id: AccountId,
    verification_base_fee: u32,
) -> anyhow::Result<AccountBuilder> {
    let pricer = network_note_pricer(verification_base_fee);
    let fee_policy = pricer.basic_constant_fee_policy(AggLayerFaucet::allowed_notes())?;
    let faucet_admin = bridge_admin_account_id();
    Ok(AggLayerFaucet::account_builder(
        seed,
        token_symbol,
        decimals,
        max_supply,
        initial_supply,
        faucet_admin,
        faucet_admin,
        bridge_account_id,
        pricer.fee_parameters().fee_faucet_id(),
        fee_policy,
    ))
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
    pub pauser: Account,
}

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
    let pauser = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let bridge_admin = bridge_admin_account_id();
    let bridge = create_existing_bridge_account_with_roles(
        builder.rng_mut().draw_word(),
        bridge_admin,
        faucet_manager.id(),
        ger_injector.id(),
        ger_remover.id(),
        bridge_admin,
        pauser.id(),
        MIDEN_NETWORK_ID,
    );
    builder.add_account(bridge.clone())?;

    Ok(BridgeSetup {
        bridge,
        faucet_manager,
        ger_injector,
        ger_remover,
        pauser,
    })
}
