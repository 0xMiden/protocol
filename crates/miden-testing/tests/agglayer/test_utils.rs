extern crate alloc;

use miden_agglayer::agglayer_package;
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
use miden_core_lib::CoreLibrary;
use miden_crypto::Felt;
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
use miden_protocol::account::{Account, AccountId};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{ProtocolLib, Word};
use miden_standards::StandardsLib;
use miden_standards::account::access::PausableStorage;
use miden_testing::{Auth, MockChain, MockChainBuilder};

// TEST NETWORK ID
// ================================================================================================

/// The AggLayer network ID encoded as `destination_network` in the bundled Solidity-generated claim
/// test vectors.
pub const MIDEN_NETWORK_ID: u32 = 77;

// KECCAK-256
// ================================================================================================

/// Returns the Keccak-256 digest of `data` as the eight packed u32 field elements the
/// AggLayer MASM code works with.
pub fn hash_with_keccak256_to_elements(data: &[u8]) -> alloc::vec::Vec<Felt> {
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
