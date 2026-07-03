extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;

pub use miden_agglayer::testing::{
    ClaimDataSource,
    LEAF_VALUE_VECTORS_JSON,
    LeafValueVector,
    MerkleProofVerificationFile,
    MtfVectorsFile,
    SOLIDITY_CANONICAL_ZEROS,
    SOLIDITY_MERKLE_PROOF_VECTORS,
};
use miden_agglayer::{BridgeRoleMember, agglayer_library, create_existing_bridge_account};
use miden_assembly::{Assembler, DefaultSourceManager, Linkage};
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
use miden_protocol::Word;
use miden_protocol::account::{
    Account,
    AccountId,
    AccountIdVersion,
    AccountType,
    AssetCallbackFlag,
};
use miden_protocol::errors::MasmError;
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::utils::sync::LazyLock;

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

// BRIDGE ACCOUNT HELPERS
// ================================================================================================

/// A fixed dummy governance owner used for bridge accounts in tests that don't exercise the
/// owner's role-management powers (granting/revoking roles, transferring ownership).
pub fn bridge_test_owner() -> AccountId {
    AccountId::dummy(
        [0xee; 15],
        AccountIdVersion::Version1,
        AccountType::Public,
        AssetCallbackFlag::Disabled,
    )
}

/// Creates an existing bridge account seeded with the three operational roles held by the given
/// accounts (`FAUCET_ADMIN`, `GER_INJECTOR`, `GER_REMOVER`) and the fixed [`bridge_test_owner`]
/// as the governance owner.
///
/// Drop-in replacement for `create_existing_bridge_account` in tests: same `(seed, faucet_admin,
/// ger_injector, ger_remover)` arguments, but wires up the RBAC role seeding.
pub fn create_existing_bridge_account_with_roles(
    seed: Word,
    faucet_admin: AccountId,
    ger_injector: AccountId,
    ger_remover: AccountId,
) -> Account {
    create_existing_bridge_account(
        seed,
        bridge_test_owner(),
        vec![
            BridgeRoleMember::FaucetAdmin(vec![faucet_admin]),
            BridgeRoleMember::GerInjector(vec![ger_injector]),
            BridgeRoleMember::GerRemover(vec![ger_remover]),
        ],
    )
}

// HELPER FUNCTIONS
// ================================================================================================

/// Execute a program with a default host and optional advice inputs.
pub async fn execute_program_with_default_host(
    program: Program,
    advice_inputs: Option<AdviceInputs>,
) -> Result<ExecutionOutput, ExecutionError> {
    let mut host = DefaultHost::default();

    let test_lib = TransactionKernel::library();
    host.load_library(test_lib.mast_forest()).unwrap();

    let std_lib = CoreLibrary::default();
    host.load_library(std_lib.mast_forest()).unwrap();

    for (event_name, handler) in std_lib.handlers() {
        host.register_handler(event_name, handler)?;
    }

    let agglayer_lib = agglayer_library();
    host.load_library(agglayer_lib.mast_forest()).unwrap();

    let stack_inputs = StackInputs::new(&[]).unwrap();
    let advice_inputs = advice_inputs.unwrap_or_default();

    let processor = FastProcessor::new(stack_inputs)
        .with_advice(advice_inputs)
        .map_err(ExecutionError::advice_error_no_context)?;
    processor.execute(&program, &mut host).await
}

/// Execute a MASM script with the default host
pub async fn execute_masm_script(script_code: &str) -> Result<ExecutionOutput, ExecutionError> {
    let agglayer_lib = agglayer_library();

    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_package(CoreLibrary::default().package(), Linkage::Dynamic)
        .unwrap()
        .with_package(Arc::new(agglayer_lib), Linkage::Dynamic)
        .unwrap()
        .assemble_program("agglayer-test-script", script_code)
        .unwrap()
        .try_into_program()
        .unwrap();

    execute_program_with_default_host(program, None).await
}

/// Helper to assert execution fails with a specific MASM assertion error.
pub async fn assert_execution_fails_with(script_code: &str, expected_error: &MasmError) {
    let result = execute_masm_script(script_code).await;
    assert!(result.is_err(), "Expected execution to fail but it succeeded");

    let error = result.unwrap_err();
    assert!(
        expected_error.matches_execution_error(&error),
        "Expected error {}, got: {}",
        expected_error,
        error
    );
}
