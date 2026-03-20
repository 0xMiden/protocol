extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use miden_agglayer::claim_note::{Keccak256Output, ProofData, SmtNode};
use miden_agglayer::{
    EthAddress,
    EthAmount,
    ExitRoot,
    GlobalIndex,
    LeafData,
    MetadataHash,
    agglayer_library,
};
use miden_assembly::{Assembler, DefaultSourceManager};
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
use miden_protocol::transaction::TransactionKernel;
use miden_protocol::utils::sync::LazyLock;
use miden_tx::utils::hex_to_bytes;
use serde::Deserialize;

// EMBEDDED TEST VECTOR JSON FILES
// ================================================================================================

/// Claim asset test vectors JSON — contains both LeafData and ProofData from a real claimAsset
/// transaction.
const CLAIM_ASSET_VECTORS_JSON: &str = include_str!(
    "../../../miden-agglayer/solidity-compat/test-vectors/claim_asset_vectors_real_tx.json"
);

/// Bridge asset test vectors JSON — contains test data for an L1 bridgeAsset transaction.
const BRIDGE_ASSET_VECTORS_JSON: &str = include_str!(
    "../../../miden-agglayer/solidity-compat/test-vectors/claim_asset_vectors_local_tx.json"
);

/// Rollup deposit test vectors JSON — contains test data for a rollup deposit with two-level
/// Merkle proofs.
const ROLLUP_ASSET_VECTORS_JSON: &str = include_str!(
    "../../../miden-agglayer/solidity-compat/test-vectors/claim_asset_vectors_rollup_tx.json"
);

/// Leaf data test vectors JSON from the Foundry-generated file.
pub const LEAF_VALUE_VECTORS_JSON: &str =
    include_str!("../../../miden-agglayer/solidity-compat/test-vectors/leaf_value_vectors.json");

/// Merkle proof verification vectors JSON from the Foundry-generated file.
pub const MERKLE_PROOF_VECTORS_JSON: &str =
    include_str!("../../../miden-agglayer/solidity-compat/test-vectors/merkle_proof_vectors.json");

/// Canonical zeros JSON from the Foundry-generated file.
pub const CANONICAL_ZEROS_JSON: &str =
    include_str!("../../../miden-agglayer/solidity-compat/test-vectors/canonical_zeros.json");

/// Merkle Tree Frontier (MTF) vectors JSON from the Foundry-generated file.
pub const MTF_VECTORS_JSON: &str = include_str!(
    "../../../miden-agglayer/solidity-compat/test-vectors/merkle_tree_frontier_vectors.json"
);

// SERDE HELPERS
// ================================================================================================

/// Deserializes a JSON value that may be either a number or a string into a `String`.
///
/// Foundry's `vm.serializeUint` outputs JSON numbers for uint256 values.
/// This deserializer accepts both `"100"` (string) and `100` (number) forms.
fn deserialize_uint_to_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        _ => Err(serde::de::Error::custom("expected a number or string for amount")),
    }
}

/// Deserializes a JSON array of values that may be either numbers or strings into `Vec<String>`.
///
/// Array-level counterpart of [`deserialize_uint_to_string`].
fn deserialize_uint_vec_to_strings<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let values = Vec::<serde_json::Value>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|v| match v {
            serde_json::Value::String(s) => Ok(s),
            serde_json::Value::Number(n) => Ok(n.to_string()),
            _ => Err(serde::de::Error::custom("expected a number or string for amount")),
        })
        .collect()
}

// TEST VECTOR TYPES
// ================================================================================================

/// Deserialized leaf value test vector from Solidity-generated JSON.
#[derive(Debug, Deserialize)]
pub struct LeafValueVector {
    pub origin_network: u32,
    pub origin_token_address: String,
    pub destination_network: u32,
    pub destination_address: String,
    #[serde(deserialize_with = "deserialize_uint_to_string")]
    pub amount: String,
    pub metadata_hash: String,
    #[allow(dead_code)]
    pub leaf_value: String,
}

impl LeafValueVector {
    /// Converts this test vector into a `LeafData` instance.
    pub fn to_leaf_data(&self) -> LeafData {
        LeafData {
            origin_network: self.origin_network,
            origin_token_address: EthAddress::from_hex(&self.origin_token_address)
                .expect("valid origin token address hex"),
            destination_network: self.destination_network,
            destination_address: EthAddress::from_hex(&self.destination_address)
                .expect("valid destination address hex"),
            amount: EthAmount::from_uint_str(&self.amount).expect("valid amount uint string"),
            metadata_hash: MetadataHash::new(
                hex_to_bytes(&self.metadata_hash).expect("valid metadata hash hex"),
            ),
        }
    }
}

/// Deserialized proof value test vector from Solidity-generated JSON.
/// Contains SMT proofs, exit roots, global index, and expected global exit root.
#[derive(Debug, Deserialize)]
pub struct ProofValueVector {
    pub smt_proof_local_exit_root: Vec<String>,
    pub smt_proof_rollup_exit_root: Vec<String>,
    pub global_index: String,
    pub mainnet_exit_root: String,
    pub rollup_exit_root: String,
    /// Expected global exit root: keccak256(mainnetExitRoot || rollupExitRoot)
    #[allow(dead_code)]
    pub global_exit_root: String,
    pub claimed_global_index_hash_chain: String,
}

impl ProofValueVector {
    /// Converts this test vector into a `ProofData` instance.
    pub fn to_proof_data(&self) -> ProofData {
        let smt_proof_local: [SmtNode; 32] = self
            .smt_proof_local_exit_root
            .iter()
            .map(|s| SmtNode::new(hex_to_bytes(s).expect("valid smt proof hex")))
            .collect::<Vec<_>>()
            .try_into()
            .expect("expected 32 SMT proof nodes for local exit root");

        let smt_proof_rollup: [SmtNode; 32] = self
            .smt_proof_rollup_exit_root
            .iter()
            .map(|s| SmtNode::new(hex_to_bytes(s).expect("valid smt proof hex")))
            .collect::<Vec<_>>()
            .try_into()
            .expect("expected 32 SMT proof nodes for rollup exit root");

        ProofData {
            smt_proof_local_exit_root: smt_proof_local,
            smt_proof_rollup_exit_root: smt_proof_rollup,
            global_index: GlobalIndex::from_hex(&self.global_index)
                .expect("valid global index hex"),
            mainnet_exit_root: Keccak256Output::new(
                hex_to_bytes(&self.mainnet_exit_root).expect("valid mainnet exit root hex"),
            ),
            rollup_exit_root: Keccak256Output::new(
                hex_to_bytes(&self.rollup_exit_root).expect("valid rollup exit root hex"),
            ),
        }
    }
}

/// Deserialized claim asset test vector from Solidity-generated JSON.
/// Contains both LeafData and ProofData from a real claimAsset transaction.
#[derive(Debug, Deserialize)]
pub struct ClaimAssetVector {
    #[serde(flatten)]
    pub proof: ProofValueVector,

    #[serde(flatten)]
    pub leaf: LeafValueVector,
}

/// Deserialized Merkle proof vectors from Solidity DepositContractBase.sol.
/// Uses parallel arrays for leaves and roots. For each element from leaves/roots there are 32
/// elements from merkle_paths, which represent the merkle path for that leaf + root.
#[derive(Debug, Deserialize)]
pub struct MerkleProofVerificationFile {
    pub leaves: Vec<String>,
    pub roots: Vec<String>,
    pub merkle_paths: Vec<String>,
}

/// Deserialized canonical zeros from Solidity DepositContractBase.sol.
#[derive(Debug, Deserialize)]
pub struct CanonicalZerosFile {
    pub canonical_zeros: Vec<String>,
}

/// Deserialized Merkle Tree Frontier vectors from Solidity DepositContractV2.
///
/// Each leaf is produced by `getLeafValue` using the same hardcoded fields as `bridge_out.masm`
/// (leafType=0, originNetwork=64), parametrised by
/// a shared `origin_token_address`, `amounts[i]`, per-index
/// `destination_networks[i]` / `destination_addresses[i]`, and
/// `metadataHash = keccak256(abi.encode(token_name, token_symbol, token_decimals))`.
///
/// Amounts are serialized as uint256 values (JSON numbers).
#[derive(Debug, Deserialize)]
pub struct MTFVectorsFile {
    pub leaves: Vec<String>,
    pub roots: Vec<String>,
    pub counts: Vec<u32>,
    #[serde(deserialize_with = "deserialize_uint_vec_to_strings")]
    pub amounts: Vec<String>,
    pub origin_token_address: String,
    pub destination_networks: Vec<u32>,
    pub destination_addresses: Vec<String>,
    #[allow(dead_code)]
    pub token_name: String,
    pub token_symbol: String,
    pub token_decimals: u8,
}

// LAZY-PARSED TEST VECTORS
// ================================================================================================

/// Lazily parsed claim asset test vector from the JSON file.
pub static CLAIM_ASSET_VECTOR: LazyLock<ClaimAssetVector> = LazyLock::new(|| {
    serde_json::from_str(CLAIM_ASSET_VECTORS_JSON)
        .expect("failed to parse claim asset vectors JSON")
});

/// Lazily parsed bridge asset test vector from the JSON file (locally simulated L1 transaction).
pub static CLAIM_ASSET_VECTOR_LOCAL: LazyLock<ClaimAssetVector> = LazyLock::new(|| {
    serde_json::from_str(BRIDGE_ASSET_VECTORS_JSON)
        .expect("failed to parse bridge asset vectors JSON")
});

/// Lazily parsed rollup deposit test vector from the JSON file.
pub static CLAIM_ASSET_VECTOR_ROLLUP: LazyLock<ClaimAssetVector> = LazyLock::new(|| {
    serde_json::from_str(ROLLUP_ASSET_VECTORS_JSON)
        .expect("failed to parse rollup asset vectors JSON")
});

/// Lazily parsed Merkle proof vectors from the JSON file.
pub static SOLIDITY_MERKLE_PROOF_VECTORS: LazyLock<MerkleProofVerificationFile> =
    LazyLock::new(|| {
        serde_json::from_str(MERKLE_PROOF_VECTORS_JSON)
            .expect("failed to parse Merkle proof vectors JSON")
    });

/// Lazily parsed canonical zeros from the JSON file.
pub static SOLIDITY_CANONICAL_ZEROS: LazyLock<CanonicalZerosFile> = LazyLock::new(|| {
    serde_json::from_str(CANONICAL_ZEROS_JSON).expect("failed to parse canonical zeros JSON")
});

/// Lazily parsed Merkle Tree frontier (MTF) vectors from the JSON file.
pub static SOLIDITY_MTF_VECTORS: LazyLock<MTFVectorsFile> = LazyLock::new(|| {
    serde_json::from_str(MTF_VECTORS_JSON).expect("failed to parse MTF vectors JSON")
});

// HELPER FUNCTIONS
// ================================================================================================

/// Identifies the source of claim data used in bridge-in tests.
#[derive(Debug, Clone, Copy)]
pub enum ClaimDataSource {
    /// Real on-chain claimAsset data from claim_asset_vectors_real_tx.json.
    Real,
    /// Locally simulated bridgeAsset data from claim_asset_vectors_local_tx.json.
    Simulated,
    /// Rollup deposit data from claim_asset_vectors_rollup_tx.json.
    Rollup,
}

impl ClaimDataSource {
    /// Returns the `(ProofData, LeafData, ExitRoot)` tuple for this data source.
    pub fn get_data(self) -> (ProofData, LeafData, ExitRoot, Keccak256Output) {
        let vector = match self {
            ClaimDataSource::Real => &*CLAIM_ASSET_VECTOR,
            ClaimDataSource::Simulated => &*CLAIM_ASSET_VECTOR_LOCAL,
            ClaimDataSource::Rollup => &*CLAIM_ASSET_VECTOR_ROLLUP,
        };
        let ger = ExitRoot::new(
            hex_to_bytes(&vector.proof.global_exit_root).expect("valid global exit root hex"),
        );
        let cgi_chain_hash = Keccak256Output::new(
            hex_to_bytes(&vector.proof.claimed_global_index_hash_chain)
                .expect("invalid CGI chain hash"),
        );

        (vector.proof.to_proof_data(), vector.leaf.to_leaf_data(), ger, cgi_chain_hash)
    }
}

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

    let processor =
        FastProcessor::new(stack_inputs).with_advice(advice_inputs).with_debugging(true);
    processor.execute(&program, &mut host).await
}

/// Execute a MASM script with the default host
pub async fn execute_masm_script(script_code: &str) -> Result<ExecutionOutput, ExecutionError> {
    let agglayer_lib = agglayer_library();

    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .with_dynamic_library(CoreLibrary::default())
        .unwrap()
        .with_dynamic_library(agglayer_lib)
        .unwrap()
        .assemble_program(script_code)
        .unwrap();

    execute_program_with_default_host(program, None).await
}

/// Helper to assert execution fails with a specific error message
pub async fn assert_execution_fails_with(script_code: &str, expected_error: &str) {
    let result = execute_masm_script(script_code).await;
    assert!(result.is_err(), "Expected execution to fail but it succeeded");
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains(expected_error),
        "Expected error containing '{}', got: {}",
        expected_error,
        error_msg
    );
}
