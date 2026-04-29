//! Shared test vector types and embedded JSON constants for agglayer testing.
//!
//! This module is gated behind the `testing` feature and provides:
//! - Embedded JSON test vector files from `solidity-compat/test-vectors/`
//! - Serde helpers for deserializing Foundry-generated JSON
//! - Deserialized test vector structs (`LeafValueVector`, `ProofValueVector`, etc.)
//! - Lazy-parsed static instances of the test vectors
//! - `ClaimDataSource` enum for selecting between different claim data sources

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use miden_protocol::utils::hex_to_bytes;
use miden_protocol::utils::sync::LazyLock;
use serde::Deserialize;

use crate::claim_note::{ProofData, SmtNode};
use crate::{CgiChainHash, EthAddress, EthAmount, ExitRoot, GlobalIndex, LeafData, MetadataHash};

// EMBEDDED TEST VECTOR JSON FILES
// ================================================================================================

/// Claim asset test vectors JSON — contains both LeafData and ProofData from a real claimAsset
/// transaction.
pub const CLAIM_ASSET_VECTORS_JSON: &str =
    include_str!("../../solidity-compat/test-vectors/claim_asset_vectors_real_tx.json");

/// Bridge asset test vectors JSON — contains test data for an L1 bridgeAsset transaction.
pub const BRIDGE_ASSET_VECTORS_JSON: &str =
    include_str!("../../solidity-compat/test-vectors/claim_asset_vectors_local_tx.json");

/// Rollup deposit test vectors JSON — contains test data for a rollup deposit with two-level
/// Merkle proofs.
pub const ROLLUP_ASSET_VECTORS_JSON: &str =
    include_str!("../../solidity-compat/test-vectors/claim_asset_vectors_rollup_tx.json");

/// Leaf data test vectors JSON from the Foundry-generated file.
pub const LEAF_VALUE_VECTORS_JSON: &str =
    include_str!("../../solidity-compat/test-vectors/leaf_value_vectors.json");

/// Merkle proof verification vectors JSON from the Foundry-generated file.
pub const MERKLE_PROOF_VECTORS_JSON: &str =
    include_str!("../../solidity-compat/test-vectors/merkle_proof_vectors.json");

/// Canonical zeros JSON from the Foundry-generated file.
pub const CANONICAL_ZEROS_JSON: &str =
    include_str!("../../solidity-compat/test-vectors/canonical_zeros.json");

/// Merkle Tree Frontier (MTF) vectors JSON from the Foundry-generated file.
pub const MTF_VECTORS_JSON: &str =
    include_str!("../../solidity-compat/test-vectors/merkle_tree_frontier_vectors.json");

// SERDE HELPERS
// ================================================================================================

/// Deserializes a JSON value that may be either a number or a string into a `String`.
///
/// Foundry's `vm.serializeUint` outputs JSON numbers for uint256 values.
/// This deserializer accepts both `"100"` (string) and `100` (number) forms.
pub fn deserialize_uint_to_string<'de, D>(deserializer: D) -> Result<String, D::Error>
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
pub fn deserialize_uint_vec_to_strings<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
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
    #[serde(default)]
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
            mainnet_exit_root: ExitRoot::new(
                hex_to_bytes(&self.mainnet_exit_root).expect("valid mainnet exit root hex"),
            ),
            rollup_exit_root: ExitRoot::new(
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

/// Deserialized Merkle Tree Frontier (MTF) vectors from Solidity DepositContractV2.
///
/// Each leaf is produced by `getLeafValue` using the same hardcoded fields as `bridge_out.masm`
/// (leafType=0, originNetwork=64, metadataHash=0), parametrised by
/// a shared `origin_token_address`, `amounts[i]`, and per-index
/// `destination_networks[i]` / `destination_addresses[i]`.
///
/// Amounts are serialized as uint256 values (JSON numbers).
#[derive(Debug, Deserialize)]
pub struct MtfVectorsFile {
    pub leaves: Vec<String>,
    pub roots: Vec<String>,
    pub counts: Vec<u32>,
    #[serde(deserialize_with = "deserialize_uint_vec_to_strings")]
    pub amounts: Vec<String>,
    pub origin_token_address: String,
    pub destination_networks: Vec<u32>,
    pub destination_addresses: Vec<String>,
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

/// Lazily parsed Merkle Tree Frontier (MTF) vectors from the JSON file.
pub static SOLIDITY_MTF_VECTORS: LazyLock<MtfVectorsFile> = LazyLock::new(|| {
    serde_json::from_str(MTF_VECTORS_JSON).expect("failed to parse MTF vectors JSON")
});

// CLAIM DATA SOURCE
// ================================================================================================

/// Identifies the source of claim data used in bridge-in tests and benchmarks.
#[derive(Debug, Clone, Copy)]
pub enum ClaimDataSource {
    /// Real on-chain claimAsset data from claim_asset_vectors_real_tx.json (L1 to Miden).
    RealL1ToMiden,
    /// Locally simulated bridgeAsset data from claim_asset_vectors_local_tx.json (L1 to Miden).
    SimulatedL1ToMiden,
    /// Rollup deposit data from claim_asset_vectors_rollup_tx.json (L2 to Miden).
    SimulatedL2ToMiden,
}

impl ClaimDataSource {
    /// Returns the `(ProofData, LeafData, ExitRoot, CgiChainHash)` tuple for this data source.
    pub fn get_data(self) -> (ProofData, LeafData, ExitRoot, CgiChainHash) {
        let vector = match self {
            ClaimDataSource::RealL1ToMiden => &*CLAIM_ASSET_VECTOR,
            ClaimDataSource::SimulatedL1ToMiden => &*CLAIM_ASSET_VECTOR_LOCAL,
            ClaimDataSource::SimulatedL2ToMiden => &*CLAIM_ASSET_VECTOR_ROLLUP,
        };
        let ger = ExitRoot::new(
            hex_to_bytes(&vector.proof.global_exit_root).expect("valid global exit root hex"),
        );
        let cgi_chain_hash = CgiChainHash::new(
            hex_to_bytes(&vector.proof.claimed_global_index_hash_chain)
                .expect("invalid CGI chain hash"),
        );

        (vector.proof.to_proof_data(), vector.leaf.to_leaf_data(), ger, cgi_chain_hash)
    }
}
