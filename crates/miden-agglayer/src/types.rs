use alloc::vec::Vec;

use miden_core::{Felt, Word};
use miden_protocol::crypto::SequentialCommit;

use crate::eth_types::{EthAddress, EthAmount, GlobalIndex, MetadataHash};
use crate::utils::Keccak256Output;

// TYPE ALIASES
// ================================================================================================

/// SMT node representation (32-byte Keccak256 hash)
pub type SmtNode = Keccak256Output;

/// Exit root representation (32-byte Keccak256 hash)
pub type ExitRoot = Keccak256Output;

/// Leaf value representation (32-byte Keccak256 hash)
pub type LeafValue = Keccak256Output;

/// Claimed Global Index (CGI) chain hash representation (32-byte Keccak256 hash)
pub type CgiChainHash = Keccak256Output;

// PROOF DATA
// ================================================================================================

/// Proof data for AggLayer claim verification.
/// Contains SMT proofs and root hashes using typed representations.
#[derive(Clone)]
pub struct ProofData {
    /// SMT proof for local exit root (32 SMT nodes)
    pub smt_proof_local_exit_root: [SmtNode; 32],
    /// SMT proof for rollup exit root (32 SMT nodes)
    pub smt_proof_rollup_exit_root: [SmtNode; 32],
    /// Global index (uint256 as 32 bytes)
    pub global_index: GlobalIndex,
    /// Mainnet exit root hash
    pub mainnet_exit_root: ExitRoot,
    /// Rollup exit root hash
    pub rollup_exit_root: ExitRoot,
}

impl SequentialCommit for ProofData {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        const PROOF_DATA_ELEMENT_COUNT: usize = 536; // 32*8 + 32*8 + 8 + 8 + 8 (proofs + global_index + 2 exit roots)
        let mut elements = Vec::with_capacity(PROOF_DATA_ELEMENT_COUNT);

        for node in self.smt_proof_local_exit_root.iter() {
            elements.extend(node.to_elements());
        }

        for node in self.smt_proof_rollup_exit_root.iter() {
            elements.extend(node.to_elements());
        }

        elements.extend(self.global_index.to_elements());
        elements.extend(self.mainnet_exit_root.to_elements());
        elements.extend(self.rollup_exit_root.to_elements());

        elements
    }
}

// LEAF DATA
// ================================================================================================

/// Leaf data for AggLayer claim verification.
/// Contains network, address, amount, and metadata using typed representations.
#[derive(Clone)]
pub struct LeafData {
    /// Origin network identifier (uint32)
    pub origin_network: u32,
    /// Origin token address
    pub origin_token_address: EthAddress,
    /// Destination network identifier (uint32)
    pub destination_network: u32,
    /// Destination address
    pub destination_address: EthAddress,
    /// Amount of tokens (uint256)
    pub amount: EthAmount,
    /// Metadata hash (32 bytes)
    pub metadata_hash: MetadataHash,
}

impl SequentialCommit for LeafData {
    type Commitment = Word;

    fn to_elements(&self) -> Vec<Felt> {
        const LEAF_DATA_ELEMENT_COUNT: usize = 32; // 1 + 1 + 5 + 1 + 5 + 8 + 8 + 3 (leafType + networks + addresses + amount + metadata + padding)
        let mut elements = Vec::with_capacity(LEAF_DATA_ELEMENT_COUNT);

        // LeafType (uint32 as Felt): 0u32 for transfer Ether / ERC20 tokens, 1u32 for message
        // passing. For a CLAIM note, leafType is always 0.
        elements.push(Felt::ZERO);

        // Origin network (encode as little-endian bytes for keccak)
        let origin_network = u32::from_le_bytes(self.origin_network.to_be_bytes());
        elements.push(Felt::from(origin_network));

        // Origin token address (5 u32 felts)
        elements.extend(self.origin_token_address.to_elements());

        // Destination network (encode as little-endian bytes for keccak)
        let destination_network = u32::from_le_bytes(self.destination_network.to_be_bytes());
        elements.push(Felt::from(destination_network));

        // Destination address (5 u32 felts)
        elements.extend(self.destination_address.to_elements());

        // Amount (uint256 as 8 u32 felts)
        elements.extend(self.amount.to_elements());

        // Metadata hash (8 u32 felts)
        elements.extend(self.metadata_hash.to_elements());

        // Padding
        elements.extend([Felt::ZERO; 3]);

        elements
    }
}
