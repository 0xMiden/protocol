use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use miden_core::{Felt, Word};
use miden_protocol::account::AccountId;
use miden_protocol::crypto::SequentialCommit;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{Note, NoteAssets, NoteMetadata, NoteRecipient, NoteStorage, NoteType};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};

use crate::utils::Keccak256Output;
use crate::{EthAddress, EthAmount, GlobalIndex, MetadataHash, claim_script};

// CLAIM NOTE TYPE ALIASES
// ================================================================================================

/// SMT node representation (32-byte Keccak256 hash)
pub type SmtNode = Keccak256Output;

/// Exit root representation (32-byte Keccak256 hash)
pub type ExitRoot = Keccak256Output;

/// Leaf value representation (32-byte Keccak256 hash)
pub type LeafValue = Keccak256Output;

/// Claimed Global Index (CGI) chain hash representation (32-byte Keccak256 hash)
pub type CgiChainHash = Keccak256Output;

/// Proof data for CLAIM note creation.
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

        // Convert SMT proof elements to felts (each node is 8 felts)
        for node in self.smt_proof_local_exit_root.iter() {
            elements.extend(node.to_elements());
        }

        for node in self.smt_proof_rollup_exit_root.iter() {
            elements.extend(node.to_elements());
        }

        // Global index (uint256 as 32 bytes)
        elements.extend(self.global_index.to_elements());

        // Mainnet and rollup exit roots
        elements.extend(self.mainnet_exit_root.to_elements());
        elements.extend(self.rollup_exit_root.to_elements());

        elements
    }
}

/// Leaf data for CLAIM note creation.
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
        // passing.
        // for a `CLAIM` note, leafType is always 0 (transfer Ether / ERC20 tokens)
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
        elements.extend(vec![Felt::ZERO; 3]);

        elements
    }
}

/// Data for creating a CLAIM note.
///
/// This struct groups the core data needed to create a CLAIM note that exactly
/// matches the agglayer claimAsset function signature.
#[derive(Clone)]
pub struct ClaimNoteStorage {
    /// Proof data containing SMT proofs and root hashes
    pub proof_data: ProofData,
    /// Leaf data containing network, address, amount, and metadata
    pub leaf_data: LeafData,
    /// Miden claim amount (scaled-down token amount as Felt)
    pub miden_claim_amount: Felt,
}

impl TryFrom<ClaimNoteStorage> for NoteStorage {
    type Error = NoteError;

    fn try_from(storage: ClaimNoteStorage) -> Result<Self, Self::Error> {
        // proof_data + leaf_data + miden_claim_amount
        // 536 + 32 + 1
        let mut claim_storage = Vec::with_capacity(569);

        claim_storage.extend(storage.proof_data.to_elements());
        claim_storage.extend(storage.leaf_data.to_elements());
        claim_storage.push(storage.miden_claim_amount);

        NoteStorage::new(claim_storage)
    }
}

// CLAIM NOTE CREATION
// ================================================================================================

/// Generates a CLAIM note - a note that instructs the bridge to validate a claim and create
/// a MINT note for the AggLayer Faucet.
///
/// # Parameters
/// - `storage`: The core storage for creating the CLAIM note
/// - `target_bridge_id`: The account ID of the bridge that should consume this note. Encoded as a
///   `NetworkAccountTarget` attachment on the note metadata.
/// - `sender_account_id`: The account ID of the CLAIM note creator
/// - `rng`: Random number generator for creating the CLAIM note serial number
///
/// # Errors
/// Returns an error if note creation fails.
pub fn create_claim_note<R: FeltRng>(
    storage: ClaimNoteStorage,
    target_bridge_id: AccountId,
    sender_account_id: AccountId,
    rng: &mut R,
) -> Result<Note, NoteError> {
    let note_storage = NoteStorage::try_from(storage.clone())?;

    let attachment = NetworkAccountTarget::new(target_bridge_id, NoteExecutionHint::Always)
        .map_err(|e| NoteError::other(e.to_string()))?
        .into();

    let metadata =
        NoteMetadata::new(sender_account_id, NoteType::Public).with_attachment(attachment);

    let recipient = NoteRecipient::new(rng.draw_word(), claim_script(), note_storage);
    let assets = NoteAssets::new(vec![])?;

    Ok(Note::new(assets, metadata, recipient))
}
