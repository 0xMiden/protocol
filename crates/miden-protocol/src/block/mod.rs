mod header;
pub use header::{BlockHeader, FeeParameters};

mod block_body;
pub use block_body::BlockBody;

mod block_number;
pub use block_number::BlockNumber;

mod block_proof;
pub use block_proof::BlockProof;

mod proposed_block;
pub use proposed_block::ProposedBlock;

mod signed_block;
pub use signed_block::SignedBlock;

mod proven_block;
pub use proven_block::ProvenBlock;

pub mod account_tree;
pub mod nullifier_tree;

mod blockchain;
pub use blockchain::Blockchain;

mod block_account_update;
pub use block_account_update::BlockAccountUpdate;

mod account_update_witness;
pub use account_update_witness::AccountUpdateWitness;

mod block_inputs;
pub use block_inputs::BlockInputs;

mod note_tree;
pub use note_tree::{BlockNoteIndex, BlockNoteTree};

mod signer;
pub use signer::BlockSigner;

/// The set of notes created in a transaction batch with their index in the batch.
///
/// The index is included as some notes may be erased at the block level that were part of the
/// output notes of a batch. This means the indices here may not be contiguous, i.e. any missing
/// index belongs to an erased note. To correctly build the [`BlockNoteTree`] of a block, this index
/// is required.
pub type OutputNoteBatch = alloc::vec::Vec<(usize, crate::transaction::OutputNote)>;
