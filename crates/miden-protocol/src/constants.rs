use miden_processor::ExecutionOptions;

/// Depth of the account database tree.
pub const ACCOUNT_TREE_DEPTH: u8 = 64;

/// The maximum allowed size of an account update is 256 KiB.
pub const ACCOUNT_UPDATE_MAX_SIZE: u32 = 2u32.pow(18);

/// The maximum number of assets that can be stored in a single note.
pub const MAX_ASSETS_PER_NOTE: usize = 255;

/// The maximum number of storage items that can accompany a single note.
///
/// The value is set to 1024 so that it is evenly divisible by 8.
pub const MAX_NOTE_STORAGE_ITEMS: usize = 1024;

/// The maximum number of notes that can be consumed by a single transaction.
pub const MAX_INPUT_NOTES_PER_TX: usize = 1024;

/// The maximum number of new notes created by a single transaction.
pub const MAX_OUTPUT_NOTES_PER_TX: usize = MAX_INPUT_NOTES_PER_TX;

/// The minimum proof security level used by the Miden prover & verifier.
pub const MIN_PROOF_SECURITY_LEVEL: u32 = 96;

/// The maximum number of VM cycles a transaction is allowed to take.
pub const MAX_TX_EXECUTION_CYCLES: u32 = ExecutionOptions::MAX_CYCLES;

/// The minimum number of VM cycles a transaction needs to execute.
pub const MIN_TX_EXECUTION_CYCLES: u32 = 1 << 12;

/// Maximum number of the foreign accounts that can be loaded.
pub const MAX_NUM_FOREIGN_ACCOUNTS: u8 = 64;

// TRANSACTION BATCH
// ================================================================================================

/// The depth of the Sparse Merkle Tree used to store output notes in a single batch.
pub const BATCH_NOTE_TREE_DEPTH: u8 = 10;

/// The maximum number of notes that can be created in a single batch.
pub const MAX_OUTPUT_NOTES_PER_BATCH: usize = 1 << BATCH_NOTE_TREE_DEPTH;
const _: () = assert!(MAX_OUTPUT_NOTES_PER_BATCH >= MAX_OUTPUT_NOTES_PER_TX);

/// The maximum number of input notes that can be consumed in a single batch.
pub const MAX_INPUT_NOTES_PER_BATCH: usize = MAX_OUTPUT_NOTES_PER_BATCH;
const _: () = assert!(MAX_INPUT_NOTES_PER_BATCH >= MAX_INPUT_NOTES_PER_TX);

/// The maximum number of accounts that can be updated in a single batch.
pub const MAX_ACCOUNTS_PER_BATCH: usize = 1024;

// BLOCK
// ================================================================================================

/// The final depth of the Sparse Merkle Tree used to store all notes created in a block.
pub const BLOCK_NOTE_TREE_DEPTH: u8 = 16;

/// Maximum number of batches that can be inserted into a single block.
pub const MAX_BATCHES_PER_BLOCK: usize = 1 << (BLOCK_NOTE_TREE_DEPTH - BATCH_NOTE_TREE_DEPTH);

/// Maximum number of output notes that can be created in a single block.
pub const MAX_OUTPUT_NOTES_PER_BLOCK: usize = MAX_OUTPUT_NOTES_PER_BATCH * MAX_BATCHES_PER_BLOCK;
const _: () = assert!(MAX_OUTPUT_NOTES_PER_BLOCK >= MAX_OUTPUT_NOTES_PER_BATCH);

/// Maximum number of input notes that can be consumed in a single block.
pub const MAX_INPUT_NOTES_PER_BLOCK: usize = MAX_OUTPUT_NOTES_PER_BLOCK;

/// The maximum number of accounts that can be updated in a single block.
pub const MAX_ACCOUNTS_PER_BLOCK: usize = MAX_ACCOUNTS_PER_BATCH * MAX_BATCHES_PER_BLOCK;
const _: () = assert!(MAX_ACCOUNTS_PER_BLOCK >= MAX_ACCOUNTS_PER_BATCH);
const _: () = assert!(MAX_ACCOUNTS_PER_BLOCK >= MAX_BATCHES_PER_BLOCK);
