use miden_processor::ExecutionOptions;

/// Depth of the account database tree.
pub const ACCOUNT_TREE_DEPTH: u8 = 64;

/// The maximum allowed size of an account update is 256 KiB.
pub const ACCOUNT_UPDATE_MAX_SIZE: u32 = 2u32.pow(18);

/// The maximum allowed size of a serialized note in bytes (256 KiB).
pub const NOTE_MAX_SIZE: u32 = 2u32.pow(18);

/// The maximum number of assets that can be stored in a single note.
pub const MAX_ASSETS_PER_NOTE: usize = 16;

/// The maximum number of storage items that can accompany a single note.
///
/// The value is set to 1024 so that it is evenly divisible by 8.
pub const MAX_NOTE_STORAGE_ITEMS: usize = 1024;

/// The maximum number of notes that can be consumed by a single transaction.
pub const MAX_INPUT_NOTES_PER_TX: usize = 1024;

/// The maximum number of new notes created by a single transaction.
pub const MAX_OUTPUT_NOTES_PER_TX: usize = MAX_INPUT_NOTES_PER_TX;

/// The maximum number of logs emitted by a single transaction.
pub const MAX_LOGS_PER_TX: usize = 64;

/// The maximum number of words in a log payload (8 KiB of serialized payload data).
pub const MAX_LOG_PAYLOAD_WORDS: usize = 256;

/// The maximum total number of log payload words in a transaction (16 KiB of serialized data).
///
/// This excludes the bounded emitter, topic, and length metadata.
pub const MAX_LOG_PAYLOAD_WORDS_PER_TX: usize = 512;

const _: () = assert!(MAX_LOGS_PER_TX <= u16::MAX as usize);
const _: () = assert!(MAX_LOG_PAYLOAD_WORDS <= u16::MAX as usize);
const _: () = assert!(MAX_LOG_PAYLOAD_WORDS_PER_TX >= MAX_LOG_PAYLOAD_WORDS);

/// The minimum proof security level used by the Miden prover & verifier.
pub const MIN_PROOF_SECURITY_LEVEL: u32 = 96;

/// The maximum number of VM cycles a transaction is allowed to take.
pub const MAX_TX_EXECUTION_CYCLES: u32 = ExecutionOptions::MAX_CYCLES;

/// The minimum number of VM cycles a transaction needs to execute.
pub const MIN_TX_EXECUTION_CYCLES: u32 = 1 << 12;

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

/// Maximum transaction log-data entries per batch, including empty and private entries.
pub const MAX_LOG_DATA_TRANSACTIONS_PER_BATCH: usize = 1024;
/// Maximum transaction log-data entries per block.
pub const MAX_LOG_DATA_TRANSACTIONS_PER_BLOCK: usize = 65536;
/// Maximum public records in a batch.
pub const MAX_PUBLIC_LOGS_PER_BATCH: usize = 4096;
/// Maximum public records in a block.
pub const MAX_PUBLIC_LOGS_PER_BLOCK: usize = 65536;
/// Maximum public payload words in a batch (2 MiB).
pub const MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BATCH: usize = 65536;
/// Maximum public payload words in a block (16 MiB).
pub const MAX_PUBLIC_LOG_PAYLOAD_WORDS_PER_BLOCK: usize = 524288;
/// Maximum serialized log-data collection per batch, including metadata (4 MiB).
pub const MAX_LOG_DATA_BYTES_PER_BATCH: usize = 4 * 1024 * 1024;
/// Maximum serialized log-data collection per block, including metadata (32 MiB).
pub const MAX_LOG_DATA_BYTES_PER_BLOCK: usize = 32 * 1024 * 1024;
