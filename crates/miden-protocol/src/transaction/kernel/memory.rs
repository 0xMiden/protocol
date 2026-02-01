// TYPE ALIASES
// ================================================================================================

pub type MemoryAddress = u32;
pub type MemoryOffset = u32;
pub type DataIndex = usize;
pub type MemSize = usize;
pub type StorageSlot = u8;

// PUBLIC CONSTANTS
// ================================================================================================

// General layout
//
// | Section            | Start address | Size in elements | Comment                                    |
// | ------------------ | ------------- | ---------------- | ------------------------------------------ |
// | Bookkeeping        | 0             | 89               |                                            |
// | Global inputs      | 400           | 40               |                                            |
// | Block header       | 800           | 44               |                                            |
// | Partial blockchain | 1_200         | 132              |                                            |
// | Kernel data        | 1_600         | 140              | 34 procedures in total, 4 elements each    |
// | Accounts data      | 8_192         | 524_288          | 64 accounts max, 8192 elements each        |
// | Account delta      | 532_480       | 263              |                                            |
// | Input notes        | 4_194_304     | 2_162_688        | nullifiers data segment + 1024 input notes |
// |                    |               |                  | max, 2048 elements each                    |
// | Output notes       | 16_777_216    | 2_097_152        | 1024 output notes max, 2048 elements each  |
// | Link Map Memory    | 33_554_432    | 33_554_432       | Enough for 2_097_151 key-value pairs       |

// Relative layout of one account
//
// | Section            | Start address | Size in elements | Comment                                |
// | ------------------ | ------------- | ---------------- | -------------------------------------- |
// | ID and nonce       | 0             | 4                |                                        |
// | Vault root         | 4             | 4                |                                        |
// | Storage commitment | 8             | 4                |                                        |
// | Code commitment    | 12            | 4                |                                        |
// | Padding            | 16            | 12               |                                        |
// | Num procedures     | 28            | 4                |                                        |
// | Procedures roots   | 32            | 1_024            | 256 procedures max, 4 elements each    |
// | Padding            | 1_056         | 4                |                                        |
// | Proc tracking      | 1_060         | 256              | 256 procedures max, 1 element each     |
// | Num storage slots  | 1_316         | 4                |                                        |
// | Initial slot info  | 1_320         | 1_020            | Only initialized on the native account |
// | Active slot info   | 2_340         | 1_020            | 255 slots max, 8 elements each         |
// | Padding            | 3_360         | 4_832            |                                        |
//
// Storage slots are laid out as [[0, slot_type, slot_id_suffix, slot_id_prefix], SLOT_VALUE].

// Relative layout of the native account's delta.
//
// For now each Storage Map pointer (a link map ptr) occupies a single element.
//
// | Section                      | Start address | Size in elements | Comment                             |
// | ---------------------------- | ------------- | ---------------- | ----------------------------------- |
// | Fungible Asset Delta Ptr     | 0             | 4                |                                     |
// | Non-Fungible Asset Delta Ptr | 4             | 4                |                                     |
// | Storage Map Delta Ptrs       | 8             | 256              | Max 255 storage map deltas          |

// BOOKKEEPING
// ------------------------------------------------------------------------------------------------

/// The memory address at which a pointer to the currently active input note is stored.
pub const ACTIVE_INPUT_NOTE_PTR: MemoryAddress = 0;

/// The memory address at which the number of output notes is stored.
pub const NUM_OUTPUT_NOTES_PTR: MemoryAddress = 4;

/// The memory address at which the input vault root is stored.
pub const INPUT_VAULT_ROOT_PTR: MemoryAddress = 8;

/// The memory address at which the output vault root is stored.
pub const OUTPUT_VAULT_ROOT_PTR: MemoryAddress = 12;

/// The memory address at which the dirty flag of the storage commitment of the native account is
/// stored.
///
/// This binary flag specifies whether the commitment is outdated: it holds 1 if some changes were
/// made to the account storage since the last re-computation, and 0 otherwise.
pub const NATIVE_ACCT_STORAGE_COMMITMENT_DIRTY_FLAG_PTR: MemoryAddress = 16;

/// The memory address at which the transaction expiration block number is stored.
pub const TX_EXPIRATION_BLOCK_NUM_PTR: MemoryAddress = 20;

/// The memory address at which the pointer to the stack element containing the pointer to the
/// active account data is stored.
///
/// The stack starts at the address `29`. Stack has a length of `64` elements meaning that the
/// maximum depth of FPI calls is `63` — the first slot is always occupied by the native account
/// data pointer.
///
/// ```text
/// ┌───────────────┬────────────────┬───────────────────┬─────┬────────────────────┐
/// │ STACK TOP PTR │ NATIVE ACCOUNT │ FOREIGN ACCOUNT 1 │ ... │ FOREIGN ACCOUNT 63 │
/// ├───────────────┼────────────────┼───────────────────┼─────┼────────────────────┤
///        24               25                30                         88
/// ```
pub const ACCOUNT_STACK_TOP_PTR: MemoryAddress = 24;

// GLOBAL INPUTS
// ------------------------------------------------------------------------------------------------

/// The memory address at which the global inputs section begins.
pub const GLOBAL_INPUTS_SECTION_OFFSET: MemoryOffset = 400;

/// The memory address at which the commitment of the transaction's reference block is stored.
pub const BLOCK_COMMITMENT_PTR: MemoryAddress = 400;

/// The memory address at which the native account ID is stored.
pub const NATIVE_ACCT_ID_PTR: MemoryAddress = 404;

/// The memory address at which the initial account commitment is stored.
pub const INIT_ACCT_COMMITMENT_PTR: MemoryAddress = 408;

/// The memory address at which the initial nonce is stored.
pub const INIT_NONCE_PTR: MemoryAddress = 412;

/// The memory address at which the initial vault root of the native account is stored.
pub const INIT_NATIVE_ACCT_VAULT_ROOT_PTR: MemoryAddress = 416;

/// The memory address at which the initial storage commitment of the native account is stored.
pub const INIT_NATIVE_ACCT_STORAGE_COMMITMENT_PTR: MemoryAddress = 420;

/// The memory address at which the input notes commitment is stored.
pub const INPUT_NOTES_COMMITMENT_PTR: MemoryAddress = 424;

/// The memory address at which the transaction script mast root is store
pub const TX_SCRIPT_ROOT_PTR: MemoryAddress = 428;

/// The memory address at which the transaction script arguments are stored.
pub const TX_SCRIPT_ARGS: MemoryAddress = 432;

/// The memory address at which the key of the auth procedure arguments is stored.
pub const AUTH_ARGS_PTR: MemoryAddress = 436;

// BLOCK DATA
// ------------------------------------------------------------------------------------------------

/// The memory address at which the block data section begins.
pub const BLOCK_DATA_SECTION_OFFSET: MemoryOffset = 800;

/// The memory address at which the previous block commitment is stored.
pub const PREV_BLOCK_COMMITMENT_PTR: MemoryAddress = 800;

/// The memory address at which the chain commitment is stored.
pub const CHAIN_COMMITMENT_PTR: MemoryAddress = 804;

/// The memory address at which the state root is stored.
pub const ACCT_DB_ROOT_PTR: MemoryAddress = 808;

/// The memory address at which the nullifier db root is store.
pub const NULLIFIER_DB_ROOT_PTR: MemoryAddress = 812;

/// The memory address at which the TX commitment is stored.
pub const TX_COMMITMENT_PTR: MemoryAddress = 816;

/// The memory address at which the transaction kernel commitment is stored.
pub const TX_KERNEL_COMMITMENT_PTR: MemoryAddress = 820;

/// The memory address at which the public key is stored.
pub const VALIDATOR_KEY_COMMITMENT_PTR: MemoryAddress = 824;

/// The memory address at which the block number is stored.
pub const BLOCK_METADATA_PTR: MemoryAddress = 828;

/// The index of the block number within the block metadata.
pub const BLOCK_NUMBER_IDX: DataIndex = 0;

/// The index of the protocol version within the block metadata.
pub const PROTOCOL_VERSION_IDX: DataIndex = 1;

/// The index of the timestamp within the block metadata.
pub const TIMESTAMP_IDX: DataIndex = 2;

/// The memory address at which the fee parameters are stored. These occupy a double word.
pub const FEE_PARAMETERS_PTR: MemoryAddress = 832;

/// The index of the native asset ID suffix within the block fee parameters.
pub const NATIVE_ASSET_ID_SUFFIX_IDX: DataIndex = 0;

/// The index of the native asset ID prefix within the block fee parameters.
pub const NATIVE_ASSET_ID_PREFIX_IDX: DataIndex = 1;

/// The index of the verification base fee within the block fee parameters.
pub const VERIFICATION_BASE_FEE_IDX: DataIndex = 2;

/// The memory address at which the note root is stored.
pub const NOTE_ROOT_PTR: MemoryAddress = 840;

// CHAIN DATA
// ------------------------------------------------------------------------------------------------

/// The memory address at which the chain data section begins.
pub const PARTIAL_BLOCKCHAIN_PTR: MemoryAddress = 1200;

/// The memory address at which the total number of leaves in the partial blockchain is stored.
pub const PARTIAL_BLOCKCHAIN_NUM_LEAVES_PTR: MemoryAddress = 1200;

/// The memory address at which the partial blockchain peaks are stored.
pub const PARTIAL_BLOCKCHAIN_PEAKS_PTR: MemoryAddress = 1204;

// KERNEL DATA
// ------------------------------------------------------------------------------------------------

/// The memory address at which the number of the kernel procedures is stored.
pub const NUM_KERNEL_PROCEDURES_PTR: MemoryAddress = 1600;

/// The memory address at which the section, where the hashes of the kernel procedures are stored,
/// begins.
pub const KERNEL_PROCEDURES_PTR: MemoryAddress = 1604;

// ACCOUNT DATA
// ------------------------------------------------------------------------------------------------

/// The size of the memory segment allocated to core account data (excluding new code commitment).
pub const ACCT_DATA_MEM_SIZE: MemSize = 16;

/// The memory address at which the native account is stored.
pub const NATIVE_ACCOUNT_DATA_PTR: MemoryAddress = 8192;

/// The length of the memory interval that the account data occupies.
pub const ACCOUNT_DATA_LENGTH: MemSize = 8192;

/// The offset at which the account ID and nonce are stored relative to the start of
/// the account data segment.
pub const ACCT_ID_AND_NONCE_OFFSET: MemoryOffset = 0;

/// The memory address at which the account ID and nonce are stored in the native account.
pub const NATIVE_ACCT_ID_AND_NONCE_PTR: MemoryAddress =
    NATIVE_ACCOUNT_DATA_PTR + ACCT_ID_AND_NONCE_OFFSET;

/// The index of the account ID within the account ID and nonce data.
pub const ACCT_ID_SUFFIX_IDX: DataIndex = 0;
pub const ACCT_ID_PREFIX_IDX: DataIndex = 1;

/// The index of the account nonce within the account ID and nonce data.
pub const ACCT_NONCE_IDX: DataIndex = 3;

/// The offset at which the account vault root is stored relative to the start of the account
/// data segment.
pub const ACCT_VAULT_ROOT_OFFSET: MemoryOffset = 4;

/// The memory address at which the account vault root is stored in the native account.
pub const NATIVE_ACCT_VAULT_ROOT_PTR: MemoryAddress =
    NATIVE_ACCOUNT_DATA_PTR + ACCT_VAULT_ROOT_OFFSET;

/// The offset at which the account storage commitment is stored relative to the start of the
/// account data segment.
pub const ACCT_STORAGE_COMMITMENT_OFFSET: MemoryOffset = 8;

/// The memory address at which the account storage commitment is stored in the native account.
pub const NATIVE_ACCT_STORAGE_COMMITMENT_PTR: MemoryAddress =
    NATIVE_ACCOUNT_DATA_PTR + ACCT_STORAGE_COMMITMENT_OFFSET;

/// The offset at which the account code commitment is stored relative to the start of the account
/// data segment.
pub const ACCT_CODE_COMMITMENT_OFFSET: MemoryOffset = 12;

/// The memory address at which the account code commitment is stored in the native account.
pub const NATIVE_ACCT_CODE_COMMITMENT_PTR: MemoryAddress =
    NATIVE_ACCOUNT_DATA_PTR + ACCT_CODE_COMMITMENT_OFFSET;

/// The offset at which the number of procedures contained in the account code is stored relative to
/// the start of the account data segment.
pub const ACCT_NUM_PROCEDURES_OFFSET: MemoryAddress = 28;

/// The memory address at which the number of procedures contained in the account code is stored in
/// the native account.
pub const NATIVE_NUM_ACCT_PROCEDURES_PTR: MemoryAddress =
    NATIVE_ACCOUNT_DATA_PTR + ACCT_NUM_PROCEDURES_OFFSET;

/// The offset at which the account procedures section begins relative to the start of the account
/// data segment.
pub const ACCT_PROCEDURES_SECTION_OFFSET: MemoryAddress = 32;

/// The memory address at which the account procedures section begins in the native account.
pub const NATIVE_ACCT_PROCEDURES_SECTION_PTR: MemoryAddress =
    NATIVE_ACCOUNT_DATA_PTR + ACCT_PROCEDURES_SECTION_OFFSET;

/// The offset at which the account procedures call tracking section begins relative to the start of
/// the account data segment.
pub const ACCT_PROCEDURES_CALL_TRACKING_OFFSET: MemoryAddress = 1060;

/// The memory address at which the account procedures call tracking section begins in the native
/// account.
pub const NATIVE_ACCT_PROCEDURES_CALL_TRACKING_PTR: MemoryAddress =
    NATIVE_ACCOUNT_DATA_PTR + ACCT_PROCEDURES_CALL_TRACKING_OFFSET;

/// The offset at which the number of storage slots contained in the account storage is stored
/// relative to the start of the account data segment.
pub const ACCT_NUM_STORAGE_SLOTS_OFFSET: MemoryAddress = 1316;

/// The memory address at which number of storage slots contained in the account storage is stored
/// in the native account.
pub const NATIVE_NUM_ACCT_STORAGE_SLOTS_PTR: MemoryAddress =
    NATIVE_ACCOUNT_DATA_PTR + ACCT_NUM_STORAGE_SLOTS_OFFSET;

/// The number of elements that each storage slot takes up in memory.
pub const ACCT_STORAGE_SLOT_NUM_ELEMENTS: u8 = 8;

/// The offset of the slot type in the storage slot.
pub const ACCT_STORAGE_SLOT_TYPE_OFFSET: u8 = 1;

/// The offset of the slot's ID suffix in the storage slot.
pub const ACCT_STORAGE_SLOT_ID_SUFFIX_OFFSET: u8 = 2;

/// The offset of the slot's ID prefix in the storage slot.
pub const ACCT_STORAGE_SLOT_ID_PREFIX_OFFSET: u8 = 3;

/// The offset of the slot value in the storage slot.
pub const ACCT_STORAGE_SLOT_VALUE_OFFSET: u8 = 4;

/// The offset at which the account's active storage slots section begins relative to the start of
/// the account data segment.
///
/// This section contains the current values of the account storage slots.
pub const ACCT_ACTIVE_STORAGE_SLOTS_SECTION_OFFSET: MemoryAddress = 2340;

/// The memory address at which the account's active storage slots section begins in the native
/// account.
pub const NATIVE_ACCT_STORAGE_SLOTS_SECTION_PTR: MemoryAddress =
    NATIVE_ACCOUNT_DATA_PTR + ACCT_ACTIVE_STORAGE_SLOTS_SECTION_OFFSET;

// NOTES DATA
// ================================================================================================

/// The size of the memory segment allocated to each note.
pub const NOTE_MEM_SIZE: MemoryAddress = 2048;

#[allow(clippy::empty_line_after_outer_attr)]
#[rustfmt::skip]
// INPUT NOTES DATA
// ------------------------------------------------------------------------------------------------
// Inputs note section contains data of all notes consumed by a transaction. The section starts at
// memory offset 4_194_304 with a word containing the total number of input notes and is followed
// by note nullifiers and note data like so:
//
// ┌─────────┬───────────┬───────────┬─────┬───────────┬─────────┬────────┬────────┬───────┬────────┐
// │   NUM   │  NOTE 0   │  NOTE 1   │ ... │  NOTE n   │ PADDING │ NOTE 0 │ NOTE 1 │  ...  │ NOTE n │
// │  NOTES  │ NULLIFIER │ NULLIFIER │     │ NULLIFIER │         │  DATA  │  DATA  │       │  DATA  │
// └─────────┴───────────┴───────────┴─────┴───────────┴─────────┴────────┴────────┴───────┴────────┘
//  4_194_304 4_194_308   4_194_312         4_194_304+4(n+1)  4_259_840   +2048    +4096   +2048n
//
// Here `n` represents number of input notes.
//
// Each nullifier occupies a single word. A data section for each note consists of exactly 2048
// elements and is laid out like so:
//
// ┌──────┬────────┬────────┬─────────┬────────────┬───────────┬──────────┬────────────┬───────┬─────────┬────────┬───────┬─────┬───────┬─────────┬
// │ NOTE │ SERIAL │ SCRIPT │ STORAGE │   ASSETS   | RECIPIENT │ METADATA │ ATTACHMENT │ NOTE  │ STORAGE │  NUM   │ ASSET │ ... │ ASSET │ PADDING │
// │  ID  │  NUM   │  ROOT  │  COMM   │ COMMITMENT |           │  HEADER  │            │ ARGS  │ LENGTH  │ ASSETS │   0   │     │   n   │         │
// ├──────┼────────┼────────┼─────────┼────────────┼───────────┼──────────┼────────────┼───────┼─────────┼────────┼───────┼─────┼───────┼─────────┤
// 0      4        8        12        16           20          24         28           32       36       40       44 + 4n
//
// - NUM_STORAGE_ITEMS is encoded as [num_storage_items, 0, 0, 0].
// - NUM_ASSETS is encoded as [num_assets, 0, 0, 0].
// - STORAGE_COMMITMENT is the key to look up note storage in the advice map.
// - ASSETS_COMMITMENT is the key to look up note assets in the advice map.
//
// Notice that note storage values are not loaded to the memory, only their length. In order to obtain
// the storage values the advice map should be used: they are stored there as
// `STORAGE_COMMITMENT -> STORAGE`.
//
// As opposed to the asset values, storage values are never used in kernel memory, so their presence
// there is unnecessary.

/// The memory address at which the input note section begins.
pub const INPUT_NOTE_SECTION_PTR: MemoryAddress = 4_194_304;

/// The memory address at which the nullifier section of the input notes begins.
pub const INPUT_NOTE_NULLIFIER_SECTION_PTR: MemoryAddress = 4_194_308;

/// The memory address at which the input note data section begins.
pub const INPUT_NOTE_DATA_SECTION_OFFSET: MemoryAddress = 4_259_840;

/// The memory address at which the number of input notes is stored.
pub const NUM_INPUT_NOTES_PTR: MemoryAddress = INPUT_NOTE_SECTION_PTR;

/// The offsets at which data of an input note is stored relative to the start of its data segment.
pub const INPUT_NOTE_ID_OFFSET: MemoryOffset = 0;
pub const INPUT_NOTE_SERIAL_NUM_OFFSET: MemoryOffset = 4;
pub const INPUT_NOTE_SCRIPT_ROOT_OFFSET: MemoryOffset = 8;
pub const INPUT_NOTE_STORAGE_COMMITMENT_OFFSET: MemoryOffset = 12;
pub const INPUT_NOTE_ASSETS_COMMITMENT_OFFSET: MemoryOffset = 16;
pub const INPUT_NOTE_RECIPIENT_OFFSET: MemoryOffset = 20;
pub const INPUT_NOTE_METADATA_HEADER_OFFSET: MemoryOffset = 24;
pub const INPUT_NOTE_ATTACHMENT_OFFSET: MemoryOffset = 28;
pub const INPUT_NOTE_ARGS_OFFSET: MemoryOffset = 32;
pub const INPUT_NOTE_NUM_STORAGE_ITEMS_OFFSET: MemoryOffset = 36;
pub const INPUT_NOTE_NUM_ASSETS_OFFSET: MemoryOffset = 40;
pub const INPUT_NOTE_ASSETS_OFFSET: MemoryOffset = 44;

#[allow(clippy::empty_line_after_outer_attr)]
#[rustfmt::skip]
// OUTPUT NOTES DATA
// ------------------------------------------------------------------------------------------------
// Output notes section contains data of all notes produced by a transaction. The section starts at
// memory offset 16_777_216 with each note data laid out one after another in 512 word increments.
//
//     ┌─────────────┬─────────────┬───────────────┬─────────────┐
//     │ NOTE 0 DATA │ NOTE 1 DATA │      ...      │ NOTE n DATA │
//     └─────────────┴─────────────┴───────────────┴─────────────┘
// 16_777_216      +2048         +4096           +2048n
//
// The total number of output notes for a transaction is stored in the bookkeeping section of the
// memory. Data section of each note is laid out like so:
//
// ┌──────┬──────────┬────────────┬───────────┬────────────┬────────────────┬─────────┬─────┬─────────┬─────────┐
// │ NOTE │ METADATA │  METADATA  │ RECIPIENT │   ASSETS   │   NUM ASSETS   │ ASSET 0 │ ... │ ASSET n │ PADDING │
// |  ID  |  HEADER  | ATTACHMENT |           | COMMITMENT | AND DIRTY FLAG |         |     |         |         |
// ├──────┼──────────┼────────────┼───────────┼────────────┼────────────────┼─────────┼─────┼─────────┼─────────┤
//    0        1           2           3           4              5             6             6 + n
//
// The NUM_ASSETS_AND_DIRTY_FLAG word has the following layout:
// `[num_assets, assets_commitment_dirty_flag, 0, 0]`, where:
// - `num_assets` is the number of assets in this output note.
// - `assets_commitment_dirty_flag` is the binary flag which specifies whether the assets commitment
//   stored in this note is outdated. It holds 1 if some changes were made to the note assets since
//   the last re-computation, and 0 otherwise.
//
// Dirty flag is set to 0 after every recomputation of the assets commitment in the
// `kernel::note::compute_output_note_assets_commitment` procedure. It is set to 1 in the
// `kernel::output_note::add_asset` procedure after any change was made to the assets data.

/// The memory address at which the output notes section begins.
pub const OUTPUT_NOTE_SECTION_OFFSET: MemoryOffset = 16_777_216;

/// The offsets at which data of an output note is stored relative to the start of its data segment.
pub const OUTPUT_NOTE_ID_OFFSET: MemoryOffset = 0;
pub const OUTPUT_NOTE_METADATA_HEADER_OFFSET: MemoryOffset = 4;
pub const OUTPUT_NOTE_ATTACHMENT_OFFSET: MemoryOffset = 8;
pub const OUTPUT_NOTE_RECIPIENT_OFFSET: MemoryOffset = 12;
pub const OUTPUT_NOTE_ASSET_COMMITMENT_OFFSET: MemoryOffset = 16;
pub const OUTPUT_NOTE_NUM_ASSETS_OFFSET: MemoryOffset = 20;
pub const OUTPUT_NOTE_DIRTY_FLAG_OFFSET: MemoryOffset = 21;
pub const OUTPUT_NOTE_ASSETS_OFFSET: MemoryOffset = 24;

// LINK MAP
// ------------------------------------------------------------------------------------------------

/// The inclusive start of the link map dynamic memory region.
pub const LINK_MAP_REGION_START_PTR: MemoryAddress = 33_554_448;

/// The non-inclusive end of the link map dynamic memory region.
pub const LINK_MAP_REGION_END_PTR: MemoryAddress = 67_108_864;

/// [`LINK_MAP_REGION_START_PTR`] + the currently used size stored at this pointer defines the next
/// entry pointer that will be allocated.
pub const LINK_MAP_USED_MEMORY_SIZE: MemoryAddress = 33_554_432;

/// The size of each map entry, i.e. four words.
pub const LINK_MAP_ENTRY_SIZE: MemoryOffset = 16;

const _: () = assert!(
    LINK_MAP_REGION_START_PTR.is_multiple_of(LINK_MAP_ENTRY_SIZE),
    "link map region start ptr should be aligned to entry size"
);

const _: () = assert!(
    (LINK_MAP_REGION_END_PTR - LINK_MAP_REGION_START_PTR).is_multiple_of(LINK_MAP_ENTRY_SIZE),
    "the link map memory range should cleanly contain a multiple of the entry size"
);
