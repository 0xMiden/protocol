use alloc::vec;

use miden_protocol::Hasher;
use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteAttachmentScheme, NoteMetadata, NoteRecipient,
    NoteScript, NoteStorage, NoteTag, NoteType,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word, ZERO};

use crate::StandardsLib;
use crate::note::P2idNoteStorage;

// NOTE SCRIPT
// ================================================================================================

/// Path to the PSWAP note script procedure in the standards library.
const PSWAP_SCRIPT_PATH: &str = "::miden::standards::notes::pswap::main";

// Initialize the PSWAP note script only once
static PSWAP_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    let standards_lib = StandardsLib::default();
    let path = Path::new(PSWAP_SCRIPT_PATH);
    NoteScript::from_library_reference(standards_lib.as_ref(), path)
        .expect("Standards library contains PSWAP note script procedure")
});

// PSWAP NOTE
// ================================================================================================

/// Parsed PSWAP note storage fields.
pub struct PswapParsedInputs {
    /// Requested asset key word [0-3]
    pub requested_key: Word,
    /// Requested asset value word [4-7]
    pub requested_value: Word,
    /// SWAPp note tag
    pub swapp_tag: NoteTag,
    /// P2ID routing tag
    pub p2id_tag: NoteTag,
    /// Current swap count
    pub swap_count: u64,
    /// Creator account ID
    pub creator_account_id: AccountId,
}

/// Partial swap (pswap) note for decentralized asset exchange.
///
/// This note implements a partially-fillable swap mechanism where:
/// - Creator offers an asset and requests another asset
/// - Note can be partially or fully filled by consumers
/// - Unfilled portions create remainder notes
/// - Creator receives requested assets via P2ID notes
pub struct PswapNote;

impl PswapNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Expected number of storage items for the PSWAP note.
    ///
    /// Layout (18 Felts, matching pswap.masm memory addresses):
    /// - [0-3]:   ASSET_KEY  (requested asset key from asset.to_key_word())
    /// - [4-7]:   ASSET_VALUE (requested asset value from asset.to_value_word())
    /// - [8]:     SWAPp tag
    /// - [9]:     P2ID routing tag
    /// - [10-11]: Reserved (zero)
    /// - [12]:    Swap count
    /// - [13-15]: Reserved (zero)
    /// - [16]:    Creator account ID prefix
    /// - [17]:    Creator account ID suffix
    pub const NUM_STORAGE_ITEMS: usize = 18;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the script of the PSWAP note.
    pub fn script() -> NoteScript {
        PSWAP_SCRIPT.clone()
    }

    /// Returns the PSWAP note script root.
    pub fn script_root() -> Word {
        PSWAP_SCRIPT.root()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates a PSWAP note offering one asset in exchange for another.
    ///
    /// # Arguments
    ///
    /// * `creator_account_id` - The account creating the swap offer
    /// * `offered_asset` - The asset being offered (will be locked in the note)
    /// * `requested_asset` - The asset being requested in exchange
    /// * `note_type` - Whether the note is public or private
    /// * `note_attachment` - Attachment data for the note
    /// * `rng` - Random number generator for serial number
    ///
    /// # Returns
    ///
    /// Returns a `Note` that can be consumed by anyone willing to provide the requested asset.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Assets are invalid or have the same faucet ID
    /// - Note construction fails
    pub fn create<R: FeltRng>(
        creator_account_id: AccountId,
        offered_asset: Asset,
        requested_asset: Asset,
        note_type: NoteType,
        note_attachment: NoteAttachment,
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        if offered_asset.faucet_id().prefix() == requested_asset.faucet_id().prefix() {
            return Err(NoteError::other(
                "offered and requested assets must have different faucets",
            ));
        }

        let note_script = Self::script();

        // Build note storage (18 items) using the ASSET_KEY + ASSET_VALUE format
        let tag = Self::build_tag(note_type, &offered_asset, &requested_asset);
        let swapp_tag_felt = Felt::new(u32::from(tag) as u64);
        let p2id_tag_felt = Self::compute_p2id_tag_felt(creator_account_id);

        let key_word = requested_asset.to_key_word();
        let value_word = requested_asset.to_value_word();

        let inputs = vec![
            // ASSET_KEY [0-3]
            key_word[0],
            key_word[1],
            key_word[2],
            key_word[3],
            // ASSET_VALUE [4-7]
            value_word[0],
            value_word[1],
            value_word[2],
            value_word[3],
            // Tags [8-9]
            swapp_tag_felt,
            p2id_tag_felt,
            // Padding [10-11]
            ZERO,
            ZERO,
            // Swap count [12-15]
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            // Creator ID [16-17]
            creator_account_id.prefix().as_felt(),
            creator_account_id.suffix(),
        ];

        let note_inputs = NoteStorage::new(inputs)?;

        // Generate serial number
        let serial_num = rng.draw_word();

        // Build the outgoing note
        let metadata = NoteMetadata::new(creator_account_id, note_type)
            .with_tag(tag)
            .with_attachment(note_attachment);

        let assets = NoteAssets::new(vec![offered_asset])?;
        let recipient = NoteRecipient::new(serial_num, note_script, note_inputs);
        let note = Note::new(assets, metadata, recipient);

        Ok(note)
    }

    /// Creates output notes when consuming a swap note (P2ID + optional remainder).
    ///
    /// Handles both full and partial fills:
    /// - **Full fill**: Returns P2ID note with full requested amount, no remainder
    /// - **Partial fill**: Returns P2ID note with partial amount + remainder swap note
    ///
    /// # Arguments
    ///
    /// * `original_swap_note` - The original swap note being consumed
    /// * `consumer_account_id` - The account consuming the swap note
    /// * `input_amount` - Amount debited from consumer's vault
    /// * `inflight_amount` - Amount added directly (no vault debit, for cross-swaps)
    ///
    /// # Returns
    ///
    /// Returns a tuple of `(p2id_note, Option<remainder_note>)`
    pub fn create_output_notes(
        original_swap_note: &Note,
        consumer_account_id: AccountId,
        input_amount: u64,
        inflight_amount: u64,
    ) -> Result<(Note, Option<Note>), NoteError> {
        let inputs = original_swap_note.recipient().storage();
        let parsed = Self::parse_inputs(inputs.items())?;
        let note_type = original_swap_note.metadata().note_type();

        let fill_amount = input_amount + inflight_amount;

        // Reconstruct requested faucet ID from ASSET_KEY
        let requested_faucet_id = Self::faucet_id_from_key(&parsed.requested_key)?;
        let total_requested_amount = Self::amount_from_value(&parsed.requested_value);

        // Ensure offered asset exists and is fungible
        let offered_assets = original_swap_note.assets();
        if offered_assets.num_assets() != 1 {
            return Err(NoteError::other("Swap note must have exactly 1 offered asset"));
        }
        let offered_asset =
            offered_assets.iter().next().ok_or(NoteError::other("No offered asset found"))?;
        let (offered_faucet_id, total_offered_amount) = match offered_asset {
            Asset::Fungible(fa) => (fa.faucet_id(), fa.amount()),
            _ => return Err(NoteError::other("Non-fungible offered asset not supported")),
        };

        // Validate fill amount
        if fill_amount == 0 {
            return Err(NoteError::other("Fill amount must be greater than 0"));
        }
        if fill_amount > total_requested_amount {
            return Err(NoteError::other(alloc::format!(
                "Fill amount {} exceeds requested amount {}",
                fill_amount,
                total_requested_amount
            )));
        }

        // Calculate proportional offered amount
        let offered_amount_for_fill = Self::calculate_output_amount(
            total_offered_amount,
            total_requested_amount,
            fill_amount,
        );

        // Build the P2ID asset
        let payback_asset =
            Asset::Fungible(FungibleAsset::new(requested_faucet_id, fill_amount).map_err(|e| {
                NoteError::other(alloc::format!("Failed to create P2ID asset: {}", e))
            })?);

        let aux_word = Word::from([Felt::new(fill_amount), ZERO, ZERO, ZERO]);

        let p2id_note = Self::create_p2id_payback_note(
            original_swap_note,
            consumer_account_id,
            payback_asset,
            note_type,
            parsed.p2id_tag,
            aux_word,
        )?;

        // Create remainder note if partial fill
        let remainder_note = if fill_amount < total_requested_amount {
            let remaining_offered = total_offered_amount - offered_amount_for_fill;
            let remaining_requested = total_requested_amount - fill_amount;

            let remaining_offered_asset =
                Asset::Fungible(FungibleAsset::new(offered_faucet_id, remaining_offered).map_err(
                    |e| NoteError::other(alloc::format!("Failed to create remainder asset: {}", e)),
                )?);

            Some(Self::create_remainder_note(
                original_swap_note,
                consumer_account_id,
                remaining_offered_asset,
                remaining_requested,
                offered_amount_for_fill,
            )?)
        } else {
            None
        };

        Ok((p2id_note, remainder_note))
    }

    /// Creates a P2ID (Pay-to-ID) note for the swap creator as payback.
    ///
    /// Derives a unique serial number matching the MASM: `hmerge(swap_count_word, serial_num)`.
    pub fn create_p2id_payback_note(
        original_swap_note: &Note,
        consumer_account_id: AccountId,
        payback_asset: Asset,
        note_type: NoteType,
        p2id_tag: NoteTag,
        aux_word: Word,
    ) -> Result<Note, NoteError> {
        let inputs = original_swap_note.recipient().storage();
        let parsed = Self::parse_inputs(inputs.items())?;

        // Derive P2ID serial matching PSWAP.masm:
        //   hmerge([SWAP_COUNT_WORD (top), SERIAL_NUM (second)])
        //   = Hasher::merge(&[swap_count_word, serial_num])
        // Word[0] = count+1, matching mem_loadw_le which puts mem[addr] into Word[0]
        let swap_count_word = Word::from([Felt::new(parsed.swap_count + 1), ZERO, ZERO, ZERO]);
        let original_serial = original_swap_note.recipient().serial_num();
        let p2id_serial_digest = Hasher::merge(&[swap_count_word.into(), original_serial.into()]);
        let p2id_serial_num: Word = Word::from(p2id_serial_digest);

        // P2ID recipient targets the creator
        let recipient =
            P2idNoteStorage::new(parsed.creator_account_id).into_recipient(p2id_serial_num);

        let attachment = NoteAttachment::new_word(NoteAttachmentScheme::none(), aux_word);

        let p2id_assets = NoteAssets::new(vec![payback_asset])?;
        let p2id_metadata = NoteMetadata::new(consumer_account_id, note_type)
            .with_tag(p2id_tag)
            .with_attachment(attachment);

        Ok(Note::new(p2id_assets, p2id_metadata, recipient))
    }

    /// Creates a remainder note for partial fills.
    ///
    /// Builds updated note storage with the remaining requested amount and incremented
    /// swap count, using the ASSET_KEY + ASSET_VALUE format (18 items).
    pub fn create_remainder_note(
        original_swap_note: &Note,
        consumer_account_id: AccountId,
        remaining_offered_asset: Asset,
        remaining_requested_amount: u64,
        offered_amount_for_fill: u64,
    ) -> Result<Note, NoteError> {
        let original_inputs = original_swap_note.recipient().storage();
        let parsed = Self::parse_inputs(original_inputs.items())?;
        let note_type = original_swap_note.metadata().note_type();

        // Build new requested asset with updated amount
        let requested_faucet_id = Self::faucet_id_from_key(&parsed.requested_key)?;
        let remaining_requested_asset = Asset::Fungible(
            FungibleAsset::new(requested_faucet_id, remaining_requested_amount).map_err(|e| {
                NoteError::other(alloc::format!(
                    "Failed to create remaining requested asset: {}",
                    e
                ))
            })?,
        );

        // Build new storage with updated amounts (18 items)
        let key_word = remaining_requested_asset.to_key_word();
        let value_word = remaining_requested_asset.to_value_word();

        let inputs = vec![
            // ASSET_KEY [0-3]
            key_word[0],
            key_word[1],
            key_word[2],
            key_word[3],
            // ASSET_VALUE [4-7]
            value_word[0],
            value_word[1],
            value_word[2],
            value_word[3],
            // Tags [8-9] (preserved)
            Felt::new(u32::from(parsed.swapp_tag) as u64),
            Felt::new(u32::from(parsed.p2id_tag) as u64),
            // Padding [10-11]
            ZERO,
            ZERO,
            // Swap count [12-15] (incremented)
            Felt::new(parsed.swap_count + 1),
            ZERO,
            ZERO,
            ZERO,
            // Creator ID [16-17] (preserved)
            parsed.creator_account_id.prefix().as_felt(),
            parsed.creator_account_id.suffix(),
        ];

        let note_inputs = NoteStorage::new(inputs)?;

        // Remainder serial: increment top element of serial (matching MASM add.1 on Word[0])
        let original_serial = original_swap_note.recipient().serial_num();
        let remainder_serial_num = Word::from([
            Felt::new(original_serial[0].as_canonical_u64() + 1),
            original_serial[1],
            original_serial[2],
            original_serial[3],
        ]);

        let note_script = Self::script();
        let recipient = NoteRecipient::new(remainder_serial_num, note_script, note_inputs);

        // Build tag for the remainder note
        let tag = Self::build_tag(
            note_type,
            &remaining_offered_asset,
            &Asset::from(remaining_requested_asset),
        );

        let aux_word = Word::from([Felt::new(offered_amount_for_fill), ZERO, ZERO, ZERO]);
        let attachment = NoteAttachment::new_word(NoteAttachmentScheme::none(), aux_word);

        let metadata = NoteMetadata::new(consumer_account_id, note_type)
            .with_tag(tag)
            .with_attachment(attachment);

        let assets = NoteAssets::new(vec![remaining_offered_asset])?;
        Ok(Note::new(assets, metadata, recipient))
    }

    // TAG CONSTRUCTION
    // --------------------------------------------------------------------------------------------

    /// Returns a note tag for a pswap note with the specified parameters.
    ///
    /// Layout:
    /// ```text
    /// [ note_type (2 bits) | script_root (14 bits)
    ///   | offered_asset_faucet_id (8 bits) | requested_asset_faucet_id (8 bits) ]
    /// ```
    pub fn build_tag(
        note_type: NoteType,
        offered_asset: &Asset,
        requested_asset: &Asset,
    ) -> NoteTag {
        let pswap_root_bytes = Self::script().root().as_bytes();

        // Construct the pswap use case ID from the 14 most significant bits of the script root.
        // This leaves the two most significant bits zero.
        let mut pswap_use_case_id = (pswap_root_bytes[0] as u16) << 6;
        pswap_use_case_id |= (pswap_root_bytes[1] >> 2) as u16;

        // Get bits 0..8 from the faucet IDs of both assets which will form the tag payload.
        let offered_asset_id: u64 = offered_asset.faucet_id().prefix().into();
        let offered_asset_tag = (offered_asset_id >> 56) as u8;

        let requested_asset_id: u64 = requested_asset.faucet_id().prefix().into();
        let requested_asset_tag = (requested_asset_id >> 56) as u8;

        let asset_pair = ((offered_asset_tag as u16) << 8) | (requested_asset_tag as u16);

        let tag = ((note_type as u8 as u32) << 30)
            | ((pswap_use_case_id as u32) << 16)
            | asset_pair as u32;

        NoteTag::new(tag)
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Computes the P2ID tag for routing payback notes to the creator.
    fn compute_p2id_tag_felt(account_id: AccountId) -> Felt {
        let p2id_tag = NoteTag::with_account_target(account_id);
        Felt::new(u32::from(p2id_tag) as u64)
    }

    /// Extracts the faucet ID from an ASSET_KEY word.
    fn faucet_id_from_key(key: &Word) -> Result<AccountId, NoteError> {
        // asset::key_into_faucet_id extracts [suffix, prefix] from the key.
        // Key layout: [key[0], key[1], faucet_suffix, faucet_prefix]
        // key[2] = suffix, key[3] = prefix (after key_into_faucet_id drops top 2)
        AccountId::try_from_elements(key[2], key[3]).map_err(|e| {
            NoteError::other(alloc::format!("Failed to parse faucet ID from key: {}", e))
        })
    }

    /// Extracts the amount from an ASSET_VALUE word.
    fn amount_from_value(value: &Word) -> u64 {
        // ASSET_VALUE[0] = amount (from asset::fungible_to_amount)
        value[0].as_canonical_u64()
    }

    // PARSING FUNCTIONS
    // --------------------------------------------------------------------------------------------

    /// Parses note storage items to extract swap parameters.
    ///
    /// # Arguments
    ///
    /// * `inputs` - The note storage items (must be exactly 18 Felts)
    ///
    /// # Errors
    ///
    /// Returns an error if input length is not 18 or account ID construction fails.
    pub fn parse_inputs(inputs: &[Felt]) -> Result<PswapParsedInputs, NoteError> {
        if inputs.len() != Self::NUM_STORAGE_ITEMS {
            return Err(NoteError::other(alloc::format!(
                "PSWAP note should have {} storage items, but {} were provided",
                Self::NUM_STORAGE_ITEMS,
                inputs.len()
            )));
        }

        let requested_key = Word::from([inputs[0], inputs[1], inputs[2], inputs[3]]);
        let requested_value = Word::from([inputs[4], inputs[5], inputs[6], inputs[7]]);
        let swapp_tag = NoteTag::new(inputs[8].as_canonical_u64() as u32);
        let p2id_tag = NoteTag::new(inputs[9].as_canonical_u64() as u32);
        let swap_count = inputs[12].as_canonical_u64();

        let creator_account_id =
            AccountId::try_from_elements(inputs[17], inputs[16]).map_err(|e| {
                NoteError::other(alloc::format!("Failed to parse creator account ID: {}", e))
            })?;

        Ok(PswapParsedInputs {
            requested_key,
            requested_value,
            swapp_tag,
            p2id_tag,
            swap_count,
            creator_account_id,
        })
    }

    /// Extracts the requested asset from note storage.
    pub fn get_requested_asset(inputs: &[Felt]) -> Result<Asset, NoteError> {
        let parsed = Self::parse_inputs(inputs)?;
        let faucet_id = Self::faucet_id_from_key(&parsed.requested_key)?;
        let amount = Self::amount_from_value(&parsed.requested_value);
        Ok(Asset::Fungible(FungibleAsset::new(faucet_id, amount).map_err(|e| {
            NoteError::other(alloc::format!("Failed to create asset: {}", e))
        })?))
    }

    /// Extracts the creator account ID from note storage.
    pub fn get_creator_account_id(inputs: &[Felt]) -> Result<AccountId, NoteError> {
        Ok(Self::parse_inputs(inputs)?.creator_account_id)
    }

    /// Checks if the given account is the creator of this swap note.
    pub fn is_creator(inputs: &[Felt], account_id: AccountId) -> Result<bool, NoteError> {
        let creator_id = Self::get_creator_account_id(inputs)?;
        Ok(creator_id == account_id)
    }

    /// Calculates the output amount for a fill using u64 integer arithmetic
    /// with a precision factor of 1e5 (matching the MASM on-chain calculation).
    pub fn calculate_output_amount(
        offered_total: u64,
        requested_total: u64,
        input_amount: u64,
    ) -> u64 {
        const PRECISION_FACTOR: u64 = 100_000;

        if requested_total == input_amount {
            return offered_total;
        }

        if offered_total > requested_total {
            let ratio = (offered_total * PRECISION_FACTOR) / requested_total;
            (input_amount * ratio) / PRECISION_FACTOR
        } else {
            let ratio = (requested_total * PRECISION_FACTOR) / offered_total;
            (input_amount * PRECISION_FACTOR) / ratio
        }
    }

    /// Calculates how many offered tokens a consumer receives for a given requested input,
    /// reading the offered and requested totals directly from the swap note.
    ///
    /// This is the Rust equivalent of `calculate_tokens_offered_for_requested` in pswap.masm.
    ///
    /// # Arguments
    ///
    /// * `swap_note` - The PSWAP note being consumed
    /// * `input_amount` - Amount of requested asset the consumer is providing
    ///
    /// # Returns
    ///
    /// The proportional amount of offered asset the consumer will receive.
    ///
    /// # Errors
    ///
    /// Returns an error if the note storage cannot be parsed or the offered asset is invalid.
    pub fn calculate_offered_for_requested(
        swap_note: &Note,
        input_amount: u64,
    ) -> Result<u64, NoteError> {
        let parsed = Self::parse_inputs(swap_note.recipient().storage().items())?;
        let total_requested = Self::amount_from_value(&parsed.requested_value);

        let offered_asset = swap_note
            .assets()
            .iter()
            .next()
            .ok_or(NoteError::other("No offered asset found"))?;
        let total_offered = match offered_asset {
            Asset::Fungible(fa) => fa.amount(),
            _ => return Err(NoteError::other("Non-fungible offered asset not supported")),
        };

        Ok(Self::calculate_output_amount(total_offered, total_requested, input_amount))
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_protocol::account::{AccountId, AccountIdVersion, AccountStorageMode, AccountType};
    use miden_protocol::asset::FungibleAsset;

    use super::*;

    #[test]
    fn pswap_note_creation_and_script() {
        let mut offered_faucet_bytes = [0; 15];
        offered_faucet_bytes[0] = 0xaa;

        let mut requested_faucet_bytes = [0; 15];
        requested_faucet_bytes[0] = 0xbb;

        let offered_faucet_id = AccountId::dummy(
            offered_faucet_bytes,
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        );

        let requested_faucet_id = AccountId::dummy(
            requested_faucet_bytes,
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        );

        let creator_id = AccountId::dummy(
            [1; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Public,
        );

        let offered_asset = Asset::Fungible(FungibleAsset::new(offered_faucet_id, 1000).unwrap());
        let requested_asset =
            Asset::Fungible(FungibleAsset::new(requested_faucet_id, 500).unwrap());

        use miden_protocol::crypto::rand::RpoRandomCoin;
        let mut rng = RpoRandomCoin::new(Word::default());

        let script = PswapNote::script();
        assert!(script.root() != Word::default(), "Script root should not be zero");

        let note = PswapNote::create(
            creator_id,
            offered_asset,
            requested_asset,
            NoteType::Public,
            NoteAttachment::default(),
            &mut rng,
        );

        assert!(note.is_ok(), "Note creation should succeed");
        let note = note.unwrap();

        assert_eq!(note.metadata().sender(), creator_id);
        assert_eq!(note.metadata().note_type(), NoteType::Public);
        assert_eq!(note.assets().num_assets(), 1);
        assert_eq!(note.recipient().script().root(), script.root());

        // Verify storage has 18 items
        assert_eq!(note.recipient().storage().num_items(), PswapNote::NUM_STORAGE_ITEMS as u16,);
    }

    #[test]
    fn pswap_tag() {
        let mut offered_faucet_bytes = [0; 15];
        offered_faucet_bytes[0] = 0xcd;
        offered_faucet_bytes[1] = 0xb1;

        let mut requested_faucet_bytes = [0; 15];
        requested_faucet_bytes[0] = 0xab;
        requested_faucet_bytes[1] = 0xec;

        let offered_asset = Asset::Fungible(
            FungibleAsset::new(
                AccountId::dummy(
                    offered_faucet_bytes,
                    AccountIdVersion::Version0,
                    AccountType::FungibleFaucet,
                    AccountStorageMode::Public,
                ),
                100,
            )
            .unwrap(),
        );
        let requested_asset = Asset::Fungible(
            FungibleAsset::new(
                AccountId::dummy(
                    requested_faucet_bytes,
                    AccountIdVersion::Version0,
                    AccountType::FungibleFaucet,
                    AccountStorageMode::Public,
                ),
                200,
            )
            .unwrap(),
        );

        let tag = PswapNote::build_tag(NoteType::Public, &offered_asset, &requested_asset);
        let tag_u32 = u32::from(tag);

        // Verify note_type bits (top 2 bits should be 10 for Public)
        let note_type_bits = tag_u32 >> 30;
        assert_eq!(note_type_bits, NoteType::Public as u32);
    }

    #[test]
    fn calculate_output_amount() {
        // Equal ratio
        assert_eq!(PswapNote::calculate_output_amount(100, 100, 50), 50);

        // 2:1 ratio
        assert_eq!(PswapNote::calculate_output_amount(200, 100, 50), 100);

        // 1:2 ratio
        assert_eq!(PswapNote::calculate_output_amount(100, 200, 50), 25);

        // Non-integer ratio (100/73)
        let result = PswapNote::calculate_output_amount(100, 73, 7);
        assert!(result > 0, "Should produce non-zero output");
    }

    #[test]
    fn parse_inputs_v014_format() {
        let creator_id = AccountId::dummy(
            [1; 15],
            AccountIdVersion::Version0,
            AccountType::RegularAccountImmutableCode,
            AccountStorageMode::Public,
        );

        let faucet_id = AccountId::dummy(
            [0xaa; 15],
            AccountIdVersion::Version0,
            AccountType::FungibleFaucet,
            AccountStorageMode::Public,
        );

        let asset = Asset::Fungible(FungibleAsset::new(faucet_id, 500).unwrap());
        let key_word = asset.to_key_word();
        let value_word = asset.to_value_word();

        let inputs = vec![
            key_word[0],
            key_word[1],
            key_word[2],
            key_word[3],
            value_word[0],
            value_word[1],
            value_word[2],
            value_word[3],
            Felt::new(0xC0000000), // swapp_tag
            Felt::new(0x80000001), // p2id_tag
            ZERO,
            ZERO,
            Felt::new(3), // swap_count
            ZERO,
            ZERO,
            ZERO,
            creator_id.prefix().as_felt(),
            creator_id.suffix(),
        ];

        let parsed = PswapNote::parse_inputs(&inputs).unwrap();
        assert_eq!(parsed.swap_count, 3);
        assert_eq!(parsed.creator_account_id, creator_id);
        assert_eq!(
            parsed.requested_key,
            Word::from([key_word[0], key_word[1], key_word[2], key_word[3]])
        );
    }
}
