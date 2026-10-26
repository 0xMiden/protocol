use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteRecipient,
    NoteScript,
    NoteScriptRoot,
    NoteStorage,
    NoteTag,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word, ZERO};

use crate::StandardsLib;

static CREATE_NOTE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    NoteScript::from_package_reference(
        StandardsLib::default().as_ref(),
        Path::new("::miden::standards::notes::create::main"),
    )
    .expect("standards library contains the CREATE note")
});

/// A private CREATE note that funds an output and an optional public TX_FEE note.
///
/// The creator builds and proves the transaction locally and checks its final outputs. Outputs
/// remain unsealed. The public account must expose BasicWallet's `create_note`.
///
/// The CREATE note and output use independent random serial numbers. Authenticated consumption
/// omits the CREATE note's header from the proven transaction. The sender can reclaim an unspent
/// CREATE note at any time using [`Self::reclaim_args`].
#[derive(Debug, Clone)]
pub struct CreateNote {
    note: Note,
    output: Note,
    storage: CreateNoteStorage,
}

impl CreateNote {
    /// Number of storage items, matching the CREATE note script.
    pub const NUM_STORAGE_ITEMS: usize = CreateNoteStorage::NUM_ITEMS;

    /// Creates a CREATE note for `output`, whose sender identifies the public executing account.
    ///
    /// The caller selects the chain's native fee asset and quotes the fee before funding the CREATE
    /// note; there is no fee change output. Output attachments must be added by the transaction
    /// script. The sender's account must expose `receive_asset` to reclaim.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the output is empty or contains non-fungible assets or zero amounts.
    /// - the output's sender is private or matches the CREATE note's sender.
    /// - the fee amount is zero or overflows when merged with an output asset.
    /// - the output assets and fee exceed [`NoteAssets::MAX_NUM_ASSETS`] distinct assets.
    pub fn new(
        sender: AccountId,
        serial_number: Word,
        output: Note,
        fee: Option<FungibleAsset>,
    ) -> Result<Self, NoteError> {
        let target = output.metadata().sender();
        if !target.is_public() || target == sender {
            return Err(NoteError::other(
                "CREATE note requires a separate public executing account",
            ));
        }
        if output.assets().num_assets() == 0 {
            return Err(NoteError::other("CREATE note requires output assets"));
        }
        if output
            .assets()
            .iter()
            .any(|asset| asset.as_fungible().is_none_or(|asset| asset.amount().as_u64() == 0))
        {
            return Err(NoteError::other(
                "CREATE note requires fungible assets with nonzero amounts",
            ));
        }
        if fee.is_some_and(|fee| fee.amount().as_u64() == 0) {
            return Err(NoteError::other("CREATE note fee amount must be nonzero"));
        }
        let mut input_assets = output.assets().iter().copied().collect::<Vec<_>>();
        if let Some(fee) = fee {
            if let Some(asset) = input_assets.iter_mut().find(|asset| asset.id() == fee.id()) {
                *asset = asset
                    .as_fungible()
                    .expect("output assets were validated")
                    .add(fee)
                    .map_err(|e| {
                        NoteError::other_with_source("CREATE note asset amount overflow", e)
                    })?
                    .into();
            } else {
                input_assets.push(fee.into());
            }
        }
        let input_assets = NoteAssets::new(input_assets)?;
        let storage = CreateNoteStorage::builder()
            .output_recipient(output.recipient().digest())
            .target(target)
            .output_tag(output.metadata().tag())
            .output_type(output.metadata().note_type())
            .maybe_fee(fee)
            .build();
        let recipient = storage.into_recipient(serial_number);
        let note = Note::new(
            input_assets,
            PartialNoteMetadata::new(sender, NoteType::Private)
                .with_tag(NoteTag::with_account_target(target)),
            recipient,
        );
        Ok(Self { note, output, storage })
    }

    /// Returns the CREATE note script.
    pub fn script() -> NoteScript {
        CREATE_NOTE_SCRIPT.clone()
    }

    /// Returns the CREATE note script root.
    pub fn script_root() -> NoteScriptRoot {
        CREATE_NOTE_SCRIPT.root()
    }

    /// Returns the private CREATE note to fund and publish.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// Returns the output template. Its attachments must be added by the transaction script.
    pub fn output(&self) -> &Note {
        &self.output
    }

    /// Returns the CREATE note's storage.
    pub fn storage(&self) -> &CreateNoteStorage {
        &self.storage
    }

    /// Returns the explicit native payment, which is paid in full.
    pub fn fee(&self) -> Option<FungibleAsset> {
        self.storage.fee()
    }

    /// Returns recipient advice for a public output, or an empty list for a private output.
    pub fn output_advice(&self) -> Vec<(Word, Vec<Felt>)> {
        if self.output.metadata().note_type() == NoteType::Public {
            self.output.recipient().to_advice_map_entries().into()
        } else {
            Vec::new()
        }
    }

    /// Selects recovery to the original sender, available immediately.
    pub fn reclaim_args() -> Word {
        Word::from([1u32, 0, 0, 0])
    }
}

impl From<CreateNote> for Note {
    fn from(create_note: CreateNote) -> Self {
        create_note.note
    }
}

// CREATE NOTE STORAGE
// ================================================================================================

/// Storage for a CREATE note.
///
/// | Offset | Field |
/// |--------|-------|
/// | 0..4   | Output recipient commitment |
/// | 4..8   | Fee asset ID |
/// | 8..12  | Fee asset value |
/// | 12     | Executing account ID suffix |
/// | 13     | Executing account ID prefix |
/// | 14     | Output tag |
/// | 15     | Output note type |
///
/// An absent fee is encoded as eight zero elements. The creator selects the native fee asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, bon::Builder)]
pub struct CreateNoteStorage {
    output_recipient: Word,
    target: AccountId,
    output_tag: NoteTag,
    output_type: NoteType,
    fee: Option<FungibleAsset>,
}

impl CreateNoteStorage {
    /// Expected number of storage items of the CREATE note.
    pub const NUM_ITEMS: usize = 16;

    const OUTPUT_RECIPIENT_RANGE: core::ops::Range<usize> = 0..4;
    const FEE_ID_RANGE: core::ops::Range<usize> = 4..8;
    const FEE_VALUE_RANGE: core::ops::Range<usize> = 8..12;
    const TARGET_SUFFIX_IDX: usize = 12;
    const TARGET_PREFIX_IDX: usize = 13;
    const OUTPUT_TAG_IDX: usize = 14;
    const OUTPUT_TYPE_IDX: usize = 15;

    /// Consumes the storage and returns a CREATE recipient with the provided serial number.
    pub fn into_recipient(self, serial_number: Word) -> NoteRecipient {
        NoteRecipient::new(serial_number, CreateNote::script(), self.into())
    }

    /// Returns the primary output's recipient commitment.
    pub fn output_recipient(&self) -> Word {
        self.output_recipient
    }

    /// Returns the executing account ID.
    pub fn target(&self) -> AccountId {
        self.target
    }

    /// Returns the primary output's discovery tag.
    pub fn output_tag(&self) -> NoteTag {
        self.output_tag
    }

    /// Returns the primary output's visibility.
    pub fn output_type(&self) -> NoteType {
        self.output_type
    }

    /// Returns the optional payment for the TX_FEE output.
    pub fn fee(&self) -> Option<FungibleAsset> {
        self.fee
    }
}

impl From<CreateNoteStorage> for NoteStorage {
    fn from(storage: CreateNoteStorage) -> Self {
        let mut items = Vec::with_capacity(CreateNoteStorage::NUM_ITEMS);
        items.extend_from_slice(storage.output_recipient.as_elements());
        items.extend_from_slice(
            &storage.fee.map(|fee| Asset::from(fee).as_elements()).unwrap_or([ZERO; 8]),
        );
        items.extend_from_slice(&[
            storage.target.suffix(),
            storage.target.prefix().as_felt(),
            Felt::from(storage.output_tag),
            Felt::from(storage.output_type.as_u8()),
        ]);
        NoteStorage::new(items).expect("CREATE storage fits within the storage limit")
    }
}

impl TryFrom<&[Felt]> for CreateNoteStorage {
    type Error = NoteError;

    fn try_from(items: &[Felt]) -> Result<Self, Self::Error> {
        if items.len() != Self::NUM_ITEMS {
            return Err(NoteError::InvalidNoteStorageLength {
                expected: Self::NUM_ITEMS,
                actual: items.len(),
            });
        }
        let output_recipient = Word::new(
            items[Self::OUTPUT_RECIPIENT_RANGE].try_into().expect("length already checked"),
        );
        let fee_id =
            Word::new(items[Self::FEE_ID_RANGE].try_into().expect("length already checked"));
        let fee_value =
            Word::new(items[Self::FEE_VALUE_RANGE].try_into().expect("length already checked"));
        let fee = if fee_id == Word::empty() && fee_value == Word::empty() {
            None
        } else {
            let asset = Asset::from_id_and_value_words(fee_id, fee_value)
                .map_err(|err| NoteError::other_with_source("invalid CREATE fee asset", err))?;
            Some(
                asset
                    .as_fungible()
                    .ok_or_else(|| NoteError::other("CREATE fee must be fungible"))?,
            )
        };
        let target = AccountId::try_from_elements(
            items[Self::TARGET_SUFFIX_IDX],
            items[Self::TARGET_PREFIX_IDX],
        )
        .map_err(|err| NoteError::other_with_source("invalid CREATE target account ID", err))?;
        let output_tag =
            NoteTag::new(u32::try_from(items[Self::OUTPUT_TAG_IDX].as_canonical_u64()).map_err(
                |err| NoteError::other_with_source("CREATE output tag exceeds u32", err),
            )?);
        let output_type = u8::try_from(items[Self::OUTPUT_TYPE_IDX].as_canonical_u64())
            .map_err(|err| NoteError::other_with_source("CREATE output type exceeds u8", err))?
            .try_into()?;
        Ok(Self {
            output_recipient,
            target,
            output_tag,
            output_type,
            fee,
        })
    }
}
