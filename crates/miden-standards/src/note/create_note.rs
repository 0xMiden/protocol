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
/// Outputs remain unsealed; the creator is expected to build the transaction locally. The public
/// account must expose BasicWallet's `create_note` and check the fee output during authentication.
///
/// The CREATE note and output use independent random serial numbers. Authenticated consumption
/// omits the CREATE note's header from the proven transaction. The sender can reclaim an unspent
/// CREATE note at any time using [`Self::reclaim_args`].
#[derive(Debug, Clone)]
pub struct CreateNote {
    note: Note,
    output: Note,
    fee: Option<FungibleAsset>,
}

impl CreateNote {
    /// Number of storage items, matching the CREATE note script.
    pub const NUM_STORAGE_ITEMS: usize = 20;

    /// Creates a CREATE note for `output`, whose sender identifies the public executing account.
    ///
    /// `fee` must use the chain's native fee asset, checked at execution. Quote it before funding
    /// the CREATE note; there is no fee change output. Output attachments must be added by the
    /// transaction script. The sender's account must expose `receive_asset` to reclaim.
    ///
    /// # Errors
    ///
    /// Returns an error unless the output contains fungible assets with nonzero amounts and has
    /// a separate public sender. Also rejects a zero fee or asset overflow.
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
        let mut items = Vec::with_capacity(Self::NUM_STORAGE_ITEMS);
        items.extend_from_slice(output.recipient().digest().as_elements());
        items.extend_from_slice(input_assets.commitment().as_elements());
        items.extend_from_slice(&fee.map(|f| Asset::from(f).as_elements()).unwrap_or([ZERO; 8]));
        items.extend_from_slice(&[
            target.suffix(),
            target.prefix().as_felt(),
            Felt::from(output.metadata().tag()),
            Felt::from(output.metadata().note_type().as_u8()),
        ]);
        let recipient = NoteRecipient::new(serial_number, Self::script(), NoteStorage::new(items)?);
        let note = Note::new(
            input_assets,
            PartialNoteMetadata::new(sender, NoteType::Private)
                .with_tag(NoteTag::with_account_target(target)),
            recipient,
        );
        Ok(Self { note, output, fee })
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

    /// Returns the explicit native payment, which is paid in full.
    pub fn fee(&self) -> Option<FungibleAsset> {
        self.fee
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
