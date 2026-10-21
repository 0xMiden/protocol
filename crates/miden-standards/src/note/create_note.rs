use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::Path;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::block::BlockNumber;
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
        Path::new("::miden::standards::notes::create_note::main"),
    )
    .expect("standards library contains CREATE_NOTE")
});

/// A private request to create a committed output through a public account.
///
/// Carries the output's fungible assets and an optional native fee payment, paid in full through a
/// public TX_FEE note. Both outputs are sealed. The executing account must expose BasicWallet's
/// `create_note` procedure and check that the fee covers the transaction.
///
/// Use independent random serials for the request and output. Authenticated consumption hides the
/// request header from the proven transaction; the executor and prover still see its contents.
/// The sender can recover an unconsumed request using [`Self::reclaim_args`].
#[derive(Debug, Clone)]
pub struct CreateNote {
    note: Note,
    output: Note,
    fee: Option<FungibleAsset>,
    reclaim_height: BlockNumber,
}

impl CreateNote {
    /// Number of storage items, matching the CREATE_NOTE script.
    pub const NUM_STORAGE_ITEMS: usize = 25;

    /// Creates a request for `output`, whose sender identifies the public executing account.
    ///
    /// `fee` must use the chain's native fee asset, checked at execution. Quote it before funding
    /// the request; there is no change output. Reclaim becomes available at `reclaim_height`
    /// without disabling creation. The sender's account must expose `receive_asset` to reclaim.
    ///
    /// # Errors
    ///
    /// Returns an error unless the output has positive fungible assets, no attachments, and a
    /// separate public sender. Also rejects a zero fee, zero reclaim height, or asset overflow.
    pub fn new(
        sender: AccountId,
        serial_number: Word,
        output: Note,
        fee: Option<FungibleAsset>,
        reclaim_height: BlockNumber,
    ) -> Result<Self, NoteError> {
        let target = output.metadata().sender();
        if !target.is_public() || target == sender {
            return Err(NoteError::other(
                "CREATE_NOTE requires a separate public executing account",
            ));
        }
        if output.assets().num_assets() == 0 || output.attachments().num_attachments() != 0 {
            return Err(NoteError::other("CREATE_NOTE requires output assets and no attachments"));
        }
        if output
            .assets()
            .iter()
            .any(|asset| asset.as_fungible().is_none_or(|asset| asset.amount().as_u64() == 0))
        {
            return Err(NoteError::other("CREATE_NOTE requires positive fungible output assets"));
        }
        if fee.is_some_and(|fee| fee.amount().as_u64() == 0) {
            return Err(NoteError::other("CREATE_NOTE asset amounts must be positive"));
        }
        if reclaim_height.as_u32() == 0 {
            return Err(NoteError::other("CREATE_NOTE requires a nonzero reclaim height"));
        }
        let mut input_assets = output.assets().iter().copied().collect::<Vec<_>>();
        if let Some(fee) = fee {
            if let Some(asset) = input_assets.iter_mut().find(|asset| asset.id() == fee.id()) {
                *asset = asset
                    .as_fungible()
                    .expect("output assets were validated")
                    .add(fee)
                    .map_err(|e| {
                        NoteError::other_with_source("CREATE_NOTE asset amount overflow", e)
                    })?
                    .into();
            } else {
                input_assets.push(fee.into());
            }
        }
        let input_assets = NoteAssets::new(input_assets)?;
        let mut items = Vec::with_capacity(Self::NUM_STORAGE_ITEMS);
        items.extend_from_slice(output.recipient().digest().as_elements());
        items.extend_from_slice(output.id().as_elements());
        items.extend_from_slice(input_assets.commitment().as_elements());
        items.extend_from_slice(&fee.map(|f| Asset::from(f).as_elements()).unwrap_or([ZERO; 8]));
        items.extend_from_slice(&[
            target.suffix(),
            target.prefix().as_felt(),
            Felt::from(output.metadata().tag()),
            Felt::from(output.metadata().note_type().as_u8()),
            Felt::from(reclaim_height.as_u32()),
        ]);
        let recipient = NoteRecipient::new(serial_number, Self::script(), NoteStorage::new(items)?);
        let note = Note::new(
            input_assets,
            PartialNoteMetadata::new(sender, NoteType::Private)
                .with_tag(NoteTag::with_account_target(target)),
            recipient,
        );
        Ok(Self { note, output, fee, reclaim_height })
    }

    /// Returns the CREATE_NOTE script.
    pub fn script() -> NoteScript {
        CREATE_NOTE_SCRIPT.clone()
    }

    /// Returns the CREATE_NOTE script root.
    pub fn script_root() -> NoteScriptRoot {
        CREATE_NOTE_SCRIPT.root()
    }

    /// Returns the private request to fund and publish.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// Returns the exact primary output committed by the request.
    pub fn output(&self) -> &Note {
        &self.output
    }

    /// Returns the explicit native payment, which is paid in full.
    pub fn fee(&self) -> Option<FungibleAsset> {
        self.fee
    }

    /// Returns the first block height at which the sender may recover the request.
    pub fn reclaim_height(&self) -> BlockNumber {
        self.reclaim_height
    }

    /// Returns recipient advice for a public output, or an empty list for a private output.
    pub fn output_advice(&self) -> Vec<(Word, Vec<Felt>)> {
        if self.output.metadata().note_type() == NoteType::Public {
            self.output.recipient().to_advice_map_entries().into()
        } else {
            Vec::new()
        }
    }

    /// Selects recovery to the original sender at or after the committed reclaim height.
    pub fn reclaim_args() -> Word {
        Word::from([1u32, 0, 0, 0])
    }
}

impl From<CreateNote> for Note {
    fn from(request: CreateNote) -> Self {
        request.note
    }
}
