use alloc::vec;
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
/// The request carries one output asset plus an optional native fee payment. The entire fee
/// payment becomes a public TX_FEE note; quote it before funding the request. It is never deducted
/// from the output's asset. The output is created exactly as specified, without attachments, and
/// both outputs are sealed. A compatible account must expose BasicWallet's create_note procedure.
///
/// Consume the request as an authenticated input and prove locally to avoid publishing its sender
/// or giving a remote prover its private contents. The output sender is the executing account.
/// Use independent random serials for this request and its output. Amount and timing correlations
/// remain possible. After the reclaim height, the sender can recover an unconsumed request through
/// its own account using [`Self::reclaim_args`]; that account must expose receive_asset.
#[derive(Debug, Clone)]
pub struct CreateNote {
    note: Note,
    output: Note,
    fee: Option<FungibleAsset>,
    reclaim_height: BlockNumber,
}

impl CreateNote {
    /// Number of storage items, matching the CREATE_NOTE script.
    pub const NUM_STORAGE_ITEMS: usize = 33;

    /// Creates a request for `output`, whose sender identifies the public executing account.
    ///
    /// This first version supports one fungible output asset and no output attachments. `fee`
    /// must use the chain's native fee asset, which the script checks at execution. A nonzero fee
    /// is paid in full. If it is insufficient, the transaction must be retried with a separately
    /// funded fee note or the request reclaimed. Reclaim does not disable the creation path.
    ///
    /// Returns an error for an invalid output shape, a private executing account, a zero asset or
    /// fee, a zero reclaim height, or an overflowing combined asset amount.
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
        if output.assets().num_assets() != 1 || output.attachments().num_attachments() != 0 {
            return Err(NoteError::other(
                "CREATE_NOTE requires one output asset and no attachments",
            ));
        }
        let asset = output.assets().iter().next().expect("one asset checked");
        let Some(principal) = asset.as_fungible() else {
            return Err(NoteError::other("CREATE_NOTE requires a fungible output asset"));
        };
        if principal.amount().as_u64() == 0 || fee.is_some_and(|fee| fee.amount().as_u64() == 0) {
            return Err(NoteError::other("CREATE_NOTE asset amounts must be positive"));
        }
        if reclaim_height.as_u32() == 0 {
            return Err(NoteError::other("CREATE_NOTE requires a nonzero reclaim height"));
        }
        let mut input_assets = vec![*asset];
        if let Some(fee) = fee {
            if fee.faucet_id() == principal.faucet_id() {
                let amount = principal
                    .amount()
                    .as_u64()
                    .checked_add(fee.amount().as_u64())
                    .ok_or_else(|| NoteError::other("CREATE_NOTE asset amount overflow"))?;
                input_assets[0] = FungibleAsset::new(principal.faucet_id(), amount)
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
        items.extend_from_slice(&asset.as_elements());
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

    /// The public output's recipient preimages needed by the transaction executor.
    /// Private output preimages need not be shared with the executor.
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
