use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::note::{NoteAssets, NoteRecipient, NoteTag, NoteType};
use miden_protocol::transaction::{TransactionScript, TransactionScriptRoot};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::vm::AdviceMap;
use miden_protocol::{Felt, Hasher, Word};
use thiserror::Error;

use crate::note::P2idNoteStorage;
use crate::tx_script::transaction_script;

// CONSTANTS
// ================================================================================================

/// Path to the `single_p2id` pass-through transaction script procedure in the standards library,
/// assembled from `asm/standards/tx_scripts/pass_through/single_p2id.masm`.
const PASS_THROUGH_SINGLE_P2ID_TX_SCRIPT_PATH: &str =
    "::miden::standards::tx_scripts::pass_through::single_p2id::main";

// PASS-THROUGH SINGLE P2ID TRANSACTION SCRIPT
// ================================================================================================

static PASS_THROUGH_SINGLE_P2ID_TX_SCRIPT: LazyLock<TransactionScript> =
    LazyLock::new(|| transaction_script(PASS_THROUGH_SINGLE_P2ID_TX_SCRIPT_PATH));

/// The canonical transaction script that forwards the account's balance of the named assets into a
/// single P2ID output note.
///
/// The state of the account it executes against does not change: the input notes' scripts deposit
/// their assets into the account's vault, and the script moves the whole balance of each named
/// asset back out into one P2ID note addressed to `target`, so the account's vault delta is zero.
/// Its commitment is unchanged as long as the auth procedure neither bumps the nonce nor funds a
/// fee note from the vault, e.g. [`NoAuth`] on a chain with a zero verification base fee.
///
/// Naming assets rather than notes is what makes the script's cost independent of how many notes
/// the transaction consumes. The account must hold no assets of its own, since its own balance is
/// indistinguishable from what was deposited and would be moved out too. Both that and an asset
/// left unnamed leave the vault different from how it started, which the script turns into a
/// failed transaction by calling [`PassThrough::assert_vault_unchanged_root`] once it is done.
///
/// The account must expose the [`PassThrough`] component alongside a component providing
/// `create_note` and `receive_asset`, e.g. [`BasicWallet`].
///
/// The payload is embedded into the script's MAST forest and committed to by `TX_SCRIPT_ARGS`, so
/// a single [`PassThroughSingleP2idTransactionScript::script_root`] covers every target, serial
/// number and asset set, and callers only have to set the script and its arguments:
///
/// ```ignore
/// let script = PassThroughSingleP2idTransactionScript::new(target, NoteType::Public, serial_number, ids)?;
/// let tx_args = TransactionArgs::new(AdviceMap::default())
///     .with_tx_script_and_args(script.tx_script().clone(), script.tx_script_args());
/// ```
///
/// [`NoAuth`]: crate::account::auth::NoAuth
/// [`PassThrough`]: crate::account::pass_through::PassThrough
/// [`PassThrough::assert_vault_unchanged_root`]: crate::account::pass_through::PassThrough::assert_vault_unchanged_root
/// [`BasicWallet`]: crate::account::wallets::BasicWallet
#[derive(Debug, Clone)]
pub struct PassThroughSingleP2idTransactionScript {
    script: TransactionScript,
    tx_script_args: Word,
    output_note_recipient: NoteRecipient,
    output_note_tag: NoteTag,
    output_note_type: NoteType,
}

impl PassThroughSingleP2idTransactionScript {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of elements in the payload header: `[target_id_suffix, target_id_prefix, tag,
    /// note_type]` followed by `SERIAL_NUM`. One asset ID word follows per named asset.
    pub const PAYLOAD_HEADER_NUM_ELEMENTS: usize = 8;

    /// Element offset of the output note's serial number within the payload header.
    pub const SERIAL_NUM_OFFSET: usize = 4;

    /// Maximum number of asset IDs the payload may name: naming more assets than fit into a
    /// single note could never be forwarded into one.
    pub const MAX_ASSET_IDS: usize = NoteAssets::MAX_NUM_ASSETS;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Builds a pass-through script forwarding the account's balance of every asset in `asset_ids`
    /// into a P2ID note of type `note_type` addressed to `target`, carrying `serial_number`.
    ///
    /// `asset_ids` must name every asset the transaction's input notes deposit; an unnamed asset
    /// stays in the vault and fails the transaction.
    ///
    /// `serial_number` must be unique per transaction: the account's state never changes, so
    /// nothing else distinguishes two of its transactions and two notes sharing a serial number
    /// would collide.
    ///
    /// The note's tag is derived as [`NoteTag::with_account_target`], matching the tag a
    /// Rust-built [`P2idNote`](crate::note::P2idNote) carries.
    ///
    /// # Errors
    ///
    /// Returns an error if more than [`Self::MAX_ASSET_IDS`] asset IDs are given.
    pub fn new(
        target: AccountId,
        note_type: NoteType,
        serial_number: Word,
        asset_ids: impl IntoIterator<Item = AssetId>,
    ) -> Result<Self, PassThroughTransactionScriptError> {
        let asset_ids: Vec<AssetId> = asset_ids.into_iter().collect();
        if asset_ids.len() > Self::MAX_ASSET_IDS {
            return Err(PassThroughTransactionScriptError::TooManyAssetIds {
                actual: asset_ids.len(),
                max: Self::MAX_ASSET_IDS,
            });
        }

        let output_note_tag = NoteTag::with_account_target(target);
        let output_note_recipient = P2idNoteStorage::new(target).into_recipient(serial_number);

        let payload = encode_payload(target, output_note_tag, note_type, serial_number, &asset_ids);
        let tx_script_args = Hasher::hash_elements(&payload);

        // Embed the payload the script reads from the advice provider into the script's MAST
        // forest, so it is loaded automatically and callers only have to set the script and its
        // arguments.
        let mut advice_map = AdviceMap::default();
        advice_map.insert(tx_script_args, payload);

        Ok(Self {
            script: PASS_THROUGH_SINGLE_P2ID_TX_SCRIPT.clone().with_advice_map(advice_map),
            tx_script_args,
            output_note_recipient,
            output_note_tag,
            output_note_type: note_type,
        })
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// The transaction script, with the payload embedded in its MAST forest's advice map.
    pub fn tx_script(&self) -> &TransactionScript {
        &self.script
    }

    /// The `TX_SCRIPT_ARGS` word the script reads its payload under: the payload's commitment.
    pub fn tx_script_args(&self) -> Word {
        self.tx_script_args
    }

    /// The recipient of the P2ID note the script creates, for callers that have to register it as
    /// an expected output recipient.
    pub fn output_note_recipient(&self) -> &NoteRecipient {
        &self.output_note_recipient
    }

    /// The tag of the P2ID note the script creates.
    pub fn output_note_tag(&self) -> NoteTag {
        self.output_note_tag
    }

    /// The type of the P2ID note the script creates.
    pub fn output_note_type(&self) -> NoteType {
        self.output_note_type
    }

    /// The [`TransactionScriptRoot`] of the canonical script, which is independent of the payload.
    pub fn script_root() -> TransactionScriptRoot {
        PASS_THROUGH_SINGLE_P2ID_TX_SCRIPT.root()
    }
}

impl From<PassThroughSingleP2idTransactionScript> for TransactionScript {
    fn from(script: PassThroughSingleP2idTransactionScript) -> Self {
        script.script
    }
}

// PASS-THROUGH TRANSACTION SCRIPT ERROR
// ================================================================================================

/// Errors that can occur while building a [`PassThroughSingleP2idTransactionScript`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PassThroughTransactionScriptError {
    #[error("pass-through payload names {actual} assets but at most {max} fit into one note")]
    TooManyAssetIds { actual: usize, max: usize },
}

// PAYLOAD ENCODING
// ================================================================================================

/// Encodes the script's parameters into the payload it loads from the advice map.
///
/// ```text
/// word 0:  [target_id_suffix, target_id_prefix, tag, note_type]
/// word 1:  SERIAL_NUM
/// word 2+: one ASSET_ID per asset to forward
/// ```
fn encode_payload(
    target: AccountId,
    tag: NoteTag,
    note_type: NoteType,
    serial_number: Word,
    asset_ids: &[AssetId],
) -> Vec<Felt> {
    let mut payload = alloc::vec![
        target.suffix(),
        target.prefix().as_felt(),
        Felt::from(tag),
        Felt::from(note_type),
    ];
    debug_assert_eq!(
        payload.len(),
        PassThroughSingleP2idTransactionScript::SERIAL_NUM_OFFSET,
        "the serial number should start at the advertised offset"
    );

    payload.extend(serial_number.iter());
    debug_assert_eq!(
        payload.len(),
        PassThroughSingleP2idTransactionScript::PAYLOAD_HEADER_NUM_ELEMENTS,
        "the header size should match the advertised constant"
    );

    for asset_id in asset_ids {
        payload.extend(asset_id.to_word().iter());
    }

    payload
}
