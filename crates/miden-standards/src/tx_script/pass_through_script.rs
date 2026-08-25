use alloc::vec::Vec;

use miden_protocol::account::AccountId;
use miden_protocol::note::{NoteRecipient, NoteTag, NoteType};
use miden_protocol::transaction::{TransactionScript, TransactionScriptRoot};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::vm::AdviceMap;
use miden_protocol::{Felt, Hasher, Word};

use crate::note::P2idNoteStorage;
use crate::tx_script::transaction_script;

// CONSTANTS
// ================================================================================================

/// Path to the pass-through transaction script procedure in the standards library, assembled from
/// `asm/standards/tx_scripts/pass_through.masm`.
const PASS_THROUGH_TX_SCRIPT_PATH: &str = "::miden::standards::tx_scripts::pass_through::main";

// PASS-THROUGH TRANSACTION SCRIPT
// ================================================================================================

static PASS_THROUGH_TX_SCRIPT: LazyLock<TransactionScript> =
    LazyLock::new(|| transaction_script(PASS_THROUGH_TX_SCRIPT_PATH));

/// The canonical transaction script that forwards the assets of every input note into a single
/// P2ID output note.
///
/// The account the script runs on is a conduit, not a destination: the input notes' scripts
/// deposit their assets into its vault and the script moves exactly those assets back out into
/// one P2ID note addressed to `target`. The account's vault delta is therefore zero and, with an
/// authentication component that only bumps the nonce on a state change (e.g. [`NoAuth`]), its
/// commitment is unchanged.
///
/// That property is what the script exists for: a batch builder can append such a transaction to
/// every batch it builds concurrently, sweeping the batch's [`TxFeeNote`]s into a single note it
/// collects out of band. Consuming the fees into the batch builder's own account instead would
/// change that account's state and force batches to be built serially.
///
/// The forwarded assets are read from each input note's *initial* assets, since a transaction
/// script runs after every note script and the notes are empty by then. An input note that does
/// not deposit all of its initial assets into the account fails the transaction rather than
/// silently leaving assets behind.
///
/// The script takes a commitment to its parameters as `TX_SCRIPT_ARGS` and reads the payload from
/// the advice map, so a single [`PassThroughTransactionScript::script_root`] covers every target
/// and serial number. The payload is embedded into the script's MAST forest, so callers only have
/// to set the script and its arguments:
///
/// ```ignore
/// let script = PassThroughTransactionScript::new(target, NoteType::Public, serial_number);
/// let tx_args = TransactionArgs::new(AdviceMap::default())
///     .with_tx_script_and_args(script.tx_script().clone(), script.tx_script_args());
/// ```
///
/// [`NoAuth`]: crate::account::auth::NoAuth
/// [`TxFeeNote`]: crate::note::TxFeeNote
#[derive(Debug, Clone)]
pub struct PassThroughTransactionScript {
    script: TransactionScript,
    tx_script_args: Word,
    output_note_recipient: NoteRecipient,
    output_note_tag: NoteTag,
    output_note_type: NoteType,
}

impl PassThroughTransactionScript {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of elements in the payload: `[target_id_suffix, target_id_prefix, tag, note_type]`
    /// followed by `SERIAL_NUM`.
    ///
    /// Must be kept in sync with `PAYLOAD_NUM_ELEMENTS` in
    /// `asm/standards/tx_scripts/pass_through.masm`, which the script asserts the payload against.
    /// See `encode_payload` for the full payload layout.
    pub const PAYLOAD_NUM_ELEMENTS: usize = 8;

    /// Element offset of the P2ID target account ID's suffix within the payload.
    pub const TARGET_ID_SUFFIX_OFFSET: usize = 0;

    /// Element offset of the output note's tag within the payload.
    pub const TAG_OFFSET: usize = 2;

    /// Element offset of the output note's serial number within the payload.
    pub const SERIAL_NUM_OFFSET: usize = 4;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Builds a pass-through script forwarding the input notes' assets into a P2ID note of type
    /// `note_type` addressed to `target`, carrying `serial_number`.
    ///
    /// `serial_number` must be unique per transaction: the pass-through account's state never
    /// changes, so nothing else distinguishes two of its transactions and two notes sharing a
    /// serial number would collide.
    ///
    /// The note's tag is derived as [`NoteTag::with_account_target`] so the target can discover
    /// the note, matching the tag a Rust-built [`P2idNote`](crate::note::P2idNote) carries.
    pub fn new(target: AccountId, note_type: NoteType, serial_number: Word) -> Self {
        let output_note_tag = NoteTag::with_account_target(target);
        let output_note_recipient = P2idNoteStorage::new(target).into_recipient(serial_number);

        let payload = encode_payload(target, output_note_tag, note_type, serial_number);
        let tx_script_args = Hasher::hash_elements(&payload);

        // Embed the payload the script reads from the advice provider into the script's MAST
        // forest, so it is loaded automatically and callers only have to set the script and its
        // arguments.
        let mut advice_map = AdviceMap::default();
        advice_map.insert(tx_script_args, payload);

        Self {
            script: PASS_THROUGH_TX_SCRIPT.clone().with_advice_map(advice_map),
            tx_script_args,
            output_note_recipient,
            output_note_tag,
            output_note_type: note_type,
        }
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

    /// The recipient of the P2ID note the script creates.
    ///
    /// Callers that cannot reconstruct the recipient themselves (e.g. a client building the
    /// transaction) register it as an expected output recipient.
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
        PASS_THROUGH_TX_SCRIPT.root()
    }
}

impl From<PassThroughTransactionScript> for TransactionScript {
    fn from(script: PassThroughTransactionScript) -> Self {
        script.script
    }
}

// PAYLOAD ENCODING
// ================================================================================================

/// Encodes the script's parameters into the payload it loads from the advice map.
///
/// The payload is two words:
///
/// ```text
/// word 0: [target_id_suffix, target_id_prefix, tag, note_type]
/// word 1: SERIAL_NUM
/// ```
///
/// The first word is laid out in the order `p2id::create_output_note` reads its arguments off the
/// operand stack, so the script can push the payload field by field without reordering.
fn encode_payload(
    target: AccountId,
    tag: NoteTag,
    note_type: NoteType,
    serial_number: Word,
) -> Vec<Felt> {
    let mut payload = alloc::vec![
        target.suffix(),
        target.prefix().as_felt(),
        Felt::from(tag),
        Felt::from(note_type),
    ];
    debug_assert_eq!(
        payload.len(),
        PassThroughTransactionScript::SERIAL_NUM_OFFSET,
        "the serial number should start at the advertised offset"
    );

    payload.extend(serial_number.iter());
    debug_assert_eq!(
        payload.len(),
        PassThroughTransactionScript::PAYLOAD_NUM_ELEMENTS,
        "payload size should match the advertised constant"
    );

    payload
}
