use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use miden_crypto::merkle::InnerNodeInfo;

use super::script::TransactionScript;
use super::{Felt, Word};
use crate::EMPTY_WORD;
use crate::account::AccountCodeUpgrade;
use crate::account::auth::BoundSignature;
use crate::note::{NoteId, NoteRecipient};
use crate::vm::{AdviceInputs, AdviceMap};

// TRANSACTION ARGUMENTS
// ================================================================================================

/// Optional transaction arguments.
///
/// - Transaction script: a program that is executed in a transaction after all input notes scripts
///   have been executed.
/// - Transaction script arguments: a [`Word`], which will be pushed to the operand stack before the
///   transaction script execution. If these arguments are not specified, the [`EMPTY_WORD`] would
///   be used as a default value. If the [AdviceInputs] are propagated with some user defined map
///   entries, this script arguments word could be used as a key to access the corresponding value.
/// - Note arguments: data put onto the stack right before a note script is executed. These are
///   different from note storage, as the user executing the transaction can specify arbitrary note
///   args.
/// - Output note recipients: the recipients of the output notes the transaction is expected to
///   create.
/// - Signatures: signatures the transaction needs for authentication.
/// - Advice inputs: provides arbitrary user-defined data needed at runtime.
/// - Auth arguments: data put onto the stack right before authentication procedure execution. If
///   this argument is not specified, the [`EMPTY_WORD`] would be used as a default value. If the
///   [AdviceInputs] are propagated with some user defined map entries, this argument could be used
///   as a key to access the corresponding value.
/// - Account code upgrade: the [`AccountCodeUpgrade`] of the native account if the transaction
///   upgrades its code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionArgs {
    tx_script: Option<TransactionScript>,
    tx_script_args: Word,
    note_args: BTreeMap<NoteId, Word>,
    output_note_recipients: Vec<NoteRecipient>,
    signatures: Vec<BoundSignature>,
    advice_inputs: AdviceInputs,
    auth_args: Word,
    account_code_upgrade: Option<AccountCodeUpgrade>,
}

impl TransactionArgs {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Returns new [`TransactionArgs`] instantiated with the provided advice map.
    pub fn new(advice_map: AdviceMap) -> Self {
        Self::from_parts(
            None,
            EMPTY_WORD,
            BTreeMap::new(),
            Vec::new(),
            Vec::new(),
            AdviceInputs::from(advice_map),
            EMPTY_WORD,
            None,
        )
    }

    /// Creates [`TransactionArgs`] from all of its components.
    pub fn from_parts(
        tx_script: Option<TransactionScript>,
        tx_script_args: Word,
        note_args: BTreeMap<NoteId, Word>,
        output_note_recipients: Vec<NoteRecipient>,
        signatures: Vec<BoundSignature>,
        advice_inputs: AdviceInputs,
        auth_args: Word,
        account_code_upgrade: Option<AccountCodeUpgrade>,
    ) -> Self {
        Self {
            tx_script,
            tx_script_args,
            note_args,
            output_note_recipients,
            signatures,
            advice_inputs,
            auth_args,
            account_code_upgrade,
        }
    }

    /// Returns new [`TransactionArgs`] instantiated with the provided transaction script.
    ///
    /// If the transaction script is already set, it will be overwritten with the newly provided
    /// one.
    #[must_use]
    pub fn with_tx_script(mut self, tx_script: TransactionScript) -> Self {
        self.tx_script = Some(tx_script);
        self
    }

    /// Returns new [`TransactionArgs`] instantiated with the provided transaction script and its
    /// arguments.
    ///
    /// If the transaction script and arguments are already set, they will be overwritten with the
    /// newly provided ones.
    #[must_use]
    pub fn with_tx_script_and_args(
        mut self,
        tx_script: TransactionScript,
        tx_script_args: Word,
    ) -> Self {
        self.tx_script = Some(tx_script);
        self.tx_script_args = tx_script_args;
        self
    }

    /// Returns new [`TransactionArgs`] instantiated with the provided note arguments.
    ///
    /// If the note arguments were already set, they will be overwritten with the newly provided
    /// ones.
    #[must_use]
    pub fn with_note_args(mut self, note_args: BTreeMap<NoteId, Word>) -> Self {
        self.note_args = note_args;
        self
    }

    /// Returns new [`TransactionArgs`] instantiated with the provided auth arguments.
    #[must_use]
    pub fn with_auth_args(mut self, auth_args: Word) -> Self {
        self.auth_args = auth_args;
        self
    }

    /// Returns new [`TransactionArgs`] instantiated with the provided code upgrade of the native
    /// account.
    #[must_use]
    pub fn with_account_code_upgrade(mut self, account_code_upgrade: AccountCodeUpgrade) -> Self {
        self.account_code_upgrade = Some(account_code_upgrade);
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns a reference to the transaction script.
    pub fn tx_script(&self) -> Option<&TransactionScript> {
        self.tx_script.as_ref()
    }

    /// Returns the transaction script arguments, or [`EMPTY_WORD`] if the arguments were not
    /// specified.
    ///
    /// These arguments could be potentially used as a key to access the advice map during the
    /// transaction script execution. Notice that the corresponding map entry should be provided
    /// separately during the creation with the [`TransactionArgs::new`] or using the
    /// [`TransactionArgs::extend_advice_map`] method.
    pub fn tx_script_args(&self) -> Word {
        self.tx_script_args
    }

    /// Returns a reference to a specific note argument.
    pub fn get_note_args(&self, note_id: NoteId) -> Option<&Word> {
        self.note_args.get(&note_id)
    }

    /// Returns the note arguments keyed by note ID.
    pub fn note_args(&self) -> &BTreeMap<NoteId, Word> {
        &self.note_args
    }

    /// Returns the recipients of the output notes the transaction is expected to create.
    pub fn output_note_recipients(&self) -> &[NoteRecipient] {
        &self.output_note_recipients
    }

    /// Returns the signatures the transaction needs for authentication.
    pub fn signatures(&self) -> &[BoundSignature] {
        &self.signatures
    }

    /// Returns a reference to the internal [AdviceInputs].
    pub fn advice_inputs(&self) -> &AdviceInputs {
        &self.advice_inputs
    }

    /// Returns a reference to the authentication procedure argument, or [`EMPTY_WORD`] if the
    /// argument was not specified.
    ///
    /// This argument could be potentially used as a key to access the advice map during the
    /// transaction script execution. Notice that the corresponding map entry should be provided
    /// separately during the creation with the [`TransactionArgs::new`] or using the
    /// [`TransactionArgs::extend_advice_map`] method.
    pub fn auth_args(&self) -> Word {
        self.auth_args
    }

    /// Returns the code upgrade of the native account, if the transaction upgrades its code.
    pub fn account_code_upgrade(&self) -> Option<&AccountCodeUpgrade> {
        self.account_code_upgrade.as_ref()
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds the recipient of an output note the transaction is expected to create.
    ///
    /// The recipient details let the host build the full output note when the transaction creates
    /// a note with the recipient's commitment.
    pub fn add_output_note_recipient(&mut self, note_recipient: NoteRecipient) {
        self.output_note_recipients.push(note_recipient);
    }

    /// Adds a signature the transaction needs for authentication.
    pub fn add_signature(&mut self, signature: BoundSignature) {
        self.signatures.push(signature);
    }

    /// Adds the recipients of output notes the transaction is expected to create.
    ///
    /// See [`Self::add_output_note_recipient`] for details.
    pub fn extend_output_note_recipients(
        &mut self,
        note_recipients: impl IntoIterator<Item = NoteRecipient>,
    ) {
        self.output_note_recipients.extend(note_recipients);
    }

    /// Extends the internal advice inputs' map with the provided key-value pairs.
    pub fn extend_advice_map<T: IntoIterator<Item = (Word, Vec<Felt>)>>(&mut self, iter: T) {
        self.advice_inputs.extend(AdviceInputs::default().with_map(iter));
    }

    /// Extends the internal advice inputs' merkle store with the provided nodes.
    pub fn extend_merkle_store<I: Iterator<Item = InnerNodeInfo>>(&mut self, iter: I) {
        self.advice_inputs
            .extend(AdviceInputs::default().with_merkle_store(iter.collect()));
    }

    /// Extends the advice inputs in self with the provided ones.
    pub fn extend_advice_inputs(&mut self, advice_inputs: AdviceInputs) {
        self.advice_inputs.extend(advice_inputs);
    }
}

/// Concatenates two [`Word`]s into a [`Vec<Felt>`] containing 8 elements.
impl Default for TransactionArgs {
    fn default() -> Self {
        Self::new(AdviceMap::default())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::vec::Vec;

    use crate::note::Note;
    use crate::transaction::TransactionArgs;
    use crate::vm::AdviceInputs;
    use crate::{Felt, Word};

    #[test]
    fn from_parts_preserves_note_args_and_advice_inputs() {
        let note_id = Note::mock_noop(Word::empty()).id();
        let note_args = BTreeMap::from([(note_id, Word::new([Felt::from(1_u32); 4]))]);
        let advice_inputs = AdviceInputs::default()
            .with_map([(Word::new([Felt::from(2_u32); 4]), vec![Felt::from(3_u32)])]);

        let tx_args = TransactionArgs::from_parts(
            None,
            Word::new([Felt::from(4_u32); 4]),
            note_args.clone(),
            Vec::new(),
            Vec::new(),
            advice_inputs.clone(),
            Word::new([Felt::from(5_u32); 4]),
            None,
        );

        assert_eq!(tx_args.note_args(), &note_args);
        assert_eq!(tx_args.advice_inputs(), &advice_inputs);
        assert_eq!(tx_args.tx_script_args(), Word::new([Felt::from(4_u32); 4]));
        assert_eq!(tx_args.auth_args(), Word::new([Felt::from(5_u32); 4]));
    }
}
