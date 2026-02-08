use alloc::vec::Vec;
use core::fmt::Debug;

use miden_crypto::utils::{Deserializable, Serializable};

use super::PartialBlockchain;
use crate::TransactionInputError;
use crate::account::{AccountCode, PartialAccount};
use crate::asset::AssetWitness;
use crate::block::{BlockHeader, BlockNumber};
use crate::note::{Note, NoteInclusionProof};
use crate::transaction::{TransactionArgs, TransactionScript};

mod account;
pub use account::AccountInputs;

mod notes;
use miden_core::advice::AdviceInputs;
pub use notes::{InputNote, InputNotes, ToInputNoteCommitments};

// TRANSACTION INPUTS
// ================================================================================================

/// Contains the data required to execute a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionInputs {
    account: PartialAccount,
    block_header: BlockHeader,
    blockchain: PartialBlockchain,
    input_notes: InputNotes<InputNote>,
    tx_args: TransactionArgs,
    advice_inputs: AdviceInputs,
    foreign_account_code: Vec<AccountCode>,
    /// Pre-fetched asset witnesses for note assets and the fee asset.
    asset_witnesses: Vec<AssetWitness>,
}

impl TransactionInputs {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns new [`TransactionInputs`] instantiated with the specified parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The partial blockchain does not track the block headers required to prove inclusion of any
    ///   authenticated input note.
    pub fn new(
        account: PartialAccount,
        block_header: BlockHeader,
        blockchain: PartialBlockchain,
        input_notes: InputNotes<InputNote>,
    ) -> Result<Self, TransactionInputError> {
        // Check that the partial blockchain and block header are consistent.
        if blockchain.chain_length() != block_header.block_num() {
            return Err(TransactionInputError::InconsistentChainLength {
                expected: block_header.block_num(),
                actual: blockchain.chain_length(),
            });
        }
        if blockchain.peaks().hash_peaks() != block_header.chain_commitment() {
            return Err(TransactionInputError::InconsistentChainCommitment {
                expected: block_header.chain_commitment(),
                actual: blockchain.peaks().hash_peaks(),
            });
        }
        // Validate the authentication paths of the input notes.
        for note in input_notes.iter() {
            if let InputNote::Authenticated { note, proof } = note {
                let note_block_num = proof.location().block_num();
                let block_header = if note_block_num == block_header.block_num() {
                    &block_header
                } else {
                    blockchain.get_block(note_block_num).ok_or(
                        TransactionInputError::InputNoteBlockNotInPartialBlockchain(note.id()),
                    )?
                };
                validate_is_in_block(note, proof, block_header)?;
            }
        }

        Ok(Self {
            account,
            block_header,
            blockchain,
            input_notes,
            tx_args: TransactionArgs::default(),
            advice_inputs: AdviceInputs::default(),
            foreign_account_code: Vec::new(),
            asset_witnesses: Vec::new(),
        })
    }

    /// Replaces the transaction inputs and assigns the given asset witnesses.
    pub fn with_asset_witnesses(mut self, witnesses: Vec<AssetWitness>) -> Self {
        self.asset_witnesses = witnesses;
        self
    }

    /// Replaces the transaction inputs and assigns the given foreign account code.
    pub fn with_foreign_account_code(mut self, foreign_account_code: Vec<AccountCode>) -> Self {
        self.foreign_account_code = foreign_account_code;
        self
    }

    /// Replaces the transaction inputs and assigns the given transaction arguments.
    pub fn with_tx_args(mut self, tx_args: TransactionArgs) -> Self {
        self.set_tx_args_inner(tx_args);
        self
    }

    /// Replaces the transaction inputs and assigns the given advice inputs.
    pub fn with_advice_inputs(mut self, advice_inputs: AdviceInputs) -> Self {
        self.set_advice_inputs(advice_inputs);
        self
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Replaces the input notes for the transaction.
    pub fn set_input_notes(&mut self, new_notes: Vec<Note>) {
        self.input_notes = new_notes.into();
    }

    /// Replaces the advice inputs for the transaction.
    ///
    /// Note: the advice stack from the provided advice inputs is discarded.
    pub fn set_advice_inputs(&mut self, new_advice_inputs: AdviceInputs) {
        let AdviceInputs { map, store, .. } = new_advice_inputs;
        self.advice_inputs = AdviceInputs { stack: Default::default(), map, store };
        self.tx_args.extend_advice_inputs(self.advice_inputs.clone());
    }

    /// Updates the transaction arguments of the inputs.
    #[cfg(feature = "testing")]
    pub fn set_tx_args(&mut self, tx_args: TransactionArgs) {
        self.set_tx_args_inner(tx_args);
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the account against which the transaction is executed.
    pub fn account(&self) -> &PartialAccount {
        &self.account
    }

    /// Returns block header for the block referenced by the transaction.
    pub fn block_header(&self) -> &BlockHeader {
        &self.block_header
    }

    /// Returns partial blockchain containing authentication paths for all notes consumed by the
    /// transaction.
    pub fn blockchain(&self) -> &PartialBlockchain {
        &self.blockchain
    }

    /// Returns the notes to be consumed in the transaction.
    pub fn input_notes(&self) -> &InputNotes<InputNote> {
        &self.input_notes
    }

    /// Returns the block number referenced by the inputs.
    pub fn ref_block(&self) -> BlockNumber {
        self.block_header.block_num()
    }

    /// Returns the transaction script to be executed.
    pub fn tx_script(&self) -> Option<&TransactionScript> {
        self.tx_args.tx_script()
    }

    /// Returns the foreign account code to be executed.
    pub fn foreign_account_code(&self) -> &[AccountCode] {
        &self.foreign_account_code
    }

    /// Returns the pre-fetched witnesses for note and fee assets.
    pub fn asset_witnesses(&self) -> &[AssetWitness] {
        &self.asset_witnesses
    }

    /// Returns the advice inputs to be consumed in the transaction.
    pub fn advice_inputs(&self) -> &AdviceInputs {
        &self.advice_inputs
    }

    /// Returns the transaction arguments to be consumed in the transaction.
    pub fn tx_args(&self) -> &TransactionArgs {
        &self.tx_args
    }

    // CONVERSIONS
    // --------------------------------------------------------------------------------------------

    /// Consumes these transaction inputs and returns their underlying components.
    pub fn into_parts(
        self,
    ) -> (
        PartialAccount,
        BlockHeader,
        PartialBlockchain,
        InputNotes<InputNote>,
        TransactionArgs,
    ) {
        (self.account, self.block_header, self.blockchain, self.input_notes, self.tx_args)
    }

    // HELPER METHODS
    // --------------------------------------------------------------------------------------------

    /// Replaces the current tx_args with the provided value.
    ///
    /// This also appends advice inputs from these transaction inputs to the advice inputs of the
    /// tx args.
    fn set_tx_args_inner(&mut self, tx_args: TransactionArgs) {
        self.tx_args = tx_args;
        self.tx_args.extend_advice_inputs(self.advice_inputs.clone());
    }
}

impl Serializable for TransactionInputs {
    fn write_into<W: miden_crypto::utils::ByteWriter>(&self, target: &mut W) {
        self.account.write_into(target);
        self.block_header.write_into(target);
        self.blockchain.write_into(target);
        self.input_notes.write_into(target);
        self.tx_args.write_into(target);
        self.advice_inputs.write_into(target);
        self.foreign_account_code.write_into(target);
        self.asset_witnesses.write_into(target);
    }
}

impl Deserializable for TransactionInputs {
    fn read_from<R: miden_crypto::utils::ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_crypto::utils::DeserializationError> {
        let account = PartialAccount::read_from(source)?;
        let block_header = BlockHeader::read_from(source)?;
        let blockchain = PartialBlockchain::read_from(source)?;
        let input_notes = InputNotes::read_from(source)?;
        let tx_args = TransactionArgs::read_from(source)?;
        let advice_inputs = AdviceInputs::read_from(source)?;
        let foreign_account_code = Vec::<AccountCode>::read_from(source)?;
        let asset_witnesses = Vec::<AssetWitness>::read_from(source)?;

        Ok(TransactionInputs {
            account,
            block_header,
            blockchain,
            input_notes,
            tx_args,
            advice_inputs,
            foreign_account_code,
            asset_witnesses,
        })
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Validates whether the provided note belongs to the note tree of the specified block.
fn validate_is_in_block(
    note: &Note,
    proof: &NoteInclusionProof,
    block_header: &BlockHeader,
) -> Result<(), TransactionInputError> {
    let note_index = proof.location().node_index_in_block().into();
    let note_commitment = note.commitment();
    proof
        .note_path()
        .verify(note_index, note_commitment, &block_header.note_root())
        .map_err(|_| {
            TransactionInputError::InputNoteNotInBlock(note.id(), proof.location().block_num())
        })
}
