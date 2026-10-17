use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt::Debug;

use super::PartialBlockchain;
use crate::Word;
use crate::account::auth::{Signature, SignatureKey};
use crate::account::{AccountId, PartialAccount, StorageMapWitness};
use crate::asset::AssetWitness;
use crate::block::{BlockHeader, BlockNumber};
use crate::errors::TransactionInputError;
use crate::note::{Note, NoteInclusionProof, NoteScript, NoteScriptRoot};
use crate::protocol_config::ProtocolConfig;
use crate::transaction::{TransactionArgs, TransactionScript};

#[cfg(test)]
mod tests;

mod account;
pub use account::AccountInputs;

mod notes;
pub use notes::{InputNote, InputNotes, ToInputNoteCommitments};

// TRANSACTION INPUTS
// ================================================================================================

/// Contains all data required to execute a transaction.
///
/// Data that the executor loads lazily, such as foreign accounts or signatures, can be added to the
/// inputs, so that the inputs contain all necessary data for re-executing the transaction without
/// access to a data store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionInputs {
    account: PartialAccount,
    block_header: BlockHeader,
    /// The chain's protocol configuration, which `block_header` only commits to.
    protocol_config: ProtocolConfig,
    blockchain: PartialBlockchain,
    input_notes: InputNotes<InputNote>,
    tx_args: TransactionArgs,
    /// Foreign accounts the transaction accessed during execution.
    foreign_accounts: BTreeMap<AccountId, AccountInputs>,
    /// Scripts of the output notes the host resolved during execution.
    note_scripts: BTreeMap<NoteScriptRoot, NoteScript>,
    /// Signatures the authenticator generated during execution.
    signatures: BTreeMap<SignatureKey, Signature>,
}

#[bon::bon]
impl TransactionInputs {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns a builder for [`TransactionInputs`].
    ///
    /// Required setters: `account`, `block_header`, `protocol_config`, `blockchain` and
    /// `input_notes`. The other fields default to empty values.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The protocol config does not match the one committed to by the block header.
    /// - The partial blockchain does not track the block headers required to prove inclusion of any
    ///   authenticated input note.
    /// - Any of the conditions of [`Self::add_foreign_account`] is not met.
    /// - Any of the conditions of [`Self::add_signature`] is not met.
    #[builder]
    pub fn new(
        account: PartialAccount,
        block_header: BlockHeader,
        protocol_config: ProtocolConfig,
        blockchain: PartialBlockchain,
        input_notes: InputNotes<InputNote>,
        #[builder(default)] tx_args: TransactionArgs,
        #[builder(default)] foreign_accounts: Vec<AccountInputs>,
        #[builder(default)] note_scripts: Vec<NoteScript>,
        #[builder(default)] signatures: BTreeMap<SignatureKey, Signature>,
    ) -> Result<Self, TransactionInputError> {
        Self::validate(&block_header, &protocol_config, &blockchain, &input_notes)?;

        let note_scripts = note_scripts.into_iter().map(|script| (script.root(), script)).collect();

        let mut tx_inputs = Self {
            account,
            block_header,
            protocol_config,
            blockchain,
            input_notes,
            tx_args,
            foreign_accounts: BTreeMap::new(),
            note_scripts,
            signatures,
        };
        for foreign_account in foreign_accounts {
            tx_inputs.add_foreign_account(foreign_account)?;
        }

        Ok(tx_inputs)
    }

    // VALIDATION
    // --------------------------------------------------------------------------------------------

    fn validate(
        block_header: &BlockHeader,
        protocol_config: &ProtocolConfig,
        blockchain: &PartialBlockchain,
        input_notes: &InputNotes<InputNote>,
    ) -> Result<(), TransactionInputError> {
        // Check that the protocol config is the one the block header commits to.
        let protocol_config_commitment = protocol_config.to_commitment();
        if protocol_config_commitment != block_header.protocol_config_commitment() {
            return Err(TransactionInputError::InconsistentProtocolConfig {
                expected: block_header.protocol_config_commitment(),
                actual: protocol_config_commitment,
            });
        }
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
                    block_header
                } else {
                    blockchain.get_block(note_block_num).ok_or(
                        TransactionInputError::InputNoteBlockNotInPartialBlockchain(note.id()),
                    )?
                };
                validate_is_in_block(note, proof, block_header)?;
            }
        }

        Ok(())
    }

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Replaces the input notes for the transaction.
    ///
    /// # Warning
    ///
    /// The provided notes are not validated, so the caller is responsible for making sure they are
    /// consistent with the rest of the transaction inputs.
    pub fn set_input_notes(&mut self, new_notes: InputNotes<InputNote>) {
        self.input_notes = new_notes;
    }

    /// Adds a foreign account, so that re-executing the transaction does not need to fetch it
    /// again.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The account is the native account.
    /// - The inputs already contain a foreign account with the same ID.
    pub fn add_foreign_account(
        &mut self,
        foreign_account: AccountInputs,
    ) -> Result<(), TransactionInputError> {
        let account_id = foreign_account.id();
        if account_id == self.account.id() {
            return Err(TransactionInputError::ForeignAccountIsNativeAccount(account_id));
        }

        if self.foreign_accounts.contains_key(&account_id) {
            return Err(TransactionInputError::DuplicateForeignAccount(account_id));
        }

        self.foreign_accounts.insert(account_id, foreign_account);

        Ok(())
    }

    /// Adds asset witnesses to the partial account with the given ID, so that re-executing the
    /// transaction does not need to fetch them again.
    ///
    /// The account can be the native account or one of the foreign accounts.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The inputs contain no account with the given ID.
    /// - Any of the witnesses does not fit the account's vault.
    pub fn add_asset_witnesses(
        &mut self,
        account_id: AccountId,
        witnesses: impl IntoIterator<Item = AssetWitness>,
    ) -> Result<(), TransactionInputError> {
        let to_error = |source| TransactionInputError::InvalidAssetWitness {
            account_id,
            source: Box::new(source),
        };

        if account_id == self.account.id() {
            for witness in witnesses {
                self.account.add_asset_witness(witness).map_err(to_error)?;
            }
        } else {
            let foreign_account = self
                .foreign_accounts
                .get_mut(&account_id)
                .ok_or(TransactionInputError::WitnessForUnknownAccount(account_id))?;
            for witness in witnesses {
                foreign_account.add_asset_witness(witness).map_err(to_error)?;
            }
        }

        Ok(())
    }

    /// Adds storage map witnesses to the partial account with the given ID, so that re-executing
    /// the transaction does not need to fetch them again.
    ///
    /// The account can be the native account or one of the foreign accounts.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The inputs contain no account with the given ID.
    /// - Any of the witnesses does not fit a storage map of the account.
    pub fn add_storage_map_witnesses(
        &mut self,
        account_id: AccountId,
        witnesses: impl IntoIterator<Item = StorageMapWitness>,
    ) -> Result<(), TransactionInputError> {
        let to_error = |source| TransactionInputError::InvalidStorageMapWitness {
            account_id,
            source: Box::new(source),
        };

        if account_id == self.account.id() {
            for witness in witnesses {
                self.account.add_storage_map_witness(witness).map_err(to_error)?;
            }
        } else {
            let foreign_account = self
                .foreign_accounts
                .get_mut(&account_id)
                .ok_or(TransactionInputError::WitnessForUnknownAccount(account_id))?;
            for witness in witnesses {
                foreign_account.add_storage_map_witness(witness).map_err(to_error)?;
            }
        }

        Ok(())
    }

    /// Adds a note script, so that re-executing the transaction does not need to fetch it again.
    pub fn add_note_script(&mut self, script: NoteScript) {
        self.note_scripts.insert(script.root(), script);
    }

    /// Adds a signature, so that re-executing the transaction does not need the authenticator.
    pub fn add_signature(&mut self, key: SignatureKey, signature: Signature) {
        self.signatures.insert(key, signature);
    }

    /// Updates the transaction arguments of the inputs.
    #[cfg(feature = "testing")]
    pub fn set_tx_args(&mut self, tx_args: TransactionArgs) {
        self.tx_args = tx_args;
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

    /// Returns the protocol configuration committed to by the referenced block header.
    pub fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
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

    /// Returns the commitments of the blocks the transaction authenticates, keyed by block number.
    ///
    /// These are the reference block and the blocks tracked by the partial blockchain, i.e.
    /// exactly the blocks whose commitment the transaction kernel can read.
    pub fn collect_block_commitments(&self) -> BTreeMap<BlockNumber, Word> {
        let mut commitments: BTreeMap<BlockNumber, Word> = self
            .blockchain
            .block_headers()
            .map(|header| (header.block_num(), header.commitment()))
            .collect();
        commitments.insert(self.ref_block(), self.block_header.commitment());

        commitments
    }

    /// Returns the transaction script to be executed.
    pub fn tx_script(&self) -> Option<&TransactionScript> {
        self.tx_args.tx_script()
    }

    /// Returns the foreign accounts accessed during execution, keyed by their ID.
    pub fn foreign_accounts(&self) -> &BTreeMap<AccountId, AccountInputs> {
        &self.foreign_accounts
    }

    /// Returns the output note scripts resolved during execution, keyed by their root.
    pub fn note_scripts(&self) -> &BTreeMap<NoteScriptRoot, NoteScript> {
        &self.note_scripts
    }

    /// Returns the signatures generated during execution.
    pub fn signatures(&self) -> &BTreeMap<SignatureKey, Signature> {
        &self.signatures
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
}

// HELPER FUNCTIONS
// ================================================================================================

/// Validates whether the provided note belongs to the note tree of the specified block.
fn validate_is_in_block(
    note: &Note,
    proof: &NoteInclusionProof,
    block_header: &BlockHeader,
) -> Result<(), TransactionInputError> {
    let note_index = proof.location().block_note_tree_index().into();
    let note_id = note.id().as_word();
    proof
        .note_path()
        .verify(note_index, note_id, &block_header.note_root())
        .map_err(|_| {
            TransactionInputError::InputNoteNotInBlock(note.id(), proof.location().block_num())
        })
}
