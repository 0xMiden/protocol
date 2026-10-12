use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt::Debug;

use miden_crypto::merkle::NodeIndex;
use miden_crypto::merkle::smt::{SmtLeaf, SmtProof};

use super::PartialBlockchain;
use crate::Word;
use crate::account::auth::{Signature, SignatureKey};
use crate::account::{AccountId, PartialAccount, StorageMapKey, StorageMapWitness};
use crate::asset::{Asset, AssetId, AssetWitness};
use crate::block::{BlockHeader, BlockNumber};
use crate::crypto::merkle::SparseMerklePath;
use crate::errors::{TransactionInputError, TransactionInputsExtractionError};
use crate::note::{Note, NoteInclusionProof, NoteScript, NoteScriptRoot};
use crate::protocol_config::ProtocolConfig;
use crate::transaction::{TransactionArgs, TransactionScript};

#[cfg(test)]
mod tests;

mod account;
pub use account::AccountInputs;

mod notes;
pub use notes::{InputNote, InputNotes, ToInputNoteCommitments};

use crate::vm::AdviceInputs;

// TRANSACTION INPUTS
// ================================================================================================

/// Contains the data required to execute a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionInputs {
    account: PartialAccount,
    block_header: BlockHeader,
    /// The chain's protocol configuration, which `block_header` only commits to.
    protocol_config: ProtocolConfig,
    blockchain: PartialBlockchain,
    input_notes: InputNotes<InputNote>,
    tx_args: TransactionArgs,
    advice_inputs: AdviceInputs,
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
        #[builder(default)] advice_inputs: AdviceInputs,
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
            advice_inputs,
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

    /// Replaces the transaction inputs and assigns the given asset witnesses.
    pub fn with_asset_witnesses(mut self, witnesses: Vec<AssetWitness>) -> Self {
        for witness in witnesses {
            let leaf = witness.proof().leaf();
            let witness_inputs = AdviceInputs::default()
                .with_merkle_store(witness.authenticated_nodes().collect())
                .with_map([(leaf.hash(), leaf.to_elements().collect())]);
            self.advice_inputs.extend(witness_inputs);
        }

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
    ///
    /// # Warning
    ///
    /// The provided notes are not validated, so the caller is responsible for making sure they are
    /// consistent with the rest of the transaction inputs.
    pub fn set_input_notes(&mut self, new_notes: InputNotes<InputNote>) {
        self.input_notes = new_notes;
    }

    /// Replaces the advice inputs for the transaction.
    ///
    /// Note: the advice stack from the provided advice inputs is discarded.
    pub fn set_advice_inputs(&mut self, new_advice_inputs: AdviceInputs) {
        let (_stack, map, store) = new_advice_inputs.into_parts();
        self.advice_inputs = AdviceInputs::from(map).with_merkle_store(store);
        self.tx_args.extend_advice_inputs(self.advice_inputs.clone());
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

    /// Returns the advice inputs to be consumed in the transaction.
    pub fn advice_inputs(&self) -> &AdviceInputs {
        &self.advice_inputs
    }

    /// Returns the transaction arguments to be consumed in the transaction.
    pub fn tx_args(&self) -> &TransactionArgs {
        &self.tx_args
    }

    // DATA EXTRACTORS
    // --------------------------------------------------------------------------------------------

    /// Reads the storage map witness for the given account and map key.
    pub fn read_storage_map_witness(
        &self,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> Result<StorageMapWitness, TransactionInputsExtractionError> {
        // Convert map key into the index at which the key-value pair for this key is stored
        let leaf_index = map_key.hash().to_leaf_index();

        // Construct sparse Merkle path.
        let merkle_path = self.advice_inputs.store().get_path(map_root, leaf_index.into())?;
        let sparse_path = SparseMerklePath::from_sized_iter(merkle_path.path)?;

        // Construct SMT leaf.
        let merkle_node = self.advice_inputs.store().get_node(map_root, leaf_index.into())?;
        let smt_leaf_elements = self
            .advice_inputs
            .map()
            .get(&merkle_node)
            .ok_or(TransactionInputsExtractionError::MissingVaultRoot)?;
        let smt_leaf = SmtLeaf::try_from_elements(smt_leaf_elements, leaf_index)?;

        // Construct SMT proof and witness.
        let smt_proof = SmtProof::new(sparse_path, smt_leaf)?;
        let storage_witness = StorageMapWitness::new(smt_proof, [map_key])?;

        Ok(storage_witness)
    }

    /// Reads the vault asset witnesses for the given account and asset IDs.
    ///
    /// # Errors
    /// Returns an error if:
    /// - A Merkle tree with the specified root is not present in the advice data of these inputs.
    /// - Witnesses for any of the requested assets are not in the specified Merkle tree.
    /// - Construction of the Merkle path or the leaf node for the witness fails.
    pub fn read_vault_asset_witnesses(
        &self,
        vault_root: Word,
        asset_ids: BTreeSet<AssetId>,
    ) -> Result<Vec<AssetWitness>, TransactionInputsExtractionError> {
        let mut asset_witnesses = Vec::new();
        for asset_id in asset_ids {
            let smt_index = asset_id.hash().to_leaf_index();
            // Construct sparse Merkle path.
            let merkle_path = self.advice_inputs.store().get_path(vault_root, smt_index.into())?;
            let sparse_path = SparseMerklePath::from_sized_iter(merkle_path.path)?;

            // Construct SMT leaf.
            let merkle_node = self.advice_inputs.store().get_node(vault_root, smt_index.into())?;
            let smt_leaf_elements = self
                .advice_inputs
                .map()
                .get(&merkle_node)
                .ok_or(TransactionInputsExtractionError::MissingVaultRoot)?;
            let smt_leaf = SmtLeaf::try_from_elements(smt_leaf_elements, smt_index)?;

            // Construct SMT proof and witness.
            let smt_proof = SmtProof::new(sparse_path, smt_leaf)?;
            let asset_witness = AssetWitness::new(smt_proof, [asset_id])?;
            asset_witnesses.push(asset_witness);
        }
        Ok(asset_witnesses)
    }

    /// Returns true if the witness for the specified asset ID is present in these inputs.
    ///
    /// Note that this does not verify the witness' validity (i.e., that the witness is for a valid
    /// asset).
    pub fn has_vault_asset_witness(&self, vault_root: Word, asset_id: &AssetId) -> bool {
        let smt_index: NodeIndex = asset_id.hash().to_leaf_index().into();

        // make sure the path is in the Merkle store
        if !self.advice_inputs.store().has_path(vault_root, smt_index) {
            return false;
        }

        // make sure the node pre-image is in the Merkle store
        match self.advice_inputs.store().get_node(vault_root, smt_index) {
            Ok(node) => self.advice_inputs.map().contains_key(&node),
            Err(_) => false,
        }
    }

    /// Reads the asset stored under `asset_id` in the vault with the specified root.
    ///
    /// Returns `Ok(None)` when the key's leaf is tracked but holds no asset.
    ///
    /// # Errors
    /// Returns an error if:
    /// - A Merkle tree with the specified root, or the key's Merkle path, is not present in the
    ///   advice data of these inputs.
    /// - Construction of the leaf node or the asset fails.
    pub fn read_vault_asset(
        &self,
        vault_root: Word,
        asset_id: AssetId,
    ) -> Result<Option<Asset>, TransactionInputsExtractionError> {
        let witnesses =
            self.read_vault_asset_witnesses(vault_root, BTreeSet::from_iter([asset_id]))?;
        let witness = witnesses
            .into_iter()
            .next()
            .expect("one key requested should yield exactly one witness");
        Ok(witness.find(asset_id))
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
