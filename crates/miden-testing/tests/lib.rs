extern crate alloc;

mod agglayer;
mod auth;
mod scripts;
mod wallet;

use miden_processor::utils::Deserializable;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::utils::Serializable;
use miden_protocol::note::{Note, NoteAssets, NoteMetadata, NoteRecipient, NoteStorage, NoteType};
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::{ExecutedTransaction, ProvenTransaction};
use miden_standards::code_builder::CodeBuilder;
use miden_tx::{
    LocalTransactionProver,
    ProvingOptions,
    TransactionVerifier,
    TransactionVerifierError,
};

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(test)]
pub fn prove_and_verify_transaction(
    executed_transaction: ExecutedTransaction,
) -> Result<(), TransactionVerifierError> {
    use miden_protocol::transaction::TransactionHeader;

    let executed_transaction_id = executed_transaction.id();
    let executed_tx_header = TransactionHeader::from(&executed_transaction);
    // Prove the transaction

    let proof_options = ProvingOptions::default();
    let prover = LocalTransactionProver::new(proof_options);
    let proven_transaction = prover.prove(executed_transaction).unwrap();
    let proven_tx_header = TransactionHeader::from(&proven_transaction);

    assert_eq!(proven_transaction.id(), executed_transaction_id);
    assert_eq!(proven_tx_header, executed_tx_header);

    // Serialize & deserialize the ProvenTransaction
    let serialised_transaction = proven_transaction.to_bytes();
    let proven_transaction = ProvenTransaction::read_from_bytes(&serialised_transaction).unwrap();

    // Verify that the generated proof is valid
    let verifier = TransactionVerifier::new(miden_protocol::MIN_PROOF_SECURITY_LEVEL);

    verifier.verify(&proven_transaction)
}

#[cfg(test)]
pub fn get_note_with_fungible_asset_and_script(
    fungible_asset: FungibleAsset,
    note_script: &str,
) -> Note {
    let note_script = CodeBuilder::default().compile_note_script(note_script).unwrap();
    let serial_num = Word::from([1, 2, 3, 4u32]);
    let sender_id = AccountId::try_from(ACCOUNT_ID_SENDER).unwrap();

    let vault = NoteAssets::new(vec![fungible_asset.into()]).unwrap();
    let metadata = NoteMetadata::new(sender_id, NoteType::Public, 1.into());
    let inputs = NoteStorage::new(vec![]).unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, inputs);

    Note::new(vault, metadata, recipient)
}
