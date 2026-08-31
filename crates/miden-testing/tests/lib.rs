extern crate alloc;

mod agglayer;
mod auth;
mod scripts;
mod standards;
mod wallet;

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::crypto::utils::Serializable;
use miden_protocol::errors::TransactionVerifierError;
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteRecipient,
    NoteStorage,
    NoteType,
    PartialNoteMetadata,
};
use miden_protocol::testing::account_id::ACCOUNT_ID_SENDER;
use miden_protocol::transaction::{ExecutedTransaction, ProvenTransaction, TransactionVerifier};
use miden_protocol::utils::serde::Deserializable;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};
use miden_tx::{LocalTransactionProver, Prover};

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(test)]
pub async fn prove_and_verify_transaction(
    executed_transaction: ExecutedTransaction,
) -> Result<(), TransactionVerifierError> {
    use miden_protocol::transaction::TransactionHeader;

    let executed_transaction_id = executed_transaction.id();
    let executed_tx_header = TransactionHeader::from(&executed_transaction);
    // Prove the transaction

    // `Prover::new()` keeps the Blake3 hash function this helper has always proven with; the
    // `LocalTransactionProver` default is Poseidon2, which is markedly slower to prove.
    let prover = LocalTransactionProver::new(Prover::new());
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

/// A proof that leaves its deferred precompile work unproven must be rejected.
///
/// The standard auth components verify signatures through precompiles, so accepting such a proof
/// would accept a transaction whose signature check was asserted but never proved. `miden-vm`
/// v0.29 rejected these inside `verify`; v0.30 reports them through the verification outcome and
/// leaves the policy to [`TransactionVerifier`], which is what this pins down.
#[tokio::test]
async fn transaction_verifier_rejects_proof_with_unproven_precompile_work() -> anyhow::Result<()> {
    use assert_matches::assert_matches;

    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::basic_ecdsa())?;
    let mock_chain = builder.build()?;

    let executed = mock_chain.build_transaction(account.id()).build()?.execute().await?;

    let prover = LocalTransactionProver::new(Prover::new());
    let deferred = prover.prove_deferred(executed)?;

    // The proof must survive a round trip: a deferred proof is a shape the wire format accepts, so
    // rejecting it is the verifier's job rather than the deserializer's.
    let deferred = ProvenTransaction::read_from_bytes(&deferred.to_bytes()).unwrap();

    let err = TransactionVerifier::new(miden_protocol::MIN_PROOF_SECURITY_LEVEL)
        .verify(&deferred)
        .unwrap_err();
    assert_matches!(err, TransactionVerifierError::IncompleteProof(_));

    Ok(())
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
    let metadata = PartialNoteMetadata::new(sender_id, NoteType::Public).with_tag(1.into());
    let inputs = NoteStorage::new(vec![]).unwrap();
    let recipient = NoteRecipient::new(serial_num, note_script, inputs);

    Note::new(vault, metadata, recipient)
}

/// Consumes a single authenticated input note against `account_id` in its own transaction and
/// commits the resulting block, so the note's effects are visible to subsequent transactions.
#[cfg(test)]
pub async fn consume_note(
    mock_chain: &mut MockChain,
    account_id: AccountId,
    note: &Note,
) -> anyhow::Result<()> {
    let executed = mock_chain
        .build_transaction(account_id)
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    Ok(())
}
