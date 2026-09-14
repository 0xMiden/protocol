extern crate alloc;

mod agglayer;
mod auth;
mod scripts;
mod standards;
mod wallet;

use std::iter;
use std::sync::Arc;

use miden_processor::ExecutionError;
use miden_processor::advice::AdviceError;
use miden_protocol::MIN_PROOF_SECURITY_LEVEL;
#[cfg(test)]
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::batch::ProposedBatch;
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
#[cfg(test)]
use miden_protocol::vm::VerificationOutcome;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};
use miden_tx::{ExecutionOptions, LocalTransactionProver, Prover, TransactionProverError};
use rstest::rstest;

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(test)]
pub async fn prove_and_verify_transaction_deferred(
    executed_transaction: ExecutedTransaction,
) -> Result<(), TransactionVerifierError> {
    let (_, outcome) = prove_and_verify_transaction(executed_transaction).await?;
    assert!(!outcome.is_complete());
    Ok(())
}

/// Proves `executed_transaction` locally, round-trips it and verifies it.
#[cfg(test)]
pub async fn prove_and_verify_transaction_complete(
    executed_transaction: ExecutedTransaction,
) -> Result<(), TransactionVerifierError> {
    let (_, outcome) = prove_and_verify_transaction(executed_transaction).await?;
    assert!(outcome.is_complete());
    Ok(())
}

/// Proves `executed_transaction` locally, round-trips it and verifies it, returning the proven
/// transaction together with its verification outcome.
#[cfg(test)]
pub async fn prove_and_verify_transaction(
    executed_transaction: ExecutedTransaction,
) -> Result<(ProvenTransaction, VerificationOutcome), TransactionVerifierError> {
    use miden_protocol::transaction::TransactionHeader;

    let executed_transaction_id = executed_transaction.id();
    let executed_tx_header = TransactionHeader::from(&executed_transaction);
    // Prove the transaction

    let prover = LocalTransactionProver::new(Prover::default());
    let proven_transaction = prover.prove(executed_transaction).unwrap();
    let proven_tx_header = TransactionHeader::from(&proven_transaction);

    assert_eq!(proven_transaction.id(), executed_transaction_id);
    assert_eq!(proven_tx_header, executed_tx_header);

    // Serialize & deserialize the ProvenTransaction
    let serialised_transaction = proven_transaction.to_bytes();
    let proven_transaction = ProvenTransaction::read_from_bytes(&serialised_transaction).unwrap();

    // Verify that the generated proof is valid
    let verifier = TransactionVerifier::new(miden_protocol::MIN_PROOF_SECURITY_LEVEL);

    let outcome = verifier.verify(&proven_transaction)?;

    Ok((proven_transaction, outcome))
}

/// The local prover leaves precompile claims for the batch prover, so a transaction that
/// authenticates with ECDSA verifies while its precompile obligation is still outstanding. Falcon
/// is the control: it verifies in-circuit and uses no precompile, so its proof is complete.
///
/// Both must also pass `ProposedBatch::new`, which verifies the proof of every transaction it
/// batches.
#[rstest]
#[case::ecdsa(Auth::basic_ecdsa(), false)]
#[case::falcon(Auth::basic_falcon(), true)]
#[tokio::test]
async fn prove_and_verify_defers_precompile_claims(
    #[case] auth: Auth,
    #[case] is_complete: bool,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(auth)?;
    let note = builder.add_p2any_note(account.id(), NoteType::Public, [])?;
    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;

    let (proven_transaction, outcome) = prove_and_verify_transaction(executed).await?;
    assert_eq!(outcome.is_complete(), is_complete);

    let transactions = vec![Arc::new(proven_transaction)];
    let (batch_reference_block, partial_blockchain, unauthenticated_note_proofs) = mock_chain
        .get_batch_inputs(transactions.iter().map(|tx| tx.ref_block_num()), iter::empty())?;

    let batch = ProposedBatch::new(
        transactions,
        batch_reference_block,
        partial_blockchain,
        unauthenticated_note_proofs,
        MIN_PROOF_SECURITY_LEVEL,
    )?;
    assert_eq!(batch.transactions().len(), 1);

    Ok(())
}

/// Deferred transaction proofs are validated by the VM verifier rather than rejected by their
/// lifecycle state alone.
#[tokio::test]
async fn transaction_verifier_delegates_deferred_proof_validation() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::basic_ecdsa())?;
    let note = builder.add_p2any_note(account.id(), NoteType::Public, [])?;
    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;
    let proven = LocalTransactionProver::default().prove_dummy_deferred(executed)?;

    let err = TransactionVerifier::new(0).verify(&proven).unwrap_err();
    assert_matches::assert_matches!(
        err,
        TransactionVerifierError::TransactionVerificationFailed(_)
    );

    Ok(())
}

#[tokio::test]
async fn transaction_verifier_rejects_settled_precompile_proofs() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::basic_ecdsa())?;
    let note = builder.add_p2any_note(account.id(), NoteType::Public, [])?;
    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;
    let proven = LocalTransactionProver::default().prove_dummy_precompile(executed)?;

    let error = TransactionVerifier::new(0).verify(&proven).unwrap_err();
    assert_matches::assert_matches!(
        error,
        TransactionVerifierError::TransactionProofContainsPrecompiles
    );

    Ok(())
}

/// The prover's [`ExecutionOptions`] reach the VM: an advice size limit far below what the kernel
/// needs makes proving fail while the initial advice inputs are loaded.
#[tokio::test]
async fn custom_execution_options_reach_the_vm() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::basic_ecdsa())?;
    let note = builder.add_p2any_note(account.id(), NoteType::Public, [])?;
    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await?;

    let prover = LocalTransactionProver::default()
        .with_execution_options(ExecutionOptions::default().with_max_advice_size_bytes(1));

    let error = prover.prove(executed).unwrap_err();
    assert_matches::assert_matches!(
        error,
        TransactionProverError::TransactionProgramExecutionFailed(ExecutionError::AdviceError {
            err: AdviceError::SizeBudgetExceeded { .. },
            ..
        })
    );

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

/// Rebuilds `note` as a private note, keeping its script, storage, assets and attachments.
///
/// The typed note builders of the standard config notes fix the note type to
/// [`NoteType::Public`], so this is how a sender would hand-craft a private note that is
/// otherwise indistinguishable from a legitimate config note.
#[cfg(test)]
pub fn into_private_note(note: Note) -> Note {
    let metadata = PartialNoteMetadata::new(note.metadata().sender(), NoteType::Private)
        .with_tag(note.metadata().tag());

    Note::with_attachments(
        note.assets().clone(),
        metadata,
        note.recipient().clone(),
        note.attachments().clone(),
    )
}
