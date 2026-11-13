extern crate alloc;

mod agglayer;
mod auth;
mod oracle;
mod precompile_handling;
mod scripts;
mod standards;
mod wallet;

use std::iter;
use std::sync::Arc;

use miden_objects::prost::Message;
use miden_objects::{BuildUnchecked, DecodeMessage, proto};
use miden_processor::ExecutionError;
use miden_processor::advice::AdviceError;
use miden_protocol::account::AccountId;
use miden_protocol::asset::FungibleAsset;
use miden_protocol::batch::ProposedBatch;
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
use miden_protocol::vm::{HashFunction, PrecompileStatus, VerificationOutcome};
use miden_protocol::{MIN_PROOF_SECURITY_LEVEL, PROTOCOL_PROOF_HASH, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};
use miden_tx::{ExecutionOptions, LocalTransactionProver, Prover, TransactionProverError};
use rstest::rstest;

// HELPER FUNCTIONS
// ================================================================================================

/// Proves `executed_transaction` locally, round-trips it and verifies it.
pub async fn prove_and_verify_transaction_complete(
    executed_transaction: ExecutedTransaction,
) -> Result<(), TransactionVerifierError> {
    let (_, outcome) = prove_and_verify_transaction(executed_transaction).await?;
    assert!(outcome.is_complete());
    Ok(())
}

/// Proves `executed_transaction` locally, round-trips it and verifies it, returning the proven
/// transaction together with its verification outcome.
pub async fn prove_and_verify_transaction(
    executed_transaction: ExecutedTransaction,
) -> Result<(ProvenTransaction, VerificationOutcome), TransactionVerifierError> {
    use miden_protocol::transaction::TransactionHeader;

    let executed_transaction_id = executed_transaction.id();
    let executed_tx_header = TransactionHeader::from(&executed_transaction);
    // Prove the transaction

    // Supply a different hash to verify that the protocol wrapper selects Eidos.
    let prover = LocalTransactionProver::new(Prover::new().with_hash_fn(HashFunction::Blake3_256));
    let proven_transaction = prover.prove(executed_transaction).unwrap();
    let proven_tx_header = TransactionHeader::from(&proven_transaction);

    assert_eq!(proven_transaction.proof().vm().proof.hash_fn(), PROTOCOL_PROOF_HASH);
    assert!(matches!(proven_transaction.proof().precompile(), PrecompileStatus::Empty));

    assert_eq!(proven_transaction.id(), executed_transaction_id);
    assert_eq!(proven_tx_header, executed_tx_header);

    // Round-trip the transaction through its transport encoding.
    let encoded = proto::transaction::ProvenTransaction::from(&proven_transaction).encode_to_vec();
    let proven_transaction = proto::transaction::ProvenTransaction::decode(encoded.as_slice())
        .unwrap()
        .decode_fields()
        .unwrap()
        .build_unchecked()
        .unwrap();

    // Verify that the generated proof is valid
    let verifier = TransactionVerifier::new(miden_protocol::MIN_PROOF_SECURITY_LEVEL);

    let outcome = verifier.verify(&proven_transaction)?;
    assert!(outcome.is_complete());
    assert!(outcome.outstanding_precompile_root().is_none());

    Ok((proven_transaction, outcome))
}

/// The epilogue settles both script and authentication precompile work. Falcon and nonce-only
/// authentication exercise the empty-root path. The complete proof must also pass batch admission.
#[rstest]
#[case::ecdsa(Auth::basic_ecdsa(), false)]
#[case::falcon(Auth::basic_falcon(), false)]
#[case::no_precompiles(Auth::IncrNonce, false)]
#[case::script_precompile(Auth::IncrNonce, true)]
#[case::script_and_auth_precompiles(Auth::basic_ecdsa(), true)]
#[tokio::test]
async fn prove_and_verify_settles_precompile_claims(
    #[case] auth: Auth,
    #[case] script_precompile: bool,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(auth)?;
    let note = builder.add_p2any_note(account.id(), NoteType::Public, [])?;
    let mock_chain = builder.build()?;

    let mut transaction =
        mock_chain.build_transaction(account.id()).authenticated_input_note(note.id());
    if script_precompile {
        transaction = transaction.tx_script(CodeBuilder::default().compile_tx_script(
            "use miden::core::precompiles::u256
             @transaction_script
             pub proc main
                 exec.u256::push_one_digest
                 dupw exec.u256::add
                 exec.u256::push_two_digest
                 exec.u256::assert_eq
             end",
        )?);
    }
    let executed = transaction.build()?.execute().await?;

    let (proven_transaction, outcome) = prove_and_verify_transaction(executed).await?;
    assert!(outcome.is_complete());

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

/// Transaction proof lifecycle checks reject deferred work before attempting STARK verification.
#[tokio::test]
async fn transaction_verifier_rejects_deferred_precompile_proofs() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
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
        TransactionVerifierError::TransactionProofContainsPrecompiles
    );

    Ok(())
}

#[tokio::test]
async fn transaction_verifier_rejects_settled_precompile_proofs() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
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

/// Authentication code cannot discard precompile obligations, even when the current root is TRUE.
#[tokio::test]
async fn authentication_code_cannot_clear_precompile_work() -> anyhow::Result<()> {
    use miden_protocol::account::{AccountBuilder, AccountComponent, AccountComponentMetadata};
    use miden_standards::account::wallets::BasicWallet;

    let mut builder = MockChain::builder();
    let code = CodeBuilder::default().compile_component_code(
        "mock::clear_precompiles_auth",
        "use miden::protocol::native_account
         @auth_script
         pub proc auth
             exec.native_account::incr_nonce drop
             padw clear_deferred dropw
             dropw dropw dropw dropw
         end",
    )?;
    let component = AccountComponent::new(
        code,
        vec![],
        AccountComponentMetadata::mock("mock::clear_precompiles_auth"),
    )?;
    let account = AccountBuilder::new([42; 32])
        .with_component(component)
        .with_component(BasicWallet)
        .build_existing()?;
    builder.add_account(account.clone())?;
    let chain = builder.build()?;
    let result = chain.build_transaction(account).build()?.execute().await;
    assert_matches::assert_matches!(
        result,
        Err(miden_tx::TransactionExecutorError::TransactionProgramExecutionFailed(
            ExecutionError::OperationError {
                err: miden_processor::operation::OperationError::ClearDeferredOutsideRootContext { .. },
                ..
            }
        ))
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
pub async fn consume_note(
    mock_chain: &mut MockChain,
    account_id: AccountId,
    note: &Note,
) -> anyhow::Result<()> {
    let executed = mock_chain
        .build_transaction(account_id)
        .authenticated_input_note(note.clone())
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
