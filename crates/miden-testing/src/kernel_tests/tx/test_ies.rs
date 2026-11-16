//! Tests for encrypting to an EcGFp5 public key inside a transaction.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::ExecutionError;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::crypto::ecdh::ecgfp5::{PublicKey, SecretKey};
use miden_protocol::crypto::hash::eidos::domains::ECGFP5_PUBLIC_KEY;
use miden_protocol::crypto::ies::ecgfp5_eidos::{self, Envelope};
use miden_protocol::note::NoteType;
use miden_protocol::transaction::{ExecutedTransaction, TransactionScript};
use miden_protocol::{Felt, Hasher, WORD_SIZE, Word, ZERO};
use miden_standards::code_builder::CodeBuilder;
use miden_tx::{LocalTransactionProver, TransactionExecutorError, TransactionKernelError};
use rstest::rstest;

use crate::{Auth, MockChain, assert_transaction_executor_error};

// CONSTANTS
// ================================================================================================

const PLAINTEXT: [u32; 4] = [11, 22, 33, 44];
const CONTEXT: [u32; 4] = [5, 6, 7, 8];

const PLAINTEXT_PTR: u32 = 0;
const CONTEXT_PTR: u32 = PLAINTEXT_PTR + PLAINTEXT.len() as u32;
const ENVELOPE_PTR: u32 = CONTEXT_PTR + CONTEXT.len() as u32;
/// The envelope header has eight elements and each plaintext element encrypts to two.
const ENVELOPE_LEN: u32 = 8 + 2 * PLAINTEXT.len() as u32;
const ENVELOPE_NUM_WORDS: u32 = ENVELOPE_LEN / WORD_SIZE as u32;

const ENVELOPE_ATTACHMENT_SCHEME: u16 = 1;

// TESTS
// ================================================================================================

/// How the transaction gets the recipient public key to the host.
#[derive(Clone, Copy)]
enum RecipientKeySource {
    /// The script calls `miden::protocol::ies::seal` with the public key.
    ProtocolProcedure,
    /// The script calls the core library's `seal` with the public key commitment and the
    /// transaction arguments map the commitment to the public key in the advice map.
    TransactionArguments,
}

/// Where the plaintext is encrypted.
#[derive(Clone, Copy)]
enum SealingAccount {
    /// The transaction script of the native account encrypts.
    Native,
    /// A procedure of a foreign account encrypts and returns the envelope.
    Foreign,
}

/// Tests that a transaction encrypts to the recipient public key, and that the host records the
/// ephemeral secret it drew.
#[rstest]
#[case::protocol_procedure(RecipientKeySource::ProtocolProcedure, SealingAccount::Native)]
#[case::transaction_arguments(RecipientKeySource::TransactionArguments, SealingAccount::Native)]
#[case::foreign_account(RecipientKeySource::ProtocolProcedure, SealingAccount::Foreign)]
#[tokio::test]
async fn ies_seal_encrypts_to_recipient_public_key(
    #[case] key_source: RecipientKeySource,
    #[case] sealing_account: SealingAccount,
) -> anyhow::Result<()> {
    let recipient_secret = recipient_secret_key(1);
    let recipient = recipient_secret.public_key();

    let executed_tx = execute_sealing_transaction(recipient, key_source, sealing_account).await?;

    let plaintext =
        ecgfp5_eidos::open(&recipient_secret, &felts(CONTEXT), &envelope(&executed_tx)?)?;
    assert_eq!(plaintext, felts(PLAINTEXT));

    let secrets = executed_tx.tx_inputs().ies_seal_secrets();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].recipient(), recipient);

    Ok(())
}

/// Tests that the prover answers the `seal` request with the recorded ephemeral secret, so that
/// the proven transaction has the envelope of the executed one.
#[rstest]
#[case::native_account(SealingAccount::Native)]
#[case::foreign_account(SealingAccount::Foreign)]
#[tokio::test]
async fn prove_ies_seal_reproduces_executed_envelope(
    #[case] sealing_account: SealingAccount,
) -> anyhow::Result<()> {
    let recipient = recipient_secret_key(1).public_key();
    let executed_tx = execute_sealing_transaction(
        recipient,
        RecipientKeySource::ProtocolProcedure,
        sealing_account,
    )
    .await?;

    let proven_tx = LocalTransactionProver::default().prove(executed_tx.clone())?;

    // The transaction ID commits to the output notes, which hold the envelope.
    assert_eq!(proven_tx.id(), executed_tx.id());

    Ok(())
}

/// Tests that the host rejects a public key that is not a valid EcGFp5 point.
#[tokio::test]
async fn ies_seal_rejects_invalid_public_key() -> anyhow::Result<()> {
    // The all-zero encoding is the identity, which is not a valid public key.
    let public_key = [ZERO; 5];
    let commitment = Hasher::hash_elements_in_domain(&public_key, ECGFP5_PUBLIC_KEY);

    let tx_script = compile_tx_script(&seal_to_public_key(&public_key), None)?;
    let result = execute(tx_script, None, None).await;

    assert_transaction_executor_error!(
        result,
        matches ExecutionError::EventError { error: ref event_err, .. }
            if matches!(
                event_err.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::IesPublicKeyInvalid { commitment: actual, .. })
                    if *actual == commitment
            )
    );

    Ok(())
}

/// Tests that the host rejects a `seal` request whose public key commitment has no advice map
/// entry.
#[tokio::test]
async fn ies_seal_rejects_unknown_public_key_commitment() -> anyhow::Result<()> {
    let commitment = recipient_secret_key(1).public_key().to_commitment();

    let tx_script = compile_tx_script(&seal_to_commitment(commitment), None)?;
    let result = execute(tx_script, None, None).await;

    assert_transaction_executor_error!(
        result,
        matches ExecutionError::EventError { error: ref event_err, .. }
            if matches!(
                event_err.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::IesPublicKeyMissing(actual)) if *actual == commitment
            )
    );

    Ok(())
}

/// Tests that the host rejects an advice map entry that maps a public key commitment to a
/// different public key.
#[tokio::test]
async fn ies_seal_rejects_public_key_with_other_commitment() -> anyhow::Result<()> {
    let commitment = recipient_secret_key(1).public_key().to_commitment();
    let other_key = recipient_secret_key(2).public_key();

    let tx_script = compile_tx_script(&seal_to_commitment(commitment), None)?;
    let advice_map_entry = (commitment, other_key.to_elements().to_vec());
    let result = execute(tx_script, None, Some(advice_map_entry)).await;

    assert_transaction_executor_error!(
        result,
        matches ExecutionError::EventError { error: ref event_err, .. }
            if matches!(
                event_err.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::IesPublicKeyCommitmentMismatch { expected, actual })
                    if *expected == commitment && *actual == other_key.to_commitment()
            )
    );

    Ok(())
}

// HELPERS
// ================================================================================================

/// Executes a transaction that encrypts [`PLAINTEXT`] under [`CONTEXT`] to `recipient` and adds
/// the envelope as an attachment to an output note.
async fn execute_sealing_transaction(
    recipient: PublicKey,
    key_source: RecipientKeySource,
    sealing_account: SealingAccount,
) -> anyhow::Result<ExecutedTransaction> {
    let seal = match key_source {
        RecipientKeySource::ProtocolProcedure => seal_to_public_key(&recipient.to_elements()),
        RecipientKeySource::TransactionArguments => seal_to_commitment(recipient.to_commitment()),
    };
    let advice_map_entry = match key_source {
        RecipientKeySource::ProtocolProcedure => None,
        RecipientKeySource::TransactionArguments => {
            Some((recipient.to_commitment(), recipient.to_elements().to_vec()))
        },
    };

    let (tx_script, foreign_account) = match sealing_account {
        SealingAccount::Native => (compile_tx_script(&seal, None)?, None),
        SealingAccount::Foreign => {
            let source_manager = Arc::new(DefaultSourceManager::default());
            let foreign_component = AccountComponent::new(
                CodeBuilder::with_kernel_core_package(source_manager.clone())
                    .compile_component_code("ies_sealer", sealing_component_code(&seal))?,
                Vec::new(),
                AccountComponentMetadata::mock("ies_sealer"),
            )?;
            let foreign_account = AccountBuilder::new([3; 32])
                .with_components(Auth::IncrNonce)
                .with_component(foreign_component.clone())
                .build_existing()?;

            let code = format!(
                r#"
                padw padw padw push.0.0.0
                # => [pad(15)]

                procref.::ies_sealer::seal_envelope
                push.{prefix} push.{suffix}
                # => [foreign_account_id_suffix, foreign_account_id_prefix, FOREIGN_PROC_ROOT,
                #     pad(15)]

                exec.::miden::protocol::tx::execute_foreign_procedure
                # => [envelope(16)]

                {store_envelope}
                # => []
                "#,
                prefix = foreign_account.id().prefix().as_felt(),
                suffix = foreign_account.id().suffix(),
                store_envelope = store_envelope_from_stack(),
            );
            let tx_script = compile_tx_script(&code, Some(&foreign_component))?;
            (tx_script, Some(foreign_account))
        },
    };

    Ok(execute(tx_script, foreign_account, advice_map_entry).await?)
}

/// Executes `tx_script` against a mock account on a mock chain that also holds
/// `foreign_account`, with `advice_map_entry` in the transaction arguments.
async fn execute(
    tx_script: TransactionScript,
    foreign_account: Option<Account>,
    advice_map_entry: Option<(Word, Vec<Felt>)>,
) -> Result<ExecutedTransaction, TransactionExecutorError> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(Auth::IncrNonce).unwrap();
    if let Some(foreign_account) = &foreign_account {
        builder.add_account(foreign_account.clone()).unwrap();
    }
    let mut mock_chain = builder.build().unwrap();
    mock_chain.prove_next_block().unwrap();

    let mut tx_builder = mock_chain.build_transaction(account.id()).tx_script(tx_script);
    if let Some(foreign_account) = foreign_account {
        tx_builder = tx_builder
            .foreign_accounts([mock_chain.get_foreign_account_inputs(foreign_account).unwrap()]);
    }
    if let Some((key, values)) = advice_map_entry {
        tx_builder = tx_builder.add_advice_map_entry(key, values);
    }

    tx_builder.build().unwrap().execute().await
}

/// Compiles a transaction script that runs `sealing_code`, which leaves the envelope at
/// [`ENVELOPE_PTR`], and adds the envelope as an attachment to a new private output note.
fn compile_tx_script(
    sealing_code: &str,
    foreign_component: Option<&AccountComponent>,
) -> anyhow::Result<TransactionScript> {
    let code = format!(
        r#"
        use miden::core::sys
        use miden::protocol::output_note

        @transaction_script
        pub proc main
            {sealing_code}
            # => []

            push.{recipient}
            push.{note_type}
            push.0
            call.::mock::account::create_note
            # => [note_idx, pad(15)]

            push.{ENVELOPE_PTR} push.{ENVELOPE_NUM_WORDS} push.{ENVELOPE_ATTACHMENT_SCHEME}
            # => [attachment_scheme, num_words, attachment_ptr, note_idx, pad(15)]

            exec.output_note::add_attachment_from_memory
            # => [pad(15)]

            exec.sys::truncate_stack
            # => [pad(16)]
        end
        "#,
        recipient = Word::from([1, 2, 3, 4u32]),
        note_type = NoteType::Private.as_u8(),
    );

    let mut code_builder = CodeBuilder::with_mock_packages();
    if let Some(foreign_component) = foreign_component {
        code_builder =
            code_builder.with_dynamically_linked_package(foreign_component.component_code())?;
    }

    code_builder
        .compile_tx_script(code)
        .context("failed to compile transaction script")
}

/// Returns the code of an account component whose `seal_envelope` procedure runs `sealing_code`
/// and returns the envelope.
fn sealing_component_code(sealing_code: &str) -> String {
    let load_envelope = (0..ENVELOPE_NUM_WORDS)
        .rev()
        .map(|word_idx| {
            format!("padw push.{} mem_loadw_le", ENVELOPE_PTR + word_idx * WORD_SIZE as u32)
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"
        use miden::core::sys

        @account_procedure
        pub proc seal_envelope
            {sealing_code}
            # => [pad(16)]

            {load_envelope}
            # => [envelope(16), pad(16)]

            exec.sys::truncate_stack
            # => [envelope(16)]
        end
        "#
    )
}

/// Returns MASM that stores the 16-element envelope on top of the stack at [`ENVELOPE_PTR`].
fn store_envelope_from_stack() -> String {
    (0..ENVELOPE_NUM_WORDS)
        .map(|word_idx| {
            format!("push.{} mem_storew_le dropw", ENVELOPE_PTR + word_idx * WORD_SIZE as u32)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Returns MASM that encrypts [`PLAINTEXT`] under [`CONTEXT`] to `public_key` with
/// `miden::protocol::ies::seal`.
fn seal_to_public_key(public_key: &[Felt; 5]) -> String {
    format!(
        "{}\n{}\nexec.::miden::protocol::ies::seal",
        store_inputs(),
        push_reversed(public_key)
    )
}

/// Returns MASM that encrypts [`PLAINTEXT`] under [`CONTEXT`] to the public key with `commitment`
/// with the core library's `seal`.
fn seal_to_commitment(commitment: Word) -> String {
    format!(
        "{}\n{}\nexec.::miden::core::crypto::ies::ecgfp5_eidos::seal",
        store_inputs(),
        push_reversed(commitment.as_elements())
    )
}

/// Returns MASM that writes [`PLAINTEXT`] and [`CONTEXT`] to memory and pushes the remaining
/// `seal` arguments.
fn store_inputs() -> String {
    let store = |ptr: u32, values: [u32; 4]| {
        values
            .iter()
            .enumerate()
            .map(|(idx, value)| format!("push.{value} push.{} mem_store", ptr + idx as u32))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        "{}\n{}\npush.{ENVELOPE_PTR} push.{} push.{CONTEXT_PTR} push.{} push.{PLAINTEXT_PTR}",
        store(PLAINTEXT_PTR, PLAINTEXT),
        store(CONTEXT_PTR, CONTEXT),
        CONTEXT.len(),
        PLAINTEXT.len(),
    )
}

/// Returns MASM that pushes `elements` so that the first one is on top of the stack.
fn push_reversed(elements: &[Felt]) -> String {
    elements
        .iter()
        .rev()
        .map(|element| format!("push.{element}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Returns the envelope attached to the first output note of the transaction.
fn envelope(executed_tx: &ExecutedTransaction) -> anyhow::Result<Envelope> {
    let attachment = executed_tx
        .output_notes()
        .get_note(0)
        .attachments()
        .get(0)
        .context("output note should have the envelope attachment")?;

    Ok(Envelope::from_elements(attachment.as_elements())?)
}

fn recipient_secret_key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 40]).expect("bytes should encode a valid secret key")
}

fn felts(values: [u32; 4]) -> Vec<Felt> {
    values.map(Felt::from).to_vec()
}
