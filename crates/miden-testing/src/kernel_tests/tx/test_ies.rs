//! Tests for encrypting to an EcGFp5 public key inside a transaction.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::ExecutionError;
use miden_processor::advice::AdviceError;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::crypto::ecdh::ecgfp5::{PublicKey, SecretKey};
use miden_protocol::crypto::hash::eidos::domains::ECGFP5_PUBLIC_KEY;
use miden_protocol::crypto::ies::ecgfp5_eidos::{self, Envelope};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::{
    ExecutedTransaction,
    IesSealSecret,
    TransactionInputs,
    TransactionScript,
    TransactionWitness,
};
use miden_protocol::{Felt, Hasher, WORD_SIZE, Word, ZERO};
use miden_standards::account::auth::{Approver, ApproverSet, MultisigAuthArgs};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::auth::{
    BasicAuthenticator,
    SigningInputs,
    TransactionAuthenticator,
    UnreachableAuth,
};
use miden_tx::{
    LocalTransactionProver,
    NoteConsumptionChecker,
    TransactionExecutor,
    TransactionExecutorError,
    TransactionKernelError,
    TransactionProverError,
};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rstest::rstest;

use super::ExecutionOutputExt;
use crate::{
    Auth,
    MockChain,
    MockChainBuilder,
    TestTransactionBuilder,
    assert_transaction_executor_error,
};

// CONSTANTS
// ================================================================================================

const PLAINTEXT: [u32; 4] = [11, 22, 33, 44];
const CONTEXT: [u32; 4] = [5, 6, 7, 8];

const PLAINTEXT_PTR: u32 = 0;
const CONTEXT_PTR: u32 = PLAINTEXT_PTR + PLAINTEXT.len() as u32;
/// The memory address of the first envelope. The envelopes follow each other.
const ENVELOPES_PTR: u32 = CONTEXT_PTR + CONTEXT.len() as u32;
/// The envelope header has eight elements and each plaintext element encrypts to two.
const ENVELOPE_LEN: u32 = 8 + 2 * PLAINTEXT.len() as u32;
const ENVELOPE_NUM_WORDS: u32 = ENVELOPE_LEN / WORD_SIZE as u32;

/// The attachment scheme of the first envelope. The schemes of the next envelopes follow it.
const ENVELOPE_ATTACHMENT_SCHEME: u16 = 1;

// TESTS
// ================================================================================================

/// How the transaction gets the recipient public key to the host.
#[derive(Clone, Copy)]
pub(super) enum RecipientKeySource {
    /// The script calls `miden::protocol::ies::seal` with the public key.
    ProtocolProcedure,
    /// The script calls the core library's `seal` with the public key commitment and the
    /// transaction arguments map the commitment to the public key in the advice map.
    TransactionArguments,
}

/// Where the plaintext is encrypted.
#[derive(Clone, Copy)]
pub(super) enum SealingAccount {
    /// The transaction script of the native account encrypts.
    Native,
    /// A procedure of a foreign account encrypts and returns the envelope.
    Foreign,
}

/// Tests that a transaction encrypts to the recipient public key, that the host records the
/// ephemeral secret it drew, and that proving with the recorded secret reproduces the envelope.
#[rstest]
#[case::protocol_procedure(RecipientKeySource::ProtocolProcedure, SealingAccount::Native)]
#[case::transaction_arguments(RecipientKeySource::TransactionArguments, SealingAccount::Native)]
#[case::foreign_account(RecipientKeySource::ProtocolProcedure, SealingAccount::Foreign)]
#[tokio::test]
async fn ies_seal_encrypts_to_recipient_public_key(
    #[case] key_source: RecipientKeySource,
    #[case] sealing_account: SealingAccount,
) -> anyhow::Result<()> {
    let recipient_secret = secret_key(1);
    let recipient = recipient_secret.public_key();

    let executed_tx =
        execute_sealing_transaction(&[recipient], key_source, sealing_account).await?;

    let plaintext =
        ecgfp5_eidos::open(&recipient_secret, &felts(CONTEXT), &envelope(&executed_tx, 0)?)?;
    assert_eq!(plaintext, felts(PLAINTEXT));

    let secrets = executed_tx.tx_inputs().ies_seal_secrets();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].recipient(), recipient);

    let proven_tx = LocalTransactionProver::default().prove(executed_tx.clone())?;

    // The transaction ID commits to the output notes, which hold the envelope.
    assert_eq!(proven_tx.id(), executed_tx.id());

    Ok(())
}

/// Tests that a transaction sealing twice draws and records a fresh secret per request, and that
/// proving uses them in the same order.
#[rstest]
#[case::different_recipients([1, 2])]
#[case::same_recipient([1, 1])]
#[tokio::test]
async fn prove_ies_seals_replay_secrets_in_request_order(
    #[case] recipient_seeds: [u8; 2],
) -> anyhow::Result<()> {
    let recipient_secrets = recipient_seeds.map(secret_key);
    let recipients = recipient_secrets.each_ref().map(SecretKey::public_key);

    let executed_tx = execute_sealing_transaction(
        &recipients,
        RecipientKeySource::ProtocolProcedure,
        SealingAccount::Native,
    )
    .await?;

    let recorded_recipients = executed_tx
        .tx_inputs()
        .ies_seal_secrets()
        .iter()
        .map(IesSealSecret::recipient)
        .collect::<Vec<_>>();
    assert_eq!(recorded_recipients, recipients);

    let ephemeral_keys = executed_tx
        .tx_inputs()
        .ies_seal_secrets()
        .iter()
        .map(|secret| secret.ephemeral_secret().public_key())
        .collect::<Vec<_>>();
    assert_ne!(ephemeral_keys[0], ephemeral_keys[1], "each request should draw a fresh secret");

    let envelopes = [envelope(&executed_tx, 0)?, envelope(&executed_tx, 1)?];
    for (recipient_secret, envelope) in recipient_secrets.iter().zip(&envelopes) {
        let plaintext = ecgfp5_eidos::open(recipient_secret, &felts(CONTEXT), envelope)?;
        assert_eq!(plaintext, felts(PLAINTEXT));
    }

    let proven_tx = LocalTransactionProver::default().prove(executed_tx.clone())?;
    assert_eq!(proven_tx.id(), executed_tx.id());

    Ok(())
}

/// Tests that the host uses the supplied secrets before drawing fresh ones, and that proving uses
/// them in the same order.
#[tokio::test]
async fn prove_ies_seal_uses_supplied_secrets_before_drawn_ones() -> anyhow::Result<()> {
    let recipients = [secret_key(1).public_key(), secret_key(2).public_key()];
    let supplied_secret = IesSealSecret::new(recipients[0], secret_key(9));

    let tx_script = compile_tx_script(
        &sealing_code(&recipients, RecipientKeySource::ProtocolProcedure),
        2,
        None,
    )?;
    let executed_tx =
        execute(&mock_account(), None, tx_script, Vec::new(), vec![supplied_secret.clone()])
            .await?;

    // The first envelope carries the ephemeral key of the supplied secret.
    assert_eq!(executed_tx.tx_inputs().tx_args().ies_seal_secrets(), [supplied_secret]);
    assert_eq!(envelope(&executed_tx, 0)?.ephemeral_key(), secret_key(9).public_key());

    // The second envelope carries the ephemeral key of the only recorded secret, which the host
    // drew.
    let recorded_secrets = executed_tx.tx_inputs().ies_seal_secrets();
    assert_eq!(recorded_secrets.len(), 1);
    assert_eq!(recorded_secrets[0].recipient(), recipients[1]);
    assert_eq!(
        envelope(&executed_tx, 1)?.ephemeral_key(),
        recorded_secrets[0].ephemeral_secret().public_key()
    );

    let proven_tx = LocalTransactionProver::default().prove(executed_tx.clone())?;
    assert_eq!(proven_tx.id(), executed_tx.id());

    Ok(())
}

/// Tests that proving fails with a specific error when the recorded secrets do not match the
/// `seal` requests of the transaction.
#[tokio::test]
async fn prove_ies_seal_rejects_inconsistent_recorded_secrets() -> anyhow::Result<()> {
    let recipients = [secret_key(1).public_key(), secret_key(2).public_key()];
    let executed_tx = execute_sealing_transaction(
        &recipients,
        RecipientKeySource::ProtocolProcedure,
        SealingAccount::Native,
    )
    .await?;
    let secrets = executed_tx.tx_inputs().ies_seal_secrets().to_vec();

    let prove_with = |secrets: Vec<IesSealSecret>| -> anyhow::Result<TransactionProverError> {
        let witness = witness_with_recorded_secrets(executed_tx.clone(), secrets)?;
        Ok(LocalTransactionProver::default()
            .prove(witness)
            .expect_err("proving should reject the changed secrets"))
    };

    // Dropping the secret of the second request leaves that request without one.
    let error = prove_with(secrets[..1].to_vec())?;
    assert!(
        matches!(prover_kernel_error(&error), Some(TransactionKernelError::IesSealSecretMissing)),
        "expected IesSealSecretMissing, got: {error}"
    );

    // Swapping the secrets gives the first request the secret of the second recipient.
    let error = prove_with(secrets.iter().rev().cloned().collect())?;
    assert!(
        matches!(
            prover_kernel_error(&error),
            Some(TransactionKernelError::IesSealSecretRecipientMismatch { supplied, requested })
                if *supplied == recipients[1].to_commitment()
                    && *requested == recipients[0].to_commitment()
        ),
        "expected IesSealSecretRecipientMismatch, got: {error}"
    );

    // Appending a secret that no request uses leaves it unused.
    let mut extended_secrets = secrets;
    extended_secrets.push(IesSealSecret::new(recipients[0], secret_key(9)));
    let error = prove_with(extended_secrets)?;
    assert!(
        matches!(error, TransactionProverError::UnusedIesSealSecrets(1)),
        "expected UnusedIesSealSecrets(1), got: {error}"
    );

    Ok(())
}

/// Tests that proving with a different secret for the same recipient yields a different
/// transaction ID, so that comparing IDs detects an envelope that proving did not reproduce.
#[tokio::test]
async fn prove_ies_seal_with_other_secret_changes_transaction_id() -> anyhow::Result<()> {
    let recipient = secret_key(1).public_key();
    let executed_tx = execute_sealing_transaction(
        &[recipient],
        RecipientKeySource::ProtocolProcedure,
        SealingAccount::Native,
    )
    .await?;
    let executed_tx_id = executed_tx.id();

    let other_secret = IesSealSecret::new(recipient, secret_key(9));
    let witness = witness_with_recorded_secrets(executed_tx, vec![other_secret])?;
    let proven_tx = LocalTransactionProver::default().prove(witness)?;

    assert_ne!(proven_tx.id(), executed_tx_id);

    Ok(())
}

/// Tests that the secrets an unauthorized execution returns let the signed execution of a
/// two-pass authentication flow reproduce the summary the signers approved, and that an
/// unauthorized execution with unused supplied secrets returns no summary to sign.
#[tokio::test]
async fn signed_execution_with_returned_secrets_reproduces_unauthorized_summary()
-> anyhow::Result<()> {
    use miden_protocol::crypto::SequentialCommit;

    let recipient = secret_key(1).public_key();
    let signer =
        AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut ChaCha20Rng::from_seed([7; 32]));
    let signer_commitment = signer.public_key().to_commitment();
    let approver_set =
        ApproverSet::new(vec![Approver::new(signer_commitment, AuthScheme::EcdsaK256Keccak)], 1)?;
    let account = AccountBuilder::new([42; 32])
        .with_components(Auth::Multisig {
            approver_set,
            proc_threshold_map: Vec::new(),
        })
        .with_component(MockAccountComponent::with_empty_slots())
        .build_existing()?;
    let tx_script = compile_tx_script(
        &sealing_code(&[recipient], RecipientKeySource::ProtocolProcedure),
        1,
        None,
    )?;
    let mut mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    mock_chain.prove_next_block()?;

    let auth_args = MultisigAuthArgs::new(
        mock_chain.latest_block_header().block_num(),
        Word::from([1, 2, 3, 4u32]),
    );
    let tx_builder = |ies_seal_secrets: Vec<IesSealSecret>| {
        let mut tx_builder = mock_chain
            .build_transaction(account.clone())
            .tx_script(tx_script.clone())
            .auth_args(auth_args.to_commitment())
            .add_advice_map_entry(auth_args.to_commitment(), auth_args.to_elements())
            .required_block(auth_args.bound_block_num());
        for secret in ies_seal_secrets {
            tx_builder = tx_builder.add_ies_seal_secret(secret);
        }
        tx_builder
    };
    let execute_unauthorized = async |ies_seal_secrets: Vec<IesSealSecret>| {
        let result = tx_builder(ies_seal_secrets).build()?.execute().await;
        match result {
            Err(TransactionExecutorError::Unauthorized { tx_summary, ies_seal_secrets }) => {
                Ok((tx_summary, ies_seal_secrets))
            },
            other => Err(anyhow::anyhow!("expected an unauthorized execution, got {other:?}")),
        }
    };

    let (tx_summary, drawn_secrets) = execute_unauthorized(Vec::new()).await?;
    assert_eq!(drawn_secrets.len(), 1);

    // The signature over the summary verifies only if the signed execution reproduces it.
    let msg = tx_summary.to_commitment();
    let signature = BasicAuthenticator::new(&[signer])
        .get_signature(signer_commitment, &SigningInputs::TransactionSummary(tx_summary.clone()))
        .await?;
    let executed_tx = tx_builder(drawn_secrets)
        .add_signature(signer_commitment, msg, signature)
        .build()?
        .execute()
        .await?;
    assert_eq!(executed_tx.output_notes().commitment(), tx_summary.output_notes().commitment());
    assert!(executed_tx.tx_inputs().ies_seal_secrets().is_empty());

    // Without the drawn secrets, a fresh secret changes the envelope and thereby the summary.
    let (fresh_summary, _) = execute_unauthorized(Vec::new()).await?;
    assert_ne!(fresh_summary.to_commitment(), msg);

    // A surplus supplied secret fails the unsigned execution instead of yielding a summary.
    let surplus_secrets = vec![
        IesSealSecret::new(recipient, secret_key(9)),
        IesSealSecret::new(recipient, secret_key(8)),
    ];
    let result = tx_builder(surplus_secrets).build()?.execute().await;
    assert!(
        matches!(result, Err(TransactionExecutorError::UnusedIesSealSecrets(1))),
        "expected UnusedIesSealSecrets(1), got: {result:?}"
    );

    Ok(())
}

/// How a test supplies secrets that do not match the `seal` request of a transaction.
enum InconsistentSuppliedSecrets {
    /// Supplies a secret for another recipient.
    OtherRecipient,
    /// Supplies a second secret that no request uses.
    Unused,
}

/// Tests that the executor rejects supplied secrets that do not match the `seal` requests of the
/// transaction.
#[rstest]
#[case::other_recipient(InconsistentSuppliedSecrets::OtherRecipient)]
#[case::unused(InconsistentSuppliedSecrets::Unused)]
#[tokio::test]
async fn ies_seal_rejects_inconsistent_supplied_secrets(
    #[case] supplied: InconsistentSuppliedSecrets,
) -> anyhow::Result<()> {
    let recipient = secret_key(1).public_key();
    let other_recipient = secret_key(2).public_key();
    let secrets = match supplied {
        InconsistentSuppliedSecrets::OtherRecipient => {
            vec![IesSealSecret::new(other_recipient, secret_key(9))]
        },
        InconsistentSuppliedSecrets::Unused => vec![
            IesSealSecret::new(recipient, secret_key(9)),
            IesSealSecret::new(recipient, secret_key(8)),
        ],
    };

    let tx_script = compile_tx_script(
        &sealing_code(&[recipient], RecipientKeySource::ProtocolProcedure),
        1,
        None,
    )?;
    let result = execute(&mock_account(), None, tx_script, Vec::new(), secrets).await;

    match supplied {
        InconsistentSuppliedSecrets::OtherRecipient => assert_transaction_executor_error!(
            result,
            matches ExecutionError::EventError { error: ref event_err, .. }
                if matches!(
                    event_err.downcast_ref::<TransactionKernelError>(),
                    Some(TransactionKernelError::IesSealSecretRecipientMismatch {
                        supplied,
                        requested,
                    }) if *supplied == other_recipient.to_commitment()
                        && *requested == recipient.to_commitment()
                )
        ),
        InconsistentSuppliedSecrets::Unused => assert!(
            matches!(result, Err(TransactionExecutorError::UnusedIesSealSecrets(1))),
            "unexpected result: {result:?}"
        ),
    }

    Ok(())
}

/// Tests that the notes checker draws fresh secrets in every run, so that a note sealing after an
/// eliminated note does not get the secret the eliminated note drew.
#[tokio::test]
async fn notes_checker_draws_fresh_secrets_after_eliminating_a_note() -> anyhow::Result<()> {
    let sender = AccountId::try_from(ACCOUNT_ID_SENDER)?;
    let sealing_note = |recipient_seed: u8, after_sealing: &str| {
        let sealing_code = sealing_code(
            &[secret_key(recipient_seed).public_key()],
            RecipientKeySource::ProtocolProcedure,
        );
        NoteBuilder::new(sender, ChaCha20Rng::from_seed([recipient_seed; 32]))
            .code(format!("@note_script pub proc main {sealing_code} {after_sealing} end"))
            .build()
    };
    // The failing note seals first, so that replaying its secret in the next run would give it to
    // the other note.
    let failing_note = sealing_note(1, "push.1 drop push.0 div")?;
    let succeeding_note = sealing_note(2, "")?;

    let mut builder = MockChain::builder();
    let account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let mock_chain = builder.build()?;
    let notes = vec![failing_note.clone(), succeeding_note.clone()];
    let mock_tx = mock_chain
        .build_transaction(account)
        .unauthenticated_input_notes(notes.clone())
        .build()?;

    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&mock_tx);
    let consumption_info = NoteConsumptionChecker::new(&executor)
        .check_notes_consumability(
            mock_tx.account().id(),
            mock_tx.tx_inputs().block_header().block_num(),
            notes,
            mock_tx.tx_args().clone(),
        )
        .await?;

    let successful = consumption_info.successful();
    let failed = consumption_info.failed();
    assert_eq!(successful.len(), 1);
    assert_eq!(successful[0].note().id(), succeeding_note.id());
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].note().id(), failing_note.id());

    Ok(())
}

/// Tests that the host rejects a public key that is not a valid EcGFp5 point.
#[tokio::test]
async fn ies_seal_rejects_invalid_public_key() -> anyhow::Result<()> {
    // The all-zero encoding is the identity, which is not a valid public key.
    let public_key = [ZERO; 5];
    let commitment = Hasher::hash_elements_in_domain(&public_key, ECGFP5_PUBLIC_KEY);

    let code = format!("{}\n{}", store_inputs(), seal_to_public_key(&public_key, 0));
    let result =
        execute(&mock_account(), None, compile_tx_script(&code, 1, None)?, vec![], vec![]).await;

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
/// entry, or an entry that is not a public key with that commitment.
#[rstest]
#[case::missing(None)]
#[case::invalid_length(Some(vec![ZERO; 4]))]
#[case::other_public_key(Some(secret_key(2).public_key().to_elements().to_vec()))]
#[tokio::test]
async fn ies_seal_rejects_invalid_advice_map_entry(
    #[case] entry: Option<Vec<Felt>>,
) -> anyhow::Result<()> {
    let commitment = secret_key(1).public_key().to_commitment();

    let code = format!("{}\n{}", store_inputs(), seal_to_commitment(commitment, 0));
    let tx_script = compile_tx_script(&code, 1, None)?;
    let advice_map_entries = entry.clone().map(|values| (commitment, values)).into_iter().collect();
    let result = execute(&mock_account(), None, tx_script, advice_map_entries, vec![]).await;

    let other_commitment = secret_key(2).public_key().to_commitment();
    assert_transaction_executor_error!(
        result,
        matches ExecutionError::EventError { error: ref event_err, .. }
            if match (event_err.downcast_ref::<TransactionKernelError>(), &entry) {
                (Some(TransactionKernelError::IesPublicKeyMissing(actual)), None) => {
                    *actual == commitment
                },
                (
                    Some(TransactionKernelError::IesPublicKeyInvalidLength { commitment: actual, len: 4 }),
                    Some(_),
                ) => *actual == commitment,
                (
                    Some(TransactionKernelError::IesPublicKeyCommitmentMismatch { expected, actual }),
                    Some(_),
                ) => *expected == commitment && *actual == other_commitment,
                _ => false,
            }
    );

    Ok(())
}

/// Tests that `miden::protocol::ies::seal` fails when the advice map already maps the public key
/// commitment to other values.
#[tokio::test]
async fn ies_seal_rejects_conflicting_advice_map_entry() -> anyhow::Result<()> {
    let recipient = secret_key(1).public_key();
    let commitment = recipient.to_commitment();

    let tx_script = compile_tx_script(
        &sealing_code(&[recipient], RecipientKeySource::ProtocolProcedure),
        1,
        None,
    )?;
    let conflicting_entry = (commitment, secret_key(2).public_key().to_elements().to_vec());
    let result = execute(&mock_account(), None, tx_script, vec![conflicting_entry], vec![]).await;

    assert_transaction_executor_error!(
        result,
        matches ExecutionError::AdviceError {
            err: AdviceError::MapKeyAlreadyPresent { key, .. },
            ..
        } if key == commitment
    );

    Ok(())
}

/// Tests that code run through `execute_code` can encrypt.
#[tokio::test]
async fn execute_code_handles_seal_request() -> anyhow::Result<()> {
    // The code runs in the root context, so the plaintext, the context and the envelope are placed
    // above the transaction kernel's memory.
    const SCRATCH_PTR: u32 = 1 << 27;
    const ENVELOPE_PTR: u32 = SCRATCH_PTR + (PLAINTEXT.len() + CONTEXT.len()) as u32;
    let recipient_secret = secret_key(1);

    let store_inputs = PLAINTEXT
        .iter()
        .chain(&CONTEXT)
        .enumerate()
        .map(|(idx, value)| format!("push.{value} push.{} mem_store", SCRATCH_PTR + idx as u32))
        .collect::<Vec<_>>()
        .join("\n");
    let code = format!(
        r#"
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction
            {store_inputs}
            push.{ENVELOPE_PTR} push.{context_len} push.{context_ptr} push.{plaintext_len}
            push.{SCRATCH_PTR}
            {public_key}
            exec.::miden::protocol::ies::seal
        end
        "#,
        context_len = CONTEXT.len(),
        context_ptr = SCRATCH_PTR + PLAINTEXT.len() as u32,
        plaintext_len = PLAINTEXT.len(),
        public_key = push_reversed(&recipient_secret.public_key().to_elements()),
    );

    let exec_output = TestTransactionBuilder::with_existing_mock_account()
        .build()?
        .execute_code(&code)
        .await?;

    let envelope_elements = (0..ENVELOPE_NUM_WORDS)
        .flat_map(|word_idx| {
            exec_output
                .get_kernel_mem_word(ENVELOPE_PTR + word_idx * WORD_SIZE as u32)
                .into_elements()
        })
        .collect::<Vec<_>>();
    let envelope = Envelope::from_elements(&envelope_elements)?;
    let plaintext = ecgfp5_eidos::open(&recipient_secret, &felts(CONTEXT), &envelope)?;
    assert_eq!(plaintext, felts(PLAINTEXT));

    Ok(())
}

// HELPERS
// ================================================================================================

/// Executes a transaction that encrypts [`PLAINTEXT`] under [`CONTEXT`] to each recipient and
/// adds the envelopes as attachments to an output note.
///
/// A foreign account can seal to one recipient only.
pub(super) async fn execute_sealing_transaction(
    recipients: &[PublicKey],
    key_source: RecipientKeySource,
    sealing_account: SealingAccount,
) -> anyhow::Result<ExecutedTransaction> {
    let sealing_code = sealing_code(recipients, key_source);
    let advice_map_entries = match key_source {
        RecipientKeySource::ProtocolProcedure => Vec::new(),
        RecipientKeySource::TransactionArguments => recipients
            .iter()
            .map(|recipient| (recipient.to_commitment(), recipient.to_elements().to_vec()))
            .collect(),
    };

    let (tx_script, foreign_account) = match sealing_account {
        SealingAccount::Native => (compile_tx_script(&sealing_code, recipients.len(), None)?, None),
        SealingAccount::Foreign => {
            anyhow::ensure!(recipients.len() == 1, "a foreign account seals to one recipient");

            let source_manager = Arc::new(DefaultSourceManager::default());
            let foreign_component = AccountComponent::new(
                CodeBuilder::with_kernel_core_package(source_manager.clone())
                    .compile_component_code("ies_sealer", sealing_component_code(&sealing_code))?,
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
            let tx_script = compile_tx_script(&code, 1, Some(&foreign_component))?;
            (tx_script, Some(foreign_account))
        },
    };

    Ok(execute(
        &mock_account(),
        foreign_account.as_ref(),
        tx_script,
        advice_map_entries,
        Vec::new(),
    )
    .await?)
}

/// Executes `tx_script` against `account` on a mock chain that also holds `foreign_account`, with
/// `advice_map_entries` and `ies_seal_secrets` in the transaction arguments.
async fn execute(
    account: &Account,
    foreign_account: Option<&Account>,
    tx_script: TransactionScript,
    advice_map_entries: Vec<(Word, Vec<Felt>)>,
    ies_seal_secrets: Vec<IesSealSecret>,
) -> Result<ExecutedTransaction, TransactionExecutorError> {
    let accounts = [Some(account), foreign_account].into_iter().flatten().cloned();
    let mut mock_chain = MockChainBuilder::with_accounts(accounts).unwrap().build().unwrap();
    mock_chain.prove_next_block().unwrap();

    let mut tx_builder = mock_chain.build_transaction(account.clone()).tx_script(tx_script);
    if let Some(foreign_account) = foreign_account {
        tx_builder = tx_builder.foreign_accounts([mock_chain
            .get_foreign_account_inputs(foreign_account.clone())
            .unwrap()]);
    }
    for (key, values) in advice_map_entries {
        tx_builder = tx_builder.add_advice_map_entry(key, values);
    }
    for secret in ies_seal_secrets {
        tx_builder = tx_builder.add_ies_seal_secret(secret);
    }

    tx_builder.build().unwrap().execute().await
}

/// Returns the witness of `executed_tx` with `ies_seal_secrets` recorded in place of the secrets
/// drawn during execution.
fn witness_with_recorded_secrets(
    executed_tx: ExecutedTransaction,
    ies_seal_secrets: Vec<IesSealSecret>,
) -> anyhow::Result<TransactionWitness> {
    let (tx_inputs, final_account, expiration_block_num) =
        TransactionWitness::from(executed_tx).into_parts();
    let tx_inputs = TransactionInputs::builder()
        .account(tx_inputs.account().clone())
        .block_header(tx_inputs.block_header().clone())
        .protocol_config(tx_inputs.protocol_config().clone())
        .blockchain(tx_inputs.blockchain().clone())
        .input_notes(tx_inputs.input_notes().clone())
        .code_tree(tx_inputs.code_tree().clone())
        .tx_args(tx_inputs.tx_args().clone())
        .foreign_accounts(tx_inputs.foreign_accounts().values().cloned().collect())
        .note_scripts(tx_inputs.note_scripts().values().cloned().collect())
        .signatures(tx_inputs.signatures().to_vec())
        .ies_seal_secrets(ies_seal_secrets)
        .build()?;

    Ok(TransactionWitness::new_unchecked(
        tx_inputs,
        final_account,
        expiration_block_num,
    ))
}

/// Returns the error a transaction event handler raised when proving failed with `error`, if any.
fn prover_kernel_error(error: &TransactionProverError) -> Option<&TransactionKernelError> {
    match error {
        TransactionProverError::TransactionProgramExecutionFailed(ExecutionError::EventError {
            error,
            ..
        }) => error.downcast_ref::<TransactionKernelError>(),
        _ => None,
    }
}

/// Compiles a transaction script that runs `sealing_code`, which leaves `num_envelopes` envelopes
/// at [`ENVELOPES_PTR`], and adds them as attachments to a new private output note.
fn compile_tx_script(
    sealing_code: &str,
    num_envelopes: usize,
    foreign_component: Option<&AccountComponent>,
) -> anyhow::Result<TransactionScript> {
    let attach_envelopes = (0..num_envelopes)
        .map(|idx| {
            format!(
                "dup push.{} push.{ENVELOPE_NUM_WORDS} push.{}
                exec.output_note::add_attachment_from_memory",
                envelope_ptr(idx),
                ENVELOPE_ATTACHMENT_SCHEME + idx as u16,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

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

            {attach_envelopes}
            # => [note_idx, pad(15)]

            exec.output_note::seal
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

/// Returns MASM that encrypts [`PLAINTEXT`] under [`CONTEXT`] to each recipient, writing the
/// envelopes one after the other from [`ENVELOPES_PTR`].
fn sealing_code(recipients: &[PublicKey], key_source: RecipientKeySource) -> String {
    let seals = recipients.iter().enumerate().map(|(idx, recipient)| match key_source {
        RecipientKeySource::ProtocolProcedure => seal_to_public_key(&recipient.to_elements(), idx),
        RecipientKeySource::TransactionArguments => {
            seal_to_commitment(recipient.to_commitment(), idx)
        },
    });

    [store_inputs()].into_iter().chain(seals).collect::<Vec<_>>().join("\n")
}

/// Returns the code of an account component whose `seal_envelope` procedure runs `sealing_code`
/// and returns the envelope at [`ENVELOPES_PTR`].
fn sealing_component_code(sealing_code: &str) -> String {
    let load_envelope = (0..ENVELOPE_NUM_WORDS)
        .rev()
        .map(|word_idx| {
            format!("padw push.{} mem_loadw_le", ENVELOPES_PTR + word_idx * WORD_SIZE as u32)
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

/// Returns MASM that stores the 16-element envelope on top of the stack at [`ENVELOPES_PTR`].
fn store_envelope_from_stack() -> String {
    (0..ENVELOPE_NUM_WORDS)
        .map(|word_idx| {
            format!("push.{} mem_storew_le dropw", ENVELOPES_PTR + word_idx * WORD_SIZE as u32)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Returns MASM that encrypts the plaintext under the context to `public_key` with
/// `miden::protocol::ies::seal`, writing the envelope with index `envelope_idx`.
fn seal_to_public_key(public_key: &[Felt; 5], envelope_idx: usize) -> String {
    format!(
        "{}\n{}\nexec.::miden::protocol::ies::seal",
        push_seal_arguments(envelope_idx),
        push_reversed(public_key)
    )
}

/// Returns MASM that encrypts the plaintext under the context to the public key with `commitment`
/// with the core library's `seal`, writing the envelope with index `envelope_idx`.
fn seal_to_commitment(commitment: Word, envelope_idx: usize) -> String {
    format!(
        "{}\n{}\nexec.::miden::core::crypto::ies::ecgfp5_eidos::seal",
        push_seal_arguments(envelope_idx),
        push_reversed(commitment.as_elements())
    )
}

/// Returns MASM that writes [`PLAINTEXT`] and [`CONTEXT`] to memory.
fn store_inputs() -> String {
    let store = |ptr: u32, values: [u32; 4]| {
        values
            .iter()
            .enumerate()
            .map(|(idx, value)| format!("push.{value} push.{} mem_store", ptr + idx as u32))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!("{}\n{}", store(PLAINTEXT_PTR, PLAINTEXT), store(CONTEXT_PTR, CONTEXT))
}

/// Returns MASM that pushes the `seal` arguments below the key for the envelope with index
/// `envelope_idx`.
fn push_seal_arguments(envelope_idx: usize) -> String {
    format!(
        "push.{} push.{} push.{CONTEXT_PTR} push.{} push.{PLAINTEXT_PTR}",
        envelope_ptr(envelope_idx),
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

/// Returns the envelope attached with index `envelope_idx` to the first output note.
fn envelope(executed_tx: &ExecutedTransaction, envelope_idx: usize) -> anyhow::Result<Envelope> {
    let attachment = executed_tx
        .output_notes()
        .get_note(0)
        .attachments()
        .get(envelope_idx)
        .context("output note should have the envelope attachment")?;

    Ok(Envelope::from_elements(attachment.as_elements())?)
}

fn envelope_ptr(envelope_idx: usize) -> u32 {
    ENVELOPES_PTR + envelope_idx as u32 * ENVELOPE_LEN
}

fn mock_account() -> Account {
    Account::mock(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE, Auth::IncrNonce)
}

/// Returns a secret key, which the tests use as recipient key or as ephemeral secret.
pub(super) fn secret_key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 40]).expect("bytes should encode a valid secret key")
}

fn felts(values: [u32; 4]) -> Vec<Felt> {
    values.map(Felt::from).to_vec()
}
