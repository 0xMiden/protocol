//! Tests for encrypting to an EcGFp5 public key inside a transaction.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::ExecutionError;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{Account, AccountBuilder, AccountComponent, AccountId};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::crypto::ecdh::ecgfp5::{PublicKey, SecretKey};
use miden_protocol::crypto::ies::ecgfp5_eidos::{self, Envelope};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::{ExecutedTransaction, IesSealSeed, TransactionScript};
use miden_protocol::{Felt, WORD_SIZE, Word, ZERO};
use miden_standards::account::auth::{Approver, ApproverSet, MultisigAuthArgs};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use miden_tx::{LocalTransactionProver, TransactionExecutorError, TransactionKernelError};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rstest::rstest;

use super::ExecutionOutputExt;
use crate::{Auth, MockChainBuilder, TestTransactionBuilder, assert_transaction_executor_error};

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

/// Where the plaintext is encrypted.
#[derive(Clone, Copy)]
pub(super) enum SealingAccount {
    /// The transaction script of the native account encrypts.
    Native,
    /// A procedure of a foreign account encrypts and returns the envelope.
    Foreign,
}

/// Tests that a transaction encrypts to the recipient public key, and that proving reproduces the
/// envelope.
#[rstest]
#[case::native_account(SealingAccount::Native)]
#[case::foreign_account(SealingAccount::Foreign)]
#[tokio::test]
async fn ies_seal_encrypts_to_recipient_public_key(
    #[case] sealing_account: SealingAccount,
) -> anyhow::Result<()> {
    let recipient_secret = secret_key(1);

    let executed_tx =
        execute_sealing_transaction(&[recipient_secret.public_key()], sealing_account).await?;

    let plaintext =
        ecgfp5_eidos::open(&recipient_secret, &felts(CONTEXT), &envelope(&executed_tx, 0)?)?;
    assert_eq!(plaintext, felts(PLAINTEXT));

    let proven_tx = LocalTransactionProver::default().prove(executed_tx.clone())?;

    // The transaction ID commits to the output notes, which hold the envelope.
    assert_eq!(proven_tx.id(), executed_tx.id());

    Ok(())
}

/// Tests that each request of a transaction gets its own ephemeral secret, also when two requests
/// encrypt the same plaintext under the same context to the same recipient, and that proving
/// reproduces the envelopes.
#[rstest]
#[case::different_recipients([1, 2])]
#[case::same_recipient([1, 1])]
#[tokio::test]
async fn ies_seal_derives_a_secret_per_request(
    #[case] recipient_seeds: [u8; 2],
) -> anyhow::Result<()> {
    let recipient_secrets = recipient_seeds.map(secret_key);
    let recipients = recipient_secrets.each_ref().map(SecretKey::public_key);

    let executed_tx = execute_sealing_transaction(&recipients, SealingAccount::Native).await?;

    let envelopes = [envelope(&executed_tx, 0)?, envelope(&executed_tx, 1)?];
    assert_ne!(envelopes[0].ephemeral_key(), envelopes[1].ephemeral_key());
    for (recipient_secret, envelope) in recipient_secrets.iter().zip(&envelopes) {
        let plaintext = ecgfp5_eidos::open(recipient_secret, &felts(CONTEXT), envelope)?;
        assert_eq!(plaintext, felts(PLAINTEXT));
    }

    let proven_tx = LocalTransactionProver::default().prove(executed_tx.clone())?;
    assert_eq!(proven_tx.id(), executed_tx.id());

    Ok(())
}

/// Tests that sealing another plaintext with the same seed, recipient, context and request index
/// derives another ephemeral secret.
#[tokio::test]
async fn ies_seal_secret_depends_on_plaintext() -> anyhow::Result<()> {
    let recipient_secret = secret_key(1);
    let recipient = recipient_secret.public_key();
    let executed_tx = execute_sealing_transaction(&[recipient], SealingAccount::Native).await?;

    let mut other_plaintext = felts(PLAINTEXT);
    other_plaintext[0] = Felt::from(99_u32);
    let code = format!(
        "{}\npush.{} push.{PLAINTEXT_PTR} mem_store\n{}",
        store_inputs(),
        other_plaintext[0],
        seal_to_public_key(&recipient.to_elements(), 0),
    );
    let other_tx = execute(None, compile_tx_script(&code, 1, None)?).await?;

    let other_envelope = envelope(&other_tx, 0)?;
    let plaintext = ecgfp5_eidos::open(&recipient_secret, &felts(CONTEXT), &other_envelope)?;
    assert_eq!(plaintext, other_plaintext);
    assert_ne!(other_envelope.ephemeral_key(), envelope(&executed_tx, 0)?.ephemeral_key());

    Ok(())
}

/// Tests that the same request with the same seed in the next transaction of the same account
/// derives another ephemeral secret.
#[tokio::test]
async fn ies_seal_secret_depends_on_transaction() -> anyhow::Result<()> {
    let account = mock_account();
    let mut mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    mock_chain.prove_next_block()?;
    let tx_script = compile_tx_script(&sealing_code(&[secret_key(1).public_key()]), 1, None)?;

    let mut ephemeral_keys = Vec::new();
    for _ in 0..2 {
        let executed_tx = mock_chain
            .build_transaction(account.id())
            .tx_script(tx_script.clone())
            .build()?
            .execute()
            .await?;
        ephemeral_keys.push(envelope(&executed_tx, 0)?.ephemeral_key());

        mock_chain.add_pending_executed_transaction(&executed_tx)?;
        mock_chain.prove_next_block()?;
    }
    assert_ne!(ephemeral_keys[0], ephemeral_keys[1]);

    Ok(())
}

/// Tests that a note that repeats the request of another requester, in a second execution of the
/// same transaction with the same seed at a later reference block, does not get that request's
/// ephemeral secret.
///
/// The transaction script seals in both executions. The note seals only in the second one, before
/// the transaction script and with the same plaintext, context and recipient, so its request has
/// the request index that the request of the transaction script had in the first execution.
#[tokio::test]
async fn ies_seal_secret_depends_on_requester() -> anyhow::Result<()> {
    let recipient_secret = secret_key(1);
    let sealing_code = sealing_code(&[recipient_secret.public_key()]);
    let account = mock_account();
    let mut mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    mock_chain.prove_next_block()?;
    let first_block = mock_chain.latest_block_header().block_num();
    mock_chain.prove_next_block()?;
    let second_block = mock_chain.latest_block_header().block_num();

    let probing_note =
        NoteBuilder::new(AccountId::try_from(ACCOUNT_ID_SENDER)?, ChaCha20Rng::from_seed([5; 32]))
            .code(format!(
                r#"
                use miden::core::sys
                use miden::protocol::output_note
                use miden::protocol::tx

                @note_script
                pub proc main
                    exec.tx::get_reference_block_number push.{second_block} gte
                    # => [is_second_execution]

                    if.true
                        {sealing_code}
                        # => []

                        padw padw push.{recipient} push.{note_type} push.0
                        call.::mock::account::create_note
                        # => [note_idx, pad(15)]

                        dup push.{ENVELOPES_PTR} push.{ENVELOPE_NUM_WORDS}
                        push.{ENVELOPE_ATTACHMENT_SCHEME}
                        exec.output_note::add_attachment_from_memory
                        # => [note_idx, pad(15)]

                        dup exec.output_note::seal
                        # => [note_idx, pad(15)]
                    end

                    exec.sys::truncate_stack
                    # => [pad(16)]
                end
                "#,
                recipient = Word::from([9, 9, 9, 9u32]),
                note_type = NoteType::Private.as_u8(),
            ))
            .dynamically_linked_packages(CodeBuilder::mock_packages())
            .build()?;
    let tx_script = compile_tx_script(&sealing_code, 1, None)?;
    let execute_at = async |reference_block| {
        mock_chain
            .build_transaction(account.id())
            .tx_script(tx_script.clone())
            .unauthenticated_input_note(probing_note.clone())
            .reference_block(reference_block)
            .build()?
            .execute()
            .await
            .context("failed to execute the transaction")
    };

    // In the first execution, the note of the transaction script is the only output note. In the
    // second one, the note of the probing note comes first.
    let first_tx = execute_at(first_block).await?;
    assert_eq!(first_tx.output_notes().num_notes(), 1);
    let second_tx = execute_at(second_block).await?;
    assert_eq!(second_tx.output_notes().num_notes(), 2);

    let probe = envelope(&second_tx, 0)?;
    let plaintext = ecgfp5_eidos::open(&recipient_secret, &felts(CONTEXT), &probe)?;
    assert_eq!(plaintext, felts(PLAINTEXT));
    assert_ne!(probe.ephemeral_key(), envelope(&first_tx, 0)?.ephemeral_key());

    Ok(())
}

/// Tests that the signed execution of a two-pass authentication flow with the same transaction
/// arguments reproduces the summary the signers approved at a later reference block, and that the
/// summary depends on the IES seal seed.
#[tokio::test]
async fn signed_execution_reproduces_unauthorized_summary() -> anyhow::Result<()> {
    use miden_protocol::crypto::SequentialCommit;

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
    let tx_script = compile_tx_script(&sealing_code(&[secret_key(1).public_key()]), 1, None)?;
    let mut mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    mock_chain.prove_next_block()?;

    let auth_args = MultisigAuthArgs::new(
        mock_chain.latest_block_header().block_num(),
        Word::from([1, 2, 3, 4u32]),
    );
    mock_chain.prove_next_block()?;
    let tx_builder = || {
        mock_chain
            .build_transaction(account.clone())
            .tx_script(tx_script.clone())
            .auth_args(auth_args.to_commitment())
            .add_advice_map_entry(auth_args.to_commitment(), auth_args.to_elements())
            .required_block(auth_args.bound_block_num())
    };

    // The unauthorized execution runs at the bound block, the signed one at the next block.
    let tx_summary = tx_builder()
        .reference_block(auth_args.bound_block_num())
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();

    // The signature over the summary verifies only if the signed execution reproduces it.
    let msg = tx_summary.to_commitment();
    let signature = BasicAuthenticator::new(&[signer])
        .get_signature(signer_commitment, &SigningInputs::TransactionSummary(tx_summary.clone()))
        .await?;
    let executed_tx = tx_builder()
        .add_signature(signer_commitment, msg, signature)
        .build()?
        .execute()
        .await?;
    assert_eq!(executed_tx.output_notes().commitment(), tx_summary.output_notes().commitment());
    assert!(executed_tx.block_header().block_num() > auth_args.bound_block_num());

    // Another seed changes the envelope and thereby the summary.
    let other_summary = tx_builder()
        .ies_seal_seed(Some(IesSealSeed::new([1; 32])))
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    assert_ne!(other_summary.to_commitment(), msg);

    Ok(())
}

/// Tests that the host rejects an IES seal request it cannot answer: one with a public key that is
/// not a valid EcGFp5 point, one without an IES seal seed, and a call to the core library's `seal`
/// that does not go through `miden::protocol::ies::ecgfp5_eidos::seal`.
#[rstest]
#[case::invalid_public_key(
    // The all-zero encoding is the identity, which is not a valid public key.
    seal_to_public_key(&[ZERO; 5], 0),
    Some(IesSealSeed::new([1; 32])),
    |error: &TransactionKernelError| {
        matches!(error, TransactionKernelError::IesPublicKeyInvalid(_))
    },
)]
#[case::missing_seed(
    seal_to_public_key(&secret_key(1).public_key().to_elements(), 0),
    None,
    |error: &TransactionKernelError| matches!(error, TransactionKernelError::IesSealSeedMissing),
)]
#[case::core_seal(
    seal_to_commitment(secret_key(1).public_key().to_commitment(), 0),
    Some(IesSealSeed::new([1; 32])),
    |error: &TransactionKernelError| {
        matches!(error, TransactionKernelError::IesSealWithoutProtocolProcedure)
    },
)]
#[tokio::test]
async fn ies_seal_rejects_unanswerable_request(
    #[case] seal_code: String,
    #[case] ies_seal_seed: Option<IesSealSeed>,
    #[case] is_expected_error: fn(&TransactionKernelError) -> bool,
) -> anyhow::Result<()> {
    let account = mock_account();
    let mut mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    mock_chain.prove_next_block()?;
    let tx_script = compile_tx_script(&format!("{}\n{seal_code}", store_inputs()), 1, None)?;

    let result = mock_chain
        .build_transaction(account)
        .tx_script(tx_script)
        .ies_seal_seed(ies_seal_seed)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        matches ExecutionError::EventError { error: ref event_err, .. }
            if event_err.downcast_ref::<TransactionKernelError>().is_some_and(is_expected_error)
    );

    Ok(())
}

/// Tests that the host answers a request event and a key agreement event that code emits directly,
/// without `miden::protocol::ies::ecgfp5_eidos::seal` and the core library's `seal`.
///
/// The request event carries the digests of the plaintext and the context instead of their memory
/// ranges, so the host does constant work: the empty plaintext and the context of nearly 2^28
/// elements that the values below the public key describe are not part of the event.
#[tokio::test]
async fn ies_seal_events_carry_no_memory_ranges() -> anyhow::Result<()> {
    let recipient = secret_key(1).public_key();
    let code = format!(
        r#"
        use miden::tx_kernel_core::prologue

        begin
            exec.prologue::prepare_transaction

            push.0 push.{context_len} push.0 push.0 push.0
            {public_key}
            {context_digest}
            {plaintext_digest}
            # => [PLAINTEXT_DIGEST, CONTEXT_DIGEST, public_key(5), src_ptr, plaintext_len,
            #     context_ptr, context_len, dst_ptr]

            emit.event("miden::protocol::ies::ecgfp5_eidos::seal")
            dropw dropw dropw dropw drop drop
            # => []

            {commitment}
            emit.event("miden::core::crypto::ies::ecgfp5_eidos::seal")
            dropw
            # => []
        end
        "#,
        context_len = (1 << 28) - 6,
        public_key = push_reversed(&recipient.to_elements()),
        context_digest = push_reversed(Word::from([1, 2, 3, 4u32]).as_elements()),
        plaintext_digest = push_reversed(Word::from([5, 6, 7, 8u32]).as_elements()),
        commitment = push_reversed(recipient.to_commitment().as_elements()),
    );

    TestTransactionBuilder::with_existing_mock_account()
        .build()?
        .execute_code(&code)
        .await?;

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
            exec.::miden::protocol::ies::ecgfp5_eidos::seal
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
    sealing_account: SealingAccount,
) -> anyhow::Result<ExecutedTransaction> {
    let sealing_code = sealing_code(recipients);

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

    Ok(execute(foreign_account.as_ref(), tx_script).await?)
}

/// Executes `tx_script` against the mock account on a mock chain that also holds
/// `foreign_account`, with the default IES seal seed of the mock transaction builder.
async fn execute(
    foreign_account: Option<&Account>,
    tx_script: TransactionScript,
) -> Result<ExecutedTransaction, TransactionExecutorError> {
    let account = mock_account();
    let accounts = [Some(&account), foreign_account].into_iter().flatten().cloned();
    let mut mock_chain = MockChainBuilder::with_accounts(accounts).unwrap().build().unwrap();
    mock_chain.prove_next_block().unwrap();

    let mut tx_builder = mock_chain.build_transaction(account).tx_script(tx_script);
    if let Some(foreign_account) = foreign_account {
        tx_builder = tx_builder.foreign_accounts([mock_chain
            .get_foreign_account_inputs(foreign_account.clone())
            .unwrap()]);
    }

    tx_builder.build().unwrap().execute().await
}

/// Compiles a transaction script that runs `sealing_code`, which leaves `num_envelopes` envelopes
/// at [`ENVELOPES_PTR`], and adds them as attachments to a new private output note, which it then
/// seals.
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

            dup exec.output_note::seal
            # => [note_idx, pad(15)]

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
fn sealing_code(recipients: &[PublicKey]) -> String {
    let seals = recipients
        .iter()
        .enumerate()
        .map(|(idx, recipient)| seal_to_public_key(&recipient.to_elements(), idx));

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
/// `miden::protocol::ies::ecgfp5_eidos::seal`, writing the envelope with index `envelope_idx`.
fn seal_to_public_key(public_key: &[Felt; 5], envelope_idx: usize) -> String {
    format!(
        "{}\n{}\nexec.::miden::protocol::ies::ecgfp5_eidos::seal",
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

/// Returns the secret key of a recipient.
pub(super) fn secret_key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 40]).expect("bytes should encode a valid secret key")
}

fn felts(values: [u32; 4]) -> Vec<Felt> {
    values.map(Felt::from).to_vec()
}
