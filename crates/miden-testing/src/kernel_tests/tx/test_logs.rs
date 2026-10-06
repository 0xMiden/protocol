use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::ExecutionError;
use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountDelta,
    AccountType,
};
use miden_protocol::block::ProvenBlock;
use miden_protocol::errors::{MasmError, TransactionVerifierError, tx_kernel};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::{
    ExecutedTransaction,
    LogTopic,
    ProvenTransaction,
    TransactionEffects,
    TransactionLog,
    TransactionLogData,
    TransactionLogs,
    TransactionSummary,
    TransactionSummaryUserParams,
    TransactionVerifier,
};
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_protocol::{
    Felt,
    Hasher,
    MAX_LOG_PAYLOAD_WORDS,
    MAX_LOG_PAYLOAD_WORDS_PER_TX,
    MAX_LOGS_PER_TX,
    MIN_PROOF_SECURITY_LEVEL,
    WORD_SIZE,
    Word,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::{LocalTransactionProver, TransactionKernelError};
use rstest::rstest;

use crate::{AccountState, Auth, MockChain, MockChainBuilder, TestTransactionBuilder};

const EMIT_LOG_PROC: &str = "test::transaction_logs::emit_log";

#[rstest]
#[case::max_count(MAX_LOGS_PER_TX, 0, None)]
#[case::count(MAX_LOGS_PER_TX + 1, 0, Some(tx_kernel::ERR_TX_LOG_COUNT))]
#[case::max_payload(1, MAX_LOG_PAYLOAD_WORDS, None)]
#[case::max_total_payload(MAX_LOG_PAYLOAD_WORDS_PER_TX / MAX_LOG_PAYLOAD_WORDS, MAX_LOG_PAYLOAD_WORDS, None)]
#[case::individual_payload(1, MAX_LOG_PAYLOAD_WORDS + 1, Some(tx_kernel::ERR_TX_LOG_PAYLOAD))]
#[case::total_payload(MAX_LOG_PAYLOAD_WORDS_PER_TX / MAX_LOG_PAYLOAD_WORDS + 1, MAX_LOG_PAYLOAD_WORDS, Some(tx_kernel::ERR_TX_LOG_TOTAL_PAYLOAD))]
#[tokio::test]
async fn kernel_log_limits(
    #[case] count: usize,
    #[case] payload_words: usize,
    #[case] error: Option<MasmError>,
) -> anyhow::Result<()> {
    let payload = vec![Word::from([71u32; 4]); payload_words];
    let commitment = Hasher::hash_elements(Word::words_as_elements(&payload));
    let tx = TestTransactionBuilder::with_existing_mock_account()
        .add_advice_map_entry(commitment, Word::words_as_elements(&payload).to_vec())
        .build()?;
    let code = kernel_log_program(&format!(
        r"
        repeat.{count}
            push.{commitment} push.29.17 exec.tx_log::add_log
        end
        "
    ));
    if let Some(error) = error {
        crate::assert_execution_error!(tx.execute_code(&code).await, error);
    } else {
        tx.execute_code(&code).await?;
    }
    Ok(())
}

#[rstest]
#[case::forged_payload(WORD_SIZE, tx_kernel::ERR_TX_LOG_PREIMAGE)]
#[case::partial_word(WORD_SIZE - 1, tx_kernel::ERR_TX_LOG_PAYLOAD)]
#[tokio::test]
async fn kernel_logs_reject_invalid_payloads(
    #[case] num_elements: usize,
    #[case] error: MasmError,
) -> anyhow::Result<()> {
    let commitment = Word::from([19u32; WORD_SIZE]);
    let tx = TestTransactionBuilder::with_existing_mock_account()
        .add_advice_map_entry(commitment, vec![71u32.into(); num_elements])
        .build()?;
    let code = kernel_log_program(&format!("push.{commitment} push.29.17 exec.tx_log::add_log"));
    crate::assert_execution_error!(tx.execute_code(&code).await, error);
    Ok(())
}

#[tokio::test]
async fn private_transaction_logs_require_a_nonzero_secret_salt() -> anyhow::Result<()> {
    let account = Account::mock(ACCOUNT_ID_PRIVATE_SENDER, [NoopAuthComponent]);
    let tx = TestTransactionBuilder::new(account)
        .add_advice_map_entry(Word::empty(), vec![])
        .build()?;
    let code = kernel_log_program(
        "padw push.29.17 exec.tx_log::add_log exec.tx_log::get_commitment dropw",
    );
    crate::assert_execution_error!(tx.execute_code(&code).await, tx_kernel::ERR_TX_LOG_SALT);
    Ok(())
}

#[tokio::test]
async fn transaction_scripts_cannot_log_directly() -> anyhow::Result<()> {
    let script = CodeBuilder::default().compile_tx_script(
        r"
            use miden::protocol::tx
            @transaction_script
            pub proc main
                padw push.29.17 exec.tx::add_log
            end
            ",
    )?;
    let tx = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(script)
        .add_advice_map_entry(Word::empty(), vec![])
        .build()?;
    crate::assert_transaction_executor_error!(
        tx.execute().await,
        matches ExecutionError::EventError { error: ref event_err, .. }
            if matches!(
                event_err.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::UnknownAccountProcedure(_))
            )
    );
    Ok(())
}

#[rstest]
#[case::public(AccountType::Public, false)]
#[case::private(AccountType::Private, false)]
#[case::direct_public(AccountType::Public, true)]
#[case::direct_private(AccountType::Private, true)]
#[tokio::test]
async fn unauthenticated_note_logs(
    #[case] account_type: AccountType,
    #[case] direct: bool,
) -> anyhow::Result<()> {
    let payload = vec![Word::from([11u32, 22, 33, 44])];
    let payload_commitment = Hasher::hash_elements(Word::words_as_elements(&payload));
    let component = log_emitter_component(payload_commitment)?;
    let root = component.get_procedure_root_by_path(EMIT_LOG_PROC).unwrap();
    let account = AccountBuilder::new([83; 32])
        .account_type(account_type)
        .with_components(Auth::IncrNonce)
        .with_component(component)
        .build_existing()?;
    let emit = if direct {
        format!("push.{payload_commitment} push.29.17 exec.tx::add_log")
    } else {
        format!("call.{root}")
    };
    let script = CodeBuilder::default().compile_note_script(format!(
        r"
        use miden::protocol::tx
        use miden::core::sys
        @note_script
        pub proc main
            dropw {emit} exec.sys::truncate_stack
        end
        "
    ))?;
    let note = NoteBuilder::new(account.id(), &mut RandomCoin::new(Word::from([1u32; 4])))
        .note_type(NoteType::Private)
        .script(script)
        .build()?;
    let note_id = note.id();
    let chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    let mut tx = chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .add_advice_map_entry(payload_commitment, Word::words_as_elements(&payload).to_vec())
        .build()?;
    tx.set_tx_args(tx.tx_args().clone().with_log_salt(Word::from([91u32, 82, 73, 64])));
    if direct {
        crate::assert_transaction_executor_error!(
            tx.execute().await,
            matches ExecutionError::EventError { error: ref event_err, .. }
                if matches!(
                    event_err.downcast_ref::<TransactionKernelError>(),
                    Some(TransactionKernelError::UnknownAccountProcedure(_))
                )
        );
        return Ok(());
    }
    let executed = tx.execute().await?;
    let expected =
        TransactionLog::new(account.id(), LogTopic::new([17u32.into(), 29u32.into()]), payload)?;
    assert_eq!(executed.logs().iter().collect::<Vec<_>>(), vec![&expected]);
    let proven = LocalTransactionProver::default().prove(executed.clone())?;
    assert_eq!(proven.input_notes().iter().next().unwrap().header().unwrap().id(), note_id);
    assert!(!proven.input_notes().iter().next().unwrap().is_authenticated());
    assert_eq!(proven.log_data().commitment(), executed.logs_commitment());
    if let TransactionLogData::Public(logs) = proven.log_data() {
        assert_eq!(logs, executed.logs());
    }
    assert_eq!(
        matches!(proven.log_data(), TransactionLogData::Public(_)),
        account_type.is_public()
    );
    assert!(
        TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL)
            .verify(&proven)?
            .is_complete()
    );
    Ok(())
}

#[rstest]
#[case::public(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE)]
#[case::private(ACCOUNT_ID_PRIVATE_SENDER)]
#[tokio::test]
async fn kernel_log_commitments_match_rust_and_invalidate_cache(
    #[case] account_id: u128,
) -> anyhow::Result<()> {
    let account = Account::mock(account_id, [NoopAuthComponent]);
    let topic = LogTopic::new([17u32.into(), 29u32.into()]);
    let salt = Word::from([73u32, 37, 19, 91]);
    let mut logs = TransactionLogs::default();
    let mut builder = TestTransactionBuilder::new(account.clone());
    let mut code = String::from("exec.tx_log::get_commitment padw assert_eqw\n");
    for num_words in [0usize, 1, 2, 3, MAX_LOG_PAYLOAD_WORDS] {
        let payload = (0..num_words).map(|i| Word::from([i as u32 + 1; 4])).collect();
        let entry = TransactionLog::new(account.id(), topic, payload)?;
        let payload_commitment = entry.payload_commitment();
        builder = builder.add_advice_map_entry(
            payload_commitment,
            Word::words_as_elements(entry.payload()).to_vec(),
        );
        logs.try_push(entry)?;
        let expected = logs.commitment_for_account(account.id(), salt)?;
        code.push_str(&format!(
            r"
            push.{payload_commitment} push.29.17 exec.tx_log::add_log
            exec.tx_log::get_commitment push.{expected} assert_eqw
            exec.tx_log::get_commitment push.{expected} assert_eqw
            ",
        ));
    }
    let code = kernel_log_program(&code);
    let mut tx = builder.build()?;
    tx.set_tx_args(tx.tx_args().clone().with_log_salt(salt));
    tx.execute_code(&code).await?;
    Ok(())
}

#[rstest]
#[case::public(AccountType::Public)]
#[case::private(AccountType::Private)]
#[tokio::test]
async fn transaction_logs_execute_prove_verify_and_reject_tampering(
    #[case] account_type: AccountType,
) -> anyhow::Result<()> {
    let payload = vec![Word::from([111u32, 222, 333, 444])];
    let payload_commitment = Hasher::hash_elements(Word::words_as_elements(&payload));
    let component = AccountComponent::new(
        CodeBuilder::default().compile_component_code(
            "test::log_auth",
            format!(
                r"
            use miden::protocol::tx
            use miden::protocol::native_account
            @auth_script
            pub proc auth
                # Both transaction log APIs must preserve the caller's deeper stack.
                push.101.102.103.104.105.106.107.108
                push.{payload_commitment} push.29.17 exec.tx::add_log
                exec.tx::get_logs_commitment dropw
                push.{payload_commitment} push.31.17 exec.tx::add_log
                exec.tx::get_logs_commitment dropw
                push.105.106.107.108 assert_eqw
                push.101.102.103.104 assert_eqw
                exec.native_account::incr_nonce drop
            end
            ",
            ),
        )?,
        vec![],
        AccountComponentMetadata::mock("test::log_auth"),
    )?;
    let account = AccountBuilder::new([41; 32])
        .account_type(account_type)
        .with_component(component)
        .with_component(BasicWallet)
        .build_existing()?;
    let salt = Word::from([345u32, 678, 123, 901]);
    let mut tx = TestTransactionBuilder::new(account.clone())
        .add_advice_map_entry(payload_commitment, Word::words_as_elements(&payload).to_vec())
        .build()?;
    tx.set_tx_args(tx.tx_args().clone().with_log_salt(salt));
    let executed = tx.execute().await?;
    assert_eq!(executed.logs().num_logs(), 2);
    let log = &executed.logs().iter().next().unwrap();
    assert_eq!(log.emitter(), account.id());
    assert_eq!(log.payload(), payload);
    let local_copy = ExecutedTransaction::read_from_bytes(&executed.to_bytes())?;
    assert_eq!(local_copy.logs(), executed.logs());

    let proven = LocalTransactionProver::default().prove(executed.clone())?;
    assert_eq!(proven.id(), executed.id());
    let verifier = TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL);
    assert!(verifier.verify(&proven)?.is_complete());
    let encoded = proven.to_bytes();
    assert_eq!(ProvenTransaction::read_from_bytes(&encoded)?, proven);
    assert_eq!(
        matches!(proven.log_data(), TransactionLogData::Public(_)),
        account_type.is_public()
    );
    let tampered_data = match proven.log_data() {
        TransactionLogData::Public(logs) => tampered_public_log_data(logs)?,
        TransactionLogData::Private(_) => {
            for private in [salt.to_bytes(), executed.logs().to_bytes()] {
                assert!(!encoded.windows(private.len()).any(|window| window == private));
            }
            vec![(
                "changed private commitment",
                TransactionLogData::Private(Word::from([1u32; WORD_SIZE])),
            )]
        },
    };
    for (case, log_data) in tampered_data {
        let tampered = proven.clone().with_log_data(log_data)?;
        assert!(
            matches!(
                verifier.verify(&tampered),
                Err(TransactionVerifierError::TransactionVerificationFailed(_))
            ),
            "accepted tampered transaction log data: {case}"
        );
    }
    Ok(())
}

#[rstest]
#[case::public(AccountType::Public)]
#[case::private(AccountType::Private)]
#[tokio::test]
async fn foreign_logs_use_the_emitter_and_native_visibility(
    #[case] native_type: AccountType,
) -> anyhow::Result<()> {
    let component = log_emitter_component(Word::empty())?;
    let proc_root = component
        .get_procedure_root_by_path(EMIT_LOG_PROC)
        .context("foreign transaction log procedure")?;
    let foreign = AccountBuilder::new([51; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(component)
        .build_existing()?;
    let intermediate_code = CodeBuilder::default().compile_component_code(
        "test::nested_logs",
        format!(
            r"
            use miden::protocol::tx
            use miden::core::sys
            @account_procedure
            pub proc emit_log
                padw push.31.17 exec.tx::add_log
                padw padw push.0.0 push.{proc_root} push.{prefix}.{suffix}
                exec.tx::execute_foreign_procedure exec.sys::truncate_stack
            end
            ",
            prefix = foreign.id().prefix().as_felt(),
            suffix = foreign.id().suffix(),
        ),
    )?;
    let intermediate_component = AccountComponent::new(
        intermediate_code,
        vec![],
        AccountComponentMetadata::mock("test::nested_logs"),
    )?;
    let proc_root = intermediate_component
        .get_procedure_root_by_path("test::nested_logs::emit_log")
        .context("nested logging procedure")?;
    let intermediate = AccountBuilder::new([53; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(intermediate_component)
        .build_existing()?;
    let native = AccountBuilder::new([52; 32])
        .account_type(native_type)
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build_existing()?;
    let mut chain =
        MockChainBuilder::with_accounts([native.clone(), intermediate.clone(), foreign.clone()])?
            .build()?;
    chain.prove_next_block()?;
    let inputs = chain.get_foreign_account_inputs(foreign.clone())?;
    let intermediate_inputs = chain.get_foreign_account_inputs(intermediate.clone())?;
    let script = CodeBuilder::default().compile_tx_script(format!(
        r"
            use miden::protocol::tx
            use miden::core::sys
            @transaction_script
            pub proc main
                padw padw push.0.0
                push.{proc_root} push.{prefix}.{suffix}
                exec.tx::execute_foreign_procedure exec.sys::truncate_stack
            end
            ",
        prefix = intermediate.id().prefix().as_felt(),
        suffix = intermediate.id().suffix(),
    ))?;
    let mut tx = chain
        .build_transaction(native.clone())
        .foreign_accounts([inputs, intermediate_inputs])
        .tx_script(script)
        .add_advice_map_entry(Word::empty(), vec![])
        .build()?;
    tx.set_tx_args(tx.tx_args().clone().with_log_salt(Word::from([89u32; 4])));
    let executed = tx.execute().await?;
    let entries = executed.logs().iter().collect::<Vec<_>>();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].emitter(), intermediate.id());
    assert_eq!(entries[1].emitter(), foreign.id());
    let proven = LocalTransactionProver::default().prove(executed)?;
    assert_eq!(
        matches!(proven.log_data(), TransactionLogData::Public(_)),
        native_type.is_public()
    );
    assert!(
        TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL)
            .verify(&proven)?
            .is_complete()
    );
    let expected_data = proven.log_data().clone();
    chain.add_pending_proven_transaction(proven);
    let block = chain.prove_next_block()?;
    assert_eq!(block.body().log_data().as_slice(), &[expected_data]);
    let copy = ProvenBlock::read_from_bytes(&block.to_bytes())?;
    assert_eq!(copy.body().log_data(), block.body().log_data());
    Ok(())
}

#[tokio::test]
async fn logs_do_not_make_an_empty_transaction_valid() -> anyhow::Result<()> {
    let tx = TestTransactionBuilder::with_noop_auth_account()
        .add_advice_map_entry(Word::empty(), vec![])
        .build()?;
    crate::assert_execution_error!(
        tx.execute_code(
            r"
            use miden::tx_kernel_core::prologue
            use miden::tx_kernel_core::tx_log
            use miden::tx_kernel_core::epilogue
            begin
                exec.prologue::prepare_transaction
                padw push.29.17 exec.tx_log::add_log
                exec.epilogue::finalize_transaction
            end
            "
        )
        .await,
        tx_kernel::ERR_EPILOGUE_EXECUTED_TRANSACTION_IS_EMPTY
    );
    Ok(())
}

#[rstest]
#[case::public_falcon(AccountType::Public, AuthScheme::Falcon512Poseidon2)]
#[case::private_falcon(AccountType::Private, AuthScheme::Falcon512Poseidon2)]
#[case::public_ecdsa(AccountType::Public, AuthScheme::EcdsaK256Keccak)]
#[case::private_ecdsa(AccountType::Private, AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn standard_auth_signs_nonempty_logs(
    #[case] account_type: AccountType,
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let component = log_emitter_component(Word::empty())?;
    let root = component.get_procedure_root_by_path(EMIT_LOG_PROC).unwrap();
    let mut builder = MockChain::builder();
    let account = builder.add_account_from_builder(
        Auth::BasicAuth { auth_scheme },
        AccountBuilder::new([76; 32])
            .account_type(account_type)
            .with_component(component),
        AccountState::Exists,
    )?;
    let chain = builder.build()?;
    let mut tx = chain
        .build_transaction(account.clone())
        .tx_script(CodeBuilder::default().compile_tx_script(format!(
            r"
            use miden::core::sys
            @transaction_script
            pub proc main
                call.{root} exec.sys::truncate_stack
            end
            "
        ))?)
        .add_advice_map_entry(Word::empty(), vec![])
        .build()?;
    tx.set_tx_args(tx.tx_args().clone().with_log_salt(Word::from([1u32, 2, 3, 4])));
    let executed = tx.execute().await?;
    let effects = TransactionEffects::from(&executed);
    let final_nonce = account.nonce() + Felt::ONE;
    let summary = TransactionSummary::new(
        AccountDelta::new(
            account.id(),
            Default::default(),
            Default::default(),
            Default::default(),
            Felt::ONE,
        )?,
        executed.input_notes().clone(),
        executed.output_notes().clone(),
        effects.ref_block_number(),
        effects.ref_block_commitment(),
        0,
        TransactionSummaryUserParams::new([
            final_nonce,
            0u32.into(),
            0u32.into(),
            0u32.into(),
            0u32.into(),
            0u32.into(),
        ]),
    )
    .with_logs(executed.logs().clone(), effects.log_salt())?;
    assert_eq!(summary.logs_commitment(), executed.logs_commitment());
    let keys = miden_standards::testing::account_interface::get_public_keys_from_account(&account);
    let key = Hasher::merge(&[keys[0], summary.to_commitment()]);
    assert!(executed.advice_witness().map().get(&key).is_some());
    Ok(())
}

// TEST HELPERS
// ================================================================================================

/// Runs a kernel transaction log procedure after initializing the transaction context.
fn kernel_log_program(body: &str) -> String {
    format!(
        r"
        use miden::tx_kernel_core::prologue
        use miden::tx_kernel_core::tx_log
        begin
            exec.prologue::prepare_transaction
            {body}
        end
        "
    )
}

/// An account procedure that emits one transaction log with the supplied payload commitment.
fn log_emitter_component(payload_commitment: Word) -> anyhow::Result<AccountComponent> {
    Ok(AccountComponent::new(
        CodeBuilder::default().compile_component_code(
            "test::transaction_logs",
            format!(
                r"
                use miden::protocol::tx
                @account_procedure
                pub proc emit_log
                    push.{payload_commitment} push.29.17 exec.tx::add_log
                end
                "
            ),
        )?,
        vec![],
        AccountComponentMetadata::mock("test::transaction_logs"),
    )?)
}

/// Mutations of the two public transaction logs emitted by the proof test.
fn tampered_public_log_data(
    logs: &TransactionLogs,
) -> anyhow::Result<Vec<(&'static str, TransactionLogData)>> {
    let entries = logs.clone().into_vec();
    let mut added = entries.clone();
    added.push(entries[0].clone());
    let mut reordered = entries.clone();
    reordered.reverse();
    let mut altered = entries.clone();
    altered[0] =
        TransactionLog::new(entries[0].emitter(), entries[0].topic(), vec![Word::empty()])?;
    [
        ("removed all", vec![]),
        ("removed last", entries[..1].to_vec()),
        ("added", added),
        ("reordered", reordered),
        ("changed payload", altered),
    ]
    .into_iter()
    .map(|(case, entries)| Ok((case, TransactionLogData::Public(TransactionLogs::new(entries)?))))
    .collect()
}
