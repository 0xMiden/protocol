use alloc::string::String;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::ExecutionError;
use miden_processor::crypto::random::RandomCoin;
use miden_processor::operation::OperationError;
use miden_protocol::account::auth::{AuthScheme, SignatureKey};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountDelta,
    AccountType,
};
use miden_protocol::errors::{MasmError, TransactionVerifierError, tx_kernel};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PRIVATE_SENDER,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_protocol::testing::noop_auth_component::NoopAuthComponent;
use miden_protocol::transaction::{
    LogTopic,
    ProvenTransaction,
    TransactionEffects,
    TransactionLog,
    TransactionLogDetails,
    TransactionLogs,
    TransactionSummary,
    TransactionSummaryUserParams,
    TransactionVerifier,
};
use miden_protocol::{Felt, Hasher, MIN_PROOF_SECURITY_LEVEL, WORD_SIZE, Word};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_interface::get_public_keys_from_account;
use miden_standards::testing::mock_account::MockAccountExt;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::{
    LocalTransactionProver,
    TransactionExecutor,
    TransactionExecutorError,
    TransactionKernelError,
};
use rstest::rstest;

use crate::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    TestTransactionBuilder,
    assert_execution_error,
    assert_transaction_executor_error,
};

const EMIT_LOG_PROC: &str = "test::transaction_logs::emit_log";

#[rstest]
#[case::max_count(TransactionLogs::MAX_COUNT, 1, None)]
#[case::count(TransactionLogs::MAX_COUNT + 1, 0, Some(tx_kernel::ERR_TX_LOG_COUNT_EXCEEDED))]
#[case::max_content(1, TransactionLog::MAX_NUM_WORDS, None)]
#[case::max_total_content(2, TransactionLogs::MAX_NUM_WORDS / 2, None)]
#[case::individual_content(1, TransactionLog::MAX_NUM_WORDS + 1, Some(tx_kernel::ERR_TX_LOG_CONTENT_TOO_LARGE))]
#[case::total_content(2, TransactionLogs::MAX_NUM_WORDS / 2 + 1, Some(tx_kernel::ERR_TX_LOG_TOTAL_CONTENT_TOO_LARGE))]
#[tokio::test]
async fn kernel_enforces_log_limits(
    #[case] count: usize,
    #[case] content_words: usize,
    #[case] error: Option<MasmError>,
) -> anyhow::Result<()> {
    let (content, commitment) = content(vec![Word::from([71u32; 4]); content_words]);
    let tx = TestTransactionBuilder::with_existing_mock_account()
        .add_advice_map_entry(commitment, Word::words_as_elements(&content).to_vec())
        .build()?;
    let code = kernel_log_program(&format!(
        r"
        repeat.{count}
            push.{commitment} push.29.17 exec.tx::add_log
        end
        "
    ));
    if let Some(error) = error {
        assert_execution_error!(tx.execute_code(&code).await, error);
    } else {
        tx.execute_code(&code).await?;
    }
    Ok(())
}

#[tokio::test]
async fn kernel_logs_reject_forged_content() -> anyhow::Result<()> {
    let commitment = Word::from([19u32; WORD_SIZE]);
    let tx = TestTransactionBuilder::with_existing_mock_account()
        .add_advice_map_entry(commitment, vec![71u32.into(); WORD_SIZE])
        .build()?;
    let code = kernel_log_program(&format!("push.{commitment} push.29.17 exec.tx::add_log"));
    assert_execution_error!(
        tx.execute_code(&code).await,
        matches ExecutionError::OperationError {
            err: OperationError::FailedAssertion { err_code, .. },
            ..
        } if err_code == Felt::ZERO
    );
    Ok(())
}

#[rstest]
#[case::partial_first_word(WORD_SIZE - 1)]
#[case::partial_second_word(WORD_SIZE + 1)]
#[tokio::test]
async fn kernel_logs_reject_partial_words(#[case] num_elements: usize) -> anyhow::Result<()> {
    let elements = vec![71u32.into(); num_elements];
    // Even a valid content hash must not bypass the full-word requirement.
    let commitment = Hasher::hash_elements(&elements);
    let tx = TestTransactionBuilder::with_existing_mock_account()
        .add_advice_map_entry(commitment, elements)
        .build()?;
    let code = kernel_log_program(&format!("push.{commitment} push.29.17 exec.tx::add_log"));
    assert_execution_error!(
        tx.execute_code(&code).await,
        tx_kernel::ERR_TX_LOG_CONTENT_NOT_WORD_ALIGNED
    );
    Ok(())
}

#[rstest]
#[case::empty(0, None)]
#[case::odd_words(3, None)]
#[case::max_content(TransactionLog::MAX_NUM_WORDS, None)]
#[case::oversized(TransactionLog::MAX_NUM_WORDS + 1, Some(tx_kernel::ERR_TX_LOG_CONTENT_TOO_LARGE))]
#[tokio::test]
async fn add_log_from_memory(
    #[case] num_words: usize,
    #[case] error: Option<MasmError>,
) -> anyhow::Result<()> {
    let word = Word::from([11u32, 22, 33, 44]);
    let store_content: String = (0..num_words)
        .map(|i| format!("push.{word} loc_storew_le.{} dropw\n", i * WORD_SIZE))
        .collect();
    let component = AccountComponent::new(
        CodeBuilder::default().compile_component_code(
            "test::log_from_memory",
            format!(
                r"
                use miden::protocol::tx
                use miden::protocol::native_account

                @auth_script
                @locals({num_locals})
                pub proc auth
                    {store_content}
                    push.101.102.103.104
                    # => [CALLER_WORD]

                    locaddr.0 push.{num_words}.29.17
                    # => [topic_suffix, topic_prefix, num_words, content_ptr, CALLER_WORD]

                    exec.tx::add_log_from_memory
                    # => [CALLER_WORD]

                    push.101.102.103.104 assert_eqw
                    # => []

                    exec.native_account::incr_nonce drop
                end
                ",
                num_locals = num_words.max(1) * WORD_SIZE,
            ),
        )?,
        vec![],
        AccountComponentMetadata::mock("test::log_from_memory"),
    )?;
    let account = Account::mock(ACCOUNT_ID_PRIVATE_SENDER, [component]);
    let emitter = account.id();
    let tx = TestTransactionBuilder::new(account).build()?;
    if let Some(error) = error {
        assert_transaction_executor_error!(tx.execute().await, error);
    } else {
        let executed = tx.execute().await?;
        let log = TransactionLog::new(emitter, LogTopic::mock(17, 29), vec![word; num_words])?;
        let expected = TransactionLogs::new(vec![log])?;
        assert_eq!(executed.logs(), &expected);
    }
    Ok(())
}

#[tokio::test]
async fn transaction_scripts_cannot_log_directly() -> anyhow::Result<()> {
    let empty_commitment = Hasher::hash_elements::<Felt>(&[]);
    let script = CodeBuilder::default().compile_tx_script(format!(
        r"
            use miden::protocol::tx
            @transaction_script
            pub proc main
                push.{empty_commitment} push.29.17 exec.tx::add_log
            end
            ",
    ))?;
    let tx = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(script)
        .add_advice_map_entry(empty_commitment, vec![])
        .build()?;
    assert_transaction_executor_error!(
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
#[tokio::test]
async fn unauthenticated_note_logs(
    #[case] account_type: AccountType,
    #[case] direct: bool,
) -> anyhow::Result<()> {
    let (content, content_commitment) = content(vec![Word::from([11u32, 22, 33, 44])]);
    let component = log_emitter_component(content_commitment)?;
    let root = component.get_procedure_root_by_path(EMIT_LOG_PROC).unwrap();
    let account = AccountBuilder::new([83; 32])
        .account_type(account_type)
        .with_components(Auth::IncrNonce)
        .with_component(component)
        .build_existing()?;
    let emit = if direct {
        format!("push.{content_commitment} push.29.17 exec.tx::add_log")
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
    let chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    let tx = chain
        .build_transaction(account.clone())
        .unauthenticated_input_note(note)
        .add_advice_map_entry(content_commitment, Word::words_as_elements(&content).to_vec())
        .build()?;
    if direct {
        assert_transaction_executor_error!(
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
        TransactionLog::new(account.id(), LogTopic::new(17u32.into(), 29u32.into()), content)?;
    assert_eq!(executed.logs().iter().collect::<Vec<_>>(), vec![&expected]);
    let (_, outputs, ..) = executed.into_parts();
    let (_, _, log_details) = outputs.into_parts();
    assert_eq!(
        matches!(log_details, TransactionLogDetails::Public(_)),
        account_type.is_public()
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
    let topic = LogTopic::new(17u32.into(), 29u32.into());
    let mut entries = Vec::new();
    let mut builder = TestTransactionBuilder::new(account.clone());
    let mut code = String::from("exec.tx::get_logs_commitment padw assert_eqw\n");
    // Leave room for the empty, one-word, and odd/even content cases before filling the budget.
    for num_words in [0usize, 1, 2, 3, TransactionLogs::MAX_NUM_WORDS - 6] {
        let content = (0..num_words).map(|i| Word::from([i as u32 + 1; 4])).collect();
        let entry = TransactionLog::new(account.id(), topic, content)?;
        let content_commitment = entry.content_commitment();
        builder = builder.add_advice_map_entry(
            content_commitment,
            Word::words_as_elements(entry.content()).to_vec(),
        );
        entries.push(entry);
        let expected = TransactionLogs::new(entries.clone())?.commitment();
        code.push_str(&format!(
            r"
            push.{content_commitment} push.29.17 exec.tx::add_log
            exec.tx::get_logs_commitment push.{expected} assert_eqw
            exec.tx::get_logs_commitment push.{expected} assert_eqw
            ",
        ));
    }
    let code = kernel_log_program(&code);
    let tx = builder.build()?;
    tx.execute_code(&code).await?;
    Ok(())
}

#[rstest]
#[case::public(AccountType::Public)]
#[case::private(AccountType::Private)]
#[tokio::test]
async fn transaction_proofs_bind_logs(#[case] account_type: AccountType) -> anyhow::Result<()> {
    let (content, content_commitment) = content(vec![Word::from([111u32, 222, 333, 444])]);
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
                push.{content_commitment} push.29.17 exec.tx::add_log
                exec.tx::get_logs_commitment dropw
                push.{content_commitment} push.31.17 exec.tx::add_log
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
    let tx = TestTransactionBuilder::new(account.clone())
        .add_advice_map_entry(content_commitment, Word::words_as_elements(&content).to_vec())
        .build()?;
    let executed = tx.execute().await?;
    assert_eq!(executed.logs().num_logs(), 2);
    assert_eq!(executed.logs_commitment(), executed.logs().commitment());
    let log = &executed.logs().iter().next().unwrap();
    assert_eq!(log.emitter(), account.id());
    assert_eq!(log.content(), content);

    let proven = LocalTransactionProver::default().prove(executed.clone())?;
    assert_eq!(proven.id(), executed.id());
    let verifier = TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL);
    assert!(verifier.verify(&proven)?.is_complete());
    assert_eq!(
        matches!(proven.log_details(), TransactionLogDetails::Public(_)),
        account_type.is_public()
    );
    let log_details = match proven.log_details() {
        TransactionLogDetails::Public(logs) => {
            let mut entries = logs.clone().into_vec();
            let log = &entries[0];
            entries[0] = TransactionLog::new(log.emitter(), log.topic(), vec![Word::empty()])?;
            TransactionLogDetails::Public(TransactionLogs::new(entries)?)
        },
        TransactionLogDetails::Private(commitment) => {
            let mut commitment = *commitment;
            commitment[0] += Felt::ONE;
            TransactionLogDetails::Private(commitment)
        },
    };
    let tampered = ProvenTransaction::new(
        proven.account_update().clone(),
        proven.input_notes().iter().cloned(),
        proven.output_notes().iter().cloned(),
        proven.ref_block_num(),
        proven.ref_block_commitment(),
        proven.expiration_block_num(),
        proven.proof().clone(),
        log_details,
    )?;
    assert!(matches!(
        verifier.verify(&tampered),
        Err(TransactionVerifierError::TransactionVerificationFailed(_))
    ));
    Ok(())
}

#[rstest]
#[case::public_native_private_emitter(AccountType::Public, AccountType::Private)]
#[case::private_native_public_emitter(AccountType::Private, AccountType::Public)]
#[tokio::test]
async fn foreign_logs_use_the_emitter_and_native_visibility(
    #[case] native_type: AccountType,
    #[case] foreign_type: AccountType,
) -> anyhow::Result<()> {
    let empty_commitment = Hasher::hash_elements::<Felt>(&[]);
    let component = log_emitter_component(empty_commitment)?;
    let proc_root = component
        .get_procedure_root_by_path(EMIT_LOG_PROC)
        .context("foreign transaction log procedure")?;
    let foreign = AccountBuilder::new([51; 32])
        .account_type(foreign_type)
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
                push.{empty_commitment} push.31.17 exec.tx::add_log
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
        .account_type(foreign_type)
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
    let tx = chain
        .build_transaction(native.clone())
        .foreign_accounts([inputs, intermediate_inputs])
        .tx_script(script)
        .add_advice_map_entry(empty_commitment, vec![])
        .build()?;
    let executed = tx.execute().await?;
    let entries = executed.logs().iter().collect::<Vec<_>>();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].emitter(), intermediate.id());
    assert_eq!(entries[1].emitter(), foreign.id());
    let (_, outputs, ..) = executed.into_parts();
    let (_, _, log_details) = outputs.into_parts();
    assert_eq!(matches!(log_details, TransactionLogDetails::Public(_)), native_type.is_public());
    Ok(())
}

#[rstest]
#[case::public_falcon(AccountType::Public, AuthScheme::Falcon512Eidos)]
#[case::private_ecdsa(AccountType::Private, AuthScheme::EcdsaK256Keccak)]
#[tokio::test]
async fn standard_auth_rejects_replayed_transaction_log_signatures(
    #[case] account_type: AccountType,
    #[case] auth_scheme: AuthScheme,
) -> anyhow::Result<()> {
    let empty_commitment = Hasher::hash_elements::<Felt>(&[]);
    let component = log_emitter_component(empty_commitment)?;
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
    let tx = chain
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
        .add_advice_map_entry(empty_commitment, vec![])
        .build()?;
    let executed = tx.execute().await?;
    let effects = TransactionEffects::from(&executed);
    let final_nonce = account.nonce() + Felt::ONE;
    let account_delta = AccountDelta::new(
        account.id(),
        Default::default(),
        Default::default(),
        Default::default(),
        Felt::ONE,
    )?;
    let build_summary = |logs| {
        TransactionSummary::new(
            account_delta.clone(),
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
            logs,
        )
    };
    let summary = build_summary(executed.logs().clone());
    assert_eq!(summary.logs_commitment(), executed.logs_commitment());
    let keys = get_public_keys_from_account(&account);
    let key = SignatureKey::new(keys[0].into(), summary.to_commitment());
    let signature = executed
        .tx_inputs()
        .signatures()
        .iter()
        .find(|signature| signature.key() == key)
        .context("transaction should have signed the log summary")?;

    // Replay a real signature with no authenticator available to replace it. First establish
    // that the same transaction succeeds, then change only its transaction logs.
    let replay = chain.build_transaction(account.clone()).build()?;
    let executor = TransactionExecutor::<_, ()>::new(&replay);
    let execute = |args| {
        executor.execute_transaction(
            account.id(),
            effects.ref_block_number(),
            executed.input_notes().clone(),
            args,
        )
    };
    let mut args = executed.tx_args().clone();
    args.add_signature(signature.clone());
    assert_eq!(execute(args).await?.id(), executed.id());

    let twice = CodeBuilder::default().compile_tx_script(format!(
        r"
        use miden::core::sys
        @transaction_script
        pub proc main
            call.{root} call.{root}
            # => [pad(16)]

            exec.sys::truncate_stack
        end
        "
    ))?;
    let doubled = TransactionLogs::new(vec![executed.logs().iter().next().unwrap().clone(); 2])?;
    let changed_summary = build_summary(doubled);
    let mut args = executed.tx_args().clone().with_tx_script(twice);
    let changed_key = SignatureKey::new(keys[0].into(), changed_summary.to_commitment());
    assert_ne!(key, changed_key);
    args.extend_advice_map([(changed_key.to_advice_map_key(), signature.to_encoded_signature())]);
    // The supplied signature reaches verification and fails there, rather than failing
    // because no signature or authenticator was available.
    let error = execute(args).await.unwrap_err();
    assert!(
        matches!(
            error,
            TransactionExecutorError::TransactionProgramExecutionFailed(
                ExecutionError::OperationError {
                    err: OperationError::NotU32Values { .. },
                    ..
                } | ExecutionError::DeferredError { .. }
            )
        ),
        "unexpected signature replay failure: {error}"
    );

    Ok(())
}

#[tokio::test]
async fn signing_summary_cannot_omit_transaction_logs() -> anyhow::Result<()> {
    let empty_commitment = Hasher::hash_elements::<Felt>(&[]);
    let component = AccountComponent::new(
        CodeBuilder::default().compile_component_code(
            "test::omitted_transaction_logs",
            format!(
                r#"
            use miden::protocol::native_account
            use miden::protocol::tx
            use miden::standards::auth
            const UNAUTHORIZED = event("miden::protocol::auth::unauthorized")

            @auth_script
            pub proc authenticate
                dropw exec.native_account::incr_nonce drop
                # => []

                padw push.0.0 exec.auth::get_default_tx_summary_commitment
                # => [MESSAGE_WITHOUT_LOGS]

                push.{empty_commitment} push.29.17 exec.tx::add_log
                # => [MESSAGE_WITHOUT_LOGS]

                emit.UNAUTHORIZED
            end
            "#
            ),
        )?,
        vec![],
        AccountComponentMetadata::mock("test::omitted_transaction_logs"),
    )?;
    let account = AccountBuilder::new([77; 32])
        .account_type(AccountType::Private)
        .with_component(component)
        .with_component(BasicWallet)
        .build_existing()?;
    let tx = TestTransactionBuilder::new(account)
        .add_advice_map_entry(empty_commitment, vec![])
        .build()?;
    assert_transaction_executor_error!(
        tx.execute().await,
        matches ExecutionError::EventError { error: ref event_err, .. }
            if matches!(
                event_err.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::Other { message, .. })
                    if message.as_ref() == "summary transaction logs commitment mismatch"
            )
    );
    Ok(())
}

// TEST HELPERS
// ================================================================================================

/// Returns content and its commitment for the advice map.
fn content(words: Vec<Word>) -> (Vec<Word>, Word) {
    let commitment = Hasher::hash_elements(Word::words_as_elements(&words));
    (words, commitment)
}

/// Runs a kernel transaction log procedure after initializing the transaction context.
fn kernel_log_program(body: &str) -> String {
    format!(
        r"
        use miden::tx_kernel_core::prologue
        use miden::tx_kernel_core::tx
        begin
            exec.prologue::prepare_transaction
            {body}
        end
        "
    )
}

/// An account procedure that emits one transaction log with the supplied content commitment.
fn log_emitter_component(content_commitment: Word) -> anyhow::Result<AccountComponent> {
    Ok(AccountComponent::new(
        CodeBuilder::default().compile_component_code(
            "test::transaction_logs",
            format!(
                r"
                use miden::protocol::tx
                @account_procedure
                pub proc emit_log
                    push.{content_commitment} push.29.17 exec.tx::add_log
                end
                "
            ),
        )?,
        vec![],
        AccountComponentMetadata::mock("test::transaction_logs"),
    )?)
}
