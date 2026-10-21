use miden_processor::operation::OperationError;
use miden_processor::{ExecutionError, MemoryError};
use miden_protocol::account::{
    AccountBuilder,
    AccountCodePatch,
    AccountComponent,
    AccountComponentMetadata,
    AccountDelta,
    AccountStoragePatch,
    AccountType,
    AccountVaultDelta,
    StorageArray,
    StorageArrayLength,
    StorageArrayPatch,
    StorageArrayPatchEntries,
    StorageSlot,
    StorageSlotName,
    StorageSlotPatch,
    StorageSlotType,
};
use miden_protocol::errors::tx_kernel::{
    ERR_ACCOUNT_IS_NOT_NATIVE,
    ERR_ACCOUNT_SETTING_VALUE_ITEM_ON_NON_VALUE_SLOT,
    ERR_ACCOUNT_STORAGE_ARRAY_LENGTH_INVALID,
    ERR_ACCOUNT_STORAGE_ARRAY_PREIMAGE_LENGTH,
    ERR_ACCOUNT_STORAGE_PAYLOAD_TOO_LARGE,
    ERR_ACCOUNT_STORAGE_SLOT_NOT_ARRAY,
};
use miden_protocol::transaction::TransactionVerifier;
use miden_protocol::transaction::memory::{
    ACCT_STORAGE_SLOT_NUM_ELEMENTS,
    ACCT_STORAGE_SLOT_TYPE_OFFSET,
};
use miden_protocol::{Felt, Hasher, MIN_PROOF_SECURITY_LEVEL, Word};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_tx::{LocalTransactionProver, TransactionKernelError};
use rstest::rstest;

use crate::{
    Auth,
    MockChainBuilder,
    TestTransactionBuilder,
    assert_execution_error,
    assert_transaction_executor_error,
};

fn array_slot() -> StorageSlotName {
    StorageSlotName::new("test::arrays::values").unwrap()
}

fn array_component(body: &str, array: StorageArray) -> anyhow::Result<AccountComponent> {
    let active_import = if body.contains("active_account::") {
        "use miden::protocol::active_account"
    } else {
        ""
    };
    let native_import = if body.contains("native_account::") {
        "use miden::protocol::native_account"
    } else {
        ""
    };
    Ok(AccountComponent::new(
        CodeBuilder::default().compile_component_code(
            "test::arrays",
            format!(
                r"
            {active_import}
            {native_import}
            @account_procedure
            pub proc exercise
                {body}
            end
        "
            ),
        )?,
        vec![StorageSlot::with_array(array_slot(), array)],
        AccountComponentMetadata::mock("test::arrays"),
    )?)
}

#[rstest]
#[case::one_word(1)]
#[case::odd_length(3)]
#[case::payload_limit(256)]
#[tokio::test]
async fn storage_array_read_write_and_sparse_patch(#[case] length: usize) -> anyhow::Result<()> {
    let initial = StorageArray::new((0..length).map(|i| Word::from([i as u32 + 1; 4])).collect())?;
    let id = array_slot().id();
    let slot = format!("{}.{}", id.prefix(), id.suffix());
    let end_ptr = 1024 + length * Word::NUM_ELEMENTS;
    let body = format!(
        r"
        # A deeper stack word and buffer sentinels must survive all wrappers.
        push.101.102.103.104
        push.77 mem_store.1020 push.88 mem_store.{end_ptr}
        push.{slot} exec.active_account::get_array_length eq.{length} assert
        push.1024 push.{slot} exec.active_account::get_array eq.{length} assert
        padw mem_loadw_le.1024 push.1.1.1.1 assert_eqw
        padw mem_storew_le.1024 dropw
        push.1024 push.{slot} exec.native_account::set_array eq.{length} assert
        push.4096 push.{slot} exec.native_account::get_initial_array eq.{length} assert
        padw mem_loadw_le.4096 push.1.1.1.1 assert_eqw
        push.1024 push.{slot} exec.active_account::get_array eq.{length} assert
        padw mem_loadw_le.1024 padw assert_eqw
        mem_load.1020 eq.77 assert mem_load.{end_ptr} eq.88 assert
        push.101.102.103.104 assert_eqw
    "
    );
    let component = array_component(&body, initial.clone())?;
    let root = component.get_procedure_root_by_path("test::arrays::exercise").unwrap();
    let account = AccountBuilder::new([37; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(component)
        .build_existing()?;
    let script = CodeBuilder::default().compile_tx_script(format!(
        r"
        @transaction_script
        pub proc main
            call.{root}
        end
    "
    ))?;
    let executed = TestTransactionBuilder::new(account.clone())
        .tx_script(script)
        .build()?
        .execute()
        .await?;
    let expected = StorageArrayPatchEntries::new(initial.length(), [(0, Word::empty())])?;
    assert_eq!(
        executed.account_patch().storage().get(&array_slot()),
        Some(&StorageSlotPatch::Array(StorageArrayPatch::Update { entries: expected }))
    );
    let mut updated = account;
    updated.apply_patch(executed.account_patch())?;
    assert_eq!(updated.storage().get_array(&array_slot())?.values()[0], Word::empty());
    Ok(())
}

#[tokio::test]
async fn storage_array_restored_words_are_omitted() -> anyhow::Result<()> {
    let initial = StorageArray::new(vec![Word::from([1u32; 4]); 3])?;
    let id = array_slot().id();
    let slot = format!("{}.{}", id.prefix(), id.suffix());
    let body = format!(
        r"
        push.1024 push.{slot} exec.active_account::get_array drop
        padw mem_storew_le.1024 dropw
        push.1024 push.{slot} exec.native_account::set_array drop
        push.1.1.1.1 mem_storew_le.1024 dropw
        push.1024 push.{slot} exec.native_account::set_array drop
    "
    );
    let component = array_component(&body, initial)?;
    let root = component.get_procedure_root_by_path("test::arrays::exercise").unwrap();
    let account = AccountBuilder::new([38; 32])
        .with_components(Auth::IncrNonce)
        .with_component(component)
        .build_existing()?;
    let script = CodeBuilder::default()
        .compile_tx_script(format!(r"@transaction_script pub proc main call.{root} end"))?;
    let executed = TestTransactionBuilder::new(account)
        .tx_script(script)
        .build()?
        .execute()
        .await?;
    assert!(executed.account_patch().storage().is_empty());
    Ok(())
}

#[tokio::test]
async fn prove_storage_array_update() -> anyhow::Result<()> {
    let initial = StorageArray::new(vec![Word::empty(); 3])?;
    let id = array_slot().id();
    let slot = format!("{}.{}", id.prefix(), id.suffix());
    let body = format!(
        r"
        push.1024 push.{slot} exec.active_account::get_array drop
        push.4.3.2.1 mem_storew_le.1028 dropw
        push.1024 push.{slot} exec.native_account::set_array drop
    "
    );
    let component = array_component(&body, initial)?;
    let root = component.get_procedure_root_by_path("test::arrays::exercise").unwrap();
    let account = AccountBuilder::new([39; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(component)
        .build_existing()?;
    let script = CodeBuilder::default()
        .compile_tx_script(format!(r"@transaction_script pub proc main call.{root} end"))?;
    let executed = TestTransactionBuilder::new(account)
        .tx_script(script)
        .build()?
        .execute()
        .await?;
    let proven = LocalTransactionProver::default().prove(executed.clone())?;
    assert_eq!(proven.account_update().details().unwrap_public(), executed.account_patch());
    assert!(
        TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL)
            .verify(&proven)?
            .is_complete()
    );
    Ok(())
}

#[tokio::test]
async fn storage_array_setter_rejects_malformed_preimages() -> anyhow::Result<()> {
    let initial = StorageArray::new(vec![Word::empty(); 3])?;
    let id = array_slot().id();
    let slot = format!("{}.{}", id.prefix(), id.suffix());
    let component = array_component("push.0 drop", initial)?;
    let account = AccountBuilder::new([40; 32])
        .with_components(Auth::IncrNonce)
        .with_component(component)
        .build_existing()?;
    let data = vec![Felt::ONE; 12];
    let root = Hasher::hash_elements(&data);
    let mut corrupted = data.clone();
    corrupted[0] += Felt::ONE;
    for preimage in [data[..8].to_vec(), corrupted] {
        let preimage_length_is_invalid = preimage.len() != data.len();
        let tx = TestTransactionBuilder::new(account.clone())
            .add_advice_map_entry(root, preimage)
            .build()?;
        let code = format!(
            r"
            use miden::tx_kernel_core::account
            use miden::tx_kernel_core::prologue
            begin
                exec.prologue::prepare_transaction
                push.{root} push.{slot} exec.account::set_array drop
            end
        "
        );
        if preimage_length_is_invalid {
            assert_execution_error!(
                tx.execute_code(&code).await,
                ERR_ACCOUNT_STORAGE_ARRAY_PREIMAGE_LENGTH
            );
        } else {
            // The core preimage pipe uses an unlabelled assertion for commitment equality.
            assert_execution_error!(tx.execute_code(&code).await, matches ExecutionError::OperationError {
                err: OperationError::FailedAssertion { err_code, .. }, ..
            } if err_code == Felt::ZERO);
        }
    }
    Ok(())
}

#[rstest]
#[case::odd_length(3)]
#[case::max_length(256)]
#[tokio::test]
async fn storage_array_creation_commits_untouched_zero_words(
    #[case] length: usize,
) -> anyhow::Result<()> {
    let array = StorageArray::new(vec![Word::empty(); length])?;
    let component = array_component("push.0 drop", array.clone())?;
    let account = AccountBuilder::new([42; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(component)
        .build()?;
    let executed = TestTransactionBuilder::new(account).build()?.execute().await?;
    assert_eq!(
        executed.account_patch().storage().get(&array_slot()),
        Some(&StorageSlotPatch::Array(StorageArrayPatch::Create { array }))
    );
    Ok(())
}

#[rstest]
#[case::read(None)]
#[case::write(Some("set_array"))]
#[case::initial_read(Some("get_initial_array"))]
#[tokio::test]
async fn storage_array_foreign_access(
    #[case] native_procedure: Option<&str>,
) -> anyhow::Result<()> {
    let array = StorageArray::new(vec![Word::from([7u32; 4]); 3])?;
    let id = array_slot().id();
    let slot = format!("{}.{}", id.prefix(), id.suffix());
    let mut body = format!(
        r"
        push.1024 push.{slot} exec.active_account::get_array eq.3 assert
        padw mem_loadw_le.1024 push.7.7.7.7 assert_eqw
    "
    );
    if let Some(procedure) = native_procedure {
        body.push_str(&format!("push.1024 push.{slot} exec.native_account::{procedure} drop"));
    }
    let component = array_component(&body, array)?;
    let root = component.get_procedure_root_by_path("test::arrays::exercise").unwrap();
    let foreign = AccountBuilder::new([43; 32])
        .with_components(Auth::IncrNonce)
        .with_component(component)
        .build_existing()?;
    let native = AccountBuilder::new([44; 32])
        .with_components(Auth::IncrNonce)
        .with_component(BasicWallet)
        .build_existing()?;
    let mut chain = MockChainBuilder::with_accounts([native.clone(), foreign.clone()])?.build()?;
    chain.prove_next_block()?;
    let inputs = chain.get_foreign_account_inputs(foreign.clone())?;
    let script = CodeBuilder::default().compile_tx_script(format!(
        r"
        use miden::protocol::tx
        use miden::core::sys
        @transaction_script
        pub proc main
            padw padw push.0.0
            push.{root} push.{prefix}.{suffix}
            exec.tx::execute_foreign_procedure exec.sys::truncate_stack
        end
    ",
        prefix = foreign.id().prefix().as_felt(),
        suffix = foreign.id().suffix()
    ))?;
    let tx = chain
        .build_transaction(native)
        .foreign_accounts([inputs])
        .tx_script(script)
        .build()?;
    if native_procedure.is_some() {
        assert_transaction_executor_error!(tx.execute().await, ERR_ACCOUNT_IS_NOT_NATIVE);
    } else {
        let executed = tx.execute().await?;
        assert!(executed.account_patch().storage().is_empty());
        // Re-execution must retain the foreign header's full array preimage.
        LocalTransactionProver::default().prove_dummy(executed)?;
    }
    Ok(())
}

#[tokio::test]
async fn storage_array_new_account_checks_initial_preimage_before_overwrite() -> anyhow::Result<()>
{
    let array = StorageArray::new(vec![Word::from([7u32; 4]); 3])?;
    let initial_root = array.commitment();
    let id = array_slot().id();
    let component = array_component(
        &format!(
            "push.1024 push.{}.{} exec.native_account::set_array drop",
            id.prefix(),
            id.suffix()
        ),
        array,
    )?;
    let root = component.get_procedure_root_by_path("test::arrays::exercise").unwrap();
    let account = AccountBuilder::new([45; 32])
        .with_components(Auth::IncrNonce)
        .with_component(component)
        .build()?;
    let script = CodeBuilder::default()
        .compile_tx_script(format!("@transaction_script pub proc main call.{root} end"))?;
    let tx = TestTransactionBuilder::new(account)
        .tx_script(script)
        .add_advice_map_entry(initial_root, vec![Felt::ONE; 12])
        .build()?;
    assert_transaction_executor_error!(tx.execute().await, matches ExecutionError::OperationError {
        err: OperationError::FailedAssertion { err_code, .. }, ..
    } if err_code == Felt::ZERO);
    Ok(())
}

#[rstest]
#[case::at_limit(false)]
#[case::over_limit(true)]
#[tokio::test]
async fn storage_array_payload_budget_is_enforced_in_kernel(
    #[case] overflow: bool,
) -> anyhow::Result<()> {
    let tx = TestTransactionBuilder::with_existing_mock_account().build()?;
    let num_slots = usize::from(tx.account().storage().num_slots());
    // All unmodified slots contribute one word. Split the remaining budget between two arrays.
    let first_length = 128;
    let second_length = 256 - (num_slots - 2) - first_length + usize::from(overflow);
    let first_type = StorageSlotType::Array(StorageArrayLength::try_from(first_length)?).as_felt();
    let second_type =
        StorageSlotType::Array(StorageArrayLength::try_from(second_length)?).as_felt();
    let code = format!(
        r"
        use miden::tx_kernel_core::account
        use miden::tx_kernel_core::memory
        use miden::tx_kernel_core::prologue
        begin
            exec.prologue::prepare_transaction
            push.{first_type}
            exec.memory::get_native_account_active_storage_slots_ptr add.{ACCT_STORAGE_SLOT_TYPE_OFFSET} mem_store
            push.{second_type}
            exec.memory::get_native_account_active_storage_slots_ptr
            add.{ACCT_STORAGE_SLOT_NUM_ELEMENTS} add.{ACCT_STORAGE_SLOT_TYPE_OFFSET} mem_store
            exec.account::validate_storage
        end
    "
    );
    if overflow {
        assert_execution_error!(
            tx.execute_code(&code).await,
            ERR_ACCOUNT_STORAGE_PAYLOAD_TOO_LARGE
        );
    } else {
        tx.execute_code(&code).await?;
    }
    Ok(())
}

#[tokio::test]
async fn storage_array_repeated_delta_computation_matches_host() -> anyhow::Result<()> {
    let initial = StorageArray::new(vec![Word::empty(); 3])?;
    let id = array_slot().id();
    let slot = format!("{}.{}", id.prefix(), id.suffix());
    let auth = AccountComponent::new(
        CodeBuilder::default().compile_component_code(
            "test::array_auth",
            format!(
                r"
        use miden::protocol::native_account
        use {{AUTH_UNAUTHORIZED_EVENT}} from miden::protocol::auth
        @auth_script
        pub proc auth
            exec.native_account::incr_nonce drop
            push.1.1.1.1 mem_storew_le.1024 dropw
            push.1024 push.{slot} exec.native_account::set_array drop
            exec.native_account::compute_delta_commitment dropw
            # Restore one index and change another before computing the signing summary.
            padw mem_storew_le.1024 dropw
            push.2.2.2.2 mem_storew_le.1028 dropw
            push.1024 push.{slot} exec.native_account::set_array drop
            dropw padw push.0.0
            exec.::miden::standards::auth::get_default_tx_summary_commitment
            emit.AUTH_UNAUTHORIZED_EVENT
            push.0 assert
        end
    "
            ),
        )?,
        vec![],
        AccountComponentMetadata::mock("test::array_auth"),
    )?;
    let account = AccountBuilder::new([46; 32])
        .with_component(auth)
        .with_component(array_component("push.0 drop", initial.clone())?)
        .build_existing()?;
    let expected_storage = AccountStoragePatch::from_entries([(
        array_slot(),
        StorageSlotPatch::Array(StorageArrayPatch::Update {
            entries: StorageArrayPatchEntries::new(initial.length(), [(1, Word::from([2u32; 4]))])?,
        }),
    )])?;
    let expected = AccountDelta::new(
        account.id(),
        expected_storage,
        AccountVaultDelta::default(),
        AccountCodePatch::default(),
        Felt::ONE,
    )?;
    let summary = TestTransactionBuilder::new(account)
        .build()?
        .execute()
        .await
        .unwrap_err()
        .unwrap_unauthorized_err();
    assert_eq!(summary.account_delta(), &expected);
    Ok(())
}

#[rstest]
#[case::read("ACCOUNT_GET_ARRAY_INFO_OFFSET")]
#[case::initial_read("ACCOUNT_GET_INITIAL_ARRAY_INFO_OFFSET")]
#[case::write("ACCOUNT_SET_ARRAY_OFFSET")]
#[tokio::test]
async fn storage_array_syscall_requires_account_origin(#[case] offset: &str) -> anyhow::Result<()> {
    let array = StorageArray::new(vec![Word::empty(); 3])?;
    let commitment = array.commitment();
    let id = array_slot().id();
    let account = AccountBuilder::new([47; 32])
        .with_components(Auth::IncrNonce)
        .with_component(array_component("push.0 drop", array)?)
        .build_existing()?;
    let script = CodeBuilder::default().compile_tx_script(format!(
        r"
        use {{{offset}}} from miden::protocol::kernel_proc_offsets
        @transaction_script
        pub proc main
            push.{commitment} push.{prefix}.{suffix} push.{offset}
            push.0 movdn.7 padw padw swapdw
            syscall.exec_kernel_proc
        end
    ",
        prefix = id.prefix(),
        suffix = id.suffix()
    ))?;
    let tx = TestTransactionBuilder::new(account).tx_script(script).build()?;
    assert_transaction_executor_error!(tx.execute().await,
        matches ExecutionError::EventError { error: ref event_err, .. }
            if matches!(event_err.downcast_ref::<TransactionKernelError>(), Some(TransactionKernelError::UnknownAccountProcedure(_)))
    );
    Ok(())
}

#[tokio::test]
async fn storage_array_cannot_be_changed_through_value_setter() -> anyhow::Result<()> {
    let array = StorageArray::new(vec![Word::empty(); 3])?;
    let id = array_slot().id();
    let account = AccountBuilder::new([48; 32])
        .with_components(Auth::IncrNonce)
        .with_component(array_component("push.0 drop", array)?)
        .build_existing()?;
    let tx = TestTransactionBuilder::new(account).build()?;
    let code = format!(
        r"
        use miden::tx_kernel_core::account
        use miden::tx_kernel_core::prologue
        begin
            exec.prologue::prepare_transaction
            padw push.{prefix}.{suffix} exec.account::set_item dropw
        end
    ",
        prefix = id.prefix(),
        suffix = id.suffix()
    );
    assert_execution_error!(
        tx.execute_code(&code).await,
        ERR_ACCOUNT_SETTING_VALUE_ITEM_ON_NON_VALUE_SLOT
    );
    Ok(())
}

#[rstest]
#[case::unaligned(1025)]
#[case::range_overflow(u64::from(u32::MAX) - 3)]
#[case::non_u32(1u64 << 32)]
#[tokio::test]
async fn storage_array_rejects_invalid_memory_ranges(
    #[case] ptr: u64,
    #[values(
        "active_account::get_array",
        "native_account::get_initial_array",
        "native_account::set_array"
    )]
    procedure: &str,
) -> anyhow::Result<()> {
    let array = StorageArray::new(vec![Word::empty(); 3])?;
    let id = array_slot().id();
    let component = array_component(
        &format!("push.{ptr} push.{}.{} exec.{procedure} drop", id.prefix(), id.suffix()),
        array,
    )?;
    let root = component.get_procedure_root_by_path("test::arrays::exercise").unwrap();
    let account = AccountBuilder::new([49; 32])
        .with_components(Auth::IncrNonce)
        .with_component(component)
        .build_existing()?;
    let script = CodeBuilder::default()
        .compile_tx_script(format!(r"@transaction_script pub proc main call.{root} end"))?;
    let tx = TestTransactionBuilder::new(account).tx_script(script).build()?;
    if !ptr.is_multiple_of(Word::NUM_ELEMENTS as u64) {
        assert_transaction_executor_error!(tx.execute().await, matches ExecutionError::MemoryError {
            err: MemoryError::UnalignedWordAccess { .. }, ..
        });
    } else {
        assert_transaction_executor_error!(tx.execute().await, matches ExecutionError::OperationError {
            err: OperationError::NotU32Values { .. }, ..
        });
    }
    Ok(())
}

#[rstest]
#[case::zero_length(2, true)]
#[case::excessive_length(2 + (257u64 << 32), true)]
#[case::wrong_tag(3 + (3u64 << 32), false)]
#[tokio::test]
async fn storage_array_kernel_rejects_invalid_type_encodings(
    #[case] encoded_type: u64,
    #[case] invalid_length: bool,
) -> anyhow::Result<()> {
    let tx = TestTransactionBuilder::with_existing_mock_account().build()?;
    let code = format!(
        "use miden::tx_kernel_core::account begin push.{encoded_type} exec.account::array_length_from_type drop end"
    );
    if invalid_length {
        assert_execution_error!(
            tx.execute_code(&code).await,
            ERR_ACCOUNT_STORAGE_ARRAY_LENGTH_INVALID
        );
    } else {
        assert_execution_error!(tx.execute_code(&code).await, ERR_ACCOUNT_STORAGE_SLOT_NOT_ARRAY);
    }
    Ok(())
}
