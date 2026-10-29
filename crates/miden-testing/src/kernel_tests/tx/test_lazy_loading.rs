//! This module tests lazy loading.
//!
//! Once lazy loading is enabled generally, it can be removed and/or integrated into other tests.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Context;
use assert_matches::assert_matches;
use miden_processor::{ExecutionError, FutureMaybeSend, LoadedMastForest, MastForestStore};
use miden_protocol::Felt;
use miden_protocol::account::{
    AccountBuilder,
    AccountId,
    AccountStorage,
    AccountType,
    PartialAccount,
    StorageMap,
    StorageMapKey,
    StorageMapWitness,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, AssetId, AssetWitness, FungibleAsset};
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{NoteScript, NoteScriptRoot, NoteType};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2,
};
use miden_protocol::testing::constants::FUNGIBLE_ASSET_AMOUNT;
use miden_protocol::testing::storage::MOCK_MAP_SLOT;
use miden_protocol::transaction::{AccountInputs, PartialBlockchain};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockAccountComponent;
use miden_standards::testing::note::NoteBuilder;
use miden_tx::auth::UnreachableAuth;
use miden_tx::{
    DataStore,
    DataStoreError,
    DataStoreRequest,
    MAX_DATA_STORE_REQUESTS_PER_TX,
    NoteCheckerError,
    NoteConsumptionChecker,
    TransactionExecutor,
    TransactionExecutorError,
    TransactionKernelError,
};

use super::Word;
use crate::{
    Auth,
    MockChain,
    MockChainBuilder,
    MockTransaction,
    TestTransactionBuilder,
    assert_transaction_executor_error,
};

struct CountingDataStore<'a> {
    inner: &'a MockTransaction,
    storage_map_requests: AtomicUsize,
    fail_storage_map_requests: bool,
    note_script_requests: AtomicUsize,
    fail_note_script_requests: bool,
}

impl<'a> CountingDataStore<'a> {
    fn new(inner: &'a MockTransaction) -> Self {
        Self {
            inner,
            storage_map_requests: AtomicUsize::new(0),
            fail_storage_map_requests: false,
            note_script_requests: AtomicUsize::new(0),
            fail_note_script_requests: false,
        }
    }

    fn failing_storage_map_requests(inner: &'a MockTransaction) -> Self {
        Self {
            inner,
            storage_map_requests: AtomicUsize::new(0),
            fail_storage_map_requests: true,
            note_script_requests: AtomicUsize::new(0),
            fail_note_script_requests: false,
        }
    }

    fn failing_note_script_requests(inner: &'a MockTransaction) -> Self {
        Self {
            inner,
            storage_map_requests: AtomicUsize::new(0),
            fail_storage_map_requests: false,
            note_script_requests: AtomicUsize::new(0),
            fail_note_script_requests: true,
        }
    }

    fn storage_map_request_count(&self) -> usize {
        self.storage_map_requests.load(Ordering::Relaxed)
    }

    fn note_script_request_count(&self) -> usize {
        self.note_script_requests.load(Ordering::Relaxed)
    }
}

impl DataStore for CountingDataStore<'_> {
    fn get_transaction_inputs(
        &self,
        account_id: AccountId,
        ref_blocks: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<
        Result<(PartialAccount, BlockHeader, ProtocolConfig, PartialBlockchain), DataStoreError>,
    > {
        self.inner.get_transaction_inputs(account_id, ref_blocks)
    }

    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        self.inner.get_foreign_account_inputs(foreign_account_id, ref_block)
    }

    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        vault_root: Word,
        asset_ids: BTreeSet<AssetId>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        self.inner.get_vault_asset_witnesses(account_id, vault_root, asset_ids)
    }

    fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        map_root: Word,
        map_key: StorageMapKey,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        self.storage_map_requests.fetch_add(1, Ordering::Relaxed);
        async move {
            if self.fail_storage_map_requests {
                Err(DataStoreError::other("storage map request failed for test"))
            } else {
                self.inner.get_storage_map_witness(account_id, map_root, map_key).await
            }
        }
    }

    fn get_note_script(
        &self,
        script_root: NoteScriptRoot,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        self.note_script_requests.fetch_add(1, Ordering::Relaxed);
        async move {
            if self.fail_note_script_requests {
                Err(DataStoreError::other_with_source(
                    "note script request failed for test",
                    std::io::Error::other("nested note script cause"),
                ))
            } else {
                self.inner.get_note_script(script_root).await
            }
        }
    }
}

impl MastForestStore for CountingDataStore<'_> {
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest> {
        self.inner.get(procedure_hash)
    }
}

// ASSET LAZY LOADING
// ================================================================================================

/// Tests that adding two different assets to the account vault succeeds when lazy loading is
/// enabled.
#[tokio::test]
async fn adding_fungible_assets_with_lazy_loading_succeeds() -> anyhow::Result<()> {
    let faucet_id1: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let faucet_id2: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().unwrap();

    let fungible_asset1 =
        FungibleAsset::new(faucet_id1, FungibleAsset::MAX_AMOUNT.as_u64() - FUNGIBLE_ASSET_AMOUNT)?;
    let fungible_asset2 = FungibleAsset::new(faucet_id2, FUNGIBLE_ASSET_AMOUNT)?;

    // Build a note that adds the assets to the input vault of the transaction. This is necessary
    // to adhere to asset preservation rules.
    let asset_note = NoteBuilder::new(faucet_id1, rand::rng())
        .add_assets([fungible_asset1, fungible_asset2].map(Asset::from))
        .build()?;

    let code = format!(
        "
      use mock::account

      @transaction_script
      pub proc main
          push.{FUNGIBLE_ASSET_VALUE1}
          push.{FUNGIBLE_ASSET_ID1}
          call.account::add_asset dropw dropw

          push.{FUNGIBLE_ASSET_VALUE2}
          push.{FUNGIBLE_ASSET_ID2}
          call.account::add_asset dropw dropw
      end
      ",
        FUNGIBLE_ASSET_ID1 = fungible_asset1.to_id_word(),
        FUNGIBLE_ASSET_VALUE1 = fungible_asset1.to_value_word(),
        FUNGIBLE_ASSET_ID2 = fungible_asset2.to_id_word(),
        FUNGIBLE_ASSET_VALUE2 = fungible_asset2.to_value_word()
    );

    let builder = CodeBuilder::with_mock_packages();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;
    let mock_tx = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .input_note(asset_note)
        .with_source_manager(source_manager)
        .build()?;
    let account = mock_tx.account().clone();
    let tx = mock_tx.execute().await?;

    let mut account_vault = account.vault().clone();
    account_vault.add_asset(fungible_asset1.into())?;
    account_vault.add_asset(fungible_asset2.into())?;

    assert_eq!(tx.final_account().vault_root(), account_vault.root());

    Ok(())
}

/// Tests that removing two different assets from the account vault succeeds when lazy loading is
/// enabled.
#[tokio::test]
async fn removing_fungible_assets_with_lazy_loading_succeeds() -> anyhow::Result<()> {
    let faucet_id1: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into().unwrap();
    let faucet_id2: AccountId = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into().unwrap();

    let fungible_asset1 =
        FungibleAsset::new(faucet_id1, FungibleAsset::MAX_AMOUNT.as_u64() - FUNGIBLE_ASSET_AMOUNT)?;
    let fungible_asset2 = FungibleAsset::new(faucet_id2, FUNGIBLE_ASSET_AMOUNT)?;

    let code = format!(
        "
      use mock::account
      use mock::util

      @transaction_script
      pub proc main
          push.{FUNGIBLE_ASSET1_VALUE}
          push.{FUNGIBLE_ASSET1_KEY}
          call.account::remove_asset
          # drop the excess words from the call
          dropw dropw
          # => []

          # move asset to note to adhere to asset preservation rules
          push.{FUNGIBLE_ASSET1_VALUE}
          push.{FUNGIBLE_ASSET1_KEY}
          exec.util::create_default_note_with_asset
          # => []

          push.{FUNGIBLE_ASSET2_VALUE}
          push.{FUNGIBLE_ASSET2_KEY}
          call.account::remove_asset
          # drop the excess words from the call
          dropw dropw
          # => []

          # move asset to note to adhere to asset preservation rules
          push.{FUNGIBLE_ASSET2_VALUE}
          push.{FUNGIBLE_ASSET2_KEY}
          exec.util::create_default_note_with_asset
          # => []
      end
      ",
        FUNGIBLE_ASSET1_KEY = fungible_asset1.to_id_word(),
        FUNGIBLE_ASSET1_VALUE = fungible_asset1.to_value_word(),
        FUNGIBLE_ASSET2_KEY = fungible_asset2.to_id_word(),
        FUNGIBLE_ASSET2_VALUE = fungible_asset2.to_value_word(),
    );

    let builder = CodeBuilder::with_mock_packages();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;

    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account_with_assets(
        crate::Auth::IncrNonce,
        [fungible_asset1, fungible_asset2].map(Asset::from),
    )?;
    let mock_tx = builder
        .build()?
        .build_transaction(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;
    let account = mock_tx.account().clone();
    let tx = mock_tx.execute().await?;

    let mut account_vault = account.vault().clone();
    account_vault.remove_asset(fungible_asset1.into())?;
    account_vault.remove_asset(fungible_asset2.into())?;

    assert_eq!(tx.final_account().vault_root(), account_vault.root());

    // The lazy loaded witnesses must be in the native partial vault of the executed inputs.
    let partial_vault = tx.tx_inputs().account().vault();
    assert_eq!(partial_vault.get(fungible_asset1.id())?, Some(fungible_asset1.into()));
    assert_eq!(partial_vault.get(fungible_asset2.id())?, Some(fungible_asset2.into()));

    Ok(())
}

// STORAGE LAZY LOADING
// ================================================================================================

#[tokio::test]
async fn lazy_data_store_requests_are_bounded() -> anyhow::Result<()> {
    let map_keys = (0..=MAX_DATA_STORE_REQUESTS_PER_TX)
        .map(|index| StorageMapKey::from_array([0, 0, 0, index as u32]))
        .collect::<Vec<_>>();
    let map_entries = map_keys
        .iter()
        .enumerate()
        .map(|(index, key)| (*key, Word::from([index as u32 + 1, 0, 0, 0])))
        .collect::<Vec<_>>();
    let map_slot_name = StorageSlotName::mock(0);
    let account = AccountBuilder::new([3; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(vec![StorageSlot::with_map(
            map_slot_name.clone(),
            StorageMap::with_entries(map_entries.into_iter())?,
        )]))
        .build_existing()?;
    let accesses = map_keys
        .iter()
        .map(|key| {
            format!(
                "push.{key}\n\
                 push.MOCK_MAP_SLOT[0..2]\n\
                 call.account::get_map_item\n\
                 dropw\n\
                 exec.sys::truncate_stack"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let code = format!(
        r#"
        use miden::core::sys
        use mock::account

        const MOCK_MAP_SLOT = word("{map_slot_name}")

        @transaction_script
        pub proc main
            {accesses}
        end
        "#
    );
    let builder = CodeBuilder::with_mock_packages();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;
    let mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    let mock_tx = mock_chain
        .build_transaction(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;
    let data_store = CountingDataStore::new(&mock_tx);
    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&data_store);

    let result = executor
        .execute_transaction(
            mock_tx.account().id(),
            mock_tx.tx_inputs().block_header().block_num(),
            mock_tx.tx_inputs().input_notes().clone(),
            mock_tx.tx_args().clone(),
        )
        .await;

    assert_transaction_executor_error!(
        result,
        matches ExecutionError::EventError { error: ref event_error, .. }
            if matches!(
                event_error.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::DataStoreRequestLimitExceeded {
                    max_requests: MAX_DATA_STORE_REQUESTS_PER_TX,
                })
            )
    );
    assert_eq!(data_store.storage_map_request_count(), MAX_DATA_STORE_REQUESTS_PER_TX);

    Ok(())
}

#[tokio::test]
async fn note_script_fetches_share_the_lazy_data_store_limit() -> anyhow::Result<()> {
    let storage_request_count = MAX_DATA_STORE_REQUESTS_PER_TX - 1;
    let map_keys = (0..storage_request_count)
        .map(|index| StorageMapKey::from_array([0, 0, 0, index as u32]))
        .collect::<Vec<_>>();
    let map_entries = map_keys
        .iter()
        .enumerate()
        .map(|(index, key)| (*key, Word::from([index as u32 + 1, 0, 0, 0])))
        .collect::<Vec<_>>();
    let map_slot_name = StorageSlotName::mock(0);
    let account = AccountBuilder::new([5; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(vec![StorageSlot::with_map(
            map_slot_name.clone(),
            StorageMap::with_entries(map_entries.into_iter())?,
        )]))
        .build_existing()?;
    let output_notes = [1_u32, 2]
        .map(|value| {
            NoteBuilder::new(account.id(), rand::rng())
                .note_type(NoteType::Private)
                .code(format!(
                    r#"
                    @note_script
                    pub proc main
                        push.{value} drop
                    end
                    "#
                ))
                .build()
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let storage_accesses = map_keys
        .iter()
        .map(|key| {
            format!(
                "push.{key}\n\
                 push.MOCK_MAP_SLOT[0..2]\n\
                 call.account::get_map_item\n\
                 dropw\n\
                 exec.sys::truncate_stack"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let note_creations = output_notes
        .iter()
        .map(|note| {
            format!(
                "push.{recipient}\n\
                 push.{note_type}\n\
                 push.{tag}\n\
                 call.account::create_note\n\
                 drop\n\
                 exec.sys::truncate_stack",
                recipient = note.recipient().digest(),
                note_type = NoteType::Private as u8,
                tag = Felt::from(note.metadata().tag()),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let code = format!(
        r#"
        use miden::core::sys
        use mock::account

        const MOCK_MAP_SLOT = word("{map_slot_name}")

        @transaction_script
        pub proc main
            {storage_accesses}
            {note_creations}
        end
        "#
    );
    let code_builder = CodeBuilder::with_mock_packages();
    let source_manager = code_builder.source_manager();
    let tx_script = code_builder.compile_tx_script(code)?;
    let mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    let mut tx_builder = mock_chain
        .build_transaction(account)
        .tx_script(tx_script)
        .with_source_manager(source_manager);
    for note in &output_notes {
        let script_root = Word::from(note.script().root());
        for (key, value) in note
            .recipient()
            .to_advice_map_entries()
            .into_iter()
            .filter(|(key, _)| *key != script_root)
        {
            tx_builder = tx_builder.add_advice_map_entry(key, value);
        }
    }
    let mock_tx = tx_builder.build()?;
    let data_store = CountingDataStore::new(&mock_tx);
    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&data_store);

    let result = executor
        .execute_transaction(
            mock_tx.account().id(),
            mock_tx.tx_inputs().block_header().block_num(),
            mock_tx.tx_inputs().input_notes().clone(),
            mock_tx.tx_args().clone(),
        )
        .await;

    assert_transaction_executor_error!(
        result,
        matches ExecutionError::EventError { error: ref event_error, .. }
            if matches!(
                event_error.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::DataStoreRequestLimitExceeded {
                    max_requests: MAX_DATA_STORE_REQUESTS_PER_TX,
                })
            )
    );
    assert_eq!(data_store.storage_map_request_count(), storage_request_count);
    assert_eq!(data_store.note_script_request_count(), 1);

    Ok(())
}

#[tokio::test]
async fn note_checker_caches_failed_data_store_requests_across_retries() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account_with_storage(
        crate::Auth::IncrNonce,
        [AccountStorage::mock_map_slot()],
    )?;
    let map_key = *AccountStorage::mock_map().entries().next().unwrap().0;
    let mock_map_slot = &*MOCK_MAP_SLOT;
    let note_script = format!(
        r#"
        use mock::account

        const MOCK_MAP_SLOT = word("{mock_map_slot}")

        @note_script
        pub proc main
            push.{map_key}
            push.MOCK_MAP_SLOT[0..2]
            call.account::get_map_item
            dropw
        end
        "#
    );
    let notes = [1_u32, 2]
        .map(|_| {
            NoteBuilder::new(account.id(), rand::rng())
                .code(&note_script)
                .dynamically_linked_packages(CodeBuilder::mock_packages())
                .build()
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mock_chain = builder.build()?;
    let mock_tx = mock_chain
        .build_transaction(account)
        .unauthenticated_input_notes(notes.clone())
        .build()?;
    let data_store = CountingDataStore::failing_storage_map_requests(&mock_tx);
    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&data_store);

    let result = NoteConsumptionChecker::new(&executor)
        .check_notes_consumability(
            mock_tx.account().id(),
            mock_tx.tx_inputs().block_header().block_num(),
            notes,
            mock_tx.tx_args().clone(),
        )
        .await?;

    assert!(result.successful().is_empty());
    assert_eq!(result.failed().len(), 2);
    assert_eq!(data_store.storage_map_request_count(), 1);

    Ok(())
}

#[tokio::test]
async fn note_checker_reports_data_store_limit_exhausted_across_retries() -> anyhow::Result<()> {
    let map_keys = (0..=MAX_DATA_STORE_REQUESTS_PER_TX)
        .map(|index| StorageMapKey::from_array([0, 0, 0, index as u32]))
        .collect::<Vec<_>>();
    let map_entries = map_keys
        .iter()
        .enumerate()
        .map(|(index, key)| (*key, Word::from([index as u32 + 1, 0, 0, 0])))
        .collect::<Vec<_>>();
    let map_slot_name = StorageSlotName::mock(0);
    let account = AccountBuilder::new([4; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_component(MockAccountComponent::with_slots(vec![StorageSlot::with_map(
            map_slot_name.clone(),
            StorageMap::with_entries(map_entries.into_iter())?,
        )]))
        .build_existing()?;
    let note_script = |keys: &[StorageMapKey]| {
        let accesses = keys
            .iter()
            .map(|key| {
                format!(
                    "push.{key}\n\
                     push.MOCK_MAP_SLOT[0..2]\n\
                     call.account::get_map_item\n\
                     dropw\n\
                     exec.sys::truncate_stack"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            r#"
            use miden::core::sys
            use mock::account

            const MOCK_MAP_SLOT = word("{map_slot_name}")

            @note_script
            pub proc main
                {accesses}
                push.0 assert.err="force another checker attempt"
            end
            "#
        )
    };
    let notes = [note_script(&map_keys[..128]), note_script(&map_keys[128..])]
        .map(|script| {
            NoteBuilder::new(account.id(), rand::rng())
                .code(script)
                .dynamically_linked_packages(CodeBuilder::mock_packages())
                .build()
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mock_chain = MockChainBuilder::with_accounts([account.clone()])?.build()?;
    let mock_tx = mock_chain
        .build_transaction(account)
        .unauthenticated_input_notes(notes.clone())
        .build()?;
    let data_store = CountingDataStore::new(&mock_tx);
    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&data_store);

    let error = NoteConsumptionChecker::new(&executor)
        .check_notes_consumability(
            mock_tx.account().id(),
            mock_tx.tx_inputs().block_header().block_num(),
            notes,
            mock_tx.tx_args().clone(),
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        NoteCheckerError::DataStoreRequestLimitExceeded {
            max_requests: MAX_DATA_STORE_REQUESTS_PER_TX,
        }
    ));
    assert_eq!(data_store.storage_map_request_count(), MAX_DATA_STORE_REQUESTS_PER_TX);

    Ok(())
}

#[tokio::test]
async fn note_checker_caches_failed_note_script_requests_across_retries() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(crate::Auth::IncrNonce)?;
    let output_note = NoteBuilder::new(account.id(), rand::rng())
        .note_type(NoteType::Public)
        .code(
            r#"
            @note_script
            pub proc main
                push.0 drop
            end
            "#,
        )
        .build()?;
    let recipient_digest = output_note.recipient().digest();
    let script_root = output_note.script().root();
    let output_note_tag = Felt::from(output_note.metadata().tag());
    let input_note_script = format!(
        r#"
        use mock::account

        @note_script
        pub proc main
            push.{recipient_digest}
            push.{note_type}
            push.{output_note_tag}
            call.account::create_note
            drop
        end
        "#,
        note_type = NoteType::Public as u8,
    );
    let input_notes = [1_u32, 2]
        .map(|_| {
            NoteBuilder::new(account.id(), rand::rng())
                .code(&input_note_script)
                .dynamically_linked_packages(CodeBuilder::mock_packages())
                .build()
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mock_chain = builder.build()?;
    let mut tx_builder = mock_chain
        .build_transaction(account)
        .unauthenticated_input_notes(input_notes.clone());
    for (key, value) in output_note
        .recipient()
        .to_advice_map_entries()
        .into_iter()
        .filter(|(key, _)| *key != Word::from(script_root))
    {
        tx_builder = tx_builder.add_advice_map_entry(key, value);
    }
    let mock_tx = tx_builder.build()?;
    let data_store = CountingDataStore::failing_note_script_requests(&mock_tx);
    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&data_store);

    let result = NoteConsumptionChecker::new(&executor)
        .check_notes_consumability(
            mock_tx.account().id(),
            mock_tx.tx_inputs().block_header().block_num(),
            input_notes,
            mock_tx.tx_args().clone(),
        )
        .await?;

    assert!(result.successful().is_empty());
    assert_eq!(result.failed().len(), 2);
    assert_eq!(data_store.note_script_request_count(), 1);
    assert!(result.failed().iter().filter_map(|failure| failure.error()).any(|error| {
        matches!(
            error,
            miden_tx::TransactionExecutorError::TransactionProgramExecutionFailed(
                ExecutionError::EventError { error, .. }
            ) if matches!(
                error.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::CachedDataStoreRequestFailure {
                    request: DataStoreRequest::NoteScript { script_root: cached_root },
                    original_error,
                }) if *cached_root == script_root
                    && original_error.as_ref()
                        == "note script request failed for test: nested note script cause"
            )
        )
    }));

    Ok(())
}

#[tokio::test]
async fn note_checker_caches_missing_private_note_scripts_across_retries() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(crate::Auth::IncrNonce)?;
    let output_notes = [1_u32, 2]
        .map(|_| {
            NoteBuilder::new(account.id(), rand::rng())
                .note_type(NoteType::Private)
                .code(
                    r#"
                    @note_script
                    pub proc main
                        push.0 drop
                    end
                    "#,
                )
                .build()
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let script_root = output_notes[0].script().root();
    let input_note_scripts = output_notes.iter().enumerate().map(|(index, output_note)| {
        let create_output_note = format!(
            "push.{recipient}\n\
             push.{note_type}\n\
             push.{tag}\n\
             call.account::create_note\n\
             drop\n\
             exec.sys::truncate_stack",
            recipient = output_note.recipient().digest(),
            note_type = NoteType::Private as u8,
            tag = Felt::from(output_note.metadata().tag()),
        );
        let forced_failure = if index == 1 {
            "push.0 assert.err=\"force another checker attempt\""
        } else {
            ""
        };

        format!(
            r#"
            use miden::core::sys
            use mock::account
            @note_script
            pub proc main
                {create_output_note}
                {forced_failure}
            end
            "#
        )
    });
    let input_notes = input_note_scripts
        .map(|script| {
            NoteBuilder::new(account.id(), rand::rng())
                .code(script)
                .dynamically_linked_packages(CodeBuilder::mock_packages())
                .build()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mock_chain = builder.build()?;
    let mut tx_builder = mock_chain
        .build_transaction(account)
        .unauthenticated_input_notes(input_notes.clone());
    for output_note in &output_notes {
        for (key, value) in output_note
            .recipient()
            .to_advice_map_entries()
            .into_iter()
            .filter(|(key, _)| *key != Word::from(script_root))
        {
            tx_builder = tx_builder.add_advice_map_entry(key, value);
        }
    }
    let mock_tx = tx_builder.build()?;
    let data_store = CountingDataStore::new(&mock_tx);
    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&data_store);

    let result = NoteConsumptionChecker::new(&executor)
        .check_notes_consumability(
            mock_tx.account().id(),
            mock_tx.tx_inputs().block_header().block_num(),
            input_notes.clone(),
            mock_tx.tx_args().clone(),
        )
        .await?;

    assert_eq!(result.successful().len(), 1);
    assert_eq!(result.successful()[0].note().id(), input_notes[0].id());
    assert_eq!(result.failed().len(), 1);
    assert_eq!(result.failed()[0].note().id(), input_notes[1].id());
    assert_matches!(
        result.failed()[0].error().expect("the failed note should carry its error"),
        TransactionExecutorError::TransactionProgramExecutionFailed(
            ExecutionError::OperationError {
                err: miden_processor::operation::OperationError::FailedAssertion {
                    err_msg,
                    ..
                },
                ..
            }
        ) if err_msg.as_ref().map(AsRef::as_ref) == Some("force another checker attempt")
    );
    assert_eq!(data_store.note_script_request_count(), 1);

    Ok(())
}

#[tokio::test]
async fn note_checker_caches_missing_public_note_scripts_across_retries() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = builder.add_existing_mock_account(crate::Auth::IncrNonce)?;
    let output_note = NoteBuilder::new(account.id(), rand::rng())
        .note_type(NoteType::Public)
        .code(
            r#"
            @note_script
            pub proc main
                push.0 drop
            end
            "#,
        )
        .build()?;
    let script_root = output_note.script().root();
    let input_note_script = format!(
        r#"
        use mock::account

        @note_script
        pub proc main
            push.{recipient}
            push.{note_type}
            push.{tag}
            call.account::create_note
            drop
        end
        "#,
        recipient = output_note.recipient().digest(),
        note_type = NoteType::Public as u8,
        tag = Felt::from(output_note.metadata().tag()),
    );
    let input_notes = [1_u32, 2]
        .map(|_| {
            NoteBuilder::new(account.id(), rand::rng())
                .code(&input_note_script)
                .dynamically_linked_packages(CodeBuilder::mock_packages())
                .build()
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mock_chain = builder.build()?;
    let mut tx_builder = mock_chain
        .build_transaction(account)
        .unauthenticated_input_notes(input_notes.clone());
    for (key, value) in output_note
        .recipient()
        .to_advice_map_entries()
        .into_iter()
        .filter(|(key, _)| *key != Word::from(script_root))
    {
        tx_builder = tx_builder.add_advice_map_entry(key, value);
    }
    let mock_tx = tx_builder.build()?;
    let data_store = CountingDataStore::new(&mock_tx);
    let executor = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&data_store);

    let result = NoteConsumptionChecker::new(&executor)
        .check_notes_consumability(
            mock_tx.account().id(),
            mock_tx.tx_inputs().block_header().block_num(),
            input_notes,
            mock_tx.tx_args().clone(),
        )
        .await?;

    assert!(result.successful().is_empty());
    assert_eq!(result.failed().len(), 2);
    let expected_error = format!(
        "note script with root {} not found in data store for public note",
        Word::from(script_root),
    );
    assert!(result.failed().iter().all(|failure| {
        matches!(
            failure.error(),
            Some(TransactionExecutorError::TransactionProgramExecutionFailed(
                ExecutionError::EventError { error, .. }
            )) if matches!(
                error.downcast_ref::<TransactionKernelError>(),
                Some(TransactionKernelError::Other { message, .. })
                    if message.as_ref() == expected_error
            )
        )
    }));
    assert_eq!(data_store.note_script_request_count(), 1);

    Ok(())
}

/// Tests that updating or inserting a map item into a storage map succeeds when lazy loading is
/// enabled.
#[tokio::test]
async fn setting_map_item_with_lazy_loading_succeeds() -> anyhow::Result<()> {
    // Fetch a random existing key from the map.
    let mock_map = AccountStorage::mock_map();
    let existing_key = *mock_map.entries().next().unwrap().0;

    let non_existent_key = StorageMapKey::from_array([5, 5, 5, 5u32]);
    assert!(
        mock_map.open(&non_existent_key).get(non_existent_key).unwrap() == Word::empty(),
        "test setup requires that the non existent key does not exist"
    );

    // The slot name of the mock map in account storage.
    let mock_map_slot = &*MOCK_MAP_SLOT;

    let value0 = Word::from([3, 4, 5, 6u32]);
    let value1 = Word::from([9, 8, 7, 6u32]);

    let code = format!(
        r#"
      use mock::account

      const MOCK_MAP_SLOT = word("{mock_map_slot}")

      @transaction_script
      pub proc main
          # Update an existing key.
          push.{value0}
          push.{existing_key}
          push.MOCK_MAP_SLOT[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          call.account::set_map_item

          # Insert a non-existent key.
          push.{value1}
          push.{non_existent_key}
          push.MOCK_MAP_SLOT[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY, VALUE]
          call.account::set_map_item

          exec.::miden::core::sys::truncate_stack
      end
      "#
    );

    let builder = CodeBuilder::with_mock_packages();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;

    let tx = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    let storage_patch = tx.account_patch().storage();
    assert_eq!(storage_patch.updated_map_item(mock_map_slot, &existing_key), Some(value0));
    assert_eq!(storage_patch.updated_map_item(mock_map_slot, &non_existent_key), Some(value1));

    Ok(())
}

/// Tests that getting a map item from a storage map succeeds when lazy loading is enabled.
#[tokio::test]
async fn getting_map_item_with_lazy_loading_succeeds() -> anyhow::Result<()> {
    // Fetch a random existing key from the map.
    let mock_map = AccountStorage::mock_map();
    let (existing_key, existing_value) = mock_map.entries().next().unwrap();

    let non_existent_key = StorageMapKey::from_array([5, 5, 5, 5u32]);
    assert!(
        mock_map.open(&non_existent_key).get(non_existent_key).unwrap() == Word::empty(),
        "test setup requires that the non existent key does not exist"
    );

    let mock_map_slot = &*MOCK_MAP_SLOT;

    let code = format!(
        r#"
      use miden::core::word
      use mock::account

      const MOCK_MAP_SLOT = word("{mock_map_slot}")

      @transaction_script
      pub proc main
          # Fetch value from existing key.
          push.{existing_key}
          push.MOCK_MAP_SLOT[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY]
          call.account::get_map_item

          push.{existing_value}
          assert_eqw.err="existing value does not match expected value"

          # Fetch a non-existent key.
          push.{non_existent_key}
          push.MOCK_MAP_SLOT[0..2]
          # => [slot_id_suffix, slot_id_prefix, KEY]
          call.account::get_map_item

          padw assert_eqw.err="non-existent value should be the empty word"

          exec.::miden::core::sys::truncate_stack
      end
      "#
    );

    let builder = CodeBuilder::with_mock_packages();
    let source_manager = builder.source_manager();
    let tx_script = builder.compile_tx_script(code)?;

    let tx = TestTransactionBuilder::with_existing_mock_account()
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?
        .execute()
        .await?;

    // The lazy loaded witnesses must be in the native partial storage of the executed inputs.
    let partial_map = tx
        .tx_inputs()
        .account()
        .storage()
        .maps()
        .find(|map| map.root() == mock_map.root())
        .context("partial storage should contain the mock map")?;
    assert_eq!(partial_map.get(existing_key), Some(*existing_value));
    assert_eq!(partial_map.get(&non_existent_key), Some(Word::empty()));

    Ok(())
}
