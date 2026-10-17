//! Tests that an executed transaction can be proven and re-executed from its inputs alone.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use anyhow::Context;
use miden_processor::{FutureMaybeSend, LoadedMastForest, MastForestStore};
use miden_protocol::Word;
use miden_protocol::account::{
    AccountBuilder,
    AccountId,
    AccountType,
    PartialAccount,
    StorageMapKey,
    StorageMapWitness,
};
use miden_protocol::asset::{AssetAmount, AssetId, AssetWitness, FungibleAsset};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::block::{BlockHeader, BlockNumber};
use miden_protocol::note::{Note, NoteScript, NoteScriptRoot, PartialNote};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::testing::account_id::ACCOUNT_ID_PRIVATE_SENDER;
use miden_protocol::transaction::{AccountInputs, PartialBlockchain, TransactionInputs};
use miden_standards::account::access::Authority;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::note::P2idNote;
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_tx::auth::UnreachableAuth;
use miden_tx::{
    DataStore,
    DataStoreError,
    LocalTransactionProver,
    TransactionExecutor,
    TransactionMastStore,
};

use crate::{AccountState, Auth, MockChain};

/// Tests that a transaction which uses FPI and a signature can be re-executed and proven from its
/// executed inputs without fetching any data again.
///
/// The FPI happens through the asset callbacks of a blocklist faucet, which read the faucet's
/// blocklist storage map lazily.
#[tokio::test]
async fn executed_transaction_can_be_proven_and_reexecuted_from_its_inputs() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let faucet = builder.add_account_from_builder(
        Auth::IncrNonce,
        AccountBuilder::new([7; 32])
            .account_type(AccountType::Public)
            .with_component(
                FungibleFaucet::builder()
                    .name(TokenName::new("SYM")?)
                    .symbol("SYM".try_into()?)
                    .decimals(8)
                    .max_supply(AssetAmount::new(1_000)?)
                    .build()?,
            )
            .with_component(Authority::AuthControlled)
            .with_components(
                TokenPolicyManager::builder()
                    .active_mint_policy(MintPolicy::allow_all())
                    .active_burn_policy(BurnPolicy::allow_all())
                    .active_send_policy(TransferPolicy::empty_basic_blocklist())
                    .active_receive_policy(TransferPolicy::empty_basic_blocklist())
                    .build(),
            ),
        AccountState::Exists,
    )?;
    let faucet_asset = FungibleAsset::new(faucet.id(), 100)?;
    // The native account uses basic auth, so the transaction requires a signature.
    let native_account =
        builder.add_existing_wallet_with_assets(Auth::basic_ecdsa(), [faucet_asset.into()])?;
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Adding the faucet asset to the output note invokes the faucet's send callback through FPI.
    let output_note = Note::from(
        P2idNote::builder()
            .sender(native_account.id())
            .target(ACCOUNT_ID_PRIVATE_SENDER.try_into()?)
            .serial_number(Word::from([1, 2, 3, 4u32]))
            .asset(faucet_asset)
            .build()?,
    );
    let send_notes_script = SendNotesTransactionScript::new(
        &native_account.code_interface(),
        &[PartialNote::from(output_note)],
    )?;

    let executed_tx = mock_chain
        .build_transaction(native_account.id())
        .foreign_accounts([mock_chain.get_foreign_account_inputs(faucet.id())?])
        .send_notes_script(&send_notes_script)
        .build()?
        .execute()
        .await?;

    let tx_inputs = executed_tx.tx_inputs().clone();
    assert_eq!(tx_inputs.signatures().len(), 1);
    let foreign_inputs = tx_inputs
        .foreign_accounts()
        .get(&faucet.id())
        .context("faucet should be a foreign account")?;
    let blocklist_key = StorageMapKey::new(AccountIdKey::from(native_account.id()).as_word());
    assert!(
        foreign_inputs
            .storage()
            .maps()
            .any(|map| map.get(&blocklist_key) == Some(Word::empty()))
    );

    // Test that re-execution during proving works as well.
    // TODO: Remove this once prover re-execution is removed (https://github.com/0xMiden/protocol/issues/3852).
    LocalTransactionProver::default().prove(executed_tx.clone())?;

    // execute_transaction does not take the full tx inputs as a parameter and signatures do not go
    // through the data store, so they need to be added via the transaction arguments.
    // TODO: This should be addressed in https://github.com/0xMiden/protocol/issues/2293.
    let mut tx_args = tx_inputs.tx_args().clone();
    for (key, signature) in tx_inputs.signatures() {
        tx_args.add_signature(key.pub_key_commitment(), key.message(), signature.clone());
    }
    let data_store = TransactionInputsDataStore::new(tx_inputs.clone());
    let reexecuted_tx = TransactionExecutor::<'_, '_, _, UnreachableAuth>::new(&data_store)
        .execute_transaction(
            tx_inputs.account().id(),
            tx_inputs.ref_block(),
            tx_inputs.input_notes().clone(),
            tx_args,
        )
        .await?;
    assert_eq!(reexecuted_tx.id(), executed_tx.id());

    Ok(())
}

// TRANSACTION INPUTS DATA STORE
// ================================================================================================

/// A data store that serves only the data in the given transaction inputs.
///
/// Requests for witnesses fail, because the partial accounts in the inputs should already contain
/// all witnesses the transaction needs.
struct TransactionInputsDataStore {
    tx_inputs: TransactionInputs,
    mast_store: TransactionMastStore,
}

impl TransactionInputsDataStore {
    fn new(tx_inputs: TransactionInputs) -> Self {
        let mast_store = TransactionMastStore::new();
        mast_store.load_account_code(tx_inputs.account().code());
        for foreign_account in tx_inputs.foreign_accounts().values() {
            mast_store.load_account_code(foreign_account.code());
        }

        Self { tx_inputs, mast_store }
    }
}

impl DataStore for TransactionInputsDataStore {
    fn get_transaction_inputs(
        &self,
        _account_id: AccountId,
        _ref_blocks: BTreeSet<BlockNumber>,
    ) -> impl FutureMaybeSend<
        Result<(PartialAccount, BlockHeader, ProtocolConfig, PartialBlockchain), DataStoreError>,
    > {
        let inputs = (
            self.tx_inputs.account().clone(),
            self.tx_inputs.block_header().clone(),
            self.tx_inputs.protocol_config().clone(),
            self.tx_inputs.blockchain().clone(),
        );
        async move { Ok(inputs) }
    }

    fn get_foreign_account_inputs(
        &self,
        foreign_account_id: AccountId,
        _ref_block: BlockNumber,
    ) -> impl FutureMaybeSend<Result<AccountInputs, DataStoreError>> {
        let foreign_account = self
            .tx_inputs
            .foreign_accounts()
            .get(&foreign_account_id)
            .cloned()
            .ok_or_else(|| {
                DataStoreError::other(format!("foreign account {foreign_account_id} not in inputs"))
            });
        async move { foreign_account }
    }

    fn get_vault_asset_witnesses(
        &self,
        account_id: AccountId,
        _vault_root: Word,
        _asset_ids: BTreeSet<AssetId>,
    ) -> impl FutureMaybeSend<Result<Vec<AssetWitness>, DataStoreError>> {
        async move {
            Err(DataStoreError::other(format!(
                "asset witnesses of account {account_id} were requested again"
            )))
        }
    }

    fn get_storage_map_witness(
        &self,
        account_id: AccountId,
        _map_root: Word,
        _map_key: StorageMapKey,
    ) -> impl FutureMaybeSend<Result<StorageMapWitness, DataStoreError>> {
        async move {
            Err(DataStoreError::other(format!(
                "storage map witness of account {account_id} was requested again"
            )))
        }
    }

    fn get_note_script(
        &self,
        script_root: NoteScriptRoot,
    ) -> impl FutureMaybeSend<Result<Option<NoteScript>, DataStoreError>> {
        let note_script = self.tx_inputs.note_scripts().get(&script_root).cloned();
        async move { Ok(note_script) }
    }
}

impl MastForestStore for TransactionInputsDataStore {
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest> {
        self.mast_store.get(procedure_hash)
    }
}
