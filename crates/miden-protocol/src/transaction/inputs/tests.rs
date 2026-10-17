use alloc::vec;
use std::collections::BTreeMap;

use assert_matches::assert_matches;

use crate::account::{
    Account,
    AccountCode,
    AccountId,
    AccountStorage,
    AccountStorageHeader,
    PartialAccount,
    PartialStorage,
    StorageSlot,
    StorageSlotName,
};
use crate::asset::{AssetVault, PartialVault};
use crate::block::BlockHeader;
use crate::block::account_tree::AccountTree;
use crate::crypto::merkle::smt::Smt;
use crate::errors::TransactionInputError;
use crate::note::NoteScript;
use crate::protocol_config::ProtocolConfig;
use crate::testing::account_id::{
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE,
    ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
};
use crate::transaction::{
    AccountInputs,
    InputNotes,
    PartialBlockchain,
    TransactionArgs,
    TransactionInputs,
};
use crate::vm::AdviceInputs;
use crate::{Felt, Word};

// HELPERS
// ================================================================================================

fn native_account() -> anyhow::Result<PartialAccount> {
    Ok(PartialAccount::new(
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)?,
        Felt::new_unchecked(10),
        AccountCode::mock(),
        PartialStorage::new(AccountStorageHeader::new(vec![])?, [])?,
        PartialVault::new(Word::default()),
        None,
    )?)
}

/// Returns transaction inputs for the native account without notes or lazy loaded data.
fn empty_tx_inputs() -> anyhow::Result<TransactionInputs> {
    let blockchain = PartialBlockchain::default();
    let block_header = BlockHeader::mock(0, Some(blockchain.peaks().hash_peaks()), None, &[]);

    Ok(TransactionInputs::builder()
        .account(native_account()?)
        .block_header(block_header)
        .protocol_config(ProtocolConfig::mock())
        .blockchain(blockchain)
        .input_notes(InputNotes::new(vec![])?)
        .build()?)
}

/// Returns account inputs for an account with the given ID and one value slot.
fn foreign_account_inputs(account_id: AccountId) -> anyhow::Result<AccountInputs> {
    let slot_name = StorageSlotName::new("foreign::slot::value")?;
    let storage =
        AccountStorage::new(vec![StorageSlot::with_value(slot_name, Word::from([1, 2, 3, 4u32]))])?;
    let account = Account::new_existing(
        account_id,
        AssetVault::default(),
        storage,
        AccountCode::mock(),
        Felt::new_unchecked(5),
    );

    let mut account_tree = AccountTree::<Smt>::default();
    account_tree.insert(account_id, account.to_commitment())?;

    Ok(AccountInputs::new(
        PartialAccount::from(&account),
        account_tree.open(account_id),
    ))
}

// TESTS
// ================================================================================================

#[test]
fn builder_preserves_all_transaction_input_components() -> anyhow::Result<()> {
    let account = native_account()?;
    let blockchain = PartialBlockchain::default();
    let block_header = BlockHeader::mock(0, Some(blockchain.peaks().hash_peaks()), None, &[]);
    let protocol_config = ProtocolConfig::mock();
    let input_notes = InputNotes::new(vec![])?;
    let tx_args = TransactionArgs::from_parts(
        None,
        Word::new([Felt::from(1_u32); 4]),
        BTreeMap::new(),
        AdviceInputs::default(),
        Word::new([Felt::from(2_u32); 4]),
        None,
    );
    let advice_inputs = AdviceInputs::default()
        .with_map([(Word::new([Felt::from(3_u32); 4]), vec![Felt::from(4_u32)])]);
    let foreign_account = foreign_account_inputs(AccountId::try_from(
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2,
    )?)?;
    let note_script = NoteScript::mock();

    let tx_inputs = TransactionInputs::builder()
        .account(account.clone())
        .block_header(block_header.clone())
        .protocol_config(protocol_config.clone())
        .blockchain(blockchain.clone())
        .input_notes(input_notes.clone())
        .tx_args(tx_args.clone())
        .advice_inputs(advice_inputs.clone())
        .foreign_accounts(vec![foreign_account.clone()])
        .note_scripts(vec![note_script.clone()])
        .build()?;

    assert_eq!(tx_inputs.account(), &account);
    assert_eq!(tx_inputs.block_header(), &block_header);
    assert_eq!(tx_inputs.protocol_config(), &protocol_config);
    assert_eq!(tx_inputs.blockchain(), &blockchain);
    assert_eq!(tx_inputs.input_notes(), &input_notes);
    assert_eq!(tx_inputs.tx_args(), &tx_args);
    assert_eq!(tx_inputs.advice_inputs(), &advice_inputs);
    assert_eq!(
        tx_inputs.foreign_accounts(),
        &BTreeMap::from([(foreign_account.id(), foreign_account)])
    );
    assert_eq!(tx_inputs.note_scripts(), &BTreeMap::from([(note_script.root(), note_script)]));

    Ok(())
}

#[test]
fn builder_rejects_an_inconsistent_protocol_config() -> anyhow::Result<()> {
    let blockchain = PartialBlockchain::default();
    let block_header = BlockHeader::mock(0, Some(blockchain.peaks().hash_peaks()), None, &[]);
    let different_fee_faucet =
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2)?;
    let protocol_config =
        ProtocolConfig::current(crate::asset::AssetId::new_fungible(different_fee_faucet))?;

    let result = TransactionInputs::builder()
        .account(native_account()?)
        .block_header(block_header)
        .protocol_config(protocol_config)
        .blockchain(blockchain)
        .input_notes(InputNotes::new(vec![])?)
        .build();

    assert_matches!(result, Err(TransactionInputError::InconsistentProtocolConfig { .. }));

    Ok(())
}

#[test]
fn add_foreign_account_rejects_the_native_account_and_duplicates() -> anyhow::Result<()> {
    let mut tx_inputs = empty_tx_inputs()?;
    let native_account_id = tx_inputs.account().id();
    let foreign_account_id =
        AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2)?;

    assert_matches!(
        tx_inputs.add_foreign_account(foreign_account_inputs(native_account_id)?),
        Err(TransactionInputError::ForeignAccountIsNativeAccount(id)) if id == native_account_id
    );

    tx_inputs.add_foreign_account(foreign_account_inputs(foreign_account_id)?)?;
    assert_matches!(
        tx_inputs.add_foreign_account(foreign_account_inputs(foreign_account_id)?),
        Err(TransactionInputError::DuplicateForeignAccount(id)) if id == foreign_account_id
    );

    Ok(())
}
