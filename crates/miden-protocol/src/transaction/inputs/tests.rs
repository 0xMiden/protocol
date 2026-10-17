use alloc::vec;
use alloc::vec::Vec;
use std::collections::BTreeMap;

use assert_matches::assert_matches;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::account::auth::{AuthScheme, AuthSecretKey, BoundSignature, SignatureKey};
use crate::account::{
    Account,
    AccountCode,
    AccountId,
    AccountStorage,
    PartialAccount,
    StorageMap,
    StorageMapKey,
    StorageMapWitness,
    StorageSlot,
    StorageSlotContent,
    StorageSlotName,
};
use crate::asset::{AssetVault, FungibleAsset};
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

const MAP_SLOT_NAME: &str = "test::slot::map";

fn map_key() -> StorageMapKey {
    StorageMapKey::from_array([1, 2, 3, 4u32])
}

/// Returns an existing account with one value slot, one map slot with one entry and one asset.
fn mock_account(account_id: AccountId) -> anyhow::Result<Account> {
    let storage = AccountStorage::new(vec![
        StorageSlot::with_value(
            StorageSlotName::new("test::slot::value")?,
            Word::from([1, 2, 3, 4u32]),
        ),
        StorageSlot::with_map(
            StorageSlotName::new(MAP_SLOT_NAME)?,
            StorageMap::with_entries([(map_key(), Word::from([5, 6, 7, 8u32]))])?,
        ),
    ])?;

    Ok(Account::new_existing(
        account_id,
        AssetVault::new(&[FungibleAsset::mock(100)])?,
        storage,
        AccountCode::mock(),
        Felt::new_unchecked(5),
    ))
}

fn native_account_id() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE)?)
}

fn foreign_account_id() -> anyhow::Result<AccountId> {
    Ok(AccountId::try_from(ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_IMMUTABLE_CODE_2)?)
}

/// Returns transaction inputs for the native account without notes or lazy loaded data.
fn empty_tx_inputs() -> anyhow::Result<TransactionInputs> {
    let blockchain = PartialBlockchain::default();
    let block_header = BlockHeader::mock(0, Some(blockchain.peaks().hash_peaks()), None, &[]);

    Ok(TransactionInputs::builder()
        .account(PartialAccount::from(&mock_account(native_account_id()?)?))
        .block_header(block_header)
        .protocol_config(ProtocolConfig::mock())
        .blockchain(blockchain)
        .input_notes(InputNotes::new(vec![])?)
        .build()?)
}

/// Returns account inputs for the given account with a witness from a tree that only contains it.
fn account_inputs(account: &Account) -> anyhow::Result<AccountInputs> {
    let mut account_tree = AccountTree::<Smt>::default();
    account_tree.insert(account.id(), account.to_commitment())?;

    Ok(AccountInputs::new(
        PartialAccount::from(account),
        account_tree.open(account.id()),
    ))
}

// TESTS
// ================================================================================================

#[test]
fn builder_preserves_all_transaction_input_components() -> anyhow::Result<()> {
    let account = PartialAccount::from(&mock_account(native_account_id()?)?);
    let blockchain = PartialBlockchain::default();
    let block_header = BlockHeader::mock(0, Some(blockchain.peaks().hash_peaks()), None, &[]);
    let protocol_config = ProtocolConfig::mock();
    let input_notes = InputNotes::new(vec![])?;
    let tx_args = TransactionArgs::from_parts(
        None,
        Word::new([Felt::from(1_u32); 4]),
        BTreeMap::new(),
        Vec::new(),
        Vec::new(),
        AdviceInputs::default(),
        Word::new([Felt::from(2_u32); 4]),
        None,
    );
    let foreign_account = account_inputs(&mock_account(foreign_account_id()?)?)?;
    let note_script = NoteScript::mock();

    let tx_inputs = TransactionInputs::builder()
        .account(account.clone())
        .block_header(block_header.clone())
        .protocol_config(protocol_config.clone())
        .blockchain(blockchain.clone())
        .input_notes(input_notes.clone())
        .tx_args(tx_args.clone())
        .foreign_accounts(vec![foreign_account.clone()])
        .note_scripts(vec![note_script.clone()])
        .build()?;

    assert_eq!(tx_inputs.account(), &account);
    assert_eq!(tx_inputs.block_header(), &block_header);
    assert_eq!(tx_inputs.protocol_config(), &protocol_config);
    assert_eq!(tx_inputs.blockchain(), &blockchain);
    assert_eq!(tx_inputs.input_notes(), &input_notes);
    assert_eq!(tx_inputs.tx_args(), &tx_args);
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
    let different_fee_faucet = foreign_account_id()?;
    let protocol_config =
        ProtocolConfig::current(crate::asset::AssetId::new_fungible(different_fee_faucet))?;

    let result = TransactionInputs::builder()
        .account(PartialAccount::from(&mock_account(native_account_id()?)?))
        .block_header(block_header)
        .protocol_config(protocol_config)
        .blockchain(blockchain)
        .input_notes(InputNotes::new(vec![])?)
        .build();

    assert_matches!(result, Err(TransactionInputError::InconsistentProtocolConfig { .. }));

    Ok(())
}

#[test]
fn add_signature_rejects_a_duplicate_key() -> anyhow::Result<()> {
    let mut tx_inputs = empty_tx_inputs()?;
    let mut rng = ChaCha20Rng::from_seed([0; 32]);
    let secret_key = AuthSecretKey::with_scheme_and_rng(AuthScheme::EcdsaK256Keccak, &mut rng)?;
    let message = Word::from([1u32, 2, 3, 4]);
    let key = SignatureKey::new(secret_key.public_key().to_commitment(), message);
    let signature = BoundSignature::new(key, secret_key.sign(message))?;

    tx_inputs.add_signature(signature.clone())?;
    assert_matches!(
        tx_inputs.add_signature(signature),
        Err(TransactionInputError::DuplicateSignature(duplicate_key)) if duplicate_key == key
    );
    assert_eq!(tx_inputs.signatures().len(), 1);

    Ok(())
}

#[test]
fn add_foreign_account_rejects_the_native_account_and_duplicates() -> anyhow::Result<()> {
    let mut tx_inputs = empty_tx_inputs()?;
    let native_account_id = native_account_id()?;
    let foreign_account_id = foreign_account_id()?;

    assert_matches!(
        tx_inputs.add_foreign_account(account_inputs(&mock_account(native_account_id)?)?),
        Err(TransactionInputError::ForeignAccountIsNativeAccount(id)) if id == native_account_id
    );

    tx_inputs.add_foreign_account(account_inputs(&mock_account(foreign_account_id)?)?)?;
    assert_matches!(
        tx_inputs.add_foreign_account(account_inputs(&mock_account(foreign_account_id)?)?),
        Err(TransactionInputError::DuplicateForeignAccount(id)) if id == foreign_account_id
    );

    Ok(())
}

#[test]
fn witnesses_are_added_to_the_account_with_the_given_id() -> anyhow::Result<()> {
    let native_account = mock_account(native_account_id()?)?;
    let foreign_account = mock_account(foreign_account_id()?)?;
    let mut tx_inputs = empty_tx_inputs()?;
    tx_inputs.add_foreign_account(account_inputs(&foreign_account)?)?;

    let asset_id = FungibleAsset::mock(100).id();
    let map_slot_name = StorageSlotName::new(MAP_SLOT_NAME)?;
    let map_witness = |account: &Account| -> anyhow::Result<StorageMapWitness> {
        match account.storage().get(&map_slot_name).map(StorageSlot::content) {
            Some(StorageSlotContent::Map(map)) => Ok(map.open(&map_key())),
            _ => anyhow::bail!("account should have a map slot"),
        }
    };

    for account in [&native_account, &foreign_account] {
        tx_inputs.add_asset_witnesses(account.id(), [account.vault().open(asset_id)])?;
        tx_inputs.add_storage_map_witnesses(account.id(), [map_witness(account)?])?;
    }

    let foreign_inputs = &tx_inputs.foreign_accounts()[&foreign_account.id()];
    for (account, partial_account) in [
        (&native_account, tx_inputs.account()),
        (&foreign_account, foreign_inputs.account()),
    ] {
        assert_eq!(partial_account.vault().get(asset_id)?, account.vault().get(asset_id));
        assert!(
            partial_account
                .storage()
                .maps()
                .any(|map| map.get(&map_key()) == Some(Word::from([5, 6, 7, 8u32])))
        );
    }

    Ok(())
}

#[test]
fn witnesses_are_rejected_for_unknown_accounts_and_other_trees() -> anyhow::Result<()> {
    let mut tx_inputs = empty_tx_inputs()?;
    let native_account_id = native_account_id()?;
    let foreign_account_id = foreign_account_id()?;
    let asset_id = FungibleAsset::mock(100).id();

    assert_matches!(
        tx_inputs.add_asset_witnesses(foreign_account_id, []),
        Err(TransactionInputError::WitnessForUnknownAccount(id)) if id == foreign_account_id
    );
    assert_matches!(
        tx_inputs.add_storage_map_witnesses(foreign_account_id, []),
        Err(TransactionInputError::WitnessForUnknownAccount(id)) if id == foreign_account_id
    );

    let other_vault = AssetVault::new(&[FungibleAsset::mock(200)])?;
    assert_matches!(
        tx_inputs.add_asset_witnesses(native_account_id, [other_vault.open(asset_id)]),
        Err(TransactionInputError::InvalidAssetWitness { account_id, .. })
            if account_id == native_account_id
    );
    let other_map = StorageMap::with_entries([(map_key(), Word::from([9, 9, 9, 9u32]))])?;
    assert_matches!(
        tx_inputs.add_storage_map_witnesses(native_account_id, [other_map.open(&map_key())]),
        Err(TransactionInputError::InvalidStorageMapWitness { account_id, .. })
            if account_id == native_account_id
    );

    Ok(())
}
