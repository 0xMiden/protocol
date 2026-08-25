use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::{Asset, AssetId, FungibleAsset, NonFungibleAsset};
use miden_protocol::note::{NoteAssets, NoteType};
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::auth::NoAuth;
use miden_standards::account::pass_through::PassThrough;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::{
    ERR_PASS_THROUGH_ACCOUNT_ALREADY_HELD_ASSET,
    ERR_PASS_THROUGH_ACCOUNT_VAULT_CHANGED,
    ERR_PASS_THROUGH_PAYLOAD_LENGTH_INVALID,
    ERR_PASS_THROUGH_PAYLOAD_NOT_WORD_ALIGNED,
};
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::{
    PassThroughSingleP2idTransactionScript,
    PassThroughTransactionScriptError,
};
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

use super::pass_through_account;

// CONSTANTS
// ================================================================================================

/// The serial number of the P2ID note the pass-through script creates.
const SERIAL_NUMBER: Word = Word::new([
    Felt::new_unchecked(1),
    Felt::new_unchecked(2),
    Felt::new_unchecked(3),
    Felt::new_unchecked(4),
]);

// TESTS
// ================================================================================================

/// The pass-through script forwards the account's balance of the named asset into one P2ID note
/// addressed to the payload's target, leaving the account it runs on untouched.
#[tokio::test]
async fn forwards_fee_notes_into_a_single_p2id_note() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;
    let target = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let sender = ACCOUNT_ID_SENDER.try_into()?;
    let fee_notes = [
        builder.add_tx_fee_note(sender, &[FungibleAsset::mock(10)])?,
        builder.add_tx_fee_note(sender, &[FungibleAsset::mock(20)])?,
        builder.add_tx_fee_note(sender, &[FungibleAsset::mock(30)])?,
    ];
    let mock_chain = builder.build()?;

    let fee_asset_id = FungibleAsset::mock(1).id();
    let script = PassThroughSingleP2idTransactionScript::new(
        target.id(),
        NoteType::Public,
        SERIAL_NUMBER,
        [fee_asset_id],
    )?;

    let mut tx_builder = mock_chain.build_transaction(account.id());
    for note in &fee_notes {
        tx_builder = tx_builder.authenticated_input_note(note.id());
    }
    let executed = tx_builder.pass_through_single_p2id_script(&script).build()?.execute().await?;

    // the only output note is the P2ID note the script created
    assert_eq!(executed.output_notes().num_notes(), 1);
    let output_note = executed.output_notes().get_note(0);
    assert_eq!(output_note.recipient_digest(), script.output_note_recipient().digest());
    assert_eq!(output_note.metadata().tag(), script.output_note_tag());
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);
    assert_eq!(output_note.metadata().sender(), account.id());

    // one call moved the whole balance, no matter how many notes contributed to it
    let mock_faucet_id = FungibleAsset::mock(1).faucet_id();
    assert_eq!(
        output_note.assets(),
        &NoteAssets::new(vec![FungibleAsset::new(mock_faucet_id, 60)?.into()])?,
    );

    // the account is a conduit: none of the swept assets stuck to it
    assert!(
        executed.account_patch().vault().is_empty(),
        "a pass-through transaction must not change the account\'s vault",
    );
    assert_eq!(
        executed.final_account().nonce(),
        account.nonce(),
        "an unchanged account must not have its nonce bumped",
    );
    assert_eq!(
        executed.final_account().to_commitment(),
        account.to_commitment(),
        "the account commitment must be unchanged so batches can be built concurrently",
    );

    Ok(())
}

/// Assets of different faucets and compositions are all forwarded into the same output note.
#[tokio::test]
async fn forwards_assets_of_every_faucet_and_composition() -> anyhow::Result<()> {
    let other_faucet_id = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?;
    let mock_asset: Asset = FungibleAsset::mock(25);
    let other_asset: Asset = FungibleAsset::new(other_faucet_id, 40)?.into();
    let non_fungible_asset: Asset = NonFungibleAsset::mock(&[4, 5, 6]);

    let mut builder = MockChain::builder();
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;
    let target = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let sender = ACCOUNT_ID_SENDER.try_into()?;
    // the first note carries several assets at once, the second a single one
    let multi_asset_note = builder.add_tx_fee_note(sender, &[mock_asset, non_fungible_asset])?;
    let single_asset_note = builder.add_tx_fee_note(sender, &[other_asset])?;
    let mock_chain = builder.build()?;

    let script = PassThroughSingleP2idTransactionScript::new(
        target.id(),
        NoteType::Public,
        SERIAL_NUMBER,
        [mock_asset.id(), non_fungible_asset.id(), other_asset.id()],
    )?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(multi_asset_note.id())
        .authenticated_input_note(single_asset_note.id())
        .pass_through_single_p2id_script(&script)
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 1);
    assert_eq!(
        executed.output_notes().get_note(0).assets(),
        &NoteAssets::new(vec![mock_asset, non_fungible_asset, other_asset])?,
    );
    assert_eq!(executed.final_account().to_commitment(), account.to_commitment());

    Ok(())
}

/// A payload naming the maximum number of assets executes, pinning the script's own bound against
/// the Rust one.
#[tokio::test]
async fn forwards_the_maximum_number_of_assets() -> anyhow::Result<()> {
    let assets: Vec<Asset> = (0..PassThroughSingleP2idTransactionScript::MAX_ASSET_IDS)
        .map(|i| NonFungibleAsset::mock(&[u8::try_from(i).unwrap()]))
        .collect();

    let mut builder = MockChain::builder();
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;
    let target = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let fee_note = builder.add_tx_fee_note(ACCOUNT_ID_SENDER.try_into()?, &assets)?;
    let mock_chain = builder.build()?;

    let script = PassThroughSingleP2idTransactionScript::new(
        target.id(),
        NoteType::Public,
        SERIAL_NUMBER,
        assets.iter().map(Asset::id),
    )?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .pass_through_single_p2id_script(&script)
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 1);
    assert_eq!(executed.output_notes().get_note(0).assets(), &NoteAssets::new(assets)?,);
    assert_eq!(executed.final_account().to_commitment(), account.to_commitment());

    Ok(())
}

/// The P2ID note the script creates is claimable by its target.
#[tokio::test]
async fn output_note_is_consumable_by_the_target() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;
    let mut target = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let fee_asset = FungibleAsset::mock(100);
    let fee_note = builder.add_tx_fee_note(ACCOUNT_ID_SENDER.try_into()?, &[fee_asset])?;
    let mut mock_chain = builder.build()?;

    let script = PassThroughSingleP2idTransactionScript::new(
        target.id(),
        NoteType::Public,
        SERIAL_NUMBER,
        [fee_asset.id()],
    )?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .pass_through_single_p2id_script(&script)
        .build()?
        .execute()
        .await?;
    let p2id_note_id = executed.output_notes().get_note(0).id();

    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    let claim = mock_chain
        .build_transaction(target.id())
        .authenticated_input_note(p2id_note_id)
        .build()?
        .execute()
        .await?;

    target.apply_patch(claim.account_patch())?;
    assert_eq!(target.vault().get(fee_asset.id()), Some(fee_asset));

    Ok(())
}

/// An input note carrying no assets contributes nothing and does not break the sweep.
#[tokio::test]
async fn tolerates_an_asset_less_input_note() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;
    let target = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let sender = ACCOUNT_ID_SENDER.try_into()?;
    let fee_asset = FungibleAsset::mock(10);
    let fee_note = builder.add_tx_fee_note(sender, &[fee_asset])?;
    let asset_less_note = NoteBuilder::new(sender, &mut rand::rng()).build()?;
    builder.add_output_note(RawOutputNote::Full(asset_less_note.clone()));
    let mock_chain = builder.build()?;

    let script = PassThroughSingleP2idTransactionScript::new(
        target.id(),
        NoteType::Public,
        SERIAL_NUMBER,
        [fee_asset.id()],
    )?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(asset_less_note.id())
        .authenticated_input_note(fee_note.id())
        .pass_through_single_p2id_script(&script)
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 1);
    assert_eq!(executed.output_notes().get_note(0).assets(), &NoteAssets::new(vec![fee_asset])?,);
    assert_eq!(executed.final_account().to_commitment(), account.to_commitment());

    Ok(())
}

/// Naming an asset the vault does not hold is a no-op, so a caller may name a fixed set of
/// supported assets without knowing which of them the input notes actually deposit.
#[tokio::test]
async fn tolerates_a_named_asset_the_vault_does_not_hold() -> anyhow::Result<()> {
    let absent_asset: Asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?, 20)?.into();

    let mut builder = MockChain::builder();
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;
    let target = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let deposited_asset = FungibleAsset::mock(10);
    let fee_note = builder.add_tx_fee_note(ACCOUNT_ID_SENDER.try_into()?, &[deposited_asset])?;
    let mock_chain = builder.build()?;

    let script = PassThroughSingleP2idTransactionScript::new(
        target.id(),
        NoteType::Public,
        SERIAL_NUMBER,
        [deposited_asset.id(), absent_asset.id()],
    )?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .pass_through_single_p2id_script(&script)
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 1);
    assert_eq!(
        executed.output_notes().get_note(0).assets(),
        &NoteAssets::new(vec![deposited_asset])?,
    );
    assert_eq!(executed.final_account().to_commitment(), account.to_commitment());

    Ok(())
}

/// An account holding the asset before the transaction is rejected, so the sweep can only ever
/// move what the transaction itself deposited.
#[tokio::test]
async fn fails_when_the_account_already_held_the_asset() -> anyhow::Result<()> {
    let asset = FungibleAsset::mock(10);

    let mut builder = MockChain::builder();
    let account = AccountBuilder::new([44; 32])
        .with_component(NoAuth)
        .with_component(BasicWallet)
        .with_component(PassThrough)
        .with_assets([asset])
        .account_type(AccountType::Public)
        .build_existing()?;
    builder.add_account(account.clone())?;
    let target = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let fee_note = builder.add_tx_fee_note(ACCOUNT_ID_SENDER.try_into()?, &[asset])?;
    let mock_chain = builder.build()?;

    let script = PassThroughSingleP2idTransactionScript::new(
        target.id(),
        NoteType::Public,
        SERIAL_NUMBER,
        [asset.id()],
    )?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .pass_through_single_p2id_script(&script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PASS_THROUGH_ACCOUNT_ALREADY_HELD_ASSET);

    Ok(())
}

/// An asset the payload fails to name is left in the vault, which `assert_vault_unchanged` turns
/// into a failed transaction rather than a silently changed account.
#[tokio::test]
async fn fails_when_the_payload_does_not_name_a_deposited_asset() -> anyhow::Result<()> {
    let other_faucet_id = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?;
    let named_asset: Asset = FungibleAsset::mock(10);
    let unnamed_asset: Asset = FungibleAsset::new(other_faucet_id, 20)?.into();

    let mut builder = MockChain::builder();
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;
    let target = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let fee_note =
        builder.add_tx_fee_note(ACCOUNT_ID_SENDER.try_into()?, &[named_asset, unnamed_asset])?;
    let mock_chain = builder.build()?;

    let script = PassThroughSingleP2idTransactionScript::new(
        target.id(),
        NoteType::Public,
        SERIAL_NUMBER,
        [named_asset.id()],
    )?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .pass_through_single_p2id_script(&script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PASS_THROUGH_ACCOUNT_VAULT_CHANGED);

    Ok(())
}

/// The payload lives in the advice map, so the script root is the same for every target, serial
/// number and asset set, and can be allowlisted once.
#[test]
fn script_root_is_independent_of_payload() -> anyhow::Result<()> {
    let target = ACCOUNT_ID_SENDER.try_into()?;
    let script = PassThroughSingleP2idTransactionScript::new(
        target,
        NoteType::Public,
        SERIAL_NUMBER,
        [FungibleAsset::mock(1).id()],
    )?;
    let other =
        PassThroughSingleP2idTransactionScript::new(target, NoteType::Private, Word::empty(), [])?;

    assert_eq!(script.tx_script().root(), PassThroughSingleP2idTransactionScript::script_root());
    assert_eq!(
        script.tx_script().root(),
        other.tx_script().root(),
        "the embedded payload must not change the script root",
    );
    assert_ne!(
        script.tx_script_args(),
        other.tx_script_args(),
        "a different payload must produce different script arguments",
    );

    Ok(())
}

/// More asset IDs than fit into a single note are rejected at construction.
#[test]
fn rejects_more_asset_ids_than_fit_into_a_note() -> anyhow::Result<()> {
    let asset_ids: Vec<AssetId> = (0..=PassThroughSingleP2idTransactionScript::MAX_ASSET_IDS)
        .map(|i| {
            let faucet_id = AccountId::builder()
                .account_type(AccountType::Public)
                .build_with_seed([u8::try_from(i).unwrap(); 32]);
            FungibleAsset::new(faucet_id, 1).unwrap().id()
        })
        .collect();

    let err = PassThroughSingleP2idTransactionScript::new(
        ACCOUNT_ID_SENDER.try_into()?,
        NoteType::Public,
        SERIAL_NUMBER,
        asset_ids,
    )
    .expect_err("more asset ids than fit into a note should be rejected");

    assert!(matches!(
        err,
        PassThroughTransactionScriptError::TooManyAssetIds { actual: 17, max: 16 }
    ));

    Ok(())
}

/// A payload whose length the script does not accept is rejected before it is written to memory.
#[tokio::test]
async fn rejects_a_malformed_payload_length() -> anyhow::Result<()> {
    // (payload length in elements, expected error)
    let cases = [
        (
            PassThroughSingleP2idTransactionScript::PAYLOAD_HEADER_NUM_ELEMENTS + 2,
            ERR_PASS_THROUGH_PAYLOAD_NOT_WORD_ALIGNED,
        ),
        (
            PassThroughSingleP2idTransactionScript::PAYLOAD_HEADER_NUM_ELEMENTS - 4,
            ERR_PASS_THROUGH_PAYLOAD_LENGTH_INVALID,
        ),
        (
            PassThroughSingleP2idTransactionScript::PAYLOAD_HEADER_NUM_ELEMENTS
                + (PassThroughSingleP2idTransactionScript::MAX_ASSET_IDS + 1) * 4,
            ERR_PASS_THROUGH_PAYLOAD_LENGTH_INVALID,
        ),
    ];

    for (num_elements, expected_error) in cases {
        let mut builder = MockChain::builder();
        let account = pass_through_account()?;
        builder.add_account(account.clone())?;
        let fee_note =
            builder.add_tx_fee_note(ACCOUNT_ID_SENDER.try_into()?, &[FungibleAsset::mock(10)])?;
        let mock_chain = builder.build()?;

        let payload = vec![Felt::new_unchecked(1); num_elements];
        let tx_script_args = Hasher::hash_elements(&payload);

        let script = PassThroughSingleP2idTransactionScript::new(
            ACCOUNT_ID_SENDER.try_into()?,
            NoteType::Public,
            SERIAL_NUMBER,
            [FungibleAsset::mock(1).id()],
        )?;

        let result = mock_chain
            .build_transaction(account.id())
            .authenticated_input_note(fee_note.id())
            .tx_script(script.into())
            .tx_script_args(tx_script_args)
            .add_advice_map_entry(tx_script_args, payload)
            .build()?
            .execute()
            .await;

        assert_transaction_executor_error!(result, expected_error);
    }

    Ok(())
}
