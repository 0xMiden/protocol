use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountBuilder, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::errors::tx_kernel::ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW;
use miden_protocol::note::{NoteAssets, NoteType};
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::auth::NoAuth;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::ERR_PASS_THROUGH_PAYLOAD_LENGTH_INVALID;
use miden_standards::testing::note::NoteBuilder;
use miden_standards::tx_script::PassThroughTransactionScript;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

// HELPER FUNCTIONS
// ================================================================================================

/// The serial number of the P2ID note the pass-through script creates.
const SERIAL_NUMBER: Word = Word::new([Felt::new_unchecked(7); 4]);

/// Builds the stateless account a pass-through transaction runs on: a `NoAuth` wallet, so the
/// nonce is only bumped when the account state actually changes.
fn pass_through_account() -> anyhow::Result<Account> {
    Ok(AccountBuilder::new([42; 32])
        .with_component(NoAuth)
        .with_component(BasicWallet)
        .account_type(AccountType::Public)
        .build_existing()?)
}

// TESTS
// ================================================================================================

/// The pass-through script forwards the assets of every input note into one P2ID note addressed to
/// the payload's target, leaving the account it runs on untouched.
///
/// This is the batch-fee flow: the batch builder sweeps a batch's TX_FEE notes into a single note
/// it collects out of band, without changing the state of the account it uses to do so.
#[tokio::test]
async fn pass_through_forwards_fee_notes_into_a_single_p2id_note() -> anyhow::Result<()> {
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

    let script = PassThroughTransactionScript::new(target.id(), NoteType::Public, SERIAL_NUMBER);

    let mut tx_builder = mock_chain.build_transaction(account.id());
    for note in &fee_notes {
        tx_builder = tx_builder.authenticated_input_note(note.id());
    }
    let executed = tx_builder.pass_through_script(&script).build()?.execute().await?;

    // the only output note is the P2ID note the script created
    assert_eq!(executed.output_notes().num_notes(), 1);
    let output_note = executed.output_notes().get_note(0);
    assert_eq!(output_note.recipient_digest(), script.output_note_recipient().digest());
    assert_eq!(output_note.metadata().tag(), script.output_note_tag());
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);
    assert_eq!(output_note.metadata().sender(), account.id());

    // it carries the fees of every consumed note
    let mock_faucet_id = FungibleAsset::mock(1).faucet_id();
    assert_eq!(
        output_note.assets(),
        &NoteAssets::new(vec![FungibleAsset::new(mock_faucet_id, 60)?.into()])?,
    );

    // the account is a conduit: none of the swept assets stuck to it
    assert!(
        executed.account_patch().vault().is_empty(),
        "a pass-through transaction must not change the account's vault",
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
async fn pass_through_forwards_assets_of_every_faucet_and_composition() -> anyhow::Result<()> {
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

    let script = PassThroughTransactionScript::new(target.id(), NoteType::Public, SERIAL_NUMBER);

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(multi_asset_note.id())
        .authenticated_input_note(single_asset_note.id())
        .pass_through_script(&script)
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

/// The P2ID note the script creates is claimable by its target, closing the loop of the batch-fee
/// flow: the batch builder consumes the accumulated notes out of band.
#[tokio::test]
async fn pass_through_output_note_is_consumable_by_the_target() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;
    let mut target = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    let fee_asset = FungibleAsset::mock(100);
    let fee_note = builder.add_tx_fee_note(ACCOUNT_ID_SENDER.try_into()?, &[fee_asset])?;
    let mut mock_chain = builder.build()?;

    let script = PassThroughTransactionScript::new(target.id(), NoteType::Public, SERIAL_NUMBER);

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .pass_through_script(&script)
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

/// An input note carrying no assets contributes nothing and does not break the sweep, so a batch
/// may mix asset-less notes in with its fee notes.
#[tokio::test]
async fn pass_through_tolerates_an_asset_less_input_note() -> anyhow::Result<()> {
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

    let script = PassThroughTransactionScript::new(target.id(), NoteType::Public, SERIAL_NUMBER);

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(asset_less_note.id())
        .authenticated_input_note(fee_note.id())
        .pass_through_script(&script)
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.output_notes().num_notes(), 1);
    assert_eq!(executed.output_notes().get_note(0).assets(), &NoteAssets::new(vec![fee_asset])?,);
    assert_eq!(executed.final_account().to_commitment(), account.to_commitment());

    Ok(())
}

/// The payload lives in the advice map, so the script root is the same for every target and serial
/// number and can be allowlisted once.
#[test]
fn pass_through_script_root_is_independent_of_payload() -> anyhow::Result<()> {
    let target = ACCOUNT_ID_SENDER.try_into()?;
    let script = PassThroughTransactionScript::new(target, NoteType::Public, SERIAL_NUMBER);
    let other = PassThroughTransactionScript::new(target, NoteType::Private, Word::empty());

    assert_eq!(script.tx_script().root(), PassThroughTransactionScript::script_root());
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

/// A payload of the wrong length is rejected before it is written to memory.
#[tokio::test]
async fn pass_through_rejects_a_payload_of_the_wrong_length() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;

    let fee_note =
        builder.add_tx_fee_note(ACCOUNT_ID_SENDER.try_into()?, &[FungibleAsset::mock(10)])?;
    let mock_chain = builder.build()?;

    // a word-aligned payload that is not the expected number of elements long
    let payload =
        vec![Felt::new_unchecked(1); PassThroughTransactionScript::PAYLOAD_NUM_ELEMENTS + 4];
    let tx_script_args = Hasher::hash_elements(&payload);

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .tx_script(
            PassThroughTransactionScript::new(
                ACCOUNT_ID_SENDER.try_into()?,
                NoteType::Public,
                SERIAL_NUMBER,
            )
            .into(),
        )
        .tx_script_args(tx_script_args)
        .add_advice_map_entry(tx_script_args, payload)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PASS_THROUGH_PAYLOAD_LENGTH_INVALID);

    Ok(())
}

/// An input note that does not deposit its assets into the account fails the transaction instead of
/// silently leaving them behind: the script forwards each note's *initial* assets, so the vault
/// must hold them.
#[tokio::test]
async fn pass_through_fails_when_an_input_note_keeps_its_assets() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = pass_through_account()?;
    builder.add_account(account.clone())?;
    let target = builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })?;

    // a note whose script claims nothing, so its assets never reach the account's vault
    let inert_note = NoteBuilder::new(ACCOUNT_ID_SENDER.try_into()?, &mut rand::rng())
        .add_assets([FungibleAsset::mock(10)])
        .build()?;
    builder.add_output_note(RawOutputNote::Full(inert_note.clone()));
    let mock_chain = builder.build()?;

    let script = PassThroughTransactionScript::new(target.id(), NoteType::Public, SERIAL_NUMBER);

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(inert_note.id())
        .pass_through_script(&script)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_VAULT_FUNGIBLE_ASSET_AMOUNT_LESS_THAN_AMOUNT_TO_WITHDRAW
    );

    Ok(())
}
