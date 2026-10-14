use assert_matches::assert_matches;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey};
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::errors::MasmError;
use miden_protocol::errors::tx_kernel::ERR_EPILOGUE_EXECUTED_TRANSACTION_IS_EMPTY;
use miden_protocol::note::{Note, NoteAssets, NoteTag, NoteType};
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2, ACCOUNT_ID_SENDER};
use miden_protocol::transaction::TransactionScript;
use miden_protocol::{Felt, Word};
use miden_standards::account::auth::AuthTxFeeCollector;
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_AUTH_TX_FEE_COLLECTOR_ACCOUNT_CREATED_WITH_ASSETS,
    ERR_AUTH_TX_FEE_COLLECTOR_ACCOUNT_STATE_CHANGED,
    ERR_AUTH_TX_FEE_COLLECTOR_NOTE_MUST_CARRY_ONE_ASSET,
};
use miden_standards::note::P2idNoteStorage;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};
use miden_tx::TransactionExecutorError;
use miden_tx::auth::BasicAuthenticator;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// CONSTANTS
// ================================================================================================

/// The signature scheme these tests authenticate with. ECDSA verifies far faster than Falcon.
const AUTH_SCHEME: AuthScheme = AuthScheme::EcdsaK256Keccak;

/// The verification base fee the fee-charging chain in this module is built with. Any non-zero
/// value works.
const VERIFICATION_BASE_FEE: u32 = 500;

// HELPERS
// ================================================================================================

/// The asset the fee notes in these tests carry.
fn fee_asset() -> Asset {
    FungibleAsset::mock(10)
}

/// The components of a fee collector account: `BasicWallet` and the auth component.
fn tx_fee_collector_account_builder(
    seed: [u8; 32],
    assets: impl IntoIterator<Item = Asset>,
) -> AccountBuilder {
    AccountBuilder::new(seed)
        .with_component(BasicWallet)
        .with_assets(assets)
        .account_type(AccountType::Public)
}

/// Adds an existing fee collector account to the chain.
///
/// Registers it through the builder rather than with `add_account`, so the chain also learns the
/// authenticator that signs for it.
fn add_tx_fee_collector_account(builder: &mut MockChainBuilder) -> anyhow::Result<Account> {
    add_tx_fee_collector_account_with(builder, [42; 32], [], AccountState::Exists)
}

/// As [`add_tx_fee_collector_account`], but lets the caller pick the seed, any assets the account
/// already holds, and whether it exists or is created by the transaction under test.
fn add_tx_fee_collector_account_with(
    builder: &mut MockChainBuilder,
    seed: [u8; 32],
    assets: impl IntoIterator<Item = Asset>,
    state: AccountState,
) -> anyhow::Result<Account> {
    builder.add_account_from_builder(
        Auth::TxFeeCollector { auth_scheme: AUTH_SCHEME },
        tx_fee_collector_account_builder(seed, assets),
        state,
    )
}

/// Adds the wallet the P2ID notes in these tests go to.
fn add_target(builder: &mut MockChainBuilder) -> anyhow::Result<Account> {
    builder.add_existing_wallet(Auth::BasicAuth {
        auth_scheme: AuthScheme::Falcon512Poseidon2,
    })
}

/// Adds a TX_FEE note carrying the given assets.
fn add_fee_note(builder: &mut MockChainBuilder, assets: &[Asset]) -> anyhow::Result<Note> {
    Ok(builder.add_tx_fee_note(ACCOUNT_ID_SENDER.try_into()?, assets)?)
}

/// A transaction script that deposits `asset` into the account's wallet, changing its vault.
fn deposit_script(asset: Asset) -> anyhow::Result<TransactionScript> {
    let source = format!(
        r#"
        use miden::core::sys

        @transaction_script
        pub proc main
            push.{asset_value}
            push.{asset_id}
            call.::miden::standards::wallets::basic::receive_asset
            exec.sys::truncate_stack
        end
        "#,
        asset_value = asset.to_value_word(),
        asset_id = asset.to_id_word(),
    );

    Ok(CodeBuilder::default().compile_tx_script(source)?)
}

/// The auth args addressing a public P2ID note to `target`.
fn auth_args(target: AccountId) -> Word {
    AuthTxFeeCollector::auth_args(target, NoteType::Public)
}

/// Sets up the common shape of a fee collection transaction: the account, a target wallet to
/// forward to, and one TX_FEE note to forward.
fn tx_fee_collector_setup() -> anyhow::Result<(Account, AccountId, Note, MockChain)> {
    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account(&mut builder)?;
    let target = add_target(&mut builder)?;
    let fee_note = add_fee_note(&mut builder, &[fee_asset()])?;

    Ok((account, target.id(), fee_note, builder.build()?))
}

// FORWARDING TESTS
// ================================================================================================

/// The auth procedure merges the assets of several fee notes into one P2ID note for the
/// target, leaving the account untouched.
#[tokio::test]
async fn tx_fee_collector_auth_forwards_several_fee_notes_into_one_p2id_note() -> anyhow::Result<()>
{
    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account(&mut builder)?;
    let target = add_target(&mut builder)?;

    let fee_notes = [
        add_fee_note(&mut builder, &[FungibleAsset::mock(10)])?,
        add_fee_note(&mut builder, &[FungibleAsset::mock(20)])?,
        add_fee_note(&mut builder, &[FungibleAsset::mock(30)])?,
    ];
    let mock_chain = builder.build()?;

    let mut tx_builder = mock_chain.build_transaction(account.id());
    for note in &fee_notes {
        tx_builder = tx_builder.authenticated_input_note(note.id());
    }
    let mock_tx = tx_builder.auth_args(auth_args(target.id())).build()?;
    let serial_number = AuthTxFeeCollector::derive_serial_number(
        auth_args(target.id()),
        mock_tx.input_notes().commitment(),
    );
    let executed = mock_tx.execute().await?;

    // the only output note is the P2ID note the auth procedure created
    assert_eq!(executed.output_notes().num_notes(), 1);
    let output_note = executed.output_notes().get_note(0);
    assert_eq!(
        output_note.recipient_digest(),
        P2idNoteStorage::new(target.id()).into_recipient(serial_number).digest(),
    );
    assert_eq!(output_note.metadata().tag(), NoteTag::with_account_target(target.id()));
    assert_eq!(output_note.metadata().note_type(), NoteType::Public);
    assert_eq!(output_note.metadata().sender(), account.id());

    // the three amounts merged into one asset
    let mock_faucet_id = FungibleAsset::mock(1).faucet_id();
    assert_eq!(
        output_note.assets(),
        &NoteAssets::new(vec![FungibleAsset::new(mock_faucet_id, 60)?.into()])?,
    );

    // the account is a conduit: none of the forwarded assets stuck to it
    assert!(
        executed.account_patch().vault().is_empty(),
        "a fee collection transaction must not change the account's vault",
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

/// Assets of different faucets and compositions are all forwarded into the same output note, in
/// input-note order.
#[tokio::test]
async fn tx_fee_collector_auth_forwards_assets_of_every_faucet_and_composition()
-> anyhow::Result<()> {
    let other_faucet_id = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_2.try_into()?;
    let mock_asset: Asset = FungibleAsset::mock(25);
    let other_asset: Asset = FungibleAsset::new(other_faucet_id, 40)?.into();
    let non_fungible_asset: Asset = NonFungibleAsset::mock(&[4, 5, 6]);

    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account(&mut builder)?;
    let target = add_target(&mut builder)?;

    let notes = [
        add_fee_note(&mut builder, &[mock_asset])?,
        add_fee_note(&mut builder, &[non_fungible_asset])?,
        add_fee_note(&mut builder, &[other_asset])?,
    ];
    let mock_chain = builder.build()?;

    let mut tx_builder = mock_chain.build_transaction(account.id());
    for note in &notes {
        tx_builder = tx_builder.authenticated_input_note(note.id());
    }
    let executed = tx_builder.auth_args(auth_args(target.id())).build()?.execute().await?;

    assert_eq!(executed.output_notes().num_notes(), 1);
    assert_eq!(
        executed.output_notes().get_note(0).assets(),
        &NoteAssets::new(vec![mock_asset, non_fungible_asset, other_asset])?,
    );
    assert_eq!(executed.final_account().to_commitment(), account.to_commitment());

    Ok(())
}

/// As many distinct assets as a note can hold are forwarded into the single P2ID note.
#[tokio::test]
async fn tx_fee_collector_auth_forwards_the_maximum_number_of_distinct_assets() -> anyhow::Result<()>
{
    let assets: Vec<Asset> = (0..NoteAssets::MAX_NUM_ASSETS)
        .map(|i| NonFungibleAsset::mock(&[u8::try_from(i).unwrap()]))
        .collect();

    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account(&mut builder)?;
    let target = add_target(&mut builder)?;

    let mut notes = Vec::new();
    for asset in &assets {
        notes.push(add_fee_note(&mut builder, &[*asset])?);
    }
    let mock_chain = builder.build()?;

    let mut tx_builder = mock_chain.build_transaction(account.id());
    for note in &notes {
        tx_builder = tx_builder.authenticated_input_note(note.id());
    }
    let executed = tx_builder.auth_args(auth_args(target.id())).build()?.execute().await?;

    assert_eq!(executed.output_notes().num_notes(), 1);
    assert_eq!(executed.output_notes().get_note(0).assets(), &NoteAssets::new(assets)?);
    assert_eq!(executed.final_account().to_commitment(), account.to_commitment());

    Ok(())
}

/// The P2ID note the auth procedure creates is claimable by its target.
#[tokio::test]
async fn tx_fee_collector_auth_output_note_is_consumable_by_the_target() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account(&mut builder)?;
    let mut target = add_target(&mut builder)?;

    let fee_asset = FungibleAsset::mock(100);
    let fee_note = add_fee_note(&mut builder, &[fee_asset])?;
    let mut mock_chain = builder.build()?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .auth_args(auth_args(target.id()))
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

/// The account's own balance is not forwarded: only what the consumed notes carry is.
#[tokio::test]
async fn tx_fee_collector_auth_leaves_the_accounts_own_balance_alone() -> anyhow::Result<()> {
    let own_asset: Asset = FungibleAsset::mock(5);

    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account_with(
        &mut builder,
        [43; 32],
        [own_asset],
        AccountState::Exists,
    )?;
    let target = add_target(&mut builder)?;
    let fee_note = add_fee_note(&mut builder, &[fee_asset()])?;
    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .auth_args(auth_args(target.id()))
        .build()?
        .execute()
        .await?;

    assert_eq!(
        executed.output_notes().get_note(0).assets(),
        &NoteAssets::new(vec![fee_asset()])?,
    );
    assert_eq!(executed.final_account().to_commitment(), account.to_commitment());

    Ok(())
}

/// A consumed note carrying two assets is rejected.
#[tokio::test]
async fn tx_fee_collector_auth_rejects_a_note_carrying_two_assets() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account(&mut builder)?;
    let target = add_target(&mut builder)?;
    let two_asset_note =
        add_fee_note(&mut builder, &[fee_asset(), NonFungibleAsset::mock(&[7, 8, 9])])?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(two_asset_note.id())
        .auth_args(auth_args(target.id()))
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTH_TX_FEE_COLLECTOR_NOTE_MUST_CARRY_ONE_ASSET);

    Ok(())
}

// STATE TESTS
// ================================================================================================

/// A transaction that changes the account's vault is rejected: the commitment changed.
#[tokio::test]
async fn tx_fee_collector_auth_rejects_a_state_change() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account(&mut builder)?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.id())
        .tx_script(deposit_script(fee_asset())?)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTH_TX_FEE_COLLECTOR_ACCOUNT_STATE_CHANGED);

    Ok(())
}

/// A consumed note that moved its asset out itself (a P2ID note deposits into the wallet) leaves
/// nothing for the auth procedure to forward, so the transaction is rejected.
#[tokio::test]
async fn tx_fee_collector_auth_rejects_a_note_that_moved_its_asset_out() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account(&mut builder)?;

    let note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into()?,
        account.id(),
        &[fee_asset()],
        NoteType::Public,
    )?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(note.id())
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_AUTH_TX_FEE_COLLECTOR_NOTE_MUST_CARRY_ONE_ASSET);

    Ok(())
}

/// On a fee-charging chain the auth procedure creates no TX_FEE note, so the transaction's only
/// output is the P2ID note.
#[tokio::test]
async fn tx_fee_collector_auth_creates_no_fee_note_on_a_fee_charging_chain() -> anyhow::Result<()> {
    let mut builder = MockChain::builder().verification_base_fee(VERIFICATION_BASE_FEE);
    let account = add_tx_fee_collector_account(&mut builder)?;
    let target = add_target(&mut builder)?;
    let fee_note = add_fee_note(&mut builder, &[fee_asset()])?;
    let mock_chain = builder.build()?;

    let mock_tx = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .auth_args(auth_args(target.id()))
        .build()?;
    let serial_number = AuthTxFeeCollector::derive_serial_number(
        auth_args(target.id()),
        mock_tx.input_notes().commitment(),
    );
    let executed = mock_tx.execute().await?;

    assert_eq!(
        executed.output_notes().num_notes(),
        1,
        "a fee collection transaction pays no fee, so the P2ID note is its only output",
    );
    assert_eq!(
        executed.output_notes().get_note(0).recipient_digest(),
        P2idNoteStorage::new(target.id()).into_recipient(serial_number).digest(),
    );
    assert_eq!(executed.final_account().to_commitment(), account.to_commitment());

    Ok(())
}

/// Two successive fee collection transactions leave the account byte-identical, nonce included,
/// which is what lets batch builders build them concurrently. Their P2ID notes differ.
#[tokio::test]
async fn tx_fee_collector_auth_leaves_the_account_untouched_across_transactions()
-> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account(&mut builder)?;
    let target = add_target(&mut builder)?;

    let first_note = add_fee_note(&mut builder, &[fee_asset()])?;
    let second_note = add_fee_note(&mut builder, &[fee_asset()])?;
    let mock_chain = builder.build()?;

    let mut recipients = Vec::new();
    for note in [first_note, second_note] {
        let executed = mock_chain
            .build_transaction(account.id())
            .authenticated_input_note(note.id())
            .auth_args(auth_args(target.id()))
            .build()?
            .execute()
            .await?;

        assert_eq!(executed.final_account().to_commitment(), account.to_commitment());
        assert_eq!(executed.final_account().nonce(), account.nonce());
        recipients.push(executed.output_notes().get_note(0).recipient_digest());
    }

    assert_ne!(recipients[0], recipients[1], "each transaction derives its own serial number");

    Ok(())
}

/// A transaction consuming no input notes against an existing account creates no P2ID note and
/// changes nothing, so the kernel rejects it as empty.
#[tokio::test]
async fn tx_fee_collector_auth_rejects_a_transaction_without_input_notes() -> anyhow::Result<()> {
    let (account, target, _fee_note, mock_chain) = tx_fee_collector_setup()?;

    let result = mock_chain
        .build_transaction(account.id())
        .auth_args(auth_args(target))
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_EPILOGUE_EXECUTED_TRANSACTION_IS_EMPTY);

    Ok(())
}

// DEPLOYMENT TESTS
// ================================================================================================

/// The account's key holder can deploy it themselves: the creating transaction is the one case in
/// which the nonce is incremented, and it needs no notes.
#[tokio::test]
async fn tx_fee_collector_auth_can_create_an_account() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account_with(&mut builder, [45; 32], [], AccountState::New)?;
    let mock_chain = builder.build()?;

    // a new account is passed by value, since the chain does not yet know it
    let executed = mock_chain.build_transaction(account.clone()).build()?.execute().await?;

    assert_eq!(
        executed.final_account().nonce(),
        Felt::new_unchecked(1),
        "the creating transaction is the only one that may increment the nonce",
    );
    assert_eq!(
        executed.output_notes().num_notes(),
        0,
        "nothing was consumed, so nothing is forwarded"
    );

    Ok(())
}

/// The creating transaction can already forward fee notes.
#[tokio::test]
async fn tx_fee_collector_auth_can_create_an_account_and_forward_in_one_transaction()
-> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account_with(&mut builder, [46; 32], [], AccountState::New)?;
    let target = add_target(&mut builder)?;
    let fee_note = add_fee_note(&mut builder, &[fee_asset()])?;
    let mock_chain = builder.build()?;

    let executed = mock_chain
        .build_transaction(account.clone())
        .authenticated_input_note(fee_note.id())
        .auth_args(auth_args(target.id()))
        .build()?
        .execute()
        .await?;

    assert_eq!(executed.final_account().nonce(), Felt::new_unchecked(1));
    assert_eq!(executed.output_notes().num_notes(), 1);
    assert_eq!(
        executed.output_notes().get_note(0).assets(),
        &NoteAssets::new(vec![fee_asset()])?,
    );

    Ok(())
}

/// An account created holding assets could never move them out again (every later transaction has
/// to leave it unchanged), so the creating transaction is rejected instead.
#[tokio::test]
async fn tx_fee_collector_auth_rejects_an_account_created_holding_assets() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account_with(&mut builder, [49; 32], [], AccountState::New)?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.clone())
        .tx_script(deposit_script(fee_asset())?)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_AUTH_TX_FEE_COLLECTOR_ACCOUNT_CREATED_WITH_ASSETS
    );

    Ok(())
}

// SIGNATURE TESTS
// ================================================================================================

/// Without the key nothing can be executed against the account.
#[tokio::test]
async fn tx_fee_collector_auth_requires_a_signature() -> anyhow::Result<()> {
    let (account, target, fee_note, mock_chain) = tx_fee_collector_setup()?;

    // an otherwise valid fee collection transaction, so that only the missing key can fail it
    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .auth_args(auth_args(target))
        .authenticator(None)
        .build()?
        .execute()
        .await;

    assert_matches!(result, Err(TransactionExecutorError::MissingAuthenticator));

    Ok(())
}

/// The creating transaction is signed like any other: skipping the state check does not skip the
/// signature.
#[tokio::test]
async fn tx_fee_collector_auth_requires_a_signature_to_create_an_account() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let account = add_tx_fee_collector_account_with(&mut builder, [48; 32], [], AccountState::New)?;
    let mock_chain = builder.build()?;

    let result = mock_chain
        .build_transaction(account.clone())
        .authenticator(None)
        .build()?
        .execute()
        .await;

    assert_matches!(result, Err(TransactionExecutorError::MissingAuthenticator));

    Ok(())
}

/// A signature from a key other than the account's is rejected, so holding *a* key is not enough.
#[tokio::test]
async fn tx_fee_collector_auth_rejects_a_foreign_key_signature() -> anyhow::Result<()> {
    let (account, target, fee_note, mock_chain) = tx_fee_collector_setup()?;

    // re-derive the account's public key from the seed `Auth::TxFeeCollector` uses, then bind a
    // foreign secret key to it, so the procedure gets a signature that must fail to verify
    let mut account_rng = ChaCha20Rng::from_seed(Default::default());
    let account_pub_key =
        AuthSecretKey::with_scheme_and_rng(AUTH_SCHEME, &mut account_rng)?.public_key();

    let mut foreign_rng = ChaCha20Rng::from_seed([1u8; 32]);
    let foreign_sec_key = AuthSecretKey::with_scheme_and_rng(AUTH_SCHEME, &mut foreign_rng)?;

    let authenticator = BasicAuthenticator::from_key_pairs(&[(foreign_sec_key, account_pub_key)]);

    let result = mock_chain
        .build_transaction(account.id())
        .authenticated_input_note(fee_note.id())
        .auth_args(auth_args(target))
        .authenticator(Some(authenticator))
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        MasmError::from_static_str("invalid public key commitment")
    );

    Ok(())
}
