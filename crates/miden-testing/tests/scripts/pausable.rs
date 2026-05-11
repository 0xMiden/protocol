//! Tests for the Pausable storage component and its owner-gated wrapper `PausableOwner`.
//!
//! `Pausable` itself is a storage-only descriptor; it installs the `is_paused` slot but does
//! not export pause/unpause procedures. The wrapper [`PausableOwner`] exposes `pause` and
//! `unpause` as `Invocation: call` procedures gated by the Ownable2Step owner.
//!
//! To exercise the pause guard end-to-end through asset transfers, these tests pair the
//! storage component with a [`pausable_callbacks_component`] — a test-only [`AccountComponent`]
//! whose `on_before_asset_added_to_account` and `on_before_asset_added_to_note` procedures
//! call `exec.::miden::standards::utils::pausable::assert_not_paused`. This is the canonical
//! pattern for downstream components that want to gate asset transfers on pause state.

extern crate alloc;

use alloc::string::String;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
};
use miden_protocol::asset::{
    Asset,
    AssetCallbackFlag,
    AssetCallbacks,
    FungibleAsset,
    NonFungibleAsset,
    NonFungibleAssetDetails,
};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, utils::sync::LazyLock};
use miden_standards::account::access::AccessControl;
use miden_standards::account::faucets::BasicFungibleFaucet;
use miden_standards::account::metadata::{FungibleTokenMetadataBuilder, TokenName};
use miden_standards::account::pausable::Pausable;
use miden_standards::account::pausable_owner::PausableOwner;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::testing::account_component::MockFaucetComponent;
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};

const ERR_PAUSABLE_ENFORCED_PAUSE: MasmError = MasmError::from_static_str("the contract is paused");

const ERR_PAUSABLE_EXPECTED_PAUSE: MasmError =
    MasmError::from_static_str("the contract is not paused");

const ERR_SENDER_NOT_OWNER: MasmError =
    MasmError::from_static_str("note sender is not the owner");

/// Stable deterministic owner ID used for tests. Distinct from `non_owner_id`.
static OWNER_ID: LazyLock<AccountId> = LazyLock::new(|| test_account_id(11));

/// Stable deterministic non-owner ID used for negative auth tests.
static NON_OWNER_ID: LazyLock<AccountId> = LazyLock::new(|| test_account_id(99));

fn test_account_id(seed: u8) -> AccountId {
    AccountId::dummy(
        [seed; 15],
        AccountIdVersion::Version1,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    )
}

/// Test-only [`AccountComponent`] that gates asset transfers on the pause flag.
///
/// Wires `on_before_asset_added_to_account` and `on_before_asset_added_to_note` callback
/// procedures (registered via [`AssetCallbacks`]) to `pausable::assert_not_paused`. Compose
/// with [`Pausable`] to exercise the pause guard end-to-end through asset-callback-enabled
/// assets.
fn pausable_callbacks_component() -> anyhow::Result<AccountComponent> {
    const COMPONENT_NAME: &str = "miden::testing::pausable_callbacks";

    const SOURCE: &str = r#"
        use miden::standards::utils::pausable

        #! Inputs:  [ASSET_KEY, ASSET_VALUE, pad(8)]
        #! Outputs: [ASSET_VALUE, pad(12)]
        pub proc on_before_asset_added_to_account
            exec.pausable::assert_not_paused
            # => [ASSET_KEY, ASSET_VALUE, pad(8)]

            dropw
            # => [ASSET_VALUE, pad(12)]
        end

        #! Inputs:  [ASSET_KEY, ASSET_VALUE, note_idx, pad(7)]
        #! Outputs: [ASSET_VALUE, note_idx, pad(7)]
        pub proc on_before_asset_added_to_note
            exec.pausable::assert_not_paused
            # => [ASSET_KEY, ASSET_VALUE, note_idx, pad(7)]

            dropw
            # => [ASSET_VALUE, note_idx, pad(7)]
        end
    "#;

    let library = CodeBuilder::default().compile_component_code(COMPONENT_NAME, SOURCE)?;

    let on_account_path = format!("{COMPONENT_NAME}::on_before_asset_added_to_account");
    let on_note_path = format!("{COMPONENT_NAME}::on_before_asset_added_to_note");

    let on_account_root = library
        .as_library()
        .get_procedure_root_by_path(on_account_path.as_str())
        .expect("account callback procedure should exist");
    let on_note_root = library
        .as_library()
        .get_procedure_root_by_path(on_note_path.as_str())
        .expect("note callback procedure should exist");

    let storage_slots = AssetCallbacks::new()
        .on_before_asset_added_to_account(on_account_root)
        .on_before_asset_added_to_note(on_note_root)
        .into_storage_slots();

    let metadata = AccountComponentMetadata::new(
        COMPONENT_NAME,
        [AccountType::FungibleFaucet, AccountType::NonFungibleFaucet],
    )
    .with_description(
        "Test-only callbacks that gate asset transfers via pausable::assert_not_paused",
    );

    Ok(AccountComponent::new(library, storage_slots, metadata)?)
}

/// Adds a fungible faucet with the storage-only `Pausable`, the `PausableOwner` admin
/// wrapper gated by `Ownable2Step::new(owner)`, and the `pausable_callbacks_component`
/// that gates asset transfers on the pause flag.
fn add_faucet_with_pausable_owner(
    builder: &mut MockChainBuilder,
    owner: AccountId,
) -> anyhow::Result<Account> {
    let faucet_metadata = FungibleTokenMetadataBuilder::new(
        TokenName::new("SYM")?,
        "SYM".try_into()?,
        8,
        1_000_000u64,
    )
    .build()?;

    let account_builder = AccountBuilder::new([43u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(faucet_metadata)
        .with_component(BasicFungibleFaucet)
        .with_component(Pausable::default())
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(PausableOwner)
        .with_component(pausable_callbacks_component()?);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Adds either a fungible or non-fungible faucet with the same pause/owner wiring as
/// [`add_faucet_with_pausable_owner`], parameterised by `account_type`.
fn add_faucet_with_pausable_owner_for_account_type(
    builder: &mut MockChainBuilder,
    account_type: AccountType,
    owner: AccountId,
) -> anyhow::Result<Account> {
    if !account_type.is_faucet() {
        anyhow::bail!("account type must be a faucet");
    }

    let faucet_components: Vec<AccountComponent> = match account_type {
        AccountType::FungibleFaucet => {
            let faucet_metadata = FungibleTokenMetadataBuilder::new(
                TokenName::new("SYM")?,
                "SYM".try_into()?,
                8,
                1_000_000u64,
            )
            .build()?;
            vec![faucet_metadata.into(), BasicFungibleFaucet.into()]
        },
        AccountType::NonFungibleFaucet => vec![MockFaucetComponent.into()],
        _ => anyhow::bail!("pausable tests only use fungible or non-fungible faucet account types"),
    };

    let mut account_builder = AccountBuilder::new([43u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(account_type);
    for component in faucet_components {
        account_builder = account_builder.with_component(component);
    }
    account_builder = account_builder
        .with_component(Pausable::default())
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(PausableOwner)
        .with_component(pausable_callbacks_component()?);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds a private note whose `main` proc calls `pausable_owner::pause`. The note's sender
/// is the value passed in, which is what the Ownable2Step auth check reads.
fn build_pause_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::utils::pausable_owner

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.pausable_owner::pause
            dropw dropw dropw dropw
        end
        "#,
    )
}

/// Builds a private note whose `main` proc calls `pausable_owner::unpause`.
fn build_unpause_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::utils::pausable_owner

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.pausable_owner::unpause
            dropw dropw dropw dropw
        end
        "#,
    )
}

fn build_note(sender: AccountId, code: impl Into<String>) -> anyhow::Result<Note> {
    let seed: [u64; 4] = rand::random();
    let mut rng = RandomCoin::new(Word::from(seed.map(Felt::new)));
    Ok(NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .code(code.into())
        .build()?)
}

/// Executes a previously-staged pause/unpause note (already on-chain as a genesis note) and
/// commits the resulting tx to the chain so subsequent operations observe the updated state.
async fn execute_note_on_faucet(
    mock_chain: &mut MockChain,
    faucet_id: AccountId,
    note: &Note,
) -> anyhow::Result<()> {
    let executed = mock_chain
        .build_tx_context(faucet_id, &[note.id()], &[])?
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;
    Ok(())
}

// TESTS — ASSET TRANSFER GATING
// ================================================================================================

#[rstest::rstest]
#[case::fungible(
    AccountType::FungibleFaucet,
    |faucet_id| {
        Ok(FungibleAsset::new(faucet_id, 100)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[case::non_fungible(
    AccountType::NonFungibleFaucet,
    |faucet_id| {
        let details = NonFungibleAssetDetails::new(faucet_id, vec![1, 2, 3, 4])?;
        Ok(NonFungibleAsset::new(&details)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[tokio::test]
async fn pausable_receive_asset_succeeds_when_unpaused(
    #[case] account_type: AccountType,
    #[case] create_asset: impl FnOnce(AccountId) -> anyhow::Result<Asset>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet =
        add_faucet_with_pausable_owner_for_account_type(&mut builder, account_type, *OWNER_ID)?;

    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[create_asset(faucet.id())?],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

#[rstest::rstest]
#[case::fungible(
    AccountType::FungibleFaucet,
    |faucet_id| {
        Ok(FungibleAsset::new(faucet_id, 100)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[case::non_fungible(
    AccountType::NonFungibleFaucet,
    |faucet_id| {
        let details = NonFungibleAssetDetails::new(faucet_id, vec![1, 2, 3, 4])?;
        Ok(NonFungibleAsset::new(&details)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[tokio::test]
async fn pausable_receive_asset_fails_when_paused(
    #[case] account_type: AccountType,
    #[case] create_asset: impl FnOnce(AccountId) -> anyhow::Result<Asset>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet =
        add_faucet_with_pausable_owner_for_account_type(&mut builder, account_type, *OWNER_ID)?;

    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[create_asset(faucet.id())?],
        NoteType::Public,
    )?;

    let pause_note = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_ENFORCED_PAUSE);

    Ok(())
}

#[rstest::rstest]
#[case::fungible(
    AccountType::FungibleFaucet,
    |faucet_id| {
        Ok(FungibleAsset::new(faucet_id, 100)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[case::non_fungible(
    AccountType::NonFungibleFaucet,
    |faucet_id| {
        let details = NonFungibleAssetDetails::new(faucet_id, vec![1, 2, 3, 4])?;
        Ok(NonFungibleAsset::new(&details)?.with_callbacks(AssetCallbackFlag::Enabled).into())
    }
)]
#[tokio::test]
async fn pausable_add_asset_to_note_fails_when_paused(
    #[case] account_type: AccountType,
    #[case] create_asset: impl FnOnce(AccountId) -> anyhow::Result<Asset>,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet =
        add_faucet_with_pausable_owner_for_account_type(&mut builder, account_type, *OWNER_ID)?;

    let asset = create_asset(faucet.id())?;

    let pause_note = build_pause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    let recipient = Word::from([0u32, 1, 2, 3]);
    let script_code = format!(
        r#"
        use miden::protocol::output_note

        begin
            push.{recipient}
            push.{note_type}
            push.{tag}
            exec.output_note::create

            push.{asset_value}
            push.{asset_key}
            exec.output_note::add_asset
        end
        "#,
        recipient = recipient,
        note_type = NoteType::Private as u8,
        tag = miden_protocol::note::NoteTag::default(),
        asset_value = asset.to_value_word(),
        asset_key = asset.to_key_word(),
    );

    let tx_script = CodeBuilder::with_mock_libraries().compile_tx_script(&script_code)?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[], &[])?
        .tx_script(tx_script)
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_ENFORCED_PAUSE);

    Ok(())
}

#[tokio::test]
async fn pausable_pause_then_unpause_then_receive_succeeds() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pausable_owner(&mut builder, *OWNER_ID)?;

    let amount: u64 = 50;
    let fungible_asset =
        FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    let pause_note = build_pause_note(*OWNER_ID)?;
    let unpause_note = build_unpause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    builder.add_output_note(RawOutputNote::Full(unpause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &unpause_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    Ok(())
}

#[tokio::test]
async fn pausable_unpause_while_unpaused_fails() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let _wallet = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pausable_owner(&mut builder, *OWNER_ID)?;

    let unpause_note = build_unpause_note(*OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(unpause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[unpause_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_EXPECTED_PAUSE);

    Ok(())
}

// TESTS — OWNER AUTHORIZATION
// ================================================================================================

#[tokio::test]
async fn pausable_owner_pause_fails_when_sender_not_owner() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let _wallet = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pausable_owner(&mut builder, *OWNER_ID)?;

    // Note sender is NOT_OWNER, but pausable_owner::pause asserts sender == owner.
    let attacker_note = build_pause_note(*NON_OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(attacker_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[attacker_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

#[tokio::test]
async fn pausable_owner_unpause_fails_when_sender_not_owner() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let _wallet = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pausable_owner(&mut builder, *OWNER_ID)?;

    // Pre-stage both notes: the legitimate owner pause, and the attacker's unpause attempt.
    let pause_note = build_pause_note(*OWNER_ID)?;
    let attacker_note = build_unpause_note(*NON_OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    builder.add_output_note(RawOutputNote::Full(attacker_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Pause first (legitimately) so the unpause attempt can reach the owner check.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    // Then try to unpause as a non-owner.
    let result = mock_chain
        .build_tx_context(faucet.id(), &[attacker_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}
