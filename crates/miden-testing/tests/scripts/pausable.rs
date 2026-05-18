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
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountBuilder,
    AccountComponent,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
    RoleSymbol,
};
use miden_protocol::asset::{
    Asset,
    AssetAmount,
    AssetCallbackFlag,
    AssetCallbacks,
    FungibleAsset,
    NonFungibleAsset,
    NonFungibleAssetDetails,
};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::AccessControl;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::pausable::{
    PausableAuthControlled,
    PausableOwnerControlled,
    PausableRoleControlled,
};
use miden_standards::account::policies::{
    BasicPausable,
    BurnPolicyConfig,
    MintPolicyConfig,
    PausableBlocklist,
    PolicyAuthority,
    PolicyRegistration,
    TokenPolicyManager,
    TransferPolicy,
};
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

const ERR_SENDER_NOT_OWNER: MasmError = MasmError::from_static_str("note sender is not the owner");

const ERR_SENDER_LACKS_ROLE: MasmError =
    MasmError::from_static_str("note sender does not hold the required role");

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
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([43u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(faucet)
        .with_component(BasicPausable::default())
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(PausableOwnerControlled)
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
            let faucet = FungibleFaucet::builder()
                .name(TokenName::new("SYM")?)
                .symbol("SYM".try_into()?)
                .decimals(8)
                .max_supply(AssetAmount::new(1_000_000)?)
                .build()?;
            vec![faucet.into()]
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
        .with_component(BasicPausable::default())
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(PausableOwnerControlled)
        .with_component(pausable_callbacks_component()?);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds a private note whose `main` proc calls `pausable::owner_controlled::pause`. The note's
/// sender is the value passed in, which is what the Ownable2Step auth check reads.
fn build_pause_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::utils::pausable::owner_controlled

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.owner_controlled::pause
            dropw dropw dropw dropw
        end
        "#,
    )
}

/// Builds a private note whose `main` proc calls `pausable::owner_controlled::unpause`.
fn build_unpause_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::utils::pausable::owner_controlled

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.owner_controlled::unpause
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

    // Note sender is NOT_OWNER, but pausable::owner_controlled::pause asserts sender == owner.
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

// TESTS — PAUSABLE RBAC
// ================================================================================================

/// Adds a fungible faucet with the storage-only `Pausable`, RBAC (`AccessControl::Rbac` —
/// which also installs `Ownable2Step` with `owner` as the top-level authority), the
/// `PausableRbac` admin wrapper, and the asset-callback gating component.
fn add_faucet_with_pausable_rbac(
    builder: &mut MockChainBuilder,
    owner: AccountId,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([43u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(faucet)
        .with_component(BasicPausable::default())
        .with_components(AccessControl::Rbac { owner })
        .with_component(PausableRoleControlled)
        .with_component(pausable_callbacks_component()?);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds a note (sender = `owner`) that calls `rbac::grant_role` to add `member` to `role`.
fn build_grant_role_note(
    owner: AccountId,
    role: RoleSymbol,
    member: AccountId,
) -> anyhow::Result<Note> {
    let code = format!(
        r#"
        use miden::standards::access::rbac

        @note_script
        pub proc main
            repeat.13 push.0 end
            push.{member_prefix}
            push.{member_suffix}
            push.{role}
            call.rbac::grant_role
            dropw dropw dropw dropw
        end
        "#,
        member_prefix = member.prefix().as_felt(),
        member_suffix = member.suffix(),
        role = Felt::from(&role),
    );
    build_note(owner, code)
}

/// Builds a note (sender = `sender`) that calls `pausable::role_controlled::pause`.
fn build_pause_rbac_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::utils::pausable::role_controlled

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.role_controlled::pause
            dropw dropw dropw dropw
        end
        "#,
    )
}

/// Builds a note (sender = `sender`) that calls `pausable::role_controlled::unpause`.
fn build_unpause_rbac_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::utils::pausable::role_controlled

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.role_controlled::unpause
            dropw dropw dropw dropw
        end
        "#,
    )
}

#[tokio::test]
async fn pausable_rbac_pause_succeeds_when_sender_has_pauser_role() -> anyhow::Result<()> {
    let owner = *OWNER_ID;
    let pauser = test_account_id(21);

    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pausable_rbac(&mut builder, owner)?;

    let grant_pauser_note =
        build_grant_role_note(owner, PausableRoleControlled::pauser_role(), pauser)?;
    let pause_note = build_pause_rbac_note(pauser)?;
    builder.add_output_note(RawOutputNote::Full(grant_pauser_note.clone()));
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Owner grants PAUSER role to pauser_account.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &grant_pauser_note).await?;

    // pauser_account pauses the faucet — should succeed.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    Ok(())
}

#[tokio::test]
async fn pausable_rbac_pause_fails_when_sender_lacks_pauser_role() -> anyhow::Result<()> {
    let owner = *OWNER_ID;
    let attacker = *NON_OWNER_ID;

    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pausable_rbac(&mut builder, owner)?;

    // Attacker has no roles granted; pause attempt should panic on the role assertion.
    let attacker_note = build_pause_rbac_note(attacker)?;
    builder.add_output_note(RawOutputNote::Full(attacker_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let result = mock_chain
        .build_tx_context(faucet.id(), &[attacker_note.id()], &[])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_LACKS_ROLE);

    Ok(())
}

#[tokio::test]
async fn pausable_rbac_unpause_succeeds_when_sender_has_unpauser_role() -> anyhow::Result<()> {
    let owner = *OWNER_ID;
    let pauser = test_account_id(21);
    let unpauser = test_account_id(22);

    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pausable_rbac(&mut builder, owner)?;

    let grant_pauser_note =
        build_grant_role_note(owner, PausableRoleControlled::pauser_role(), pauser)?;
    let grant_unpauser_note =
        build_grant_role_note(owner, PausableRoleControlled::unpauser_role(), unpauser)?;
    let pause_note = build_pause_rbac_note(pauser)?;
    let unpause_note = build_unpause_rbac_note(unpauser)?;
    builder.add_output_note(RawOutputNote::Full(grant_pauser_note.clone()));
    builder.add_output_note(RawOutputNote::Full(grant_unpauser_note.clone()));
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    builder.add_output_note(RawOutputNote::Full(unpause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &grant_pauser_note).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &grant_unpauser_note).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &unpause_note).await?;

    Ok(())
}

#[tokio::test]
async fn pausable_rbac_separation_of_duties() -> anyhow::Result<()> {
    // pauser has only PAUSER, unpauser has only UNPAUSER. Each role should be limited to
    // its own action: pauser cannot unpause, unpauser cannot pause.
    let owner = *OWNER_ID;
    let pauser = test_account_id(21);
    let unpauser = test_account_id(22);

    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pausable_rbac(&mut builder, owner)?;

    let grant_pauser_note =
        build_grant_role_note(owner, PausableRoleControlled::pauser_role(), pauser)?;
    let grant_unpauser_note =
        build_grant_role_note(owner, PausableRoleControlled::unpauser_role(), unpauser)?;
    // pauser tries to also unpause — should fail.
    let pauser_unpause_attempt = build_unpause_rbac_note(pauser)?;
    // Legitimate pause by pauser so the unpause attempt can reach the role assertion.
    let legitimate_pause_note = build_pause_rbac_note(pauser)?;
    // unpauser tries to pause — should fail.
    let unpauser_pause_attempt = build_pause_rbac_note(unpauser)?;
    builder.add_output_note(RawOutputNote::Full(grant_pauser_note.clone()));
    builder.add_output_note(RawOutputNote::Full(grant_unpauser_note.clone()));
    builder.add_output_note(RawOutputNote::Full(legitimate_pause_note.clone()));
    builder.add_output_note(RawOutputNote::Full(pauser_unpause_attempt.clone()));
    builder.add_output_note(RawOutputNote::Full(unpauser_pause_attempt.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &grant_pauser_note).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &grant_unpauser_note).await?;

    // unpauser attempting to pause — denied.
    let pause_attempt_result = mock_chain
        .build_tx_context(faucet.id(), &[unpauser_pause_attempt.id()], &[])?
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(pause_attempt_result, ERR_SENDER_LACKS_ROLE);

    // pauser legitimately pauses so the next assertion can be reached.
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &legitimate_pause_note).await?;

    // pauser attempting to unpause — denied (lacks UNPAUSER).
    let unpause_attempt_result = mock_chain
        .build_tx_context(faucet.id(), &[pauser_unpause_attempt.id()], &[])?
        .build()?
        .execute()
        .await;
    assert_transaction_executor_error!(unpause_attempt_result, ERR_SENDER_LACKS_ROLE);

    Ok(())
}

#[tokio::test]
async fn pausable_rbac_paused_state_blocks_asset_receive() -> anyhow::Result<()> {
    // Integration: PausableRbac pause flows through to the asset callback guard, so an
    // unpaused faucet's outgoing P2ID cannot be received once the role-gated pause fires.
    let owner = *OWNER_ID;
    let pauser = test_account_id(21);

    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pausable_rbac(&mut builder, owner)?;

    let fungible_asset =
        FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let p2id_note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(fungible_asset)],
        NoteType::Public,
    )?;

    let grant_pauser_note =
        build_grant_role_note(owner, PausableRoleControlled::pauser_role(), pauser)?;
    let pause_note = build_pause_rbac_note(pauser)?;
    builder.add_output_note(RawOutputNote::Full(grant_pauser_note.clone()));
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &grant_pauser_note).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[p2id_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PAUSABLE_ENFORCED_PAUSE);

    Ok(())
}

// TESTS — COEXISTENCE OF PAUSABLE_OWNER AND PAUSABLE_RBAC
// ================================================================================================

/// Adds a faucet with BOTH `PausableOwner` and `PausableRbac` installed alongside the
/// shared `Pausable` storage. Useful for verifying that the two admin wrappers can coexist
/// on the same account and operate independently against the same pause flag.
fn add_faucet_with_pausable_owner_and_rbac(
    builder: &mut MockChainBuilder,
    owner: AccountId,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([43u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(faucet)
        .with_component(BasicPausable::default())
        .with_components(AccessControl::Rbac { owner })
        .with_component(PausableOwnerControlled)
        .with_component(PausableRoleControlled)
        .with_component(pausable_callbacks_component()?);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

#[tokio::test]
async fn pausable_owner_and_rbac_coexist() -> anyhow::Result<()> {
    // Owner pauses (via PausableOwnerControlled), then unpauser unpauses (via
    // PausableRoleControlled), then owner pauses again. Both wrappers share the same
    // `is_paused` storage; either path can flip the flag and the other observes the new state.
    let owner = *OWNER_ID;
    let unpauser = test_account_id(22);

    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_pausable_owner_and_rbac(&mut builder, owner)?;

    let grant_unpauser_note =
        build_grant_role_note(owner, PausableRoleControlled::unpauser_role(), unpauser)?;
    let owner_pause_note = build_pause_note(owner)?;
    let rbac_unpause_note = build_unpause_rbac_note(unpauser)?;
    let owner_pause_again_note = build_pause_note(owner)?;
    builder.add_output_note(RawOutputNote::Full(grant_unpauser_note.clone()));
    builder.add_output_note(RawOutputNote::Full(owner_pause_note.clone()));
    builder.add_output_note(RawOutputNote::Full(rbac_unpause_note.clone()));
    builder.add_output_note(RawOutputNote::Full(owner_pause_again_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    execute_note_on_faucet(&mut mock_chain, faucet.id(), &grant_unpauser_note).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &owner_pause_note).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &rbac_unpause_note).await?;
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &owner_pause_again_note).await?;

    Ok(())
}

// TESTS — BASIC PAUSABLE TRANSFER POLICY
// ================================================================================================

const ERR_ACCOUNT_IS_BLOCKED: MasmError = MasmError::from_static_str("account is blocked");

/// Adds a fungible faucet wired with the [`BasicPausable`] transfer policy as the active
/// send/receive policy. `PausableAuthControlled` is installed so any tx the account's auth
/// scheme accepts can pause / unpause.
fn add_faucet_with_pausable_policy(
    builder: &mut MockChainBuilder,
    initial_state: bool,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([43u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(faucet)
        .with_component(BasicPausable::new(initial_state))
        .with_components(
            TokenPolicyManager::new(PolicyAuthority::AuthControlled)
                .with_mint_policy(MintPolicyConfig::AllowAll, PolicyRegistration::Active)?
                .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)?
                .with_send_policy(
                    TransferPolicy::Custom(BasicPausable::root()),
                    PolicyRegistration::Active,
                )?
                .with_receive_policy(
                    TransferPolicy::Custom(BasicPausable::root()),
                    PolicyRegistration::Active,
                )?,
        )
        .with_component(PausableAuthControlled);

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds a note (any sender) that invokes `pausable::auth_controlled::pause`.
fn build_auth_pause_note(sender: AccountId) -> anyhow::Result<Note> {
    build_note(
        sender,
        r#"
        use miden::standards::utils::pausable::auth_controlled

        @note_script
        pub proc main
            repeat.16 push.0 end
            call.auth_controlled::pause
            dropw dropw dropw dropw
        end
        "#,
    )
}

#[tokio::test]
async fn basic_pausable_policy_allows_receive_when_unpaused() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pausable_policy(&mut builder, false)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
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

#[tokio::test]
async fn basic_pausable_policy_blocks_receive_when_initially_paused() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    // Faucet starts paused: the policy's check_policy must reject the transfer.
    let faucet = add_faucet_with_pausable_policy(&mut builder, true)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

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

#[tokio::test]
async fn basic_pausable_policy_blocks_receive_after_auth_pause() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pausable_policy(&mut builder, false)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    // Stage an auth-controlled pause note (sender = arbitrary, since Auth::IncrNonce accepts).
    let pause_note = build_auth_pause_note(*OWNER_ID)?;
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

// TESTS — BASIC PAUSABLE-BLOCKLIST COMBINED TRANSFER POLICY
// ================================================================================================

/// Adds a fungible faucet wired with the [`PausableBlocklist`] composite transfer policy
/// as the active send/receive policy. The policy enforces both `assert_not_paused` and
/// `assert_not_blocked` on each transfer.
fn add_faucet_with_pausable_blocklist_policy(
    builder: &mut MockChainBuilder,
    initial_pause_state: bool,
    initial_blocked: impl IntoIterator<Item = AccountId>,
) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let composite = PausableBlocklist::new()
        .with_initial_pause_state(initial_pause_state)
        .with_initial_blocked_accounts(initial_blocked);

    let account_builder = AccountBuilder::new([44u8; 32])
        .storage_mode(AccountStorageMode::Public)
        .account_type(AccountType::FungibleFaucet)
        .with_component(faucet)
        .with_component(composite)
        .with_components(
            TokenPolicyManager::new(PolicyAuthority::AuthControlled)
                .with_mint_policy(MintPolicyConfig::AllowAll, PolicyRegistration::Active)?
                .with_burn_policy(BurnPolicyConfig::AllowAll, PolicyRegistration::Active)?
                .with_send_policy(
                    TransferPolicy::Custom(PausableBlocklist::root()),
                    PolicyRegistration::Active,
                )?
                .with_receive_policy(
                    TransferPolicy::Custom(PausableBlocklist::root()),
                    PolicyRegistration::Active,
                )?,
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

#[tokio::test]
async fn pausable_blocklist_policy_allows_when_unrestricted() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pausable_blocklist_policy(&mut builder, false, [])?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
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

#[tokio::test]
async fn pausable_blocklist_policy_blocks_when_paused() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    // Combined policy with pause set; blocklist empty. Pause guard should fire first.
    let faucet = add_faucet_with_pausable_blocklist_policy(&mut builder, true, [])?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

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

#[tokio::test]
async fn pausable_blocklist_policy_blocks_when_recipient_blocked() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target_account = builder.add_existing_wallet(Auth::IncrNonce)?;
    // Combined policy with empty pause + target pre-blocked. Blocklist guard should fire.
    let faucet =
        add_faucet_with_pausable_blocklist_policy(&mut builder, false, [target_account.id()])?;

    let asset = FungibleAsset::new(faucet.id(), 100)?.with_callbacks(AssetCallbackFlag::Enabled);
    let note = builder.add_p2id_note(
        faucet.id(),
        target_account.id(),
        &[Asset::Fungible(asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let result = mock_chain
        .build_tx_context(target_account.id(), &[note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_ACCOUNT_IS_BLOCKED);

    Ok(())
}

// TESTS — PAUSABLE AUTH CONTROLLED
// ================================================================================================

#[tokio::test]
async fn pausable_auth_controlled_pause_succeeds_for_any_signed_tx() -> anyhow::Result<()> {
    // With Auth::IncrNonce + PausableAuthControlled, any sender that the account accepts can
    // call pause — there is no explicit owner / role check at the wrapper level.
    let mut builder = MockChain::builder();
    let _wallet = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_pausable_policy(&mut builder, false)?;

    let pause_note = build_auth_pause_note(*NON_OWNER_ID)?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Even a non-owner sender succeeds because PausableAuthControlled defers entirely to the
    // account's own auth component (Auth::IncrNonce accepts everything in tests).
    execute_note_on_faucet(&mut mock_chain, faucet.id(), &pause_note).await?;

    Ok(())
}
