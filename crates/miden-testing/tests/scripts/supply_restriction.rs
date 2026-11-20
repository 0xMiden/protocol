//! Tests for the [`miden_standards::account::policies::SupplyRestrictionManager`] component and the
//! `SUPPLY_RESTRICTION_CONFIG` standard note that dispatches its admin procedures.

use miden_protocol::Felt;
use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, StorageMapKey};
use miden_protocol::asset::{AssetAmount, FungibleAsset};
use miden_protocol::block::account_tree::AccountIdKey;
use miden_protocol::errors::protocol::ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO;
use miden_protocol::note::Note;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::access::{Authority, Ownable2Step};
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::SupplyRestrictionManager;
use miden_standards::errors::standards::{
    ERR_FAUCET_SUPPLY_DECREASE_EXCEEDS_TOKEN_SUPPLY,
    ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT,
    ERR_SENDER_NOT_OWNER,
    ERR_SUPPLY_RESTRICTION_AMOUNT_EXCEEDS_MAX_AMOUNT,
    ERR_SUPPLY_RESTRICTION_CONFIG_NOTE_IS_NOT_PUBLIC,
    ERR_SUPPLY_RESTRICTION_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_SUPPLY_RESTRICTION_CONFIG_UNKNOWN_VARIANT,
    ERR_SUPPLY_RESTRICTION_TOTAL_EXCEEDS_MAX_AMOUNT,
    ERR_SUPPLY_RESTRICTION_UNFREEZE_EXCEEDS_FROZEN_AMOUNT,
};
use miden_standards::note::config::{SupplyRestrictionConfig, SupplyRestrictionConfigNote};
use miden_standards::note::{NetworkAccountTarget, NoteExecutionHint};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};
use rand::RngExt;
use rstest::rstest;

use super::rbac::test_account_id;
use crate::into_private_note;

// CONSTANTS
// ================================================================================================

/// Token supply the test faucets start with.
const INITIAL_TOKEN_SUPPLY: u32 = 1_000;

/// Note storage variants of the supply restriction config note.
const VARIANT_FREEZE: u32 = 0;
const VARIANT_CONFISCATE: u32 = 2;

// HELPERS
// ================================================================================================

fn dummy_owner() -> AccountId {
    AccountId::mock_private(9)
}

/// Builds a fungible faucet with an initial token supply of [`INITIAL_TOKEN_SUPPLY`] carrying
/// the [`SupplyRestrictionManager`] component, gated by `owner_id` via
/// `Authority::OwnerControlled`.
fn add_faucet_with_owner_supply_restriction(
    builder: &mut MockChainBuilder,
    owner_id: AccountId,
) -> anyhow::Result<Account> {
    let account_builder = AccountBuilder::new([43u8; 32])
        .account_type(AccountType::Public)
        .with_component(fungible_faucet()?)
        .with_component(Ownable2Step::new(owner_id))
        .with_component(Authority::OwnerControlled)
        .with_component(SupplyRestrictionManager);

    builder.add_account_from_builder(
        Auth::BasicAuth { auth_scheme: AuthScheme::Falcon512Eidos },
        account_builder,
        AccountState::Exists,
    )
}

fn fungible_faucet() -> anyhow::Result<FungibleFaucet> {
    Ok(FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(FungibleAsset::MAX_AMOUNT)
        .token_supply(AssetAmount::from(INITIAL_TOKEN_SUPPLY))
        .build()?)
}

/// Builds a [`SupplyRestrictionConfigNote`] for `config`, sent by `sender` and targeting the
/// faucet.
fn supply_restriction_config_note(
    sender: AccountId,
    faucet_id: AccountId,
    config: SupplyRestrictionConfig,
) -> anyhow::Result<Note> {
    let note = SupplyRestrictionConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(config)
        .serial_number(rand::rng().random())
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the SupplyRestrictionConfig script with hand-crafted storage, bypassing
/// the builder so malformed inputs can be exercised.
///
/// It carries a `NetworkAccountTarget` for the consuming account, like a real config note, so
/// the note passes the script's target check and reaches the guard under test.
fn malformed_supply_restriction_config_note(
    sender: AccountId,
    target: AccountId,
    storage: Vec<Felt>,
) -> anyhow::Result<Note> {
    let note = NoteBuilder::new(sender, rand::rng())
        .script(SupplyRestrictionConfigNote::script())
        .note_storage(storage)?
        .attachment(NetworkAccountTarget::new(target, NoteExecutionHint::Always)?)
        .build()?;
    Ok(note)
}

/// Returns the `(frozen, confiscated)` amounts of `holder` in the faucet's latest committed
/// restricted amounts map.
fn restricted_amounts(
    mock_chain: &MockChain,
    faucet_id: AccountId,
    holder: AccountId,
) -> anyhow::Result<(Felt, Felt)> {
    let faucet = mock_chain.committed_account(faucet_id)?;
    let key = StorageMapKey::new(AccountIdKey::from(holder).as_word());
    let value = faucet
        .storage()
        .get_map_item(SupplyRestrictionManager::restricted_amounts_slot(), key)?;
    assert_eq!(value[2], Felt::ZERO, "unused restriction element should be zero");
    assert_eq!(value[3], Felt::ZERO, "unused restriction element should be zero");
    Ok((value[0], value[1]))
}

/// Returns the faucet's latest committed token supply.
fn token_supply(mock_chain: &MockChain, faucet_id: AccountId) -> anyhow::Result<AssetAmount> {
    let faucet = mock_chain.committed_account(faucet_id)?;
    Ok(FungibleFaucet::try_from(faucet.storage())?.token_supply())
}

// TESTS
// ================================================================================================

/// The note dispatches every action: freezing and unfreezing change only the frozen amount,
/// confiscating changes only the confiscated amount and decreases the token supply, and other
/// holders are unaffected.
#[tokio::test]
async fn freeze_unfreeze_and_confiscate() -> anyhow::Result<()> {
    const FREEZE_AMOUNT: u32 = 300;
    const PARTIAL_UNFREEZE_AMOUNT: u32 = 100;
    const CONFISCATE_AMOUNT: u32 = 50;
    const REMAINING_FROZEN_AMOUNT: u32 = FREEZE_AMOUNT - PARTIAL_UNFREEZE_AMOUNT;
    const REMAINING_TOKEN_SUPPLY: u32 = INITIAL_TOKEN_SUPPLY - CONFISCATE_AMOUNT;

    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let other_holder = AccountId::mock_private(4);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;

    let configs = [
        SupplyRestrictionConfig::Freeze {
            account: holder,
            amount: AssetAmount::from(FREEZE_AMOUNT),
        },
        SupplyRestrictionConfig::Unfreeze {
            account: holder,
            amount: AssetAmount::from(PARTIAL_UNFREEZE_AMOUNT),
        },
        SupplyRestrictionConfig::Confiscate {
            account: holder,
            amount: AssetAmount::from(CONFISCATE_AMOUNT),
        },
        SupplyRestrictionConfig::Unfreeze {
            account: holder,
            amount: AssetAmount::from(REMAINING_FROZEN_AMOUNT),
        },
    ];
    let notes = configs
        .into_iter()
        .map(|config| supply_restriction_config_note(owner_id, faucet.id(), config))
        .collect::<anyhow::Result<Vec<_>>>()?;
    for note in &notes {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // (frozen, confiscated, token supply) after each note
    let expected = [
        (FREEZE_AMOUNT, 0, INITIAL_TOKEN_SUPPLY),
        (REMAINING_FROZEN_AMOUNT, 0, INITIAL_TOKEN_SUPPLY),
        (REMAINING_FROZEN_AMOUNT, CONFISCATE_AMOUNT, REMAINING_TOKEN_SUPPLY),
        (0, CONFISCATE_AMOUNT, REMAINING_TOKEN_SUPPLY),
    ];
    for (note, (frozen, confiscated, supply)) in notes.into_iter().zip(expected) {
        mock_chain.consume_notes_and_commit(faucet.id(), [note]).await?;

        assert_eq!(
            restricted_amounts(&mock_chain, faucet.id(), holder)?,
            (Felt::from(frozen), Felt::from(confiscated))
        );
        assert_eq!(token_supply(&mock_chain, faucet.id())?, AssetAmount::from(supply));
    }

    assert_eq!(
        restricted_amounts(&mock_chain, faucet.id(), other_holder)?,
        (Felt::ZERO, Felt::ZERO)
    );

    Ok(())
}

/// Unfreezing more than the frozen amount fails, even if the holder also has confiscated amounts.
///
/// The holder has 100 frozen and 100 confiscated. Unfreezing 101 fails because only the frozen
/// amount can be unfrozen: the confiscated amount is tracked separately and is never released.
#[tokio::test]
async fn unfreeze_more_than_frozen_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;

    let freeze = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Freeze {
            account: holder,
            amount: AssetAmount::from(100u32),
        },
    )?;
    let confiscate = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Confiscate {
            account: holder,
            amount: AssetAmount::from(100u32),
        },
    )?;
    for note in [&freeze, &confiscate] {
        builder.add_output_note(RawOutputNote::Full(note.clone()));
    }

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;
    mock_chain.consume_notes_and_commit(faucet.id(), [freeze.clone()]).await?;
    mock_chain.consume_notes_and_commit(faucet.id(), [confiscate.clone()]).await?;

    let unfreeze = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Unfreeze {
            account: holder,
            amount: AssetAmount::from(101u32),
        },
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [unfreeze]).await?;

    assert_transaction_executor_error!(
        result,
        ERR_SUPPLY_RESTRICTION_UNFREEZE_EXCEEDS_FROZEN_AMOUNT
    );

    Ok(())
}

/// Confiscating more than the token supply fails.
#[tokio::test]
async fn confiscate_more_than_token_supply_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    let confiscate = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Confiscate {
            account: AccountId::mock_private(3),
            amount: AssetAmount::from(INITIAL_TOKEN_SUPPLY + 1),
        },
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [confiscate]).await?;

    assert_transaction_executor_error!(result, ERR_FAUCET_SUPPLY_DECREASE_EXCEEDS_TOKEN_SUPPLY);

    Ok(())
}

/// Freezing or confiscating an amount above the maximum fungible asset amount fails, including
/// an amount that would wrap the stored amounts around the field modulus.
#[rstest]
#[case::freeze_above_max(VARIANT_FREEZE, Felt::from(FungibleAsset::MAX_AMOUNT) + Felt::ONE)]
#[case::freeze_wrapping(VARIANT_FREEZE, Felt::ZERO - Felt::ONE)]
#[case::confiscate_above_max(VARIANT_CONFISCATE, Felt::from(FungibleAsset::MAX_AMOUNT) + Felt::ONE)]
#[case::confiscate_wrapping(VARIANT_CONFISCATE, Felt::ZERO - Felt::ONE)]
#[tokio::test]
async fn amount_above_max_amount_fails(
    #[case] variant: u32,
    #[case] amount: Felt,
) -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    let note = malformed_supply_restriction_config_note(
        owner_id,
        faucet.id(),
        vec![Felt::from(variant), holder.suffix(), holder.prefix().as_felt(), amount],
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(result, ERR_SUPPLY_RESTRICTION_AMOUNT_EXCEEDS_MAX_AMOUNT);

    Ok(())
}

/// Freezing or confiscating for a malformed account ID fails, so a typo in the account ID cannot
/// restrict a balance that no account holds.
#[rstest]
#[case::freeze(VARIANT_FREEZE)]
#[case::confiscate(VARIANT_CONFISCATE)]
#[tokio::test]
async fn malformed_account_id_fails(#[case] variant: u32) -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    // a valid suffix has its lower 8 bits set to zero
    let malformed_suffix = holder.suffix() + Felt::ONE;
    let note = malformed_supply_restriction_config_note(
        owner_id,
        faucet.id(),
        vec![Felt::from(variant), malformed_suffix, holder.prefix().as_felt(), Felt::ONE],
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(
        result,
        ERR_ACCOUNT_ID_SUFFIX_LEAST_SIGNIFICANT_BYTE_MUST_BE_ZERO
    );

    Ok(())
}

/// The frozen plus confiscated amount of a holder cannot exceed the maximum fungible asset
/// amount, even when every single amount is within it.
#[rstest]
#[case::freeze(SupplyRestrictionConfig::Freeze { account: AccountId::mock_private(3), amount: AssetAmount::from(1u32) })]
#[case::confiscate(SupplyRestrictionConfig::Confiscate { account: AccountId::mock_private(3), amount: AssetAmount::from(1u32) })]
#[tokio::test]
async fn total_above_max_amount_fails(
    #[case] config: SupplyRestrictionConfig,
) -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;

    let freeze_max = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Freeze {
            account: AccountId::mock_private(3),
            amount: FungibleAsset::MAX_AMOUNT,
        },
    )?;
    builder.add_output_note(RawOutputNote::Full(freeze_max.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;
    mock_chain.consume_notes_and_commit(faucet.id(), [freeze_max.clone()]).await?;

    let note = supply_restriction_config_note(owner_id, faucet.id(), config)?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(result, ERR_SUPPLY_RESTRICTION_TOTAL_EXCEEDS_MAX_AMOUNT);

    Ok(())
}

/// A sender other than the owner cannot dispatch any action.
#[rstest]
#[case::freeze(SupplyRestrictionConfig::Freeze { account: AccountId::mock_private(3), amount: AssetAmount::from(1u32) })]
#[case::unfreeze(SupplyRestrictionConfig::Unfreeze { account: AccountId::mock_private(3), amount: AssetAmount::from(0u32) })]
#[case::confiscate(SupplyRestrictionConfig::Confiscate { account: AccountId::mock_private(3), amount: AssetAmount::from(1u32) })]
#[tokio::test]
async fn non_owner_cannot_restrict(#[case] config: SupplyRestrictionConfig) -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let stranger = test_account_id(63);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    let note = supply_restriction_config_note(stranger, faucet.id(), config)?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

/// A note whose variant matches no known action is rejected by the script's dispatch guard.
#[tokio::test]
async fn unknown_variant_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    // variant 99 is not a known action
    let note = malformed_supply_restriction_config_note(
        owner_id,
        faucet.id(),
        vec![Felt::from(99u32), holder.suffix(), holder.prefix().as_felt(), Felt::from(1u32)],
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(result, ERR_SUPPLY_RESTRICTION_CONFIG_UNKNOWN_VARIANT);

    Ok(())
}

/// A note whose storage item count does not match the layout is rejected by the count guard.
#[tokio::test]
async fn wrong_storage_item_count_fails() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let holder = AccountId::mock_private(3);
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    // Freeze variant but the amount is missing
    let note = malformed_supply_restriction_config_note(
        owner_id,
        faucet.id(),
        vec![Felt::from(VARIANT_FREEZE), holder.suffix(), holder.prefix().as_felt()],
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [note]).await?;

    assert_transaction_executor_error!(
        result,
        ERR_SUPPLY_RESTRICTION_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
    );

    Ok(())
}

/// The note is bound to its target faucet, so a decoy faucet with the same owner cannot consume
/// a note meant for another one.
#[tokio::test]
async fn decoy_faucet_cannot_consume_note_of_another_faucet() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let decoy = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    // The note's intended target. It need not be built: the note only references its ID.
    let target = AccountId::mock_public(9);

    let note = supply_restriction_config_note(
        owner_id,
        target,
        SupplyRestrictionConfig::Freeze {
            account: AccountId::mock_private(3),
            amount: AssetAmount::from(1u32),
        },
    )?;
    let result = mock_chain.consume_notes(decoy.id(), [note]).await?;

    assert_transaction_executor_error!(
        result,
        ERR_NOTE_ACTIVE_ACCOUNT_IS_NOT_NETWORK_TARGET_ACCOUNT
    );

    Ok(())
}

/// A private note carrying the same script and storage as a legitimate config note is rejected
/// before any restriction changes.
#[tokio::test]
async fn private_note_cannot_dispatch_the_action() -> anyhow::Result<()> {
    let owner_id = dummy_owner();
    let mut builder = MockChain::builder();
    let faucet = add_faucet_with_owner_supply_restriction(&mut builder, owner_id)?;
    let mock_chain = builder.build()?;

    let note = supply_restriction_config_note(
        owner_id,
        faucet.id(),
        SupplyRestrictionConfig::Freeze {
            account: AccountId::mock_private(3),
            amount: AssetAmount::from(1u32),
        },
    )?;
    let result = mock_chain.consume_notes(faucet.id(), [into_private_note(note)]).await?;

    assert_transaction_executor_error!(result, ERR_SUPPLY_RESTRICTION_CONFIG_NOTE_IS_NOT_PUBLIC);

    Ok(())
}
