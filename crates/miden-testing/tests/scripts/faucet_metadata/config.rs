//! Tests for the `FUNGIBLE_FAUCET_CONFIG` standard note, which dispatches the
//! [`miden_standards::account::faucets::FungibleFaucet`] metadata setters from a note.
//!
//! The suite covers the note itself: that each selector dispatches to the matching setter, and that
//! the script's own guards reject malformed storage. The setters' own behaviour — the advice-map
//! argument contract, the mutability flags and the `Authority` gate — is covered by the parent
//! [`super`] suite.

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::Felt;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::Note;
use miden_standards::account::faucets::{Description, ExternalLink, FungibleFaucet, LogoURI};
use miden_standards::errors::standards::{
    ERR_FUNGIBLE_FAUCET_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS,
    ERR_FUNGIBLE_FAUCET_CONFIG_UNKNOWN_SELECTOR,
};
use miden_standards::note::{FungibleFaucetConfig, FungibleFaucetConfigNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{MockChain, assert_transaction_executor_error};

use super::{INITIAL_MAX_SUPPLY, consume_note, create_faucet, metadata, owner_id};

// HELPERS
// ================================================================================================

/// Builds a [`FungibleFaucetConfigNote`] for `config`, sent by `sender` and targeting the faucet.
fn config_note(
    sender: AccountId,
    faucet_id: AccountId,
    config: FungibleFaucetConfig,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    let note = FungibleFaucetConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(config)
        .generate_serial_number(&mut rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a note carrying the FungibleFaucetConfig script with hand-crafted storage, bypassing the
/// builder so malformed inputs can be exercised.
fn malformed_config_note(
    sender: AccountId,
    storage: Vec<Felt>,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    let note = NoteBuilder::new(sender, &mut rng)
        .script(FungibleFaucetConfigNote::script())
        .note_storage(storage)?
        .build()?;
    Ok(note)
}

/// Reads the faucet's maximum supply back from its storage.
fn max_supply(faucet: &Account) -> anyhow::Result<AssetAmount> {
    Ok(FungibleFaucet::try_from(faucet.storage())?.max_supply())
}

// TESTS — DISPATCH
// ================================================================================================

/// Selector `0` dispatches to `set_max_supply`.
#[tokio::test]
async fn set_max_supply_dispatch() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let new_max_supply = AssetAmount::new(INITIAL_MAX_SUPPLY / 2)?;
    let note = config_note(
        owner,
        faucet.id(),
        FungibleFaucetConfig::SetMaxSupply { max_supply: new_max_supply },
        1,
    )?;

    let updated = consume_note(&mock_chain, &faucet, &note).await?;

    assert_eq!(max_supply(&updated)?, new_max_supply);

    Ok(())
}

/// Selectors `1`, `2` and `3` dispatch to `set_description`, `set_logo_uri` and
/// `set_external_link`, each writing its own field.
///
/// The three run against the same faucet in sequence, so a selector wired to the wrong setter shows
/// up as a field that did not change — or as one that changed twice.
#[tokio::test]
async fn string_actions_dispatch() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let description = Description::new("dispatched through the config note")?;
    let logo_uri = LogoURI::new("https://example.com/dispatched.png")?;
    let external_link = ExternalLink::new("https://example.com/dispatched")?;

    let notes = [
        config_note(
            owner,
            faucet.id(),
            FungibleFaucetConfig::SetDescription { description: description.clone() },
            2,
        )?,
        config_note(
            owner,
            faucet.id(),
            FungibleFaucetConfig::SetLogoUri { logo_uri: logo_uri.clone() },
            3,
        )?,
        config_note(
            owner,
            faucet.id(),
            FungibleFaucetConfig::SetExternalLink { external_link: external_link.clone() },
            4,
        )?,
    ];

    let mut updated = faucet;
    for note in &notes {
        updated = consume_note(&mock_chain, &updated, note).await?;
    }

    let metadata = metadata(&updated)?;
    assert_eq!(metadata.description(), Some(&description));
    assert_eq!(metadata.logo_uri(), Some(&logo_uri));
    assert_eq!(metadata.external_link(), Some(&external_link));

    Ok(())
}

// TESTS — SCRIPT GUARDS
// ================================================================================================

/// A note whose selector matches no known action is rejected by the script's dispatch guard.
#[tokio::test]
async fn unknown_selector_fails() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    // selector 99 is not a known action
    let note = malformed_config_note(owner, vec![Felt::from(99u32), Felt::ZERO], 5)?;

    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_FUNGIBLE_FAUCET_CONFIG_UNKNOWN_SELECTOR);

    Ok(())
}

/// A `SetMaxSupply` note whose storage item count does not match the action is rejected.
#[tokio::test]
async fn wrong_storage_item_count_fails_for_max_supply() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    // SetMaxSupply selector (0) but the new cap is missing
    let note = malformed_config_note(owner, vec![Felt::ZERO], 6)?;

    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_FUNGIBLE_FAUCET_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
    );

    Ok(())
}

/// A string note whose storage is shorter than the 7-Word payload is rejected before the script
/// commits to memory it never wrote.
#[tokio::test]
async fn wrong_storage_item_count_fails_for_string_action() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    // SetDescription selector (1) with only the reserved selector word, no payload
    let note = malformed_config_note(
        owner,
        vec![Felt::from(1u32), Felt::ZERO, Felt::ZERO, Felt::ZERO],
        7,
    )?;

    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(
        result,
        ERR_FUNGIBLE_FAUCET_CONFIG_UNEXPECTED_NUMBER_OF_STORAGE_ITEMS
    );

    Ok(())
}
