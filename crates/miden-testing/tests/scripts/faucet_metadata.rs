//! Tests for the token-metadata string setters of the
//! [`miden_standards::account::faucets::FungibleFaucet`] component: `set_description`,
//! `set_logo_uri` and `set_external_link`.
//!
//! Unlike the other authority-gated faucet mutators, these three do not take their argument on the
//! operand stack. The caller passes the Poseidon2 commitment of the new 7-Word value and provides
//! the preimage in the advice map under it; the setter pipes the preimage back out and validates it
//! against the commitment. The notes below satisfy that contract the way a real caller does: the
//! payload travels in the note storage, and the script commits to the memory `get_storage` wrote it
//! to and inserts it into the advice map before making the call.
//!
//! The `assert_not_paused` guard these setters share with the other mutators is covered by
//! [`super::pausable`]; this suite does not repeat it.

extern crate alloc;

use alloc::vec::Vec;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::access::AccessControl;
use miden_standards::account::access::pausable::Pausable;
use miden_standards::account::faucets::{
    Description,
    ExternalLink,
    FungibleFaucet,
    LogoURI,
    TokenMetadata,
    TokenName,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_DESCRIPTION_NOT_MUTABLE,
    ERR_EXTERNAL_LINK_NOT_MUTABLE,
    ERR_LOGO_URI_NOT_MUTABLE,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

// HELPERS
// ================================================================================================

/// Number of felts encoding a metadata string: 7 Words.
const STRING_NUM_ELEMENTS: usize = 28;

/// Memory address the note scripts below write the note storage to. Word-aligned, as
/// `poseidon2::hash_elements` requires.
const STRING_PTR: usize = 0;

fn owner_id() -> AccountId {
    AccountIdBuilder::new().build_with_seed([1; 32])
}

/// Builds an existing fungible faucet owned by `owner` via `Authority::OwnerControlled`, with the
/// three metadata mutability flags set to `mutable`.
fn create_faucet(owner: AccountId, mutable: bool) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .is_description_mutable(mutable)
        .is_logo_uri_mutable(mutable)
        .is_external_link_mutable(mutable)
        .build()?;

    let account = AccountBuilder::new([43; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(Pausable::unpaused())
        .with_component(faucet)
        .build_existing()?;

    Ok(account)
}

/// Builds a `sender`-authored note that calls `setter` with `value` as the new metadata string.
///
/// The 7-Word payload travels in the note storage. The script writes it to memory via
/// `active_note::get_storage`, commits to it, and inserts it into the advice map under that
/// commitment so the setter can pipe it back out.
///
/// When `commitment` is `Some`, that caller-supplied value is used as the advice map key instead of
/// one computed in MASM, which is how [`set_description_accepts_caller_computed_commitment`] pins
/// the Rust and MASM commitment conventions to each other.
fn build_set_string_note(
    sender: AccountId,
    setter: &str,
    value: &[Word],
    commitment: Option<Word>,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let push_commitment = match commitment {
        Some(commitment) => format!("push.{commitment}"),
        None => {
            format!("push.{STRING_NUM_ELEMENTS} push.{STRING_PTR} exec.poseidon2::hash_elements")
        },
    };

    let script_code = format!(
        r#"
        use miden::core::crypto::hashes::poseidon2
        use miden::protocol::active_note
        use miden::standards::faucets

        @note_script
        pub proc main
            dropw
            # => [pad(16)]

            # write the payload carried by the note storage to memory
            push.{STRING_PTR} exec.active_note::get_storage
            # => [num_storage_items]
            eq.{STRING_NUM_ELEMENTS} assert
            # => []

            # pad the window the setter expects below the commitment
            padw padw padw
            # => [pad(12)]

            {push_commitment}
            # => [COMMITMENT, pad(12)]

            # publish the payload under the commitment so the setter can pipe it back out
            push.{end_ptr} push.{STRING_PTR}
            movdn.5 movdn.5
            # => [COMMITMENT, start_ptr, end_ptr, pad(12)]

            adv.insert_mem
            movup.4 drop movup.4 drop
            # => [COMMITMENT, pad(12)]

            call.faucets::{setter}
            # => [pad(16)]

            dropw dropw dropw dropw
        end
        "#,
        end_ptr = STRING_PTR + STRING_NUM_ELEMENTS,
    );

    let script = CodeBuilder::default().compile_note_script(&script_code)?;
    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    let note = NoteBuilder::new(sender, &mut rng)
        .note_type(NoteType::Private)
        .script(script)
        .note_storage(flatten(value))?
        .build()?;

    Ok(note)
}

/// Flattens a 7-Word metadata payload into the 28 felts the note storage carries.
fn flatten(words: &[Word]) -> Vec<Felt> {
    words.iter().flat_map(Word::as_elements).copied().collect()
}

/// Consumes `note` in a faucet transaction and returns the updated faucet account.
async fn consume_note(
    mock_chain: &MockChain,
    faucet: &Account,
    note: &Note,
) -> anyhow::Result<Account> {
    let executed = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note.clone())
        .build()?
        .execute()
        .await?;

    let mut updated = faucet.clone();
    updated.apply_patch(executed.account_patch())?;

    Ok(updated)
}

/// Reads the token metadata back from the faucet's storage.
fn metadata(faucet: &Account) -> anyhow::Result<TokenMetadata> {
    Ok(TokenMetadata::try_from_storage(faucet.storage())?)
}

// TESTS — HAPPY PATHS
// ================================================================================================

/// The owner sets the description; the new value round-trips through the faucet's storage slots.
#[tokio::test]
async fn set_description_updates_storage() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let description = Description::new("A thoroughly described token")?;
    let note = build_set_string_note(owner, "set_description", &description.to_words(), None, 1)?;

    let updated = consume_note(&mock_chain, &faucet, &note).await?;

    assert_eq!(metadata(&updated)?.description(), Some(&description));

    Ok(())
}

/// The owner sets the logo URI; the new value round-trips through the faucet's storage slots.
#[tokio::test]
async fn set_logo_uri_updates_storage() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let logo_uri = LogoURI::new("https://example.com/logo.png")?;
    let note = build_set_string_note(owner, "set_logo_uri", &logo_uri.to_words(), None, 2)?;

    let updated = consume_note(&mock_chain, &faucet, &note).await?;

    assert_eq!(metadata(&updated)?.logo_uri(), Some(&logo_uri));

    Ok(())
}

/// The owner sets the external link; the new value round-trips through the faucet's storage slots.
#[tokio::test]
async fn set_external_link_updates_storage() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let external_link = ExternalLink::new("https://example.com")?;
    let note =
        build_set_string_note(owner, "set_external_link", &external_link.to_words(), None, 3)?;

    let updated = consume_note(&mock_chain, &faucet, &note).await?;

    assert_eq!(metadata(&updated)?.external_link(), Some(&external_link));

    Ok(())
}

// TESTS — MUTABILITY FLAGS
// ================================================================================================

/// Each setter reads its own felt of the mutability config word, so all three flags are exercised.
#[tokio::test]
async fn set_description_fails_when_immutable() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, false)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let description = Description::new("nope")?;
    let note = build_set_string_note(owner, "set_description", &description.to_words(), None, 4)?;

    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_DESCRIPTION_NOT_MUTABLE);

    Ok(())
}

#[tokio::test]
async fn set_logo_uri_fails_when_immutable() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, false)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let logo_uri = LogoURI::new("https://example.com/nope.png")?;
    let note = build_set_string_note(owner, "set_logo_uri", &logo_uri.to_words(), None, 5)?;

    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_LOGO_URI_NOT_MUTABLE);

    Ok(())
}

#[tokio::test]
async fn set_external_link_fails_when_immutable() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, false)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let external_link = ExternalLink::new("https://example.com/nope")?;
    let note =
        build_set_string_note(owner, "set_external_link", &external_link.to_words(), None, 6)?;

    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_EXTERNAL_LINK_NOT_MUTABLE);

    Ok(())
}

// TESTS — AUTHORIZATION
// ================================================================================================

/// The setters are gated by the account-wide `Authority` component against the note sender.
#[tokio::test]
async fn set_description_fails_when_sender_is_not_owner() -> anyhow::Result<()> {
    let owner = owner_id();
    let stranger = AccountIdBuilder::new().build_with_seed([2; 32]);
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let description = Description::new("not yours")?;
    let note =
        build_set_string_note(stranger, "set_description", &description.to_words(), None, 7)?;

    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

// TESTS — COMMITMENT CONVENTION
// ================================================================================================

/// Pins the Rust and MASM commitment conventions to each other.
///
/// The setter recomputes the commitment over the piped preimage and asserts it equals the advice
/// map key. Supplying a key computed by `Hasher::hash_elements` therefore fails unless Rust applies
/// the same padding rule as `mem::pipe_preimage_to_memory` — both set the first capacity element to
/// `num_elements % 8`. Callers that compute the commitment outside the VM depend on this.
#[tokio::test]
async fn set_description_accepts_caller_computed_commitment() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let description = Description::new("committed in Rust")?;
    let words = description.to_words();
    let commitment = Hasher::hash_elements(&flatten(&words));

    let note = build_set_string_note(owner, "set_description", &words, Some(commitment), 8)?;

    let updated = consume_note(&mock_chain, &faucet, &note).await?;

    assert_eq!(metadata(&updated)?.description(), Some(&description));

    Ok(())
}
