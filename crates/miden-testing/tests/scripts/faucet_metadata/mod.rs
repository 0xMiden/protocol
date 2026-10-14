//! Tests for the token-metadata string setters of the
//! [`miden_standards::account::faucets::FungibleFaucet`] component: `set_description`,
//! `set_logo_uri` and `set_external_uri`. The
//! [`miden_standards::account::faucets::NonFungibleFaucet`] component's `set_token_base_uri`
//! follows the same argument contract and is driven through the same note.
//!
//! Unlike the other authority-gated faucet mutators, these three do not take their argument on the
//! operand stack. The caller passes the Eidos commitment of the new 7-Word value and
//! provides the preimage in the advice map under it; the setter pipes the preimage back out and
//! validates it against the commitment.
//!
//! `FaucetMetadataConfigNote` is the standard caller that satisfies this contract, so the tests
//! below drive the setters through it. The one exception is
//! [`set_description_accepts_caller_computed_commitment`], which supplies a commitment computed
//! outside the VM — something the standard note never does — and therefore uses a hand-written
//! script.
//!
//! The setters' happy paths are covered by the note's own dispatch tests in [`config`]; this suite
//! covers the guards around them. The `assert_not_paused` guard they share with the other mutators
//! is covered by [`super::pausable`] and is not repeated here.

extern crate alloc;

mod config;

use alloc::vec::Vec;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::{TransactionLog, TransactionLogs};
use miden_protocol::{Felt, Hasher, Word};
use miden_standards::account::access::AccessControl;
use miden_standards::account::access::pausable::Pausable;
use miden_standards::account::faucets::{
    Description,
    ExternalUri,
    FungibleFaucet,
    LogoUri,
    NonFungibleFaucet,
    TokenBaseUri,
    TokenMetadata,
    TokenName,
};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_DESCRIPTION_NOT_MUTABLE,
    ERR_EXTERNAL_URI_NOT_MUTABLE,
    ERR_LOGO_URI_NOT_MUTABLE,
    ERR_SENDER_NOT_OWNER,
};
use miden_standards::note::config::{FaucetMetadataConfig, FaucetMetadataConfigNote};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};

// HELPERS
// ================================================================================================

/// Number of felts encoding a metadata string: 7 Words.
const STRING_NUM_ELEMENTS: usize = 28;

/// Memory address the note scripts below write the note storage to. Word-aligned, as
/// `eidos::hash_elements` requires.
const STRING_PTR: usize = 0;

fn owner_id() -> AccountId {
    AccountIdBuilder::new().build_with_seed([1; 32])
}

/// Initial maximum supply of the faucets built by [`create_faucet`].
const INITIAL_MAX_SUPPLY: u64 = 1_000_000;

/// Builds an existing fungible faucet owned by `owner` via `Authority::OwnerControlled`, with every
/// metadata mutability flag set to `mutable`.
fn create_faucet(owner: AccountId, mutable: bool) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("SYM")?)
        .symbol("SYM".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(INITIAL_MAX_SUPPLY)?)
        .is_description_mutable(mutable)
        .is_logo_uri_mutable(mutable)
        .is_external_uri_mutable(mutable)
        .is_max_supply_mutable(mutable)
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

/// Initial token base URI of the faucets built by [`create_nft_faucet`].
const INITIAL_TOKEN_BASE_URI: &str = "ipfs://bafy-initial/";

/// Builds an existing non-fungible faucet with public token metadata, owned by `owner` via
/// `Authority::OwnerControlled`, with the token base URI mutability flag set to `mutable`.
fn create_nft_faucet(owner: AccountId, mutable: bool) -> anyhow::Result<Account> {
    let faucet = NonFungibleFaucet::builder()
        .name(TokenName::new("NFT")?)
        .symbol("NFT".try_into()?)
        .token_base_uri(TokenBaseUri::new(INITIAL_TOKEN_BASE_URI)?)
        .is_token_base_uri_mutable(mutable)
        .build()?;

    let account = AccountBuilder::new([44; 32])
        .account_type(AccountType::Public)
        .with_components(Auth::IncrNonce)
        .with_components(AccessControl::Ownable2Step { owner })
        .with_component(Pausable::unpaused())
        .with_component(faucet)
        .build_existing()?;

    Ok(account)
}

/// Builds a `sender`-authored [`FaucetMetadataConfigNote`] carrying `config`.
fn config_note(
    sender: AccountId,
    faucet_id: AccountId,
    config: FaucetMetadataConfig,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    let note = FaucetMetadataConfigNote::builder()
        .sender(sender)
        .target(faucet_id)
        .config(config)
        .generate_serial_number(&mut rng)
        .build()?
        .into();
    Ok(note)
}

/// Builds a `sender`-authored note that calls `set_description` with a caller-supplied
/// `commitment`, rather than one computed in MASM as `FaucetMetadataConfigNote` does.
///
/// The 7-Word payload travels in the note storage; the script publishes it in the advice map under
/// `commitment` so the setter can pipe it back out and validate it. Only
/// [`set_description_accepts_caller_computed_commitment`] needs this — every other test drives the
/// standard note.
fn build_caller_committed_description_note(
    sender: AccountId,
    description: &Description,
    commitment: Word,
    rng_seed: u32,
) -> anyhow::Result<Note> {
    let script_code = format!(
        r#"
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

            push.{commitment}
            # => [COMMITMENT, pad(12)]

            # publish the payload under the commitment so the setter can pipe it back out
            push.{end_ptr} push.{STRING_PTR}
            movdn.5 movdn.5
            # => [COMMITMENT, start_ptr, end_ptr, pad(12)]

            adv.insert_mem
            movup.4 drop movup.4 drop
            # => [COMMITMENT, pad(12)]

            call.faucets::set_description
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
        .note_storage(flatten(&description.to_words()))?
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
    let note =
        config_note(owner, faucet.id(), FaucetMetadataConfig::SetDescription { description }, 4)?;

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

    let logo_uri = LogoUri::new("https://example.com/nope.png")?;
    let note = config_note(owner, faucet.id(), FaucetMetadataConfig::SetLogoUri { logo_uri }, 5)?;

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
async fn set_external_uri_fails_when_immutable() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, false)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let external_uri = ExternalUri::new("https://example.com/nope")?;
    let note =
        config_note(owner, faucet.id(), FaucetMetadataConfig::SetExternalUri { external_uri }, 6)?;

    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_EXTERNAL_URI_NOT_MUTABLE);

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
    let note = config_note(
        stranger,
        faucet.id(),
        FaucetMetadataConfig::SetDescription { description },
        7,
    )?;

    let result = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_SENDER_NOT_OWNER);

    Ok(())
}

/// `set_token_base_uri` is gated the same way on a non-fungible faucet.
#[tokio::test]
async fn set_token_base_uri_fails_when_sender_is_not_owner() -> anyhow::Result<()> {
    let owner = owner_id();
    let stranger = AccountIdBuilder::new().build_with_seed([2; 32]);
    let faucet = create_nft_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let token_base_uri = TokenBaseUri::new("ipfs://bafy-not-yours/")?;
    let note = config_note(
        stranger,
        faucet.id(),
        FaucetMetadataConfig::SetTokenBaseUri { token_base_uri },
        10,
    )?;

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
/// the same framing rule as `mem::pipe_preimage_to_memory`: both bind the exact logical length into
/// Eidos's initial chaining word. Callers that compute the commitment outside the VM depend on
/// this.
#[tokio::test]
async fn set_description_accepts_caller_computed_commitment() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let description = Description::new("committed in Rust")?;
    let commitment = Hasher::hash_elements(&flatten(&description.to_words()));

    let note = build_caller_committed_description_note(owner, &description, commitment, 8)?;

    let updated = consume_note(&mock_chain, &faucet, &note).await?;

    assert_eq!(metadata(&updated)?.description(), Some(&description));

    Ok(())
}

// TESTS — LOGS
// ================================================================================================

/// `set_external_uri` announces the update in a log carrying the new value, under the topic
/// [`TokenMetadata::external_uri_updated_topic`] exposes.
#[tokio::test]
async fn set_external_uri_emits_log_with_new_value() -> anyhow::Result<()> {
    let owner = owner_id();
    let faucet = create_faucet(owner, true)?;
    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let external_uri = ExternalUri::new("ipfs://bafybeigdyrzt/collection.json")?;
    let note = config_note(
        owner,
        faucet.id(),
        FaucetMetadataConfig::SetExternalUri { external_uri: external_uri.clone() },
        9,
    )?;

    let executed = mock_chain
        .build_transaction(faucet.clone())
        .unauthenticated_input_note(note)
        .build()?
        .execute()
        .await?;

    let expected_log = TransactionLog::new(
        faucet.id(),
        TokenMetadata::external_uri_updated_topic(),
        external_uri.to_words(),
    )?;
    assert_eq!(executed.logs(), &TransactionLogs::new(vec![expected_log])?);

    Ok(())
}
