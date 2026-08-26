//! Helpers shared by the sibling `blocklist` and `allowlist` transfer policy suites, plus the
//! tests for the policy-manager dispatcher itself.
//!
//! Both suites exercise the same two shapes: a faucet that can also *receive* a foreign faucet's
//! asset (so it is subject to that faucet's transfer policy), and a mint driven through the
//! standard [`MintNote`] (so the send policy is reached the way production code reaches it).

extern crate alloc;

use alloc::vec;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType, AssetCallbackFlag};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Authority;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BurnPolicy,
    MintPolicy,
    TokenPolicyManager,
    TransferPolicy,
};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::{MintNote, MintNoteStorage, P2idNote};
use miden_testing::{AccountState, Auth, MockChain, MockChainBuilder};

use super::assert_default_expiration_limit;

// FAUCET FIXTURES
// ================================================================================================

/// Builds a fungible faucet that can also receive assets (via [`BasicWallet`]), so it can be the
/// recipient of a *foreign* faucet's asset and thus be subject to that faucet's transfer policy.
///
/// Its own asset callbacks are disabled: this faucet is never the issuer under test.
pub(crate) fn add_faucet_with_wallet(builder: &mut MockChainBuilder) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("OTH")?)
        .symbol("OTH".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([44u8; 32])
        .account_type(AccountType::Public)
        .with_asset_callbacks(AssetCallbackFlag::Disabled)
        .with_component(faucet)
        .with_component(BasicWallet)
        .with_component(Authority::AuthControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .build(),
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

/// Builds a fungible faucet with asset callbacks enabled and [`TransferPolicy::allow_all`] active
/// on both send and receive.
///
/// `allow_all` reads no state and sets no expiration limit of its own, so any limit observed on a
/// transfer of this faucet's asset comes from the policy manager's dispatcher.
fn add_faucet_with_allow_all_transfer(builder: &mut MockChainBuilder) -> anyhow::Result<Account> {
    let faucet = FungibleFaucet::builder()
        .name(TokenName::new("ALL")?)
        .symbol("ALL".try_into()?)
        .decimals(8)
        .max_supply(AssetAmount::new(1_000_000)?)
        .build()?;

    let account_builder = AccountBuilder::new([45u8; 32])
        .account_type(AccountType::Public)
        .with_asset_callbacks(AssetCallbackFlag::Enabled)
        .with_component(faucet)
        .with_component(Authority::AuthControlled)
        .with_components(
            TokenPolicyManager::builder()
                .active_mint_policy(MintPolicy::allow_all())
                .active_burn_policy(BurnPolicy::allow_all())
                .active_send_policy(TransferPolicy::allow_all())
                .active_receive_policy(TransferPolicy::allow_all())
                .build(),
        );

    builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)
}

// MINT NOTE FIXTURE
// ================================================================================================

/// A [`MintNote`] together with what the faucet is expected to emit when it consumes the note.
pub(crate) struct MintNoteFixture {
    /// The MINT note to consume against the faucet.
    pub note: Note,
    /// The asset the faucet is expected to mint.
    pub asset: FungibleAsset,
    /// The recipient digest of the output note the faucet is expected to create.
    pub recipient_digest: Word,
}

/// Builds a MINT note instructing `faucet_id` to mint `amount` units of its own asset into a
/// private P2ID note for `target`.
///
/// This replaces a hand-written `mint_and_send` transaction script: the mint runs through the
/// standard MINT note, and minting is what crosses the send transfer policy, since the faucet adds
/// the minted asset to an output note while it is itself the native account.
pub(crate) fn build_mint_note(
    sender: AccountId,
    faucet_id: AccountId,
    target: AccountId,
    amount: u64,
    rng_seed: u32,
) -> anyhow::Result<MintNoteFixture> {
    let asset = FungibleAsset::new(faucet_id, amount)?;
    let tag = NoteTag::with_account_target(target);

    let output_note = Note::from(
        P2idNote::builder()
            .sender(faucet_id)
            .target(target)
            .assets(vec![asset])
            .note_type(NoteType::Private)
            .serial_number(Word::default())
            .build()?,
    );
    let recipient_digest = output_note.recipient().digest();

    let mut rng = RandomCoin::new([Felt::from(rng_seed); 4].into());
    let note: Note = MintNote::builder()
        .sender(sender)
        .mint_storage(MintNoteStorage::new_private(recipient_digest, asset, tag))
        .generate_serial_number(&mut rng)
        .build()?
        .into();

    Ok(MintNoteFixture { note, asset, recipient_digest })
}

/// Asserts that `executed` created exactly one output note, addressed to the recipient the MINT
/// note named, carrying exactly the minted asset.
pub(crate) fn assert_minted_note(
    executed: &ExecutedTransaction,
    mint: &MintNoteFixture,
) -> anyhow::Result<()> {
    assert_eq!(executed.output_notes().num_notes(), 1);

    let note = executed.output_notes().get_note(0);
    assert_eq!(note.recipient_digest(), mint.recipient_digest);

    let expected_asset: Asset = mint.asset.into();
    assert_eq!(note.assets().num_assets(), 1);
    assert_eq!(note.assets().iter().next(), Some(&expected_asset));

    Ok(())
}

// DISPATCHER TESTS
// ================================================================================================

/// The receive callback reads the issuing faucet's pause flag and active policy root through FPI,
/// which reflects the executor-chosen reference block. The dispatcher must therefore limit the
/// transaction's expiration even when the active policy sets no limit of its own.
#[tokio::test]
async fn receive_callback_applies_default_expiration_limit() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_allow_all_transfer(&mut builder)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?;
    let note =
        builder.add_p2id_note(faucet.id(), target.id(), &[Asset::from(asset)], NoteType::Public)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;

    let executed = mock_chain
        .build_transaction(target.id())
        .authenticated_input_note(note.id())
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;

    assert_default_expiration_limit(&executed);

    Ok(())
}

/// Same for the send callback, reached here through a mint: the faucet adds the minted asset to an
/// output note, which the kernel routes through `on_before_asset_added_to_note`.
#[tokio::test]
async fn send_callback_applies_default_expiration_limit() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let target = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = add_faucet_with_allow_all_transfer(&mut builder)?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let mint = build_mint_note(target.id(), faucet.id(), target.id(), 100, 11)?;

    let executed = mock_chain
        .build_transaction(faucet.id())
        .unauthenticated_input_note(mint.note.clone())
        .build()?
        .execute()
        .await?;

    assert_minted_note(&executed, &mint)?;
    assert_default_expiration_limit(&executed);

    Ok(())
}
