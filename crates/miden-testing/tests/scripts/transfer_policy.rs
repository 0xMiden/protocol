//! Helpers shared by the sibling `blocklist` and `allowlist` transfer policy suites.
//!
//! Both suites exercise the same two shapes: a faucet that can also *receive* a foreign faucet's
//! asset (so it is subject to that faucet's transfer policy), and a mint driven through the
//! standard [`MintNote`] (so the send policy is reached the way production code reaches it).

extern crate alloc;

use alloc::vec;

use miden_processor::crypto::random::RandomCoin;
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::{Asset, AssetAmount, FungibleAsset};
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::transaction::ExecutedTransaction;
use miden_protocol::{Felt, Word};
use miden_standards::account::access::Authority;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{BurnPolicy, MintPolicy, TokenPolicyManager};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::{MintNote, MintNoteStorage, P2idNote};
use miden_testing::{AccountState, Auth, MockChainBuilder};

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
