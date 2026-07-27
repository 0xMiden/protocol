//! Benchmark scenarios where a network account with the `BasicWallet` component consumes a
//! standard note.
//!
//! Each consumer is the canonical network account of `miden_standards::note::costs`:
//! authenticated by `AuthNetworkAccount` with the consumed note's script root allowlisted and
//! holding the native fee asset, on a chain charging
//! [`super::NETWORK_VERIFICATION_BASE_FEE`], so the auth procedure pays the transaction fee by
//! creating a TX_FEE note funded from the account's vault.

use std::collections::BTreeMap;

use anyhow::Result;
use miden_protocol::Word;
use miden_protocol::asset::{Asset, FungibleAsset, NonFungibleAsset};
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::note::{Note, NoteType};
use miden_protocol::testing::account_id::{
    ACCOUNT_ID_FEE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET,
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1,
    ACCOUNT_ID_SENDER,
};
use miden_protocol::transaction::RawOutputNote;
use miden_standards::account::auth::{FeeConversionInfo, commit_fee_conversion_info};
use miden_standards::note::{
    FeeSponsorshipNote,
    P2idNote,
    P2ideNote,
    PswapNote,
    PswapNoteStorage,
    SwapNote,
};
use miden_testing::{Auth, MockTransaction};

/// The number of assets carried by the asset-count-heavy benchmark scenarios: the P2ID/P2IDE
/// asset cap, planned as 16 per <https://github.com/0xMiden/protocol/issues/3381>.
const MAX_NOTE_ASSETS: usize = 16;

/// Returns [`MAX_NOTE_ASSETS`] distinct assets: one fungible asset plus distinct non-fungible
/// assets.
fn max_note_assets() -> Vec<Asset> {
    let mut assets = vec![FungibleAsset::mock(123)];
    for index in 0..MAX_NOTE_ASSETS - 1 {
        // the byte values are arbitrary discriminators; only distinctness matters
        let index = u8::try_from(index).expect("MAX_NOTE_ASSETS fits in u8");
        assets.push(NonFungibleAsset::mock(&[index, 100]));
    }
    assets
}

// P2ID NOTE SETUPS
// ================================================================================================

/// Returns the transaction context in which a network account consumes a single P2ID note.
pub fn tx_consume_p2id_note_network() -> Result<MockTransaction> {
    tx_consume_p2id_note_with_assets(&[FungibleAsset::mock(123)])
}

/// Returns the transaction context in which a network account consumes a single P2ID note
/// carrying [`MAX_NOTE_ASSETS`] assets.
pub fn tx_consume_p2id_note_max_assets_network() -> Result<MockTransaction> {
    tx_consume_p2id_note_with_assets(&max_note_assets())
}

/// Returns the transaction context in which a network account consumes a single P2ID note
/// carrying `assets`.
fn tx_consume_p2id_note_with_assets(assets: &[Asset]) -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    let target_account = builder.add_existing_wallet_with_assets(
        super::network_auth([P2idNote::script_root()])?,
        [super::fee_funding_asset()?],
    )?;

    let note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into()?,
        target_account.id(),
        assets,
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(note.id())
        .build()
}

// P2IDE NOTE SETUPS
// ================================================================================================

/// Returns the transaction context in which a network account consumes a P2IDE note via the
/// target's claim path, carrying [`MAX_NOTE_ASSETS`] assets.
pub fn tx_consume_p2ide_note_max_assets_network() -> Result<MockTransaction> {
    tx_consume_p2ide_note_claim_with_assets(&max_note_assets())
}

/// Returns the transaction context in which a network account consumes a P2IDE note via the
/// target's claim path, carrying `assets`.
fn tx_consume_p2ide_note_claim_with_assets(assets: &[Asset]) -> Result<MockTransaction> {
    let mut builder = super::chain_builder(true);

    let target_account = builder.add_existing_wallet_with_assets(
        super::network_auth([P2ideNote::script_root()])?,
        [super::fee_funding_asset()?],
    )?;

    let note = builder.add_p2ide_note(
        ACCOUNT_ID_SENDER.try_into()?,
        target_account.id(),
        None,
        assets,
        NoteType::Public,
        None,
        None,
    )?;

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(note.id())
        .build()
}

/// Returns the transaction context in which a network account consumes a P2IDE note, either via the
/// target's claim path or, when `reclaim` is set, via the sender's reclaim path.
pub fn tx_consume_p2ide_note_network(reclaim: bool) -> Result<MockTransaction> {
    let fungible_asset: Asset = FungibleAsset::mock(123);

    if !reclaim {
        // Claim path: the network account is the note's target and consumes it directly.
        return tx_consume_p2ide_note_claim_with_assets(&[fungible_asset]);
    }

    // Reclaim path: the network account is the note's sender (and thus its default reclaimer)
    // and reclaims the note once the reclaim height has passed.
    let mut builder = super::chain_builder(true);
    let reclaim_height = BlockNumber::from(2u32);

    let sender_account = builder.add_existing_wallet_with_assets(
        super::network_auth([P2ideNote::script_root()])?,
        [super::fee_funding_asset()?],
    )?;
    let target_account = builder.add_existing_wallet(Auth::basic_ecdsa())?;

    let note = builder.add_p2ide_note(
        sender_account.id(),
        target_account.id(),
        None,
        &[fungible_asset],
        NoteType::Public,
        Some(reclaim_height),
        None,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_until_block(reclaim_height + 1)?;

    mock_chain
        .build_transaction(sender_account.id())
        .authenticated_input_note(note.id())
        .build()
}

// SWAP NOTE SETUPS
// ================================================================================================

/// Returns the transaction context in which a network account fills a SWAP note whose payback note
/// has the given note type.
pub fn tx_consume_swap_note_network(payback_note_type: NoteType) -> Result<MockTransaction> {
    let offered_asset: Asset = FungibleAsset::mock(2000);
    let requested_asset: Asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let mut builder = super::chain_builder(true);

    let sender_account =
        builder.add_existing_wallet_with_assets(Auth::basic_ecdsa(), [offered_asset])?;
    let target_account = builder.add_existing_wallet_with_assets(
        super::network_auth([SwapNote::script_root()])?,
        [requested_asset, super::fee_funding_asset()?],
    )?;

    let (swap_note, _payback_note) = builder.add_swap_note(
        sender_account.id(),
        offered_asset,
        requested_asset,
        payback_note_type,
    )?;

    let mock_chain = builder.build()?;

    mock_chain
        .build_transaction(target_account.id())
        .authenticated_input_note(swap_note.id())
        .build()
}

// PSWAP NOTE SETUPS
// ================================================================================================

/// Returns the transaction context in which a network account fills a PSWAP note, either fully or,
/// when `full_fill` is unset, partially.
///
/// A partial fill delivers half of the requested amount (the note sets no `min_fill_step` floor)
/// and re-creates a residual PSWAP note carrying the unfilled remainder.
pub fn tx_consume_pswap_note_network(full_fill: bool) -> Result<MockTransaction> {
    const OFFERED_AMOUNT: u64 = 100;
    const REQUESTED_AMOUNT: u64 = 50;

    let offered_asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?, OFFERED_AMOUNT)?;
    let min_requested_asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?, REQUESTED_AMOUNT)?;

    let fill_amount = if full_fill {
        REQUESTED_AMOUNT
    } else {
        REQUESTED_AMOUNT / 2
    };
    let fill_asset =
        FungibleAsset::new(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET_1.try_into()?, fill_amount)?;

    let mut builder = super::chain_builder(true);

    let creator_account =
        builder.add_existing_wallet_with_assets(Auth::basic_ecdsa(), [offered_asset.into()])?;
    let consumer_account = builder.add_existing_wallet_with_assets(
        super::network_auth([PswapNote::script_root()])?,
        [fill_asset.into(), super::fee_funding_asset()?],
    )?;

    let storage = PswapNoteStorage::builder()
        .min_requested_asset(min_requested_asset)
        .creator_account_id(creator_account.id())
        .build();
    let pswap = PswapNote::builder()
        .sender(creator_account.id())
        .storage(storage)
        .serial_number(builder.rng_mut().draw_word())
        .note_type(NoteType::Public)
        .offered_asset(offered_asset)
        .build()?;
    let pswap_note = Note::from(pswap.clone());
    builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));

    let mock_chain = builder.build()?;

    // Predict the output notes: the P2ID payback for the creator and, on a partial fill, the
    // residual PSWAP note carrying the remainder.
    let (payback_note, remainder_pswap) =
        pswap.execute(consumer_account.id(), Some(fill_asset), None)?;
    let mut expected_output_notes = vec![RawOutputNote::Full(payback_note)];
    if let Some(remainder) = remainder_pswap {
        expected_output_notes.push(RawOutputNote::Full(Note::from(remainder)));
    }

    mock_chain
        .build_transaction(consumer_account.id())
        .authenticated_input_note(pswap_note.id())
        .extend_note_args(BTreeMap::from([(
            pswap_note.id(),
            PswapNote::create_args(fill_amount, 0)?,
        )]))
        .expected_output_notes(expected_output_notes)
        .build()
}

// FEE SPONSORSHIP NOTE SETUPS
// ================================================================================================

/// Amount of the native fee asset carried by the benchmarked FEE_SPONSORSHIP note.
const SPONSORED_FEE_AMOUNT: u64 = 500;

/// Returns the transaction context in which a network account consumes a FEE_SPONSORSHIP note,
/// either together with its sponsored feature note or, when `reclaim` is set, via the sponsor's
/// reclaim path.
///
/// On the sponsorship path the network account's auth procedure collects the sponsored fee
/// natively while consuming the feature note directly followed by its sponsorship note. On the
/// reclaim path the note script moves the asset into the sponsor's vault itself, so the
/// sponsorship note is consumed alone.
pub fn tx_consume_fee_sponsorship_note_network(reclaim: bool) -> Result<MockTransaction> {
    let sponsored_asset: Asset =
        FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, SPONSORED_FEE_AMOUNT)?.into();

    let mut builder = super::chain_builder(true);

    if reclaim {
        // Reclaim path: the sponsor reclaims the sponsorship note once the reclaim height has
        // passed. A network account cannot consume a lone sponsorship note (its auth's fee
        // collection requires the paired feature note), so the sponsor is a regular wallet
        // paying its own fee at the native 1/1 rate.
        let reclaim_height = BlockNumber::from(1u32);

        let sponsor = builder
            .add_existing_wallet_with_assets(Auth::basic_ecdsa(), [super::fee_funding_asset()?])?;
        let network_target = builder.add_existing_wallet(Auth::basic_ecdsa())?;
        let feature_note = builder.add_p2any_note(sponsor.id(), NoteType::Public, [])?;

        let sponsorship_note = Note::from(
            FeeSponsorshipNote::builder()
                .sender(sponsor.id())
                .target_account(network_target.id())
                .feature_note_id(feature_note.id())
                .asset(sponsored_asset)
                .reclaim_height(reclaim_height)
                .generate_serial_number(builder.rng_mut())
                .build()?,
        );
        builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

        let mut mock_chain = builder.build()?;
        // Advance past genesis so the reclaim height counts as reached.
        mock_chain.prove_next_block()?;

        let (auth_args, advice_value) = commit_fee_conversion_info(
            FeeConversionInfo::one_to_one(ACCOUNT_ID_FEE_FAUCET.try_into()?),
            Word::from([9u32, 10, 11, 12]),
        );
        mock_chain
            .build_transaction(sponsor.id())
            .authenticated_input_note(sponsorship_note.id())
            .auth_args(auth_args)
            .add_advice_map_entry(auth_args, advice_value)
            .build()
    } else {
        // Sponsorship path: the network account consumes the fee-unaware feature note directly
        // followed by the FEE_SPONSORSHIP note prepaying its fee (the order
        // collect_sponsored_fees requires); the auth procedure collects the sponsored fee
        // natively. The account's fee policy prices the feature note at the sponsored amount.
        let sponsor = builder.add_existing_wallet(Auth::basic_ecdsa())?;
        // The feature note is completely fee-unaware; P2ANY stands in for a real network note.
        let feature_note = builder.add_p2any_note(sponsor.id(), NoteType::Public, [])?;

        let network_account = builder.add_existing_wallet_with_assets(
            super::network_auth_with_fees(
                [feature_note.script().root(), FeeSponsorshipNote::script_root()],
                &[(feature_note.script().root(), SPONSORED_FEE_AMOUNT)],
            )?,
            [super::fee_funding_asset()?],
        )?;

        let sponsorship_note = Note::from(
            FeeSponsorshipNote::builder()
                .sender(sponsor.id())
                .target_account(network_account.id())
                .feature_note_id(feature_note.id())
                .asset(sponsored_asset)
                .generate_serial_number(builder.rng_mut())
                .build()?,
        );
        builder.add_output_note(RawOutputNote::Full(sponsorship_note.clone()));

        let mock_chain = builder.build()?;

        mock_chain
            .build_transaction(network_account.id())
            .authenticated_input_note(feature_note.id())
            .authenticated_input_note(sponsorship_note.id())
            .build()
    }
}
