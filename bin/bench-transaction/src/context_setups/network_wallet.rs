//! Benchmark scenarios where a network-authenticated basic wallet consumes a standard note.
//!
//! Each scenario runs on a chain charging [`super::NETWORK_VERIFICATION_BASE_FEE`], so the
//! consuming account's network auth procedure pays the transaction fee by creating a TX_FEE note
//! funded from the account's own vault.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
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
use miden_protocol::transaction::{RawOutputNote, TransactionScript};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::{
    FeeSponsorshipNote,
    P2idNote,
    P2ideNote,
    PswapNote,
    PswapNoteStorage,
    SwapNote,
};
use miden_testing::{Auth, TransactionContext};

// P2ID NOTE SETUPS
// ================================================================================================

/// Returns the transaction context for a network wallet consuming a single P2ID note.
pub fn tx_consume_p2id_note_network() -> Result<TransactionContext> {
    let fungible_asset: Asset = FungibleAsset::mock(123);

    let mut builder = super::chain_builder(true);

    let target_account = builder.add_existing_wallet_with_assets(
        super::network_auth([P2idNote::script_root()]),
        [super::fee_funding_asset()?],
    )?;

    let note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into()?,
        target_account.id(),
        &[fungible_asset],
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;

    mock_chain.build_tx_context(target_account.id(), &[note.id()], &[])?.build()
}

// P2IDE NOTE SETUPS
// ================================================================================================

/// Returns the transaction context for a network wallet consuming a P2IDE note, either via the
/// target's claim path or, when `reclaim` is set, via the sender's reclaim path.
pub fn tx_consume_p2ide_note_network(reclaim: bool) -> Result<TransactionContext> {
    let fungible_asset: Asset = FungibleAsset::mock(123);

    let mut builder = super::chain_builder(true);

    if reclaim {
        // Reclaim path: the network wallet is the note's sender (and thus its default reclaimer)
        // and reclaims the note once the reclaim height has passed.
        let reclaim_height = BlockNumber::from(2u32);

        let sender_account = builder.add_existing_wallet_with_assets(
            super::network_auth([P2ideNote::script_root()]),
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

        mock_chain.build_tx_context(sender_account.id(), &[note.id()], &[])?.build()
    } else {
        // Claim path: the network wallet is the note's target and consumes it directly.
        let target_account = builder.add_existing_wallet_with_assets(
            super::network_auth([P2ideNote::script_root()]),
            [super::fee_funding_asset()?],
        )?;

        let note = builder.add_p2ide_note(
            ACCOUNT_ID_SENDER.try_into()?,
            target_account.id(),
            None,
            &[fungible_asset],
            NoteType::Public,
            None,
            None,
        )?;

        let mock_chain = builder.build()?;

        mock_chain.build_tx_context(target_account.id(), &[note.id()], &[])?.build()
    }
}

// SWAP NOTE SETUPS
// ================================================================================================

/// Returns the transaction context for a network wallet filling a SWAP note whose payback note
/// has the given note type.
pub fn tx_consume_swap_note_network(payback_note_type: NoteType) -> Result<TransactionContext> {
    let offered_asset: Asset = FungibleAsset::mock(2000);
    let requested_asset: Asset = NonFungibleAsset::mock(&[1, 2, 3, 4]);

    let mut builder = super::chain_builder(true);

    let sender_account =
        builder.add_existing_wallet_with_assets(Auth::basic_ecdsa(), [offered_asset])?;
    let target_account = builder.add_existing_wallet_with_assets(
        super::network_auth([SwapNote::script_root()]),
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
        .build_tx_context(target_account.id(), &[swap_note.id()], &[])?
        .build()
}

// PSWAP NOTE SETUPS
// ================================================================================================

/// Returns the transaction context for a network wallet filling a PSWAP note, either fully or,
/// when `full_fill` is unset, partially.
///
/// A partial fill delivers half of the requested amount (the note sets no `min_fill_step` floor)
/// and re-creates a residual PSWAP note carrying the unfilled remainder.
pub fn tx_consume_pswap_note_network(full_fill: bool) -> Result<TransactionContext> {
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
        super::network_auth([PswapNote::script_root()]),
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
        .build_tx_context(consumer_account.id(), &[pswap_note.id()], &[])?
        .extend_note_args(BTreeMap::from([(
            pswap_note.id(),
            PswapNote::create_args(fill_amount, 0)?,
        )]))
        .extend_expected_output_notes(expected_output_notes)
        .build()
}

// FEE SPONSORSHIP NOTE SETUPS
// ================================================================================================

/// Amount of the native fee asset carried by the benchmarked FEE_SPONSORSHIP note.
const SPONSORED_FEE_AMOUNT: u64 = 500;

/// Compiles a transaction script that moves `fee_asset` into the executing account's vault.
///
/// On the sponsorship path the note script leaves the sponsored assets in place, so the consuming
/// transaction has to collect them itself. Mirrors the fee-collection script used by the
/// FEE_SPONSORSHIP note tests.
fn collect_fee_tx_script(fee_asset: Asset) -> Result<TransactionScript> {
    let src = format!(
        "
        use miden::standards::wallets::basic as wallet

        @transaction_script
        pub proc main
            push.{asset_value}
            push.{asset_id}
            # => [ASSET_ID, ASSET_VALUE]

            padw padw swapdw
            # => [ASSET_ID, ASSET_VALUE, pad(8)]

            call.wallet::receive_asset
            # => [pad(16)]

            dropw dropw dropw dropw
        end
        ",
        asset_value = fee_asset.to_value_word(),
        asset_id = fee_asset.to_id_word(),
    );
    Ok(CodeBuilder::default().compile_tx_script(src)?)
}

/// Returns the transaction context for a network wallet consuming a FEE_SPONSORSHIP note, either
/// together with its sponsored feature note or, when `reclaim` is set, via the sponsor's reclaim
/// path.
///
/// On the sponsorship path the note script leaves the sponsored fee asset in the note, so the
/// consuming account collects it with an allowlisted fee-collection transaction script. On the
/// reclaim path the note script moves the asset into the sponsor's vault itself, so the
/// sponsorship note is consumed alone and without a transaction script.
pub fn tx_consume_fee_sponsorship_note_network(reclaim: bool) -> Result<TransactionContext> {
    let sponsored_asset: Asset =
        FungibleAsset::new(ACCOUNT_ID_FEE_FAUCET.try_into()?, SPONSORED_FEE_AMOUNT)?.into();

    let mut builder = super::chain_builder(true);

    if reclaim {
        // Reclaim path: the network wallet is the sponsor (and thus the default reclaimer) and
        // reclaims the sponsorship note once the reclaim height has passed.
        let reclaim_height = BlockNumber::from(1u32);

        let sponsor = builder.add_existing_wallet_with_assets(
            super::network_auth([FeeSponsorshipNote::script_root()]),
            [super::fee_funding_asset()?],
        )?;
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

        mock_chain
            .build_tx_context(sponsor.id(), &[sponsorship_note.id()], &[])?
            .build()
    } else {
        // Sponsorship path: the network wallet consumes the fee-unaware feature note together
        // with the FEE_SPONSORSHIP note paying for it, collecting the sponsored fee via an
        // allowlisted transaction script.
        let collect_script = collect_fee_tx_script(sponsored_asset)?;

        let sponsor = builder.add_existing_wallet(Auth::basic_ecdsa())?;
        // The feature note is completely fee-unaware; P2ANY stands in for a real network note.
        let feature_note = builder.add_p2any_note(sponsor.id(), NoteType::Public, [])?;

        let network_account = builder.add_existing_wallet_with_assets(
            Auth::NetworkAccount {
                allowed_script_roots: BTreeSet::from([
                    feature_note.script().root(),
                    FeeSponsorshipNote::script_root(),
                ]),
                allowed_tx_script_roots: BTreeSet::from([collect_script.root()]),
            },
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
            .build_tx_context(
                network_account.id(),
                &[sponsorship_note.id(), feature_note.id()],
                &[],
            )?
            .tx_script(collect_script)
            .build()
    }
}
