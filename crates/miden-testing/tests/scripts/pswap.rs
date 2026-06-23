use std::collections::BTreeMap;
use std::slice;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountId, AccountType, AccountVaultPatch};
use miden_protocol::asset::{Asset, AssetAmount, AssetVaultKey, FungibleAsset};
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteAttachments, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, ONE, Word, ZERO};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::{
    ERR_PSWAP_FILL_EXCEEDS_REQUESTED,
    ERR_PSWAP_FILL_SUM_OVERFLOW,
    ERR_PSWAP_NOT_VALID_ASSET_AMOUNT,
};
use miden_standards::note::{PswapNote, PswapNoteAttachment, PswapNoteStorage};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{Auth, MockChain, MockChainBuilder, assert_transaction_executor_error};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use rstest::rstest;

// CONSTANTS
// ================================================================================================

const BASIC_AUTH: Auth = Auth::BasicAuth {
    auth_scheme: AuthScheme::Falcon512Poseidon2,
};

// HELPERS
// ================================================================================================

/// Extracts the first attachment's word content from a `NoteAttachments`.
fn first_attachment_word(attachments: &NoteAttachments) -> Word {
    let content = attachments.get(0).expect("expected at least one attachment").content();
    assert_eq!(content.num_words(), 1, "expected single word attachment");
    content.as_words()[0]
}

/// Builds a PswapNote, registers it on the builder as an output note, and returns
/// both the `PswapNote` (for `.execute()`) and the protocol `Note` (for
/// `.id()` / `RawOutputNote::Full`), so callers don't need to round-trip via
/// `PswapNote::try_from(&note)?`. Serial number is drawn from the builder's rng.
fn build_pswap_note(
    builder: &mut MockChainBuilder,
    sender: AccountId,
    offered_asset: FungibleAsset,
    requested_asset: FungibleAsset,
    note_type: NoteType,
) -> anyhow::Result<(PswapNote, Note)> {
    let serial_number = builder.rng_mut().draw_word();
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(sender)
        .build();
    let pswap = PswapNote::builder()
        .sender(sender)
        .storage(storage)
        .serial_number(serial_number)
        .note_type(note_type)
        .offered_asset(offered_asset)
        .build()?;
    let note: Note = pswap.clone().into();
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    Ok((pswap, note))
}

#[track_caller]
fn assert_vault_patch(
    vault_patch: &AccountVaultPatch,
    expected_assets: impl IntoIterator<Item = FungibleAsset>,
) {
    let updated: Vec<Asset> = vault_patch.updated_assets().collect();
    let removed: Vec<AssetVaultKey> = vault_patch.removed_asset_keys().copied().collect();
    let expected_assets = expected_assets.into_iter().collect::<Vec<_>>();
    assert_eq!(vault_patch.num_assets(), expected_assets.len());

    for expected in expected_assets {
        if expected.amount().as_u64() == 0 {
            assert!(removed.contains(&expected.vault_key()));
        } else {
            let actual = updated
                .iter()
                .find(|asset| asset.vault_key() == expected.vault_key())
                .expect("updated asset should be present");
            assert_eq!(actual, &Asset::Fungible(expected));
        }
    }
}

// TESTS
// ================================================================================================

/// Verifies that Alice can independently reconstruct and consume the P2ID payback note
/// using only her original PSWAP data and the on-chain attachment data from Bob's tx.
///
/// Flow:
/// 1. Alice creates a PSWAP note (50 USDC for 25 ETH) with a parameterized payback note type.
/// 2. Bob fills it (fully or partially per case) → produces a P2ID payback (+ remainder on
///    partial).
/// 3. Alice reconstructs the payback Note via `PswapNote::payback_note` using only the on-chain
///    attachment data. On partial fills she also reconstructs the remainder via
///    `PswapNote::remainder_note`.
/// 4. Alice consumes the *reconstructed* P2ID payback (fed unauthenticated, the only path available
///    against a real chain for private paybacks where only the commitment is on-chain) and verifies
///    she receives the filled amount.
///
/// The private case is the headline discovery use case: the chain holds only a commitment,
/// so Alice's only path to consume is to reconstruct the body from her PSWAP + attachment.
#[rstest]
#[case::partial_public(NoteType::Public, 20)]
#[case::full_public(NoteType::Public, 25)]
#[case::partial_private(NoteType::Private, 20)]
#[case::full_private(NoteType::Private, 25)]
#[tokio::test]
async fn pswap_note_alice_reconstructs_and_consumes_p2id(
    #[case] payback_note_type: NoteType,
    #[case] fill_amount: u64,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), fill_amount)?.into()],
    )?;

    let offered_asset = FungibleAsset::new(usdc_faucet.id(), 50)?;
    let requested_asset = FungibleAsset::new(eth_faucet.id(), 25)?;
    let is_partial = fill_amount < u64::from(requested_asset.amount());

    let mut rng = RandomCoin::new(Word::default());
    let serial_number = rng.draw_word();
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(alice.id())
        .payback_note_type(payback_note_type)
        .build();
    let pswap = PswapNote::builder()
        .sender(alice.id())
        .storage(storage)
        .serial_number(serial_number)
        .note_type(NoteType::Public)
        .offered_asset(offered_asset)
        .build()?;
    let pswap_note: Note = pswap.clone().into();
    builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));

    let mut mock_chain = builder.build()?;

    // --- Step 1: Bob fills the PSWAP note ---

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), PswapNote::create_args(fill_amount, 0)?);

    let (p2id_note, remainder_pswap) =
        pswap.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), fill_amount)?), None)?;

    let mut expected_output_notes = vec![RawOutputNote::Full(p2id_note.clone())];
    let predicted_remainder = if is_partial {
        let r = remainder_pswap.expect("partial fill should produce remainder");
        let rn = Note::from(r);
        expected_output_notes.push(RawOutputNote::Full(rn.clone()));
        Some(rn)
    } else {
        assert!(remainder_pswap.is_none(), "full fill should not produce a remainder");
        None
    };

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .extend_expected_output_notes(expected_output_notes)
        .build()?;

    let executed_transaction = tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // --- Step 2: Alice reconstructs the P2ID payback from on-chain attachment data ---

    // Read attachments from the executed tx (the body is still here even when the note will
    // ultimately land on-chain as a header-only private commitment).
    let output_p2id = executed_transaction.output_notes().get_note(0);
    let attachment_word = first_attachment_word(output_p2id.attachments());
    let fill_amount_from_aux = attachment_word[0].as_canonical_u64();
    assert_eq!(fill_amount_from_aux, fill_amount, "fill amount from aux should match the case");

    // Parity check: Rust-predicted P2ID attachment must match the MASM output.
    assert_eq!(
        first_attachment_word(p2id_note.attachments()),
        attachment_word,
        "Rust-predicted P2ID attachment does not match the MASM-produced one",
    );

    // Depth = 1 (first fill). Consumer comes from the on-chain payback's metadata sender.
    let payback_attachment =
        PswapNoteAttachment::new(AssetAmount::new(fill_amount_from_aux)?, pswap.order_id(), 1);
    let reconstructed_payback =
        pswap.payback_note(output_p2id.metadata().sender(), &payback_attachment)?;

    assert_eq!(
        reconstructed_payback.recipient().digest(),
        output_p2id.recipient_digest(),
        "Alice's reconstructed P2ID recipient does not match the actual output"
    );

    // --- Step 2b: On partial fills, Alice also reconstructs the remainder PSWAP ---

    if is_partial {
        let output_remainder = executed_transaction.output_notes().get_note(1);
        let remainder_attachment_word = first_attachment_word(output_remainder.attachments());
        let amt_payout_from_attachment = remainder_attachment_word[0].as_canonical_u64();

        let expected_payout = pswap.calculate_offered_for_requested(fill_amount_from_aux)?;
        assert_eq!(
            amt_payout_from_attachment, expected_payout,
            "remainder aux should carry amt_payout matching the Rust-side calc",
        );

        let remaining_requested =
            (requested_asset.amount() - AssetAmount::new(fill_amount_from_aux)?)?;
        let remaining_offered =
            (pswap.offered_asset().amount() - AssetAmount::new(amt_payout_from_attachment)?)?;

        let remainder_attachment = PswapNoteAttachment::new(
            AssetAmount::new(amt_payout_from_attachment)?,
            pswap.order_id(),
            1,
        );
        let reconstructed_remainder = pswap.remainder_note(
            output_remainder.metadata().sender(),
            &remainder_attachment,
            remaining_offered,
            remaining_requested,
        )?;

        // Parity: Rust-predicted remainder must match the executed output.
        let predicted_remainder = predicted_remainder
            .as_ref()
            .expect("predicted remainder must exist on partial fill");
        assert_eq!(
            predicted_remainder.recipient().digest(),
            output_remainder.recipient_digest(),
            "Rust-predicted remainder recipient does not match executed output",
        );

        assert_eq!(
            reconstructed_remainder.details_commitment(),
            output_remainder.details_commitment(),
            "reconstructed remainder commitment must match on-chain leaf",
        );
    }

    // --- Step 3: Alice consumes the *reconstructed* P2ID payback ---
    //
    // The note is fed via the unauthenticated path: Alice provides the body herself, and
    // the chain validates that the body's commitment matches the one recorded by Bob's tx.
    // This is the only path for private paybacks (no body on-chain) and works equally for
    // public ones.

    let tx_context = mock_chain
        .build_tx_context(alice.id(), &[], slice::from_ref(&reconstructed_payback))?
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify Alice received the filled amount.
    let vault_patch = executed_transaction.account_patch().vault();
    assert_vault_patch(vault_patch, [FungibleAsset::new(eth_faucet.id(), fill_amount)?]);

    Ok(())
}

/// Dedicated regression test for the attachment word layout shared between
/// `create_p2id_note` / `create_remainder_note` in pswap.masm and
/// `create_payback_note` / `create_remainder_pswap_note` in pswap.rs.
///
/// Both sides agree on:
/// - P2ID payback attachment:   `[fill_amount, order_id, depth, 0]`, scheme = PswapAttachment
/// - Remainder PSWAP attachment: `[amt_payout, order_id, depth, 0]`, scheme = PswapAttachment
///
/// `order_id` is the original creator's `serial[1]` (stable across the lineage), and
/// `depth` is the 1-indexed round number (1 for the first fill of an original PSWAP).
/// If either side drifts (e.g. MASM switches the slots, or one side forgets the scheme),
/// this test fires.
///
/// Uses a simple partial fill — offered 50 USDC, requested 25 ETH, fill 20 ETH
/// — so both output notes exist and the expected amounts are
/// `fill_amount = 20` and `amt_payout = floor(50 * 20 / 25) = 40`.
#[tokio::test]
async fn pswap_attachment_layout_matches_masm_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    let usdc_50 = FungibleAsset::new(usdc_faucet.id(), 50)?;
    let eth_20 = FungibleAsset::new(eth_faucet.id(), 20)?;
    let eth_25 = FungibleAsset::new(eth_faucet.id(), 25)?;

    let alice = builder.add_existing_wallet_with_assets(BASIC_AUTH, [usdc_50.into()])?;
    let bob = builder.add_existing_wallet_with_assets(BASIC_AUTH, [eth_20.into()])?;

    let (pswap, pswap_note) =
        build_pswap_note(&mut builder, alice.id(), usdc_50, eth_25, NoteType::Public)?;

    let mock_chain = builder.build()?;

    let fill_amount = 20u64;
    let expected_payout = 40u64; // floor(50 * 20 / 25)
    let order_id = pswap.order_id();
    let expected_depth = 1u64; // first fill of an original PSWAP

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), PswapNote::create_args(fill_amount, 0)?);

    let (p2id_note, remainder_pswap) = pswap.execute(bob.id(), Some(eth_20), None)?;
    let remainder_note =
        Note::from(remainder_pswap.expect("partial fill should produce remainder"));

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(p2id_note.clone()),
            RawOutputNote::Full(remainder_note.clone()),
        ])
        .build()?;

    let executed_transaction = tx_context.execute().await?;
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 2, "expected P2ID + remainder");

    let p2id_attachments = output_notes.get_note(0).attachments();
    let remainder_attachments = output_notes.get_note(1).attachments();

    // Both output notes must carry exactly one attachment under PSWAP_ATTACHMENT_SCHEME.
    assert_eq!(p2id_attachments.num_attachments(), 1, "payback expects 1 attachment");
    assert_eq!(remainder_attachments.num_attachments(), 1, "remainder expects 1 attachment");

    let p2id_att = p2id_attachments.get(0).expect("payback attachment present");
    let remainder_att = remainder_attachments.get(0).expect("remainder attachment present");

    assert_eq!(
        p2id_att.attachment_scheme(),
        PswapNote::PSWAP_ATTACHMENT_SCHEME,
        "payback must use PSWAP_ATTACHMENT_SCHEME",
    );
    assert_eq!(
        remainder_att.attachment_scheme(),
        PswapNote::PSWAP_ATTACHMENT_SCHEME,
        "remainder must use PSWAP_ATTACHMENT_SCHEME",
    );

    // P2ID payback attachment word: [fill_amount, order_id, depth, 0].
    let expected_p2id_word = Word::from([
        Felt::try_from(fill_amount).expect("fill_amount fits in a felt"),
        order_id,
        Felt::try_from(expected_depth).expect("depth fits in a felt"),
        ZERO,
    ]);
    assert_eq!(
        p2id_att.content().as_words()[0],
        expected_p2id_word,
        "P2ID attachment word mismatch: expected [fill_amount, order_id, depth, 0]",
    );

    // Remainder PSWAP attachment word: [amt_payout, order_id, depth, 0].
    let expected_remainder_word = Word::from([
        Felt::try_from(expected_payout).expect("amt_payout fits in a felt"),
        order_id,
        Felt::try_from(expected_depth).expect("depth fits in a felt"),
        ZERO,
    ]);
    assert_eq!(
        remainder_att.content().as_words()[0],
        expected_remainder_word,
        "remainder attachment word mismatch: expected [amt_payout, order_id, depth, 0]",
    );

    // Cross-check: the Rust-predicted notes must produce the same attachment
    // words as the on-chain executed ones.
    assert_eq!(
        first_attachment_word(p2id_note.attachments()),
        p2id_att.content().as_words()[0],
        "Rust-predicted P2ID attachment does not match MASM output",
    );
    assert_eq!(
        first_attachment_word(remainder_note.attachments()),
        remainder_att.content().as_words()[0],
        "Rust-predicted remainder attachment does not match MASM output",
    );

    // Sanity: order_id must equal the original PSWAP's serial[1].
    assert_eq!(order_id, pswap.serial_number()[1], "order_id should equal serial[1]");

    Ok(())
}

/// Parameterized fill test covering:
/// - full public fill
/// - full private fill
/// - partial public fill (offered=8 USDC / requested=4 ETH / fill=3 ETH → payout=6 USDC,
///   remainder=2 USDC, all scaled by 10^18)
/// - full fill via a network account (no note_args → script defaults to full fill)
///
/// Amounts are scaled by `AMOUNT_SCALE = 10^18` so the test exercises realistic
/// 18-decimal token base units (the wei-equivalent of ETH / most ERC-20 tokens).
/// This stresses the MASM payout calculation at operand sizes in the ~10^18
/// range, verifying `u64::widening_mul` + `u128::div` handle them without
/// overflow. Base values stay below `AssetAmount::MAX ≈ 9.22 × 10^18`.
#[rstest]
#[case::full_public(4, NoteType::Public, false)]
#[case::full_private(4, NoteType::Private, false)]
#[case::partial_public(3, NoteType::Public, false)]
#[case::network_full_fill(4, NoteType::Public, true)]
#[tokio::test]
async fn pswap_fill_test(
    #[case] fill_base: u64,
    #[case] note_type: NoteType,
    #[case] use_network_account: bool,
) -> anyhow::Result<()> {
    // 10^18: one whole 18-decimal token (e.g. 1 ETH in wei).
    const AMOUNT_SCALE: u64 = 1_000_000_000_000_000_000;

    let fill_amount = fill_base * AMOUNT_SCALE;
    let offered_total = 8 * AMOUNT_SCALE; //  8 × 10^18  USDC offered
    let requested_total = 4 * AMOUNT_SCALE; //  4 × 10^18  ETH requested
    let max_supply = 9 * AMOUNT_SCALE; // just under AssetAmount::MAX

    let mut builder = MockChain::builder();

    let usdc_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", max_supply, Some(offered_total))?;
    let eth_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", max_supply, Some(requested_total))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), offered_total)?.into()],
    )?;

    let consumer_id = if use_network_account {
        let seed: [u8; 32] = builder.rng_mut().draw_word().into();
        let network_consumer = builder.add_account_from_builder(
            BASIC_AUTH,
            Account::builder(seed)
                .account_type(AccountType::Public)
                .with_component(BasicWallet)
                .with_assets([FungibleAsset::new(eth_faucet.id(), fill_amount)?.into()]),
            miden_testing::AccountState::Exists,
        )?;
        network_consumer.id()
    } else {
        let bob = builder.add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(eth_faucet.id(), fill_amount)?.into()],
        )?;
        bob.id()
    };

    let offered_asset = FungibleAsset::new(usdc_faucet.id(), offered_total)?;
    let requested_asset = FungibleAsset::new(eth_faucet.id(), requested_total)?;

    let (pswap, pswap_note) =
        build_pswap_note(&mut builder, alice.id(), offered_asset, requested_asset, note_type)?;

    let mut mock_chain = builder.build()?;

    let fill_asset = FungibleAsset::new(eth_faucet.id(), fill_amount)?;

    let (p2id_note, remainder_pswap) = if use_network_account {
        let p2id = pswap.execute_full_fill(consumer_id)?;
        (p2id, None)
    } else {
        pswap.execute(consumer_id, Some(fill_asset), None)?
    };

    let is_partial = fill_amount < requested_total;
    let payout_amount = pswap.calculate_offered_for_requested(fill_amount)?;

    let mut expected_notes = vec![RawOutputNote::Full(p2id_note.clone())];
    if let Some(remainder) = remainder_pswap {
        expected_notes.push(RawOutputNote::Full(Note::from(remainder)));
    }

    let mut tx_builder = mock_chain
        .build_tx_context(consumer_id, &[pswap_note.id()], &[])?
        .extend_expected_output_notes(expected_notes);

    if !use_network_account {
        let mut note_args_map = BTreeMap::new();
        note_args_map.insert(pswap_note.id(), PswapNote::create_args(fill_amount, 0)?);
        tx_builder = tx_builder.extend_note_args(note_args_map);
    }

    let tx_context = tx_builder.build()?;
    let executed_transaction = tx_context.execute().await?;

    // Verify output note count
    let output_notes = executed_transaction.output_notes();
    let expected_count = if is_partial { 2 } else { 1 };
    assert_eq!(
        output_notes.num_notes(),
        expected_count,
        "expected {expected_count} output notes"
    );

    // Verify the P2ID recipient matches our Rust prediction
    let actual_recipient = output_notes.get_note(0).recipient_digest();
    let expected_recipient = p2id_note.recipient().digest();
    assert_eq!(actual_recipient, expected_recipient, "RECIPIENT MISMATCH!");

    // P2ID note carries fill_amount ETH
    let p2id_assets = output_notes.get_note(0).assets();
    assert_eq!(p2id_assets.num_assets(), 1);
    assert_eq!(
        p2id_assets.iter().next().unwrap().unwrap_fungible(),
        FungibleAsset::new(eth_faucet.id(), fill_amount)?,
    );

    // On partial fill, assert remainder note has offered - payout USDC
    if is_partial {
        let remainder_assets = output_notes.get_note(1).assets();
        assert_eq!(
            remainder_assets.iter().next().unwrap().unwrap_fungible(),
            FungibleAsset::new(usdc_faucet.id(), offered_total - payout_amount)?,
        );
    }

    // Consumer's vault: +payout USDC, -fill ETH (the consumer spent its entire ETH balance, results
    // in 0).
    let vault_patch = executed_transaction.account_patch().vault();
    assert_vault_patch(
        vault_patch,
        [
            FungibleAsset::new(usdc_faucet.id(), payout_amount)?,
            FungibleAsset::new(eth_faucet.id(), 0)?,
        ],
    );

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    Ok(())
}

#[tokio::test]
async fn pswap_note_note_fill_cross_swap_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    // Alice offers 50 USDC for 25 ETH. Bob offers 25 ETH for 50 USDC. They
    // cross-swap through Charlie, so each side's offered asset is the other
    // side's requested asset.
    let usdc_50 = FungibleAsset::new(usdc_faucet.id(), 50)?;
    let eth_25 = FungibleAsset::new(eth_faucet.id(), 25)?;

    let alice = builder.add_existing_wallet_with_assets(BASIC_AUTH, [usdc_50.into()])?;
    let bob = builder.add_existing_wallet_with_assets(BASIC_AUTH, [eth_25.into()])?;
    let charlie = builder.add_existing_wallet_with_assets(BASIC_AUTH, [])?;

    // Alice's note: offers 50 USDC, requests 25 ETH
    let (alice_pswap, alice_pswap_note) =
        build_pswap_note(&mut builder, alice.id(), usdc_50, eth_25, NoteType::Public)?;

    // Bob's note: offers 25 ETH, requests 50 USDC
    let (bob_pswap, bob_pswap_note) =
        build_pswap_note(&mut builder, bob.id(), eth_25, usdc_50, NoteType::Public)?;

    let mock_chain = builder.build()?;

    // Note args: pure note fill (account_fill = 0, note_fill = full amount)
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(alice_pswap_note.id(), PswapNote::create_args(0, 25)?);
    note_args_map.insert(bob_pswap_note.id(), PswapNote::create_args(0, 50)?);

    // Expected P2ID notes
    let (alice_p2id_note, _) = alice_pswap.execute(charlie.id(), None, Some(eth_25))?;
    let (bob_p2id_note, _) = bob_pswap.execute(charlie.id(), None, Some(usdc_50))?;

    let tx_context = mock_chain
        .build_tx_context(charlie.id(), &[alice_pswap_note.id(), bob_pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(alice_p2id_note),
            RawOutputNote::Full(bob_p2id_note),
        ])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify: 2 P2ID notes, one carrying Alice's requested (25 ETH), one
    // carrying Bob's requested (50 USDC).
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 2);

    assert!(
        output_notes
            .iter()
            .any(|note| note.assets().iter_fungible().any(|a| a == eth_25)),
        "Alice's P2ID note ({eth_25:?}) not found",
    );
    assert!(
        output_notes
            .iter()
            .any(|note| note.assets().iter_fungible().any(|a| a == usdc_50)),
        "Bob's P2ID note ({usdc_50:?}) not found",
    );

    // Charlie's vault should be unchanged
    assert!(
        executed_transaction.account_patch().vault().is_empty(),
        "Charlie's vault should be unchanged"
    );

    Ok(())
}

/// Integration test for a PSWAP fill that uses **both** `account_fill` and
/// `note_fill` on the same note in the same transaction.
///
/// Setup:
/// - Alice's pswap: 100 USDC offered for 50 ETH requested (ratio 2:1).
/// - Bob's pswap:    30 ETH offered for 60 USDC requested (ratio 1:2).
/// - Charlie has 20 ETH in vault.
///
/// Charlie consumes both notes in one tx:
/// - Alice's: `account_fill = 20 ETH` (debited from his vault)
///            + `note_fill = 30 ETH` (sourced from inflight, produced by Bob's pswap)
///            → 50 ETH total (full fill). Payout split:
///              - 40 USDC → Charlie's vault (account_fill path)
///              - 60 USDC → inflight (note_fill path, consumed by Bob's pswap)
/// - Bob's:   `note_fill = 60 USDC` (sourced from inflight, produced by Alice's pswap) → 60 USDC
///   total (full fill). Payout: 30 ETH → inflight (matches Alice's note_fill consumption above).
///
/// Net effect: Charlie -20 ETH / +40 USDC; Alice's P2ID = 50 ETH; Bob's P2ID = 60 USDC.
#[tokio::test]
async fn pswap_note_combined_account_fill_and_note_fill_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(200))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(60))?;

    // Alice's pswap: 100 USDC offered for 50 ETH requested.
    // Bob's pswap: 30 ETH offered for 60 USDC requested.
    // Charlie consumes both; his vault supplies 20 ETH (account_fill) and
    // the other 30 ETH is sourced from Bob's offered leg via note_fill.
    let alice_offered = FungibleAsset::new(usdc_faucet.id(), 100)?;
    let alice_requested = FungibleAsset::new(eth_faucet.id(), 50)?;
    let bob_offered = FungibleAsset::new(eth_faucet.id(), 30)?;
    let bob_requested = FungibleAsset::new(usdc_faucet.id(), 60)?;

    let charlie_vault_eth = FungibleAsset::new(eth_faucet.id(), 20)?;
    let account_fill_eth = charlie_vault_eth;
    let note_fill_eth = bob_offered;
    let charlie_payout_usdc = FungibleAsset::new(usdc_faucet.id(), 40)?;

    let alice = builder.add_existing_wallet_with_assets(BASIC_AUTH, [alice_offered.into()])?;
    let bob = builder.add_existing_wallet_with_assets(BASIC_AUTH, [bob_offered.into()])?;
    let charlie =
        builder.add_existing_wallet_with_assets(BASIC_AUTH, [charlie_vault_eth.into()])?;

    let (alice_pswap, alice_pswap_note) = build_pswap_note(
        &mut builder,
        alice.id(),
        alice_offered,
        alice_requested,
        NoteType::Public,
    )?;
    let (bob_pswap, bob_pswap_note) =
        build_pswap_note(&mut builder, bob.id(), bob_offered, bob_requested, NoteType::Public)?;

    let mock_chain = builder.build()?;

    // Alice's pswap uses a combined fill; Bob's pswap uses pure note_fill.
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(alice_pswap_note.id(), PswapNote::create_args(20, 30)?);
    note_args_map.insert(bob_pswap_note.id(), PswapNote::create_args(0, 60)?);

    let (alice_p2id_note, alice_remainder) =
        alice_pswap.execute(charlie.id(), Some(account_fill_eth), Some(note_fill_eth))?;
    assert!(
        alice_remainder.is_none(),
        "combined fill hits full fill — no remainder expected"
    );

    let (bob_p2id_note, bob_remainder) =
        bob_pswap.execute(charlie.id(), None, Some(bob_requested))?;
    assert!(bob_remainder.is_none(), "bob pswap is filled completely via note_fill");

    let tx_context = mock_chain
        .build_tx_context(charlie.id(), &[alice_pswap_note.id(), bob_pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(alice_p2id_note),
            RawOutputNote::Full(bob_p2id_note),
        ])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // Exactly 2 output notes: Alice's P2ID (50 ETH) + Bob's P2ID (60 USDC).
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 2, "expected exactly 2 P2ID output notes");

    assert!(
        output_notes
            .iter()
            .any(|note| note.assets().iter_fungible().any(|a| a == alice_requested)),
        "Alice's P2ID ({alice_requested:?}) not found",
    );
    assert!(
        output_notes
            .iter()
            .any(|note| note.assets().iter_fungible().any(|a| a == bob_requested)),
        "Bob's P2ID ({bob_requested:?}) not found",
    );

    // Charlie's vault: -20 ETH, results in 0 (account_fill) + 40 USDC (account_fill_payout).
    // The note_fill legs flow entirely through inflight and never touch his vault.
    let vault_patch = executed_transaction.account_patch().vault();
    assert_vault_patch(vault_patch, [charlie_payout_usdc, FungibleAsset::new(eth_faucet.id(), 0)?]);

    Ok(())
}

#[tokio::test]
async fn pswap_note_creator_reclaim_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(50))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(25))?;

    let initial_asset = FungibleAsset::new(usdc_faucet.id(), 40)?;
    let offered_asset = FungibleAsset::new(usdc_faucet.id(), 50)?;
    let alice = builder.add_existing_wallet_with_assets(BASIC_AUTH, [initial_asset.into()])?;

    let (_, pswap_note) = build_pswap_note(
        &mut builder,
        alice.id(),
        offered_asset,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;

    let tx_context = mock_chain.build_tx_context(alice.id(), &[pswap_note.id()], &[])?.build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify: 0 output notes, Alice gets 50 USDC back
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 0, "Expected 0 output notes for reclaim");

    // The patch holds the absolute post-tx balance: Alice's initial balance plus the offered asset
    // from the reclaimed note.
    let vault_patch = executed_transaction.account_patch().vault();
    assert_vault_patch(vault_patch, [initial_asset.add(offered_asset)?]);

    Ok(())
}

/// The fill sum overflow case uses `1u64 << 63` for each fill: both are valid
/// Felt values (< field modulus), but their sum `2^64` exceeds `u64::MAX`, so
/// the `overflowing_add` check fires before `assert_valid_asset_amount`.
///
/// The max-asset-amount case uses `FungibleAsset::MAX_AMOUNT` for each fill:
/// the sum `2 * MAX_AMOUNT` fits in u64 but exceeds `MAX_AMOUNT`, so
/// `assert_valid_asset_amount` fires instead.
#[rstest]
#[case::fill_exceeds_requested(30, 0, ERR_PSWAP_FILL_EXCEEDS_REQUESTED)]
#[case::fill_sum_u64_overflow(1u64 << 63, 1u64 << 63, ERR_PSWAP_FILL_SUM_OVERFLOW)]
#[case::fill_sum_exceeds_max_asset_amount(
    FungibleAsset::MAX_AMOUNT.as_u64(),
    FungibleAsset::MAX_AMOUNT.as_u64(),
    ERR_PSWAP_NOT_VALID_ASSET_AMOUNT
)]
#[tokio::test]
async fn pswap_note_invalid_input_test(
    #[case] account_fill: u64,
    #[case] note_fill: u64,
    #[case] expected_err: MasmError,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(50))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(30))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 30)?.into()],
    )?;

    let (_, pswap_note) = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
    )?;
    let mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), PswapNote::create_args(account_fill, note_fill)?);

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .build()?;

    let result = tx_context.execute().await;
    assert_transaction_executor_error!(result, expected_err);

    Ok(())
}

/// Regression test for the `note_idx` stack-layout bug in `create_p2id_note`'s
/// `has_account_fill` branch.
///
/// The buggy frame setup left three stray zeros between `ASSET_VALUE` and the
/// real `note_idx` on the stack, so `move_asset_to_note` read a pad zero as the
/// note index. Every existing pswap test masked this because the PSWAP note
/// was always the only output-note emitter in the transaction, so `note_idx`
/// was 0 and happened to match one of the pad zeros by coincidence.
///
/// This test consumes a SPAWN note *first*, which emits an (empty) dummy note
/// at `note_idx == 0`. The subsequent PSWAP note therefore creates its P2ID at
/// `note_idx == 1`. If the bug is reintroduced, bob's 25 ETH will be routed to
/// the dummy at idx 0 instead of the P2ID at idx 1, and the asset assertions
/// below will fail.
#[tokio::test]
async fn pswap_note_idx_nonzero_regression_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(50))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(25))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 25)?.into()],
    )?;

    let (pswap, pswap_note) = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
    )?;

    // Dummy output note to be emitted by the SPAWN note. Sender must equal
    // the transaction's native account (bob) per `create_spawn_note`'s check.
    // No assets — keeps the spawn script trivial.
    let dummy_note = NoteBuilder::new(bob.id(), SmallRng::seed_from_u64(7777)).build()?;
    let spawn_note = builder.add_spawn_note([&dummy_note])?;

    let mock_chain = builder.build()?;

    // Full account-fill: 25 ETH out of bob's vault. Exercises the
    // `has_account_fill` branch where the `note_idx` bug lives.
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), PswapNote::create_args(25, 0)?);

    let (expected_p2id, _) =
        pswap.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 25)?), None)?;

    // Consume spawn first so the PSWAP-created P2ID gets note_idx == 1.
    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[spawn_note.id(), pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(dummy_note.clone()),
            RawOutputNote::Full(expected_p2id),
        ])
        .build()?;

    let executed = tx_context.execute().await?;

    // Exactly 2 output notes: dummy (from spawn) at idx 0, P2ID (from pswap) at idx 1.
    let output_notes = executed.output_notes();
    assert_eq!(output_notes.num_notes(), 2, "expected dummy + p2id");

    // Dummy at idx 0 must be empty. If the note_idx bug is reintroduced,
    // bob's 25 ETH would land here instead of on the P2ID.
    let dummy_out = output_notes.get_note(0);
    assert_eq!(
        dummy_out.assets().num_assets(),
        0,
        "SPAWN dummy should be empty; non-empty means `create_p2id_note` \
         wrote its asset to the wrong output note_idx",
    );

    // P2ID at idx 1 must carry the full 25 ETH.
    let p2id_out = output_notes.get_note(1);
    assert_eq!(p2id_out.assets().num_assets(), 1, "P2ID must have 1 asset");
    assert_eq!(
        p2id_out.assets().iter().next().unwrap().unwrap_fungible(),
        FungibleAsset::new(eth_faucet.id(), 25)?,
    );

    // Bob's vault: +50 USDC payout, -25 ETH fill (Bob spent his entire ETH balance, results in 0).
    let vault_patch = executed.account_patch().vault();
    assert_vault_patch(
        vault_patch,
        [
            FungibleAsset::new(usdc_faucet.id(), 50)?,
            FungibleAsset::new(eth_faucet.id(), 0)?,
        ],
    );

    Ok(())
}

#[rstest]
#[case(5)]
#[case(7)]
#[case(10)]
#[case(13)]
#[case(15)]
#[case(19)]
#[case(20)]
#[case(23)]
#[case(25)]
#[tokio::test]
async fn pswap_multiple_partial_fills_test(#[case] fill_amount: u64) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;

    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), fill_amount)?.into()],
    )?;

    let (pswap, pswap_note) = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), PswapNote::create_args(fill_amount, 0)?);

    let payout_amount = pswap.calculate_offered_for_requested(fill_amount)?;
    let (p2id_note, remainder_pswap) =
        pswap.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), fill_amount)?), None)?;

    let mut expected_notes = vec![RawOutputNote::Full(p2id_note)];
    if let Some(remainder) = remainder_pswap {
        expected_notes.push(RawOutputNote::Full(Note::from(remainder)));
    }

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_expected_output_notes(expected_notes)
        .extend_note_args(note_args_map)
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    let output_notes = executed_transaction.output_notes();
    let expected_count = if fill_amount < 25 { 2 } else { 1 };
    assert_eq!(output_notes.num_notes(), expected_count);

    // Verify Bob's vault: +payout USDC, and -fill ETH (Bob spent his entire ETH balance,
    // results in 0).
    let vault_patch = executed_transaction.account_patch().vault();
    assert_vault_patch(
        vault_patch,
        [
            FungibleAsset::new(usdc_faucet.id(), payout_amount)?,
            FungibleAsset::new(eth_faucet.id(), 0)?,
        ],
    );

    Ok(())
}

/// Runs one full partial-fill scenario for a `(offered, requested, fill)` triple.
///
/// Shared between the hand-picked `pswap_partial_fill_ratio_test` regression suite and the
/// seeded random `pswap_partial_fill_ratio_fuzz` coverage test.
async fn run_partial_fill_ratio_case(
    offered_usdc: u64,
    requested_eth: u64,
    fill_eth: u64,
) -> anyhow::Result<()> {
    let remaining_requested = requested_eth - fill_eth;

    let mut builder = MockChain::builder();
    let max_supply = 100_000u64;

    let usdc_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", max_supply, Some(offered_usdc))?;
    let eth_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", max_supply, Some(fill_eth))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), offered_usdc)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), fill_eth)?.into()],
    )?;

    let (pswap, pswap_note) = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), offered_usdc)?,
        FungibleAsset::new(eth_faucet.id(), requested_eth)?,
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), PswapNote::create_args(fill_eth, 0)?);

    let payout_amount = pswap.calculate_offered_for_requested(fill_eth)?;
    let remaining_offered = offered_usdc - payout_amount;

    assert!(payout_amount > 0, "payout_amount must be > 0");
    assert!(payout_amount <= offered_usdc, "payout_amount > offered");

    let (p2id_note, remainder_pswap) =
        pswap.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), fill_eth)?), None)?;

    let mut expected_notes = vec![RawOutputNote::Full(p2id_note)];
    if remaining_requested > 0 {
        let remainder = Note::from(remainder_pswap.expect("partial fill should produce remainder"));
        expected_notes.push(RawOutputNote::Full(remainder));
    }

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_expected_output_notes(expected_notes)
        .extend_note_args(note_args_map)
        .build()?;

    let executed_tx = tx_context.execute().await?;

    let output_notes = executed_tx.output_notes();
    let expected_count = if remaining_requested > 0 { 2 } else { 1 };
    assert_eq!(output_notes.num_notes(), expected_count);

    let vault_patch = executed_tx.account_patch().vault();
    // New ETH balance should be zero.
    assert_vault_patch(
        vault_patch,
        [
            FungibleAsset::new(usdc_faucet.id(), payout_amount)?,
            FungibleAsset::new(eth_faucet.id(), 0)?,
        ],
    );

    assert_eq!(payout_amount + remaining_offered, offered_usdc, "conservation");

    Ok(())
}

#[rstest]
// Single non-exact-ratio partial fill.
#[case(100, 30, 7)]
// Non-integer ratio regression cases.
#[case(23, 20, 7)]
#[case(23, 20, 13)]
#[case(23, 20, 19)]
#[case(17, 13, 5)]
#[case(97, 89, 37)]
#[case(53, 47, 23)]
#[case(7, 5, 3)]
#[case(7, 5, 1)]
#[case(7, 5, 4)]
#[case(89, 55, 21)]
#[case(233, 144, 55)]
#[case(34, 21, 8)]
#[case(50, 97, 30)]
#[case(13, 47, 20)]
#[case(3, 7, 5)]
#[case(101, 100, 50)]
#[case(100, 99, 50)]
#[case(997, 991, 500)]
#[case(1000, 3, 1)]
#[case(1000, 3, 2)]
#[case(3, 1000, 500)]
#[case(9999, 7777, 3333)]
#[case(5000, 3333, 1111)]
#[case(127, 63, 31)]
#[case(255, 127, 63)]
#[case(511, 255, 100)]
#[tokio::test]
async fn pswap_partial_fill_ratio_test(
    #[case] offered_usdc: u64,
    #[case] requested_eth: u64,
    #[case] fill_eth: u64,
) -> anyhow::Result<()> {
    run_partial_fill_ratio_case(offered_usdc, requested_eth, fill_eth).await
}

/// Seeded-random coverage for the `calculate_offered_for_requested` math + full execute path.
///
/// Each seed draws `FUZZ_ITERATIONS` random `(offered, requested, fill)` triples and runs them
/// through `run_partial_fill_ratio_case`. Seeds are baked into the case names so a failure like
/// `pswap_partial_fill_ratio_fuzz::seed_1337` is reproducible with one command: rerun that case,
/// the error message pinpoints the exact iteration and triple that broke.
#[rstest]
#[case::seed_42(42)]
#[case::seed_1337(1337)]
#[tokio::test]
async fn pswap_partial_fill_ratio_fuzz(#[case] seed: u64) -> anyhow::Result<()> {
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    const FUZZ_ITERATIONS: usize = 30;

    let mut rng = SmallRng::seed_from_u64(seed);
    for iter in 0..FUZZ_ITERATIONS {
        let offered_usdc = rng.random_range(2u64..10_000);
        let requested_eth = rng.random_range(2u64..10_000);
        let fill_eth = rng.random_range(1u64..=requested_eth);

        run_partial_fill_ratio_case(offered_usdc, requested_eth, fill_eth).await.map_err(|e| {
            anyhow::anyhow!(
                "seed={seed} iter={iter} (offered={offered_usdc}, requested={requested_eth}, fill={fill_eth}): {e}"
            )
        })?;
    }
    Ok(())
}

#[rstest]
#[case(100, 73, vec![17, 23, 19])]
#[case(53, 47, vec![7, 11, 13, 5])]
#[case(200, 137, vec![41, 37, 29])]
#[case(7, 5, vec![2, 1])]
#[case(1000, 777, vec![100, 200, 150, 100])]
#[case(50, 97, vec![20, 30, 15])]
#[case(89, 55, vec![13, 8, 21])]
#[case(23, 20, vec![3, 5, 4, 3])]
#[case(997, 991, vec![300, 300, 200])]
#[case(3, 2, vec![1])]
#[tokio::test]
async fn pswap_chained_partial_fills_test(
    #[case] initial_offered: u64,
    #[case] initial_requested: u64,
    #[case] fills: Vec<u64>,
) -> anyhow::Result<()> {
    let mut current_offered = initial_offered;
    let mut current_requested = initial_requested;
    let mut total_usdc_to_bob = 0u64;
    let mut total_eth_from_bob = 0u64;
    // Track serial for remainder chain
    let mut rng = RandomCoin::new(Word::default());
    let mut current_serial = rng.draw_word();

    for (fill_index, fill_amount) in fills.iter().enumerate() {
        let remaining_requested = current_requested - fill_amount;

        let mut builder = MockChain::builder();
        let max_supply = 100_000u64;

        let usdc_faucet = builder.add_existing_basic_faucet(
            BASIC_AUTH,
            "USDC",
            max_supply,
            Some(current_offered),
        )?;
        let eth_faucet =
            builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", max_supply, Some(*fill_amount))?;

        let alice = builder.add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(usdc_faucet.id(), current_offered)?.into()],
        )?;
        let bob = builder.add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(eth_faucet.id(), *fill_amount)?.into()],
        )?;

        // Use the PswapNote builder directly so we can inject `current_serial`
        // for this chain position (each remainder in the chain bumps
        // `serial[3] + 1`, and the test walks through that sequence manually).
        let offered_fungible = FungibleAsset::new(usdc_faucet.id(), current_offered)?;
        let requested_fungible = FungibleAsset::new(eth_faucet.id(), current_requested)?;

        let storage = PswapNoteStorage::builder()
            .requested_asset(requested_fungible)
            .creator_account_id(alice.id())
            .build();
        let pswap = PswapNote::builder()
            .sender(alice.id())
            .storage(storage)
            .serial_number(current_serial)
            .note_type(NoteType::Public)
            .offered_asset(offered_fungible)
            .build()?;
        let pswap_note: Note = pswap.clone().into();

        builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));
        let mock_chain = builder.build()?;

        let mut note_args_map = BTreeMap::new();
        note_args_map.insert(pswap_note.id(), PswapNote::create_args(*fill_amount, 0)?);

        let payout_amount = pswap.calculate_offered_for_requested(*fill_amount)?;
        let remaining_offered = current_offered - payout_amount;
        let (p2id_note, remainder_pswap) = pswap.execute(
            bob.id(),
            Some(FungibleAsset::new(eth_faucet.id(), *fill_amount)?),
            None,
        )?;

        let mut expected_notes = vec![RawOutputNote::Full(p2id_note)];
        if remaining_requested > 0 {
            let remainder =
                Note::from(remainder_pswap.expect("partial fill should produce remainder"));
            expected_notes.push(RawOutputNote::Full(remainder));
        }

        let tx_context = mock_chain
            .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
            .extend_expected_output_notes(expected_notes)
            .extend_note_args(note_args_map)
            .build()?;

        let executed_tx = tx_context.execute().await.map_err(|e| {
            anyhow::anyhow!(
                "fill {} failed: {} (offered={}, requested={}, fill={})",
                fill_index + 1,
                e,
                current_offered,
                current_requested,
                fill_amount
            )
        })?;

        let output_notes = executed_tx.output_notes();
        let expected_count = if remaining_requested > 0 { 2 } else { 1 };
        assert_eq!(output_notes.num_notes(), expected_count, "fill {}", fill_index + 1);

        // Bob's vault: +payout USDC, and -fill ETH (Bob spent his entire ETH balance,
        // results in 0).
        let vault_patch = executed_tx.account_patch().vault();
        assert_vault_patch(
            vault_patch,
            [
                FungibleAsset::new(usdc_faucet.id(), payout_amount)?,
                FungibleAsset::new(eth_faucet.id(), 0)?,
            ],
        );

        // Update state for next fill
        total_usdc_to_bob += payout_amount;
        total_eth_from_bob += fill_amount;
        current_offered = remaining_offered;
        current_requested = remaining_requested;
        // Remainder serial: [0] + 1 (matching MASM LE orientation)
        current_serial = Word::from([
            current_serial[0] + ONE,
            current_serial[1],
            current_serial[2],
            current_serial[3],
        ]);
    }

    // Verify conservation
    let total_fills: u64 = fills.iter().sum();
    assert_eq!(total_eth_from_bob, total_fills, "ETH conservation");
    assert_eq!(total_usdc_to_bob + current_offered, initial_offered, "USDC conservation");

    Ok(())
}

/// Test that PswapNote builder + try_from + execute roundtrips correctly
#[test]
fn compare_pswap_create_output_notes_vs_test_helper() {
    let mut builder = MockChain::builder();
    let usdc_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150)).unwrap();
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50)).unwrap();
    let alice = builder
        .add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(usdc_faucet.id(), 50).unwrap().into()],
        )
        .unwrap();
    let bob = builder
        .add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(eth_faucet.id(), 25).unwrap().into()],
        )
        .unwrap();

    // Create swap note using PswapNote builder
    let mut rng = RandomCoin::new(Word::default());
    let requested_asset = FungibleAsset::new(eth_faucet.id(), 25).unwrap();
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(alice.id())
        .payback_note_type(NoteType::Public)
        .build();
    let pswap_note: Note = PswapNote::builder()
        .sender(alice.id())
        .storage(storage)
        .serial_number(rng.draw_word())
        .note_type(NoteType::Public)
        .offered_asset(FungibleAsset::new(usdc_faucet.id(), 50).unwrap())
        .build()
        .unwrap()
        .into();

    // Roundtrip: try_from -> execute -> verify outputs
    let pswap = PswapNote::try_from(&pswap_note).unwrap();

    // Verify roundtripped PswapNote preserves key fields
    assert_eq!(pswap.sender(), alice.id(), "Sender mismatch after roundtrip");
    assert_eq!(pswap.note_type(), NoteType::Public, "Note type mismatch after roundtrip");
    assert_eq!(pswap.storage().requested_asset_amount(), 25, "Requested amount mismatch");
    assert_eq!(pswap.storage().creator_account_id(), alice.id(), "Creator ID mismatch");

    // Full fill: should produce P2ID note, no remainder
    let (p2id_note, remainder) = pswap
        .execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 25).unwrap()), None)
        .unwrap();
    assert!(remainder.is_none(), "Full fill should not produce remainder");

    // Verify P2ID note properties
    assert_eq!(p2id_note.metadata().sender(), bob.id(), "P2ID sender should be consumer");
    assert_eq!(p2id_note.metadata().note_type(), NoteType::Public, "P2ID note type mismatch");
    assert_eq!(p2id_note.assets().num_assets(), 1, "P2ID should have 1 asset");
    assert_eq!(
        p2id_note.assets().iter().next().unwrap().unwrap_fungible(),
        FungibleAsset::new(eth_faucet.id(), 25).unwrap(),
    );

    // Partial fill: should produce P2ID note + remainder
    let (p2id_partial, remainder_partial) = pswap
        .execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 10).unwrap()), None)
        .unwrap();
    let remainder_pswap = remainder_partial.expect("Partial fill should produce remainder");

    assert_eq!(p2id_partial.assets().num_assets(), 1);
    assert_eq!(
        p2id_partial.assets().iter().next().unwrap().unwrap_fungible(),
        FungibleAsset::new(eth_faucet.id(), 10).unwrap(),
    );

    // Verify remainder properties
    assert_eq!(
        remainder_pswap.storage().creator_account_id(),
        alice.id(),
        "Remainder creator should be Alice"
    );
    let remaining_requested = remainder_pswap.storage().requested_asset_amount();
    assert_eq!(remaining_requested, 15, "Remaining requested should be 15");
}

/// Test that PswapNote::parse_inputs roundtrips correctly
/// The original PSWAP note must NOT carry the PswapAttachment scheme. Only remainder
/// PSWAPs and payback P2IDs (which are emitted by the on-chain script) carry that
/// scheme. If an original were to carry PswapAttachment, the on-chain `get_current_depth`
/// would (incorrectly) read a non-zero parent_depth from it and corrupt the lineage's
/// depth chain.
#[test]
fn pswap_original_has_no_pswap_scheme() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(50))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;
    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;

    let (pswap, _) = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
    )?;

    if let Some(att) = pswap.attachments() {
        assert_ne!(
            att.attachment_scheme(),
            PswapNote::PSWAP_ATTACHMENT_SCHEME,
            "original PSWAP must not carry PswapAttachment — that scheme is reserved for outputs",
        );
    }

    assert_eq!(pswap.parent_depth(), 0, "parent_depth must be 0 for an original PSWAP");

    Ok(())
}

/// Regression test for the load-bearing line that sets the `attachment` field on a
/// Rust-built remainder PswapNote. If this is forgotten, the remainder defaults to
/// `attachment = None`, the on-chain `get_current_depth` reads parent_depth = 0 on the
/// *next* round, and the lineage's depth chain silently resets to 1 each round.
#[test]
fn pswap_remainder_carries_pswap_scheme() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();
    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(50))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;
    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 10)?.into()],
    )?;

    let (pswap, _) = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
    )?;

    let account_fill = FungibleAsset::new(eth_faucet.id(), 10)?;
    let (_, remainder_pswap) = pswap.execute(bob.id(), Some(account_fill), None)?;
    let remainder_pswap = remainder_pswap.expect("partial fill should produce a remainder");

    let att = remainder_pswap.attachments().expect("remainder must carry an attachment");
    assert_eq!(
        att.attachment_scheme(),
        PswapNote::PSWAP_ATTACHMENT_SCHEME,
        "remainder PSWAP must carry PswapAttachment so on-chain depth derivation works",
    );

    assert_eq!(
        remainder_pswap.parent_depth(),
        1,
        "remainder built from an original PSWAP must carry depth = 1",
    );

    Ok(())
}

/// Headline discovery test: Alice creates a PSWAP, Bob consumes it across three partial
/// fills (a 3-round lineage), and at every round Alice reconstructs the payback's
/// `NoteRecipient` from the on-chain attachment word and *consumes the reconstructed note*
/// against the chain — proving end-to-end that the body Alice rebuilds from
/// `(order_id, depth, fill_amount)` matches the commitment Bob's tx recorded.
///
/// Each round's remainder recipient is also derived and cross-checked against the on-chain
/// digest, since remainder threading carries the parent `PswapAttachment` forward (the
/// on-chain `get_current_depth` reads it to stamp the next round's depth).
#[tokio::test]
async fn pswap_creator_reconstructs_lineage_from_attachments() -> anyhow::Result<()> {
    // Three partial fills: 5, 8, 7 (sum = 20 of requested 25, so a 5-unit remainder survives).
    let fills = [5u64, 8u64, 7u64];
    let initial_offered = 50u64;
    let initial_requested = 25u64;
    let total_fill: u64 = fills.iter().sum();

    let mut builder = MockChain::builder();
    let max_supply = 100_000u64;
    let usdc_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", max_supply, Some(initial_offered))?;
    let eth_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", max_supply, Some(total_fill))?;
    let alice = builder.add_existing_wallet_with_assets(BASIC_AUTH, [])?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), total_fill)?.into()],
    )?;

    let original_pswap = PswapNote::builder()
        .sender(alice.id())
        .storage(
            PswapNoteStorage::builder()
                .requested_asset(FungibleAsset::new(eth_faucet.id(), initial_requested)?)
                .creator_account_id(alice.id())
                .build(),
        )
        .serial_number(RandomCoin::new(Word::default()).draw_word())
        .note_type(NoteType::Public)
        .offered_asset(FungibleAsset::new(usdc_faucet.id(), initial_offered)?)
        .build()?;
    let original_pswap_note: Note = original_pswap.clone().into();
    builder.add_output_note(RawOutputNote::Full(original_pswap_note.clone()));

    let mut mock_chain = builder.build()?;

    // Threaded across rounds: round 1 consumes the original PSWAP, rounds 2+ consume the
    // previous round's remainder (which carries the right `PswapAttachment` so the on-chain
    // depth derivation stamps the next round correctly).
    let mut current_pswap = original_pswap.clone();
    let mut current_pswap_note = original_pswap_note;
    let mut current_offered = initial_offered;
    let mut current_requested = initial_requested;
    // Alice starts with an empty wallet and accumulates `fill_amount` ETH each round, so the
    // patch's absolute balance is the running total of all fills consumed so far.
    let mut alice_eth_balance = 0;

    for (idx, fill_amount) in fills.iter().copied().enumerate() {
        let depth = (idx + 1) as u32;

        // --- Bob fills the current PSWAP ---
        let payout_amount = current_pswap.calculate_offered_for_requested(fill_amount)?;
        let remaining_offered = current_offered - payout_amount;
        let remaining_requested = current_requested - fill_amount;

        let (predicted_payback_note, predicted_remainder_pswap) = current_pswap.execute(
            bob.id(),
            Some(FungibleAsset::new(eth_faucet.id(), fill_amount)?),
            None,
        )?;

        let mut expected_notes = vec![RawOutputNote::Full(predicted_payback_note.clone())];
        let next_pswap_opt = if remaining_requested > 0 {
            let predicted_remainder =
                predicted_remainder_pswap.expect("partial fill should produce remainder");
            expected_notes.push(RawOutputNote::Full(Note::from(predicted_remainder.clone())));
            Some(predicted_remainder)
        } else {
            None
        };

        let mut note_args_map = BTreeMap::new();
        note_args_map.insert(current_pswap_note.id(), PswapNote::create_args(fill_amount, 0)?);

        let bob_tx = mock_chain
            .build_tx_context(bob.id(), &[current_pswap_note.id()], &[])?
            .extend_expected_output_notes(expected_notes)
            .extend_note_args(note_args_map)
            .build()?
            .execute()
            .await?;
        mock_chain.add_pending_executed_transaction(&bob_tx)?;
        mock_chain.prove_next_block()?;

        let on_chain_payback = bob_tx.output_notes().get_note(0);

        // --- Alice reconstructs the payback from the on-chain attachment word ---
        let attachment_word = first_attachment_word(on_chain_payback.attachments());
        let fill_from_attachment = attachment_word[0].as_canonical_u64();
        assert_eq!(
            fill_from_attachment, fill_amount,
            "round {depth}: attachment fill amount mismatch",
        );

        let payback_attachment = PswapNoteAttachment::new(
            AssetAmount::new(fill_from_attachment)?,
            original_pswap.order_id(),
            depth,
        );
        let reconstructed_payback = original_pswap
            .payback_note(on_chain_payback.metadata().sender(), &payback_attachment)?;
        assert_eq!(
            reconstructed_payback.details_commitment(),
            on_chain_payback.details_commitment(),
            "round {depth}: reconstructed payback commitment must match on-chain leaf",
        );

        // --- Alice reconstructs the remainder (when partial) from on-chain data alone ---
        if next_pswap_opt.is_some() {
            let on_chain_remainder = bob_tx.output_notes().get_note(1);
            let remainder_attachment_word = first_attachment_word(on_chain_remainder.attachments());
            let payout_from_attachment = remainder_attachment_word[0].as_canonical_u64();

            let remainder_attachment = PswapNoteAttachment::new(
                AssetAmount::new(payout_from_attachment)?,
                original_pswap.order_id(),
                depth,
            );
            let reconstructed_remainder = original_pswap.remainder_note(
                on_chain_remainder.metadata().sender(),
                &remainder_attachment,
                AssetAmount::new(remaining_offered)?,
                AssetAmount::new(remaining_requested)?,
            )?;
            assert_eq!(
                reconstructed_remainder.details_commitment(),
                on_chain_remainder.details_commitment(),
                "round {depth}: reconstructed remainder commitment must match on-chain leaf",
            );
        }

        // --- Alice consumes the reconstructed payback (unauthenticated path) ---
        let alice_tx = mock_chain
            .build_tx_context(alice.id(), &[], slice::from_ref(&reconstructed_payback))?
            .build()?
            .execute()
            .await?;
        alice_eth_balance += fill_amount;
        assert_vault_patch(
            alice_tx.account_patch().vault(),
            [FungibleAsset::new(eth_faucet.id(), alice_eth_balance)?],
        );
        mock_chain.add_pending_executed_transaction(&alice_tx)?;
        mock_chain.prove_next_block()?;

        // Advance state for the next round.
        if let Some(next) = next_pswap_opt {
            current_pswap_note = Note::from(next.clone());
            current_pswap = next;
            current_offered = remaining_offered;
            current_requested = remaining_requested;
        }
    }

    Ok(())
}

/// When multiple PSWAP notes from the same creator are consumed in the same transaction,
/// the on-chain payback tag is identical (it derives from the creator's account ID), so
/// tag alone cannot distinguish which payback came from which PSWAP. This test exercises
/// the `order_id` disambiguation: different PSWAPs have different `serial[1]`s, and the
/// MASM stamps each round's output notes with the parent's `serial[1]`, letting the
/// creator sort outputs back to their originating lineage purely by `order_id`.
#[tokio::test]
async fn pswap_disambiguates_multiple_creator_pswaps_in_same_tx() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1_000, Some(100))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1_000, Some(50))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 100)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 30)?.into()],
    )?;

    // Two PSWAPs from Alice, both USDC → ETH, but distinct serials → distinct order_ids.
    let pswap_a = {
        let mut rng = RandomCoin::new(Word::default());
        let serial = rng.draw_word();
        let storage = PswapNoteStorage::builder()
            .requested_asset(FungibleAsset::new(eth_faucet.id(), 20)?)
            .creator_account_id(alice.id())
            .build();

        PswapNote::builder()
            .sender(alice.id())
            .storage(storage)
            .serial_number(serial)
            .note_type(NoteType::Public)
            .offered_asset(FungibleAsset::new(usdc_faucet.id(), 40)?)
            .build()?
    };
    let pswap_b = {
        // Distinct seed → distinct serial → distinct order_id.
        let mut rng = RandomCoin::new(Word::from([Felt::from(7u32); 4]));
        let serial = rng.draw_word();
        let storage = PswapNoteStorage::builder()
            .requested_asset(FungibleAsset::new(eth_faucet.id(), 30)?)
            .creator_account_id(alice.id())
            .build();

        PswapNote::builder()
            .sender(alice.id())
            .storage(storage)
            .serial_number(serial)
            .note_type(NoteType::Public)
            .offered_asset(FungibleAsset::new(usdc_faucet.id(), 60)?)
            .build()?
    };

    assert_ne!(pswap_a.order_id(), pswap_b.order_id(), "test setup: order_ids must differ");

    let note_a: Note = pswap_a.clone().into();
    let note_b: Note = pswap_b.clone().into();
    builder.add_output_note(RawOutputNote::Full(note_a.clone()));
    builder.add_output_note(RawOutputNote::Full(note_b.clone()));
    let mock_chain = builder.build()?;

    // Bob partially fills BOTH PSWAPs in the same tx — 10 ETH from each.
    let fill_each = 10u64;
    let mut note_args = BTreeMap::new();
    note_args.insert(note_a.id(), PswapNote::create_args(fill_each, 0)?);
    note_args.insert(note_b.id(), PswapNote::create_args(fill_each, 0)?);

    let (payback_a, remainder_a) =
        pswap_a.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), fill_each)?), None)?;
    let (payback_b, remainder_b) =
        pswap_b.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), fill_each)?), None)?;
    let remainder_a_note = Note::from(remainder_a.expect("partial fill A produces remainder"));
    let remainder_b_note = Note::from(remainder_b.expect("partial fill B produces remainder"));

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[note_a.id(), note_b.id()], &[])?
        .extend_note_args(note_args)
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(payback_a.clone()),
            RawOutputNote::Full(remainder_a_note.clone()),
            RawOutputNote::Full(payback_b.clone()),
            RawOutputNote::Full(remainder_b_note.clone()),
        ])
        .build()?;
    let executed_tx = tx_context.execute().await?;

    let outputs = executed_tx.output_notes();
    assert_eq!(outputs.num_notes(), 4, "expected 2 paybacks + 2 remainders in same tx");

    // Alice's discovery: she scans the tx's 4 output notes and sorts by order_id
    // (`Word[1]` of each attachment), without inspecting tags or recipient digests.
    let order_id_a = pswap_a.order_id();
    let order_id_b = pswap_b.order_id();

    // Each lineage should yield 2 notes (payback + remainder) → preallocate.
    let mut from_a: Vec<Word> = Vec::with_capacity(2);
    let mut from_b: Vec<Word> = Vec::with_capacity(2);
    // PswapAttachment word layout is [amount, order_id, depth, 0]; order_id sits at index 1.
    const ORDER_ID_INDEX_IN_PSWAP_ATTACHMENT: usize = 1;
    for i in 0..outputs.num_notes() {
        let att_word = first_attachment_word(outputs.get_note(i).attachments());
        let oid = att_word[ORDER_ID_INDEX_IN_PSWAP_ATTACHMENT];
        let digest = outputs.get_note(i).recipient_digest();
        if oid == order_id_a {
            from_a.push(digest);
        } else if oid == order_id_b {
            from_b.push(digest);
        } else {
            panic!("output note's order_id matches neither lineage");
        }
    }
    assert_eq!(from_a.len(), 2, "lineage A should yield 2 notes (payback + remainder)");
    assert_eq!(from_b.len(), 2, "lineage B should yield 2 notes (payback + remainder)");

    // Sanity: the digests Alice sorted into each lineage match the Rust-predicted ones.
    assert!(
        from_a.contains(&payback_a.recipient().digest())
            && from_a.contains(&remainder_a_note.recipient().digest()),
        "lineage A's notes must include both Rust-predicted output digests",
    );
    assert!(
        from_b.contains(&payback_b.recipient().digest())
            && from_b.contains(&remainder_b_note.recipient().digest()),
        "lineage B's notes must include both Rust-predicted output digests",
    );

    Ok(())
}

#[test]
fn pswap_parse_inputs_roundtrip() {
    let mut builder = MockChain::builder();
    let usdc_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150)).unwrap();
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50)).unwrap();
    let alice = builder
        .add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(usdc_faucet.id(), 50).unwrap().into()],
        )
        .unwrap();

    let (_, pswap_note) = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50).unwrap(),
        FungibleAsset::new(eth_faucet.id(), 25).unwrap(),
        NoteType::Public,
    )
    .unwrap();

    let storage = pswap_note.recipient().storage();
    let items = storage.items();

    let parsed = PswapNoteStorage::try_from(items).unwrap();

    assert_eq!(parsed.creator_account_id(), alice.id(), "Creator ID roundtrip failed!");

    // Verify requested amount from value word
    assert_eq!(parsed.requested_asset_amount(), 25, "Requested amount should be 25");
}
