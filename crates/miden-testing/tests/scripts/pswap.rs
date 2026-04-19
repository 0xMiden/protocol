use std::collections::BTreeMap;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountId, AccountStorageMode, AccountVaultDelta};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteAttachment, NoteAttachmentScheme, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, ONE, Word, ZERO};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::errors::standards::{
    ERR_PSWAP_FILL_EXCEEDS_REQUESTED,
    ERR_PSWAP_FILL_SUM_OVERFLOW,
    ERR_PSWAP_NOT_VALID_ASSET_AMOUNT,
};
use miden_standards::note::{PswapNote, PswapNoteStorage};
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
fn assert_fungible_asset_eq(asset: &Asset, expected: FungibleAsset) {
    match asset {
        Asset::Fungible(f) => {
            assert_eq!(f.faucet_id(), expected.faucet_id(), "faucet id mismatch");
            assert_eq!(
                f.amount(),
                expected.amount(),
                "amount mismatch (expected {}, got {})",
                expected.amount(),
                f.amount()
            );
        },
        _ => panic!("expected fungible asset, got non-fungible"),
    }
}

#[track_caller]
fn assert_vault_added_removed(
    vault_delta: &AccountVaultDelta,
    expected_added: FungibleAsset,
    expected_removed: FungibleAsset,
) {
    let added: Vec<Asset> = vault_delta.added_assets().collect();
    let removed: Vec<Asset> = vault_delta.removed_assets().collect();
    assert_eq!(added.len(), 1, "expected exactly 1 added asset");
    assert_eq!(removed.len(), 1, "expected exactly 1 removed asset");
    assert_fungible_asset_eq(&added[0], expected_added);
    assert_fungible_asset_eq(&removed[0], expected_removed);
}

#[track_caller]
fn assert_vault_single_added(vault_delta: &AccountVaultDelta, expected: FungibleAsset) {
    let added: Vec<Asset> = vault_delta.added_assets().collect();
    assert_eq!(added.len(), 1, "expected exactly 1 added asset");
    assert_fungible_asset_eq(&added[0], expected);
}

// TESTS
// ================================================================================================

/// Verifies that Alice can independently reconstruct and consume the P2ID payback note
/// using only her original PSWAP note data and the aux data from Bob's transaction output.
///
/// Flow:
/// 1. Alice creates a PSWAP note (50 USDC for 25 ETH)
/// 2. Bob partially fills it (20 ETH) → produces P2ID payback + remainder
/// 3. Alice reconstructs the P2ID note from her PSWAP data + fill amount from aux
/// 4. Alice consumes the reconstructed P2ID note and receives 20 ETH
#[tokio::test]
async fn pswap_note_alice_reconstructs_and_consumes_p2id() -> anyhow::Result<()> {
    use miden_standards::note::P2idNoteStorage;

    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 20)?.into()],
    )?;

    let offered_asset = FungibleAsset::new(usdc_faucet.id(), 50)?;
    let requested_asset = FungibleAsset::new(eth_faucet.id(), 25)?;

    let mut rng = RandomCoin::new(Word::default());
    let serial_number = rng.draw_word();
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(alice.id())
        .payback_note_type(NoteType::Public)
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

    // --- Step 1: Bob partially fills the PSWAP note (20 out of 25 ETH) ---

    let fill_amount = 20u64;
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), PswapNote::create_args(fill_amount, 0)?);

    let (p2id_note, remainder_pswap) =
        pswap.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 20)?), None)?;
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
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // --- Step 2: Alice reconstructs the P2ID note from her PSWAP data + aux ---

    // Read the attachment from the executed transaction's output (not from the
    // Rust-predicted `p2id_note`) so this actually validates the MASM side.
    let output_p2id = executed_transaction.output_notes().get_note(0);
    let aux_word = output_p2id.metadata().attachment().content().to_word();
    let fill_amount_from_aux = aux_word[0].as_canonical_u64();
    assert_eq!(fill_amount_from_aux, 20, "Fill amount from aux should be 20 ETH");

    // Parity check: Rust-predicted P2ID attachment must match the MASM output.
    assert_eq!(
        p2id_note.metadata().attachment().content().to_word(),
        aux_word,
        "Rust-predicted P2ID attachment does not match the MASM-produced one",
    );

    // Alice reconstructs the recipient using her serial number and account ID
    let p2id_serial =
        Word::from([serial_number[0] + ONE, serial_number[1], serial_number[2], serial_number[3]]);
    let reconstructed_recipient = P2idNoteStorage::new(alice.id()).into_recipient(p2id_serial);

    // Verify the reconstructed recipient matches the actual output
    assert_eq!(
        reconstructed_recipient.digest(),
        output_p2id.recipient_digest(),
        "Alice's reconstructed P2ID recipient does not match the actual output"
    );

    // --- Step 2b: Alice reconstructs the remainder PSWAP note ---
    //
    // Alice only needs: her original PSWAP data + both on-chain attachments
    // (fill_amount from the P2ID, amt_payout from the remainder). From those
    // she derives the remaining offered/requested amounts and rebuilds the
    // remainder PswapNote.

    let output_remainder = executed_transaction.output_notes().get_note(1);
    let remainder_aux = output_remainder.metadata().attachment().content().to_word();
    let amt_payout_from_aux = remainder_aux[0].as_canonical_u64();

    let expected_payout = pswap.calculate_offered_for_requested(fill_amount_from_aux)?;
    assert_eq!(
        amt_payout_from_aux, expected_payout,
        "remainder aux should carry amt_payout matching the Rust-side calc",
    );

    let remaining_offered = offered_asset.amount() - amt_payout_from_aux;
    let remaining_requested = requested_asset.amount() - fill_amount_from_aux;

    let remainder_storage = PswapNoteStorage::builder()
        .requested_asset(FungibleAsset::new(eth_faucet.id(), remaining_requested)?)
        .creator_account_id(alice.id())
        .payback_note_type(NoteType::Public)
        .build();

    // MASM increments serial_number[3], so the remainder serial is s[3] + 1.
    let remainder_serial =
        Word::from([serial_number[0], serial_number[1], serial_number[2], serial_number[3] + ONE]);

    let remainder_attachment_word = Word::from([
        Felt::try_from(amt_payout_from_aux).expect("amt_payout fits in a felt"),
        ZERO,
        ZERO,
        ZERO,
    ]);
    let remainder_attachment =
        NoteAttachment::new_word(NoteAttachmentScheme::none(), remainder_attachment_word);

    let reconstructed_remainder: Note = PswapNote::builder()
        .sender(bob.id())
        .storage(remainder_storage)
        .serial_number(remainder_serial)
        .note_type(NoteType::Public)
        .offered_asset(FungibleAsset::new(usdc_faucet.id(), remaining_offered)?)
        .attachment(remainder_attachment)
        .build()?
        .into();

    // Sanity check: the Rust-predicted remainder (computed by pswap.execute
    // above) must match the executed output. If this fires, the Rust/MASM
    // parity itself is broken, independently of our reconstruction.
    assert_eq!(
        remainder_note.recipient().digest(),
        output_remainder.recipient_digest(),
        "Rust-predicted remainder recipient does not match executed output",
    );

    // Recipient digest covers the note's storage (creator, requested asset,
    // payback tag/type) + serial + script root.
    assert_eq!(
        reconstructed_remainder.recipient().digest(),
        output_remainder.recipient_digest(),
        "reconstructed remainder recipient does not match executed output",
    );

    // Parity on the attachment word itself.
    assert_eq!(
        reconstructed_remainder.metadata().attachment().content().to_word(),
        remainder_aux,
        "reconstructed remainder attachment does not match executed output",
    );

    // --- Step 3: Alice consumes the P2ID payback note ---

    let tx_context = mock_chain.build_tx_context(alice.id(), &[p2id_note.id()], &[])?.build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify Alice received 20 ETH
    let vault_delta = executed_transaction.account_delta().vault();
    assert_vault_single_added(vault_delta, FungibleAsset::new(eth_faucet.id(), 20)?);

    Ok(())
}

/// Dedicated regression test for the attachment word layout shared between
/// `create_p2id_note` / `create_remainder_note` in pswap.masm and
/// `create_payback_note` / `create_remainder_pswap_note` in pswap.rs.
///
/// Both sides agree on:
/// - P2ID payback attachment:   `[fill_amount, 0, 0, 0]`
/// - Remainder PSWAP attachment: `[amt_payout, 0, 0, 0]`
///
/// i.e. the load-bearing felt sits at `Word[0]` and the remaining three felts
/// are zero padding. If either side drifts (e.g. MASM switches to
/// `[0, 0, 0, x]` or Rust does), this test fires.
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

    let p2id_attachment = output_notes.get_note(0).metadata().attachment().content().to_word();
    let remainder_attachment = output_notes.get_note(1).metadata().attachment().content().to_word();

    // P2ID payback attachment: `[fill_amount, 0, 0, 0]` — fill_amount at Word[0].
    let expected_p2id_attachment = Word::from([
        Felt::try_from(fill_amount).expect("fill_amount fits in a felt"),
        ZERO,
        ZERO,
        ZERO,
    ]);
    assert_eq!(
        p2id_attachment, expected_p2id_attachment,
        "P2ID attachment layout mismatch: expected [fill_amount, 0, 0, 0] at Word[0..3]",
    );

    // Remainder PSWAP attachment: `[amt_payout, 0, 0, 0]` — amt_payout at Word[0].
    let expected_remainder_attachment = Word::from([
        Felt::try_from(expected_payout).expect("amt_payout fits in a felt"),
        ZERO,
        ZERO,
        ZERO,
    ]);
    assert_eq!(
        remainder_attachment, expected_remainder_attachment,
        "remainder attachment layout mismatch: expected [amt_payout, 0, 0, 0] at Word[0..3]",
    );

    // Cross-check: the Rust-predicted notes must produce the same attachment
    // words as the on-chain executed ones. A future drift between either side
    // would fail here even if the Word[0] position stays correct.
    assert_eq!(
        p2id_note.metadata().attachment().content().to_word(),
        p2id_attachment,
        "Rust-predicted P2ID attachment does not match MASM output",
    );
    assert_eq!(
        remainder_note.metadata().attachment().content().to_word(),
        remainder_attachment,
        "Rust-predicted remainder attachment does not match MASM output",
    );

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
                .storage_mode(AccountStorageMode::Network)
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
    assert_fungible_asset_eq(
        p2id_assets.iter().next().unwrap(),
        FungibleAsset::new(eth_faucet.id(), fill_amount)?,
    );

    // On partial fill, assert remainder note has offered - payout USDC
    if is_partial {
        let remainder_assets = output_notes.get_note(1).assets();
        assert_fungible_asset_eq(
            remainder_assets.iter().next().unwrap(),
            FungibleAsset::new(usdc_faucet.id(), offered_total - payout_amount)?,
        );
    }

    // Consumer's vault delta: +payout USDC, -fill ETH
    let vault_delta = executed_transaction.account_delta().vault();
    assert_vault_added_removed(
        vault_delta,
        FungibleAsset::new(usdc_faucet.id(), payout_amount)?,
        FungibleAsset::new(eth_faucet.id(), fill_amount)?,
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
    let vault_delta = executed_transaction.account_delta().vault();
    assert_eq!(vault_delta.added_assets().count(), 0);
    assert_eq!(vault_delta.removed_assets().count(), 0);

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

    // Charlie's vault: -20 ETH (account_fill) + 40 USDC (account_fill_payout).
    // The note_fill legs flow entirely through inflight and never touch his vault.
    let vault_delta = executed_transaction.account_delta().vault();
    assert_vault_added_removed(vault_delta, charlie_payout_usdc, charlie_vault_eth);

    Ok(())
}

#[tokio::test]
async fn pswap_note_creator_reclaim_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(50))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(25))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;

    let (_, pswap_note) = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
    )?;

    let mock_chain = builder.build()?;

    let tx_context = mock_chain.build_tx_context(alice.id(), &[pswap_note.id()], &[])?.build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify: 0 output notes, Alice gets 50 USDC back
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 0, "Expected 0 output notes for reclaim");

    let vault_delta = executed_transaction.account_delta().vault();
    assert_vault_single_added(vault_delta, FungibleAsset::new(usdc_faucet.id(), 50)?);

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
    FungibleAsset::MAX_AMOUNT,
    FungibleAsset::MAX_AMOUNT,
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
    assert_fungible_asset_eq(
        p2id_out.assets().iter().next().unwrap(),
        FungibleAsset::new(eth_faucet.id(), 25)?,
    );

    // Bob's vault: +50 USDC payout, -25 ETH fill.
    let vault_delta = executed.account_delta().vault();
    assert_vault_added_removed(
        vault_delta,
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
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

    // Verify Bob's vault
    let vault_delta = executed_transaction.account_delta().vault();
    assert_vault_single_added(vault_delta, FungibleAsset::new(usdc_faucet.id(), payout_amount)?);

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

    let vault_delta = executed_tx.account_delta().vault();
    assert_vault_added_removed(
        vault_delta,
        FungibleAsset::new(usdc_faucet.id(), payout_amount)?,
        FungibleAsset::new(eth_faucet.id(), fill_eth)?,
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

        let vault_delta = executed_tx.account_delta().vault();
        assert_vault_single_added(
            vault_delta,
            FungibleAsset::new(usdc_faucet.id(), payout_amount)?,
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
    assert_fungible_asset_eq(
        p2id_note.assets().iter().next().unwrap(),
        FungibleAsset::new(eth_faucet.id(), 25).unwrap(),
    );

    // Partial fill: should produce P2ID note + remainder
    let (p2id_partial, remainder_partial) = pswap
        .execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 10).unwrap()), None)
        .unwrap();
    let remainder_pswap = remainder_partial.expect("Partial fill should produce remainder");

    assert_eq!(p2id_partial.assets().num_assets(), 1);
    assert_fungible_asset_eq(
        p2id_partial.assets().iter().next().unwrap(),
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
