use std::collections::BTreeMap;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    Account,
    AccountComponent,
    AccountId,
    AccountType,
    AccountVaultPatch,
};
use miden_protocol::asset::{Asset, AssetAmount, AssetId, FungibleAsset};
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::errors::MasmError;
use miden_protocol::note::{Note, NoteAttachments, NoteType};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::{RawOutputNote, RawOutputNotes};
use miden_protocol::{Felt, ONE, Word, ZERO};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::errors::standards::{
    ERR_PSWAP_FILL_BELOW_MINIMUM,
    ERR_PSWAP_FILL_SUM_OVERFLOW,
    ERR_PSWAP_NOT_VALID_ASSET_AMOUNT,
    ERR_PSWAP_OFFERED_ASSET_ALTERED,
};
use miden_standards::note::{PswapNote, PswapNoteAttachment, PswapNoteStorage};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::{
    AccountState,
    Auth,
    MockChain,
    MockChainBuilder,
    assert_transaction_executor_error,
};
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
    min_requested_asset: FungibleAsset,
    note_type: NoteType,
) -> anyhow::Result<(PswapNote, Note)> {
    let serial_number = builder.rng_mut().draw_word();
    let storage = PswapNoteStorage::builder()
        .min_requested_asset(min_requested_asset)
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
    let removed: Vec<AssetId> = vault_patch.removed_asset_ids().copied().collect();
    let expected_assets = expected_assets.into_iter().collect::<Vec<_>>();
    assert_eq!(vault_patch.num_assets(), expected_assets.len());

    for expected in expected_assets {
        if expected.amount().as_u64() == 0 {
            assert!(removed.contains(&expected.id()));
        } else {
            let actual = updated
                .iter()
                .find(|asset| asset.id() == expected.id())
                .expect("updated asset should be present");
            assert_eq!(actual, &Asset::from(expected));
        }
    }
}

/// Asserts that `expected` is among the transaction's output notes.
///
/// The note ID commits to the recipient, the assets and the metadata, so an asset that was
/// deposited into a different output note leaves the expected note's ID absent.
#[track_caller]
fn assert_output_note(output_notes: &RawOutputNotes, expected: &Note) {
    assert!(
        output_notes.iter().any(|note| note.id() == expected.id()),
        "expected output note {} not found; output notes are {:?}",
        expected.id(),
        output_notes
            .iter()
            .map(|note| (note.id(), note.assets().iter_fungible().collect::<Vec<_>>()))
            .collect::<Vec<_>>(),
    );
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
#[case::over_fill_public(NoteType::Public, 30)]
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
    let min_requested_asset = FungibleAsset::new(eth_faucet.id(), 25)?;
    let is_partial = fill_amount < u64::from(min_requested_asset.amount());

    let mut rng = RandomCoin::new(Word::default());
    let serial_number = rng.draw_word();
    let storage = PswapNoteStorage::builder()
        .min_requested_asset(min_requested_asset)
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

    let mock_tx = mock_chain
        .build_transaction(bob.id())
        .authenticated_input_note(pswap_note.id())
        .extend_note_args(note_args_map)
        .expected_output_notes(expected_output_notes)
        .build()?;

    let executed_transaction = mock_tx.execute().await?;

    // The consumer (Bob) provides all his ETH and receives his offered-asset share; for an
    // over-fill (fill >= requested) this is the whole offered side. Covers
    // calculate_offered_for_requested.
    let bob_payout = pswap.calculate_offered_for_requested(fill_amount)?;
    assert_vault_patch(
        executed_transaction.account_patch().vault(),
        [
            FungibleAsset::new(usdc_faucet.id(), bob_payout)?,
            FungibleAsset::new(eth_faucet.id(), 0)?,
        ],
    );

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
            (min_requested_asset.amount() - AssetAmount::new(fill_amount_from_aux)?)?;
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

    let mock_tx = mock_chain
        .build_transaction(alice.id())
        .unauthenticated_input_note(reconstructed_payback)
        .build()?;

    let executed_transaction = mock_tx.execute().await?;

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

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = builder.add_existing_wallet_with_assets(BASIC_AUTH, [eth_20.into()])?;

    let (pswap, pswap_note) =
        build_pswap_note(&mut builder, alice, usdc_50, eth_25, NoteType::Public)?;

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

    let mock_tx = mock_chain
        .build_transaction(bob.id())
        .authenticated_input_note(pswap_note.id())
        .extend_note_args(note_args_map)
        .expected_output_notes(vec![
            RawOutputNote::Full(p2id_note.clone()),
            RawOutputNote::Full(remainder_note.clone()),
        ])
        .build()?;

    let executed_transaction = mock_tx.execute().await?;
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

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);

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
    let min_requested_asset = FungibleAsset::new(eth_faucet.id(), requested_total)?;

    let (pswap, pswap_note) =
        build_pswap_note(&mut builder, alice, offered_asset, min_requested_asset, note_type)?;

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
        .build_transaction(consumer_id)
        .authenticated_input_note(pswap_note.id())
        .expected_output_notes(expected_notes);

    if !use_network_account {
        let mut note_args_map = BTreeMap::new();
        note_args_map.insert(pswap_note.id(), PswapNote::create_args(fill_amount, 0)?);
        tx_builder = tx_builder.extend_note_args(note_args_map);
    }

    let mock_tx = tx_builder.build()?;
    let executed_transaction = mock_tx.execute().await?;

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

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = AccountIdBuilder::new().build_with_seed([2; 32]);
    let charlie = builder.add_existing_wallet_with_assets(BASIC_AUTH, [])?;

    // Alice's note: offers 50 USDC, requests 25 ETH
    let (alice_pswap, alice_pswap_note) =
        build_pswap_note(&mut builder, alice, usdc_50, eth_25, NoteType::Public)?;

    // Bob's note: offers 25 ETH, requests 50 USDC
    let (bob_pswap, bob_pswap_note) =
        build_pswap_note(&mut builder, bob, eth_25, usdc_50, NoteType::Public)?;

    let mock_chain = builder.build()?;

    // Note args: pure note fill (account_fill = 0, note_fill = full amount)
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(alice_pswap_note.id(), PswapNote::create_args(0, 25)?);
    note_args_map.insert(bob_pswap_note.id(), PswapNote::create_args(0, 50)?);

    // Expected P2ID notes
    let (alice_p2id_note, _) = alice_pswap.execute(charlie.id(), None, Some(eth_25))?;
    let (bob_p2id_note, _) = bob_pswap.execute(charlie.id(), None, Some(usdc_50))?;

    let mock_tx = mock_chain
        .build_transaction(charlie.id())
        .authenticated_input_notes([alice_pswap_note.id(), bob_pswap_note.id()])
        .extend_note_args(note_args_map)
        .expected_output_notes(vec![
            RawOutputNote::Full(alice_p2id_note.clone()),
            RawOutputNote::Full(bob_p2id_note.clone()),
        ])
        .build()?;

    let executed_transaction = mock_tx.execute().await?;

    // Verify: 2 P2ID notes, Alice's carrying exactly her requested 25 ETH and Bob's carrying
    // exactly his requested 50 USDC. Both legs are filled through note_fill, so this pins each
    // leg's deposit to its own payback note.
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 2);

    assert_output_note(output_notes, &alice_p2id_note);
    assert_output_note(output_notes, &bob_p2id_note);

    // Charlie's vault should be unchanged
    assert!(
        executed_transaction.account_patch().vault().is_empty(),
        "Charlie's vault should be unchanged"
    );

    Ok(())
}

/// Cross-swap that fills Alice's PSWAP from both `charlie_fill` (Charlie's vault) and `bob_fill`
/// (Bob's offered leg) in one transaction. The `full_fill` and `over_fill` cases (amounts in the
/// `#[case]` rows) both produce two P2IDs and no remainder; Bob's offered ETH flows through
/// inflight into Alice's note_fill leg, never touching Charlie's vault.
#[rstest]
#[case::full_fill(20, 30, 60, 40)]
#[case::over_fill(20, 50, 72, 28)]
#[tokio::test]
async fn pswap_note_combined_account_fill_and_note_fill_test(
    #[case] charlie_fill: u64,
    #[case] bob_fill: u64,
    #[case] bob_requested_amount: u64,
    #[case] charlie_payout_amount: u64,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(200))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(100))?;

    // Bob offers exactly the note_fill leg's ETH and requests `bob_requested_amount` USDC, drawn
    // from Alice's offered side via the cross-swap.
    let alice_offered = FungibleAsset::new(usdc_faucet.id(), 100)?;
    let alice_requested = FungibleAsset::new(eth_faucet.id(), 50)?;
    let bob_offered = FungibleAsset::new(eth_faucet.id(), bob_fill)?;
    let bob_requested = FungibleAsset::new(usdc_faucet.id(), bob_requested_amount)?;

    let charlie_vault_eth = FungibleAsset::new(eth_faucet.id(), charlie_fill)?;
    // Alice's P2ID carries the whole fill (charlie_fill + bob_fill ETH); the creator banks any
    // amount above her requested minimum.
    let charlie_payout_usdc = FungibleAsset::new(usdc_faucet.id(), charlie_payout_amount)?;

    let alice = AccountIdBuilder::new().build_with_seed([4; 32]);
    let bob = AccountIdBuilder::new().build_with_seed([5; 32]);
    let charlie =
        builder.add_existing_wallet_with_assets(BASIC_AUTH, [charlie_vault_eth.into()])?;

    let (alice_pswap, alice_pswap_note) =
        build_pswap_note(&mut builder, alice, alice_offered, alice_requested, NoteType::Public)?;
    let (bob_pswap, bob_pswap_note) =
        build_pswap_note(&mut builder, bob, bob_offered, bob_requested, NoteType::Public)?;

    let mock_chain = builder.build()?;

    // Alice: combined charlie_fill + bob_fill. Bob: filled exactly via pure note_fill, sourced
    // from Alice's offered side.
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(alice_pswap_note.id(), PswapNote::create_args(charlie_fill, bob_fill)?);
    note_args_map.insert(bob_pswap_note.id(), PswapNote::create_args(0, bob_requested_amount)?);

    let (alice_p2id_note, alice_remainder) =
        alice_pswap.execute(charlie.id(), Some(charlie_vault_eth), Some(bob_offered))?;
    assert!(alice_remainder.is_none(), "fill >= minimum produces no remainder");

    let (bob_p2id_note, bob_remainder) =
        bob_pswap.execute(charlie.id(), None, Some(bob_requested))?;
    assert!(bob_remainder.is_none(), "bob pswap is filled completely via note_fill");

    let mock_tx = mock_chain
        .build_transaction(charlie.id())
        .authenticated_input_notes([alice_pswap_note.id(), bob_pswap_note.id()])
        .extend_note_args(note_args_map)
        .expected_output_notes(vec![
            RawOutputNote::Full(alice_p2id_note.clone()),
            RawOutputNote::Full(bob_p2id_note.clone()),
        ])
        .build()?;

    let executed_transaction = mock_tx.execute().await?;

    // Exactly 2 P2ID output notes, no remainder: Alice's (the full fill in ETH) + Bob's (USDC).
    // Alice's leg is filled from both her account_fill and Bob's note_fill, so asserting her note's
    // exact asset set pins both deposits to it rather than to Bob's payback note.
    let output_notes = executed_transaction.output_notes();
    assert_eq!(
        output_notes.num_notes(),
        2,
        "expected exactly 2 P2ID output notes, no remainder"
    );

    assert_output_note(output_notes, &alice_p2id_note);
    assert_output_note(output_notes, &bob_p2id_note);

    // Charlie's vault: -charlie_fill ETH and +his account-share of the offered USDC
    // (floor(offered * charlie_fill / total_fill)). The note_fill legs flow through inflight and
    // never touch his vault.
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

    let mock_tx = mock_chain
        .build_transaction(alice.id())
        .authenticated_input_note(pswap_note.id())
        .build()?;

    let executed_transaction = mock_tx.execute().await?;

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

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 30)?.into()],
    )?;

    let (_, pswap_note) = build_pswap_note(
        &mut builder,
        alice,
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
    )?;
    let mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), PswapNote::create_args(account_fill, note_fill)?);

    let mock_tx = mock_chain
        .build_transaction(bob.id())
        .authenticated_input_note(pswap_note.id())
        .extend_note_args(note_args_map)
        .build()?;

    let result = mock_tx.execute().await;
    assert_transaction_executor_error!(result, expected_err);

    Ok(())
}

/// The per-fill floor (`min_fill_step`) is a pure assertion guard: it aborts the fill before
/// any asset moves or output note is created, and never changes state on its own. It rejects any
/// fill below the effective floor `min(min_fill_step, min_requested_amount)` and accepts anything
/// at or above it. Clamping to `min_requested_amount` keeps a swap whose requested amount is below
/// `min_fill_step` fillable in full (no permanently-stuck note).
///
/// Cases (offered = 200 USDC throughout; `total_fill` = the ETH amount Bob fills):
/// 1. fill 20 < min_fill_step 30                         → rejected (floor is binding)
/// 2. fill 30 == min_fill_step 30                        → accepted
/// 3. fill 40 > min_fill_step 30                         → accepted
/// 4. fill 20 < min_fill_step 50 but == min_requested 20 → accepted (floor clamps to min_requested,
///    so a full fill still completes)
/// 5. min_fill_step 0 (floor disabled) with a tiny fill 10 → accepted (a fill this small would be
///    rejected under any positive floor)
#[rstest]
#[case::below_floor(50, 30, 20, false)]
#[case::equal_floor(50, 30, 30, true)]
#[case::above_floor(50, 30, 40, true)]
#[case::clamped_to_min_requested(20, 50, 20, true)]
#[case::floor_disabled_zero(50, 0, 10, true)]
#[tokio::test]
async fn pswap_note_min_fill_step_test(
    #[case] requested_total: u64,
    #[case] min_fill_step: u64,
    #[case] fill_amount: u64,
    #[case] expect_ok: bool,
) -> anyhow::Result<()> {
    let offered_total = 200;

    let mut builder = MockChain::builder();
    let usdc_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1_000, Some(offered_total))?;
    let eth_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1_000, Some(fill_amount))?;

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), fill_amount)?.into()],
    )?;

    let offered_asset = FungibleAsset::new(usdc_faucet.id(), offered_total)?;
    let min_requested_asset = FungibleAsset::new(eth_faucet.id(), requested_total)?;

    // Build the PSWAP note via the builder, setting the per-fill floor.
    let serial_number = builder.rng_mut().draw_word();
    let storage = PswapNoteStorage::builder()
        .min_requested_asset(min_requested_asset)
        .creator_account_id(alice)
        .min_fill_step(AssetAmount::new(min_fill_step)?)
        .build();
    let pswap = PswapNote::builder()
        .sender(alice)
        .storage(storage)
        .serial_number(serial_number)
        .note_type(NoteType::Public)
        .offered_asset(offered_asset)
        .build()?;
    let pswap_note: Note = pswap.clone().into();
    builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));
    let mut mock_chain = builder.build()?;

    let fill_asset = FungibleAsset::new(eth_faucet.id(), fill_amount)?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), PswapNote::create_args(fill_amount, 0)?);

    if expect_ok {
        // The Rust mirror must agree and predict the output notes.
        let (p2id_note, remainder_pswap) = pswap.execute(bob.id(), Some(fill_asset), None)?;

        let mut expected_notes = vec![RawOutputNote::Full(p2id_note.clone())];
        if let Some(remainder) = remainder_pswap.clone() {
            expected_notes.push(RawOutputNote::Full(Note::from(remainder)));
        }

        let executed_transaction = mock_chain
            .build_transaction(bob.id())
            .authenticated_input_note(pswap_note.id())
            .expected_output_notes(expected_notes)
            .extend_note_args(note_args_map)
            .build()?
            .execute()
            .await?;

        let output_notes = executed_transaction.output_notes();
        let expected_count = if remainder_pswap.is_some() { 2 } else { 1 };
        assert_eq!(output_notes.num_notes(), expected_count);

        // Payback recipient parity: the floor guard must not perturb the P2ID payback.
        assert_eq!(
            output_notes.get_note(0).recipient_digest(),
            p2id_note.recipient().digest(),
            "on-chain payback recipient must match the Rust prediction",
        );

        // On a partial fill, the on-chain remainder must match the Rust remainder exactly. This
        // proves the remainder inherits min_fill_step (stored at slot [3] and copied verbatim by
        // the MASM `compute_and_store_recipient` over all storage items).
        if let Some(remainder) = remainder_pswap {
            assert_eq!(
                output_notes.get_note(1).recipient_digest(),
                Note::from(remainder).recipient().digest(),
                "on-chain remainder (carrying the inherited min_fill_step) must match Rust",
            );
        }

        mock_chain.add_pending_executed_transaction(&executed_transaction)?;
        mock_chain.prove_next_block()?;
    } else {
        // The Rust mirror rejects the sub-floor fill as well.
        assert!(
            pswap.execute(bob.id(), Some(fill_asset), None).is_err(),
            "Rust mirror must reject a fill below the floor",
        );

        let result = mock_chain
            .build_transaction(bob.id())
            .authenticated_input_note(pswap_note.id())
            .extend_note_args(note_args_map)
            .build()?
            .execute()
            .await;
        assert_transaction_executor_error!(result, ERR_PSWAP_FILL_BELOW_MINIMUM);
    }

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
async fn pswap_account_fill_payback_not_first_output_note_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(50))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(25))?;

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 25)?.into()],
    )?;

    let (pswap, pswap_note) = build_pswap_note(
        &mut builder,
        alice,
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
    let mock_tx = mock_chain
        .build_transaction(bob.id())
        .authenticated_input_notes([spawn_note.id(), pswap_note.id()])
        .extend_note_args(note_args_map)
        .expected_output_notes(vec![
            RawOutputNote::Full(dummy_note.clone()),
            RawOutputNote::Full(expected_p2id),
        ])
        .build()?;

    let executed = mock_tx.execute().await?;

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

/// Regression test verifying that each PSWAP payback note receives the asset its creator requested
/// when the paybacks are not the transaction's first output notes.
///
/// A SPAWN note consumed first emits an empty dummy note at index 0, so the two cross-swapped PSWAP
/// notes create their paybacks at indices 1 and 2 and the dummy must stay empty.
#[tokio::test]
async fn pswap_note_fill_payback_not_first_output_note_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    let usdc_50 = FungibleAsset::new(usdc_faucet.id(), 50)?;
    let eth_25 = FungibleAsset::new(eth_faucet.id(), 25)?;

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = AccountIdBuilder::new().build_with_seed([2; 32]);
    // Charlie holds no assets: every fill below is a pure note_fill, so the two PSWAP notes fund
    // each other inflight and Charlie's vault must stay untouched.
    let charlie = builder.add_existing_wallet_with_assets(BASIC_AUTH, [])?;

    let (alice_pswap, alice_pswap_note) =
        build_pswap_note(&mut builder, alice, usdc_50, eth_25, NoteType::Public)?;
    let (bob_pswap, bob_pswap_note) =
        build_pswap_note(&mut builder, bob, eth_25, usdc_50, NoteType::Public)?;

    // Dummy output note emitted by the SPAWN note, so the paybacks land at idx 1 and 2. Sender must
    // equal the transaction's native account (charlie) per `create_spawn_note`'s check. No assets,
    // which is exactly what makes it a usable canary.
    let dummy_note = NoteBuilder::new(charlie.id(), SmallRng::seed_from_u64(7777)).build()?;
    let spawn_note = builder.add_spawn_note([&dummy_note])?;

    let mock_chain = builder.build()?;

    // Pure note fill on both legs (account_fill = 0).
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(alice_pswap_note.id(), PswapNote::create_args(0, 25)?);
    note_args_map.insert(bob_pswap_note.id(), PswapNote::create_args(0, 50)?);

    let (alice_p2id_note, _) = alice_pswap.execute(charlie.id(), None, Some(eth_25))?;
    let (bob_p2id_note, _) = bob_pswap.execute(charlie.id(), None, Some(usdc_50))?;

    // Consume spawn first so neither payback can occupy output note 0.
    let mock_tx = mock_chain
        .build_transaction(charlie.id())
        .authenticated_input_notes([spawn_note.id(), alice_pswap_note.id(), bob_pswap_note.id()])
        .extend_note_args(note_args_map)
        .expected_output_notes(vec![
            RawOutputNote::Full(dummy_note.clone()),
            RawOutputNote::Full(alice_p2id_note.clone()),
            RawOutputNote::Full(bob_p2id_note.clone()),
        ])
        .build()?;

    let executed_transaction = mock_tx.execute().await?;

    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 3, "expected dummy + two paybacks");

    // The dummy at idx 0 must stay empty. Anything here means a note_fill leg wrote its asset to
    // the wrong output note index.
    assert_eq!(
        output_notes.get_note(0).assets().num_assets(),
        0,
        "SPAWN dummy should be empty; non-empty means a note_fill leg deposited into the wrong \
         output note_idx",
    );

    // Each payback carries exactly the asset its own creator requested.
    assert_output_note(output_notes, &alice_p2id_note);
    assert_output_note(output_notes, &bob_p2id_note);

    // Pure note_fill on both legs: the assets flow between the notes inflight, never through
    // Charlie's vault.
    assert!(
        executed_transaction.account_patch().vault().is_empty(),
        "Charlie's vault should be unchanged"
    );

    Ok(())
}

/// Regression test verifying that each PSWAP payback note receives the asset its creator
/// requested when a remainder note is created between the two paybacks.
///
/// Alice's PSWAP is filled below its minimum, so it emits a payback and a remainder before Bob's
/// payback is created at index 2, and each of the three output notes must carry exactly its own
/// asset.
#[tokio::test]
async fn pswap_note_fill_payback_after_remainder_note_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    // Alice offers 100 USDC for at least 50 ETH; Bob offers 20 ETH for at least 40 USDC.
    // Alice's leg is filled with Bob's 20 ETH — below her 50 ETH minimum, so it is a partial fill:
    // payout = floor(100 * 20 / 50) = 40 USDC, leaving a 60 USDC remainder. Those 40 USDC exactly
    // fill Bob's leg, which needs no remainder of its own. Both legs are pure note_fill, so the two
    // notes fund each other inflight and Charlie's vault stays untouched.
    let alice_offered = FungibleAsset::new(usdc_faucet.id(), 100)?;
    let alice_requested = FungibleAsset::new(eth_faucet.id(), 50)?;
    let bob_offered = FungibleAsset::new(eth_faucet.id(), 20)?;
    let bob_requested = FungibleAsset::new(usdc_faucet.id(), 40)?;

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = AccountIdBuilder::new().build_with_seed([2; 32]);
    let charlie = builder.add_existing_wallet_with_assets(BASIC_AUTH, [])?;

    let (alice_pswap, alice_pswap_note) =
        build_pswap_note(&mut builder, alice, alice_offered, alice_requested, NoteType::Public)?;
    let (bob_pswap, bob_pswap_note) =
        build_pswap_note(&mut builder, bob, bob_offered, bob_requested, NoteType::Public)?;

    let mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(alice_pswap_note.id(), PswapNote::create_args(0, 20)?);
    note_args_map.insert(bob_pswap_note.id(), PswapNote::create_args(0, 40)?);

    let (alice_p2id_note, alice_remainder) =
        alice_pswap.execute(charlie.id(), None, Some(bob_offered))?;
    let alice_remainder: Note = alice_remainder
        .expect("fill below the minimum should produce a remainder")
        .into();

    let (bob_p2id_note, bob_remainder) =
        bob_pswap.execute(charlie.id(), None, Some(bob_requested))?;
    assert!(bob_remainder.is_none(), "bob's leg is filled exactly, so it has no remainder");

    let mock_tx = mock_chain
        .build_transaction(charlie.id())
        .authenticated_input_notes([alice_pswap_note.id(), bob_pswap_note.id()])
        .extend_note_args(note_args_map)
        .expected_output_notes(vec![
            RawOutputNote::Full(alice_p2id_note.clone()),
            RawOutputNote::Full(alice_remainder.clone()),
            RawOutputNote::Full(bob_p2id_note.clone()),
        ])
        .build()?;

    let executed_transaction = mock_tx.execute().await?;

    // Alice's payback + Alice's remainder + Bob's payback.
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 3, "expected two paybacks and one remainder");

    assert_output_note(output_notes, &alice_p2id_note);
    assert_output_note(output_notes, &alice_remainder);
    assert_output_note(output_notes, &bob_p2id_note);

    assert!(
        executed_transaction.account_patch().vault().is_empty(),
        "Charlie's vault should be unchanged"
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

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);

    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), fill_amount)?.into()],
    )?;

    let (pswap, pswap_note) = build_pswap_note(
        &mut builder,
        alice,
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

    let mock_tx = mock_chain
        .build_transaction(bob.id())
        .authenticated_input_note(pswap_note.id())
        .expected_output_notes(expected_notes)
        .extend_note_args(note_args_map)
        .build()?;

    let executed_transaction = mock_tx.execute().await?;

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

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), fill_eth)?.into()],
    )?;

    let (pswap, pswap_note) = build_pswap_note(
        &mut builder,
        alice,
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

    let mock_tx = mock_chain
        .build_transaction(bob.id())
        .authenticated_input_note(pswap_note.id())
        .expected_output_notes(expected_notes)
        .extend_note_args(note_args_map)
        .build()?;

    let executed_tx = mock_tx.execute().await?;

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
    use rand::{RngExt, SeedableRng};

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

        let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
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
            .min_requested_asset(requested_fungible)
            .creator_account_id(alice)
            .build();
        let pswap = PswapNote::builder()
            .sender(alice)
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

        let mock_tx = mock_chain
            .build_transaction(bob.id())
            .authenticated_input_note(pswap_note.id())
            .expected_output_notes(expected_notes)
            .extend_note_args(note_args_map)
            .build()?;

        let executed_tx = mock_tx.execute().await.map_err(|e| {
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
    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = builder
        .add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(eth_faucet.id(), 25).unwrap().into()],
        )
        .unwrap();

    // Create swap note using PswapNote builder
    let mut rng = RandomCoin::new(Word::default());
    let min_requested_asset = FungibleAsset::new(eth_faucet.id(), 25).unwrap();
    let storage = PswapNoteStorage::builder()
        .min_requested_asset(min_requested_asset)
        .creator_account_id(alice)
        .payback_note_type(NoteType::Public)
        .build();
    let pswap_note: Note = PswapNote::builder()
        .sender(alice)
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
    assert_eq!(pswap.sender(), alice, "Sender mismatch after roundtrip");
    assert_eq!(pswap.note_type(), NoteType::Public, "Note type mismatch after roundtrip");
    assert_eq!(pswap.storage().min_requested_amount(), 25, "Requested amount mismatch");
    assert_eq!(pswap.storage().creator_account_id(), alice, "Creator ID mismatch");

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
        alice,
        "Remainder creator should be Alice"
    );
    let remaining_requested = remainder_pswap.storage().min_requested_amount();
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
    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);

    let (pswap, _) = build_pswap_note(
        &mut builder,
        alice,
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
    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 10)?.into()],
    )?;

    let (pswap, _) = build_pswap_note(
        &mut builder,
        alice,
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
                .min_requested_asset(FungibleAsset::new(eth_faucet.id(), initial_requested)?)
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
            .build_transaction(bob.id())
            .authenticated_input_note(current_pswap_note.id())
            .expected_output_notes(expected_notes)
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
            .build_transaction(alice.id())
            .unauthenticated_input_note(reconstructed_payback)
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

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 30)?.into()],
    )?;

    // Two PSWAPs from Alice, both USDC → ETH, but distinct serials → distinct order_ids.
    let pswap_a = {
        let mut rng = RandomCoin::new(Word::default());
        let serial = rng.draw_word();
        let storage = PswapNoteStorage::builder()
            .min_requested_asset(FungibleAsset::new(eth_faucet.id(), 20)?)
            .creator_account_id(alice)
            .build();

        PswapNote::builder()
            .sender(alice)
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
            .min_requested_asset(FungibleAsset::new(eth_faucet.id(), 30)?)
            .creator_account_id(alice)
            .build();

        PswapNote::builder()
            .sender(alice)
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

    let mock_tx = mock_chain
        .build_transaction(bob.id())
        .authenticated_input_notes([note_a.id(), note_b.id()])
        .extend_note_args(note_args)
        .expected_output_notes(vec![
            RawOutputNote::Full(payback_a.clone()),
            RawOutputNote::Full(remainder_a_note.clone()),
            RawOutputNote::Full(payback_b.clone()),
            RawOutputNote::Full(remainder_b_note.clone()),
        ])
        .build()?;
    let executed_tx = mock_tx.execute().await?;

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
    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);

    let (_, pswap_note) = build_pswap_note(
        &mut builder,
        alice,
        FungibleAsset::new(usdc_faucet.id(), 50).unwrap(),
        FungibleAsset::new(eth_faucet.id(), 25).unwrap(),
        NoteType::Public,
    )
    .unwrap();

    let storage = pswap_note.recipient().storage();
    let items = storage.items();

    let parsed = PswapNoteStorage::try_from(items).unwrap();

    assert_eq!(parsed.creator_account_id(), alice, "Creator ID roundtrip failed!");

    // Verify requested amount from value word
    assert_eq!(parsed.min_requested_amount(), 25, "Requested amount should be 25");
}

/// Regression test for the offered-asset drain (issue #3601, PSWAP leg).
///
/// A PSWAP note offers 1000 USDC for a minimum of 100 ETH. The consuming account exposes an
/// `@account_procedure` performing indexed input-note asset removal (`input_note::remove_asset`),
/// permitted only from the native-account context. An earlier helper input note (index 0) calls it
/// to drain 900 USDC out of the PSWAP note (index 1) before the PSWAP script runs. A partial fill
/// must then abort with `ERR_PSWAP_OFFERED_ASSET_ALTERED`.
#[tokio::test]
async fn pswap_note_offered_asset_drain_is_rejected_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 10_000, Some(1_000))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 10_000, Some(100))?;

    let alice = AccountIdBuilder::new().build_with_seed([1; 32]);

    // A component that drains a specified asset from an input note by index into the account's own
    // vault.
    let drain_component = AccountComponent::new(
        CodeBuilder::default().compile_component_code(
            "attacker_account",
            "
            use miden::protocol::asset
            use miden::protocol::input_note
            use miden::protocol::native_account

            #! Removes the given asset from the input note at `note_index` and credits it to this
            #! account's vault.
            #!
            #! Inputs:  [ASSET_ID, ASSET_VALUE, note_index, pad(7)]
            #! Outputs: [pad(16)]
            @account_procedure
            @locals(8)
            pub proc drain_note_asset
                # keep a copy of the asset so it can be credited to the vault after removal
                dupw.1 dupw.1 locaddr.0 exec.asset::store
                # => [ASSET_ID, ASSET_VALUE, note_index, pad(7)]

                exec.input_note::remove_asset
                # => [FINAL_ASSET_VALUE, pad(7)]

                dropw
                # => [pad(7)]

                # credit the drained asset to the consuming account's vault
                locaddr.0 exec.asset::load exec.native_account::add_asset dropw
                # => [pad(7)]
            end
            ",
        )?,
        Vec::new(),
        AccountComponentMetadata::mock("attacker_account"),
    )?;

    let consumer = builder.add_account_from_builder(
        BASIC_AUTH,
        Account::builder([9; 32])
            .account_type(AccountType::Public)
            .with_component(BasicWallet)
            .with_component(drain_component.clone())
            .with_assets([FungibleAsset::new(eth_faucet.id(), 100)?.into()]),
        AccountState::Exists,
    )?;

    // Alice's PSWAP note offers 1000 USDC for a minimum of 100 ETH.
    let offered_asset = FungibleAsset::new(usdc_faucet.id(), 1_000)?;
    let min_requested_asset = FungibleAsset::new(eth_faucet.id(), 100)?;
    let (_, pswap_note) = build_pswap_note(
        &mut builder,
        alice,
        offered_asset,
        min_requested_asset,
        NoteType::Public,
    )?;

    // Helper note (input note index 0) that drains 900 of the 1000 offered USDC out of the PSWAP
    // note (input note index 1) via the consuming account's procedure.
    let drained = FungibleAsset::new(usdc_faucet.id(), 900)?;
    let pswap_input_note_index = 1u8;
    let helper_code = format!(
        r#"
        use miden::core::sys

        @note_script
        pub proc main
            # Drain the offered asset from the PSWAP note by index, via the native account's
            # procedure, before the PSWAP script gets to consume its own remaining assets.
            push.0.0.0.0 push.0.0.0
            push.{pswap_input_note_index}
            push.{asset_value}
            push.{asset_id}
            call.::attacker_account::drain_note_asset
            exec.sys::truncate_stack
        end
    "#,
        asset_value = drained.to_value_word(),
        asset_id = drained.to_id_word(),
    );
    let helper_script = CodeBuilder::with_mock_packages()
        .with_dynamically_linked_package(drain_component.component_code())?
        .compile_note_script(helper_code)?;
    let helper_note = NoteBuilder::new(alice, RandomCoin::new(Word::from([7, 7, 7, 7u32])))
        .note_type(NoteType::Public)
        .script(helper_script)
        .build()?;
    // Commit the helper note so it can be consumed as an authenticated input note (index 0).
    builder.add_output_note(RawOutputNote::Full(helper_note.clone()));

    let mock_chain = builder.build()?;

    // A 50-of-100 ETH partial fill, which exercises the remainder-note pricing path.
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), PswapNote::create_args(50, 0)?);

    let result = mock_chain
        .build_transaction(consumer.id())
        .authenticated_input_notes([helper_note.id(), pswap_note.id()])
        .extend_note_args(note_args_map)
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_PSWAP_OFFERED_ASSET_ALTERED);

    Ok(())
}
