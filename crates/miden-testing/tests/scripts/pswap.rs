use std::collections::BTreeMap;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountId, AccountStorageMode, AccountVaultDelta};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::{Note, NoteAssets, NoteMetadata, NoteRecipient, NoteStorage, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, ONE, Word, ZERO};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::{PswapNote, PswapNoteStorage};
use miden_testing::{Auth, MockChain, MockChainBuilder};
use rstest::rstest;

// CONSTANTS
// ================================================================================================

const BASIC_AUTH: Auth = Auth::BasicAuth {
    auth_scheme: AuthScheme::Falcon512Poseidon2,
};

// HELPERS
// ================================================================================================

/// Builds a PswapNote, registers it on the builder as an output note, returns the Note.
fn build_pswap_note(
    builder: &mut MockChainBuilder,
    sender: AccountId,
    offered_asset: FungibleAsset,
    requested_asset: FungibleAsset,
    note_type: NoteType,
    rng: &mut RandomCoin,
) -> anyhow::Result<Note> {
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(sender)
        .build();
    let note: Note = PswapNote::builder()
        .sender(sender)
        .storage(storage)
        .serial_number(rng.draw_word())
        .note_type(note_type)
        .offered_asset(offered_asset)
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(note.clone()));
    Ok(note)
}

/// Note-args Word `[account_fill, note_fill, 0, 0]`.
fn note_args(account_fill: u64, note_fill: u64) -> Word {
    Word::from([
        Felt::try_from(account_fill).expect("account_fill fits in a felt"),
        Felt::try_from(note_fill).expect("note_fill fits in a felt"),
        ZERO,
        ZERO,
    ])
}

#[track_caller]
fn assert_fungible_asset(asset: &Asset, expected_faucet: AccountId, expected_amount: u64) {
    match asset {
        Asset::Fungible(f) => {
            assert_eq!(f.faucet_id(), expected_faucet, "faucet id mismatch");
            assert_eq!(
                f.amount(),
                expected_amount,
                "amount mismatch (expected {expected_amount}, got {})",
                f.amount()
            );
        },
        _ => panic!("expected fungible asset, got non-fungible"),
    }
}

#[track_caller]
fn assert_vault_added_removed(
    vault_delta: &AccountVaultDelta,
    expected_added: (AccountId, u64),
    expected_removed: (AccountId, u64),
) {
    let added: Vec<Asset> = vault_delta.added_assets().collect();
    let removed: Vec<Asset> = vault_delta.removed_assets().collect();
    assert_eq!(added.len(), 1, "expected exactly 1 added asset");
    assert_eq!(removed.len(), 1, "expected exactly 1 removed asset");
    assert_fungible_asset(&added[0], expected_added.0, expected_added.1);
    assert_fungible_asset(&removed[0], expected_removed.0, expected_removed.1);
}

#[track_caller]
fn assert_vault_single_added(
    vault_delta: &AccountVaultDelta,
    expected_faucet: AccountId,
    expected_amount: u64,
) {
    let added: Vec<Asset> = vault_delta.added_assets().collect();
    assert_eq!(added.len(), 1, "expected exactly 1 added asset");
    assert_fungible_asset(&added[0], expected_faucet, expected_amount);
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
    let pswap_note: Note = PswapNote::builder()
        .sender(alice.id())
        .storage(storage)
        .serial_number(serial_number)
        .note_type(NoteType::Public)
        .offered_asset(offered_asset)
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));

    let mut mock_chain = builder.build()?;

    // --- Step 1: Bob partially fills the PSWAP note (20 out of 25 ETH) ---

    let fill_amount = 20u64;
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), note_args(fill_amount, 0));

    let pswap = PswapNote::try_from(&pswap_note)?;
    let (p2id_note, remainder_pswap) =
        pswap.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 20)?), None)?;
    let remainder_note =
        Note::from(remainder_pswap.expect("partial fill should produce remainder"));

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(p2id_note.clone()),
            RawOutputNote::Full(remainder_note),
        ])
        .build()?;

    let executed_transaction = tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    let _ = mock_chain.prove_next_block();

    // --- Step 2: Alice reconstructs the P2ID note from her PSWAP data + aux ---

    // In production, Alice reads the fill amount from the P2ID note's attachment (aux data),
    // which is visible for both public and private notes. Here we read it from the
    // Rust-predicted note since the test framework doesn't preserve word attachment content
    // in executed transaction outputs.
    let aux_word = p2id_note.metadata().attachment().content().to_word();
    let fill_amount_from_aux = aux_word[0].as_canonical_u64();
    assert_eq!(fill_amount_from_aux, 20, "Fill amount from aux should be 20 ETH");

    // Alice reconstructs the recipient using her serial number and account ID
    let p2id_serial =
        Word::from([serial_number[0] + ONE, serial_number[1], serial_number[2], serial_number[3]]);
    let reconstructed_recipient = P2idNoteStorage::new(alice.id()).into_recipient(p2id_serial);

    // Verify the reconstructed recipient matches the actual output
    assert_eq!(
        reconstructed_recipient.digest(),
        p2id_note.recipient().digest(),
        "Alice's reconstructed P2ID recipient does not match the actual output"
    );

    // --- Step 3: Alice consumes the P2ID payback note ---

    let tx_context = mock_chain.build_tx_context(alice.id(), &[p2id_note.id()], &[])?.build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify Alice received 20 ETH
    let vault_delta = executed_transaction.account_delta().vault();
    assert_vault_single_added(vault_delta, eth_faucet.id(), 20);

    Ok(())
}

/// Parameterized fill test covering:
/// - full public fill
/// - full private fill
/// - partial public fill (offered=50 USDC / requested=25 ETH / fill=20 ETH → payout=40 USDC,
///   remainder=10 USDC)
/// - full fill via a network account (no note_args → script defaults to full fill)
#[rstest]
#[case::full_public(25, NoteType::Public, false)]
#[case::full_private(25, NoteType::Private, false)]
#[case::partial_public(20, NoteType::Public, false)]
#[case::network_full_fill(25, NoteType::Public, true)]
#[tokio::test]
async fn pswap_fill_test(
    #[case] fill_amount: u64,
    #[case] note_type: NoteType,
    #[case] use_network_account: bool,
) -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
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

    let offered_asset = FungibleAsset::new(usdc_faucet.id(), 50)?;
    let requested_asset = FungibleAsset::new(eth_faucet.id(), 25)?;

    let mut rng = RandomCoin::new(Word::default());
    let pswap_note = build_pswap_note(
        &mut builder,
        alice.id(),
        offered_asset,
        requested_asset,
        note_type,
        &mut rng,
    )?;

    let mut mock_chain = builder.build()?;

    let pswap = PswapNote::try_from(&pswap_note)?;
    let fill_asset = FungibleAsset::new(eth_faucet.id(), fill_amount)?;

    let (p2id_note, remainder_pswap) = if use_network_account {
        let p2id = pswap.execute_full_fill_network(consumer_id)?;
        (p2id, None)
    } else {
        pswap.execute(consumer_id, Some(fill_asset), None)?
    };

    let is_partial = fill_amount < 25;
    let payout_amount = pswap.calculate_offered_for_requested(fill_amount);

    let mut expected_notes = vec![RawOutputNote::Full(p2id_note.clone())];
    if let Some(remainder) = remainder_pswap {
        expected_notes.push(RawOutputNote::Full(Note::from(remainder)));
    }

    let mut tx_builder = mock_chain
        .build_tx_context(consumer_id, &[pswap_note.id()], &[])?
        .extend_expected_output_notes(expected_notes);

    if !use_network_account {
        let mut note_args_map = BTreeMap::new();
        note_args_map.insert(pswap_note.id(), note_args(fill_amount, 0));
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
    assert_fungible_asset(p2id_assets.iter().next().unwrap(), eth_faucet.id(), fill_amount);

    // On partial fill, assert remainder note has offered - payout USDC
    if is_partial {
        let remainder_assets = output_notes.get_note(1).assets();
        assert_fungible_asset(
            remainder_assets.iter().next().unwrap(),
            usdc_faucet.id(),
            50 - payout_amount,
        );
    }

    // Consumer's vault delta: +payout USDC, -fill ETH
    let vault_delta = executed_transaction.account_delta().vault();
    assert_vault_added_removed(
        vault_delta,
        (usdc_faucet.id(), payout_amount),
        (eth_faucet.id(), fill_amount),
    );

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    let _ = mock_chain.prove_next_block();

    Ok(())
}

#[tokio::test]
async fn pswap_note_note_fill_cross_swap_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 25)?.into()],
    )?;
    let charlie = builder.add_existing_wallet_with_assets(BASIC_AUTH, [])?;

    let mut rng = RandomCoin::new(Word::default());

    // Alice's note: offers 50 USDC, requests 25 ETH
    let alice_pswap_note = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
        &mut rng,
    )?;

    // Bob's note: offers 25 ETH, requests 50 USDC
    let bob_pswap_note = build_pswap_note(
        &mut builder,
        bob.id(),
        FungibleAsset::new(eth_faucet.id(), 25)?,
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        NoteType::Public,
        &mut rng,
    )?;

    let mock_chain = builder.build()?;

    // Note args: pure note fill (account_fill = 0, note_fill = full amount)
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(alice_pswap_note.id(), note_args(0, 25));
    note_args_map.insert(bob_pswap_note.id(), note_args(0, 50));

    // Expected P2ID notes
    let alice_pswap = PswapNote::try_from(&alice_pswap_note)?;
    let (alice_p2id_note, _) =
        alice_pswap.execute(charlie.id(), None, Some(FungibleAsset::new(eth_faucet.id(), 25)?))?;

    let bob_pswap = PswapNote::try_from(&bob_pswap_note)?;
    let (bob_p2id_note, _) =
        bob_pswap.execute(charlie.id(), None, Some(FungibleAsset::new(usdc_faucet.id(), 50)?))?;

    let tx_context = mock_chain
        .build_tx_context(charlie.id(), &[alice_pswap_note.id(), bob_pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(alice_p2id_note),
            RawOutputNote::Full(bob_p2id_note),
        ])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify: 2 P2ID notes
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 2);

    let mut alice_found = false;
    let mut bob_found = false;
    for idx in 0..output_notes.num_notes() {
        if let Asset::Fungible(f) = output_notes.get_note(idx).assets().iter().next().unwrap() {
            if f.faucet_id() == eth_faucet.id() && f.amount() == 25 {
                alice_found = true;
            }
            if f.faucet_id() == usdc_faucet.id() && f.amount() == 50 {
                bob_found = true;
            }
        }
    }
    assert!(alice_found, "Alice's P2ID note (25 ETH) not found");
    assert!(bob_found, "Bob's P2ID note (50 USDC) not found");

    // Charlie's vault should be unchanged
    let vault_delta = executed_transaction.account_delta().vault();
    assert_eq!(vault_delta.added_assets().count(), 0);
    assert_eq!(vault_delta.removed_assets().count(), 0);

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

    let mut rng = RandomCoin::new(Word::default());
    let pswap_note = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
        &mut rng,
    )?;

    let mock_chain = builder.build()?;

    let tx_context = mock_chain.build_tx_context(alice.id(), &[pswap_note.id()], &[])?.build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify: 0 output notes, Alice gets 50 USDC back
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 0, "Expected 0 output notes for reclaim");

    let vault_delta = executed_transaction.account_delta().vault();
    assert_vault_single_added(vault_delta, usdc_faucet.id(), 50);

    Ok(())
}

#[tokio::test]
async fn pswap_note_invalid_input_test() -> anyhow::Result<()> {
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

    let mut rng = RandomCoin::new(Word::default());
    let pswap_note = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
        &mut rng,
    )?;
    let mock_chain = builder.build()?;

    // Try to fill with 30 ETH when only 25 is requested - should fail
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), note_args(30, 0));

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .build()?;

    let result = tx_context.execute().await;
    assert!(
        result.is_err(),
        "Transaction should fail when fill_amount > requested_asset_total"
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

    let mut rng = RandomCoin::new(Word::default());
    let pswap_note = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50)?,
        FungibleAsset::new(eth_faucet.id(), 25)?,
        NoteType::Public,
        &mut rng,
    )?;

    let mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), note_args(fill_amount, 0));

    let pswap = PswapNote::try_from(&pswap_note)?;
    let payout_amount = pswap.calculate_offered_for_requested(fill_amount);
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
    assert_vault_single_added(vault_delta, usdc_faucet.id(), payout_amount);

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

    let mut rng = RandomCoin::new(Word::default());
    let pswap_note = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), offered_usdc)?,
        FungibleAsset::new(eth_faucet.id(), requested_eth)?,
        NoteType::Public,
        &mut rng,
    )?;

    let mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), note_args(fill_eth, 0));

    let pswap = PswapNote::try_from(&pswap_note)?;
    let payout_amount = pswap.calculate_offered_for_requested(fill_eth);
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
        (usdc_faucet.id(), payout_amount),
        (eth_faucet.id(), fill_eth),
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

    for (current_swap_count, fill_amount) in fills.iter().enumerate() {
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

        // Build storage and note manually to use the correct serial for chain position
        let offered_fungible = FungibleAsset::new(usdc_faucet.id(), current_offered)?;
        let requested_fungible = FungibleAsset::new(eth_faucet.id(), current_requested)?;

        let pswap_tag =
            PswapNote::create_tag(NoteType::Public, &offered_fungible, &requested_fungible);
        let offered_asset = Asset::Fungible(offered_fungible);

        let storage = PswapNoteStorage::builder()
            .requested_asset(requested_fungible)
            .pswap_tag(pswap_tag)
            .swap_count(current_swap_count as u16)
            .creator_account_id(alice.id())
            .build();
        let note_assets = NoteAssets::new(vec![offered_asset])?;

        // Create note with the correct serial for this chain position
        let note_storage = NoteStorage::from(storage);
        let recipient = NoteRecipient::new(current_serial, PswapNote::script(), note_storage);
        let metadata = NoteMetadata::new(alice.id(), NoteType::Public).with_tag(pswap_tag);
        let pswap_note = Note::new(note_assets, metadata, recipient);

        builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));
        let mock_chain = builder.build()?;

        let mut note_args_map = BTreeMap::new();
        note_args_map.insert(pswap_note.id(), note_args(*fill_amount, 0));

        let pswap = PswapNote::try_from(&pswap_note)?;
        let payout_amount = pswap.calculate_offered_for_requested(*fill_amount);
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
                current_swap_count + 1,
                e,
                current_offered,
                current_requested,
                fill_amount
            )
        })?;

        let output_notes = executed_tx.output_notes();
        let expected_count = if remaining_requested > 0 { 2 } else { 1 };
        assert_eq!(output_notes.num_notes(), expected_count, "fill {}", current_swap_count + 1);

        let vault_delta = executed_tx.account_delta().vault();
        assert_vault_single_added(vault_delta, usdc_faucet.id(), payout_amount);

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
    assert_eq!(pswap.storage().swap_count(), 0, "Swap count should be 0");
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
    assert_fungible_asset(p2id_note.assets().iter().next().unwrap(), eth_faucet.id(), 25);

    // Partial fill: should produce P2ID note + remainder
    let (p2id_partial, remainder_partial) = pswap
        .execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 10).unwrap()), None)
        .unwrap();
    let remainder_pswap = remainder_partial.expect("Partial fill should produce remainder");

    assert_eq!(p2id_partial.assets().num_assets(), 1);
    assert_fungible_asset(p2id_partial.assets().iter().next().unwrap(), eth_faucet.id(), 10);

    // Verify remainder properties
    assert_eq!(remainder_pswap.storage().swap_count(), 1, "Remainder swap count should be 1");
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

    let mut rng = RandomCoin::new(Word::default());
    let pswap_note = build_pswap_note(
        &mut builder,
        alice.id(),
        FungibleAsset::new(usdc_faucet.id(), 50).unwrap(),
        FungibleAsset::new(eth_faucet.id(), 25).unwrap(),
        NoteType::Public,
        &mut rng,
    )
    .unwrap();

    let storage = pswap_note.recipient().storage();
    let items = storage.items();

    let parsed = PswapNoteStorage::try_from(items).unwrap();

    assert_eq!(parsed.creator_account_id(), alice.id(), "Creator ID roundtrip failed!");
    assert_eq!(parsed.swap_count(), 0, "Swap count should be 0");

    // Verify requested amount from value word
    assert_eq!(parsed.requested_asset_amount(), 25, "Requested amount should be 25");
}
