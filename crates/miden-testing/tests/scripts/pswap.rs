use std::collections::BTreeMap;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::{Account, AccountStorageMode};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::{Note, NoteAssets, NoteMetadata, NoteRecipient, NoteStorage, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word, ONE, ZERO};
use miden_standards::account::wallets::BasicWallet;
use miden_standards::note::{PswapNote, PswapNoteStorage};
use miden_testing::{Auth, MockChain};

// CONSTANTS
// ================================================================================================

const BASIC_AUTH: Auth = Auth::BasicAuth {
    auth_scheme: AuthScheme::Falcon512Poseidon2,
};

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

    let fill_amount = 20u32;
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(
        pswap_note.id(),
        Word::from([Felt::from(fill_amount), Felt::from(0u32), ZERO, ZERO]),
    );

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

    // --- Step 2: Alice reconstructs the P2ID note from her PSWAP data ---

    // Alice knows the fill amount from the P2ID note's assets (visible on chain for public notes)
    let output_notes = executed_transaction.output_notes();
    let p2id_output_assets = output_notes.get_note(0).assets();
    let fill_asset = match p2id_output_assets.iter().next().unwrap() {
        Asset::Fungible(f) => *f,
        _ => panic!("Expected fungible asset in P2ID note"),
    };
    assert_eq!(fill_asset.amount(), 20, "Fill amount should be 20 ETH");

    // Alice reconstructs the recipient using her serial number and account ID
    let p2id_serial = Word::from([
        serial_number[0] + ONE,
        serial_number[1],
        serial_number[2],
        serial_number[3],
    ]);
    let reconstructed_recipient = P2idNoteStorage::new(alice.id()).into_recipient(p2id_serial);

    // Verify the reconstructed recipient matches the actual output
    assert_eq!(
        reconstructed_recipient.digest(),
        p2id_note.recipient().digest(),
        "Alice's reconstructed P2ID recipient does not match the actual output"
    );

    // --- Step 3: Alice consumes the P2ID payback note ---

    let tx_context = mock_chain
        .build_tx_context(alice.id(), &[p2id_note.id()], &[])?
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify Alice received 20 ETH
    let vault_delta = executed_transaction.account_delta().vault();
    let added: Vec<Asset> = vault_delta.added_assets().collect();
    assert_eq!(added.len(), 1);
    if let Asset::Fungible(f) = &added[0] {
        assert_eq!(f.faucet_id(), eth_faucet.id());
        assert_eq!(f.amount(), 20);
    } else {
        panic!("Expected fungible asset in Alice's vault");
    }

    Ok(())
}

#[tokio::test]
async fn pswap_note_full_fill_test() -> anyhow::Result<()> {
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

    let offered_asset = FungibleAsset::new(usdc_faucet.id(), 50)?;
    let requested_asset = FungibleAsset::new(eth_faucet.id(), 25)?;

    let mut rng = RandomCoin::new(Word::default());
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(alice.id())
        .build();
    let pswap_note: Note = PswapNote::builder()
        .sender(alice.id())
        .storage(storage)
        .serial_number(rng.draw_word())
        .note_type(NoteType::Public)
        .offered_asset(offered_asset)
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));

    let mut mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), Word::from([Felt::from(25u32), Felt::from(0u32), ZERO, ZERO]));

    let pswap = PswapNote::try_from(&pswap_note)?;
    let (p2id_note, _remainder) =
        pswap.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 25)?), None)?;

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .extend_expected_output_notes(vec![RawOutputNote::Full(p2id_note.clone())])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify: 1 P2ID note with 25 ETH
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 1, "Expected exactly 1 P2ID note");

    let actual_recipient = output_notes.get_note(0).recipient_digest();
    let expected_recipient = p2id_note.recipient().digest();
    assert_eq!(actual_recipient, expected_recipient, "RECIPIENT MISMATCH!");

    let p2id_assets = output_notes.get_note(0).assets();
    assert_eq!(p2id_assets.num_assets(), 1);
    if let Asset::Fungible(f) = p2id_assets.iter().next().unwrap() {
        assert_eq!(f.faucet_id(), eth_faucet.id());
        assert_eq!(f.amount(), 25);
    } else {
        panic!("Expected fungible asset in P2ID note");
    }

    // Verify Bob's vault delta: +50 USDC, -25 ETH
    let vault_delta = executed_transaction.account_delta().vault();
    let added: Vec<Asset> = vault_delta.added_assets().collect();
    let removed: Vec<Asset> = vault_delta.removed_assets().collect();

    assert_eq!(added.len(), 1);
    assert_eq!(removed.len(), 1);
    if let Asset::Fungible(f) = &added[0] {
        assert_eq!(f.faucet_id(), usdc_faucet.id());
        assert_eq!(f.amount(), 50);
    }
    if let Asset::Fungible(f) = &removed[0] {
        assert_eq!(f.faucet_id(), eth_faucet.id());
        assert_eq!(f.amount(), 25);
    }

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    let _ = mock_chain.prove_next_block();

    Ok(())
}

#[tokio::test]
async fn pswap_note_private_full_fill_test() -> anyhow::Result<()> {
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

    let offered_asset = FungibleAsset::new(usdc_faucet.id(), 50)?;
    let requested_asset = FungibleAsset::new(eth_faucet.id(), 25)?;

    let mut rng = RandomCoin::new(Word::default());
    // Create a PRIVATE swap note (output notes should also be Private)
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(alice.id())
        .build();
    let pswap_note: Note = PswapNote::builder()
        .sender(alice.id())
        .storage(storage)
        .serial_number(rng.draw_word())
        .note_type(NoteType::Private)
        .offered_asset(offered_asset)
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));

    let mut mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), Word::from([Felt::from(25u32), Felt::from(0u32), ZERO, ZERO]));

    // Expected P2ID note should inherit Private type from swap note
    let pswap = PswapNote::try_from(&pswap_note)?;
    let (p2id_note, _remainder) =
        pswap.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 25)?), None)?;

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .extend_expected_output_notes(vec![RawOutputNote::Full(p2id_note)])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify: 1 P2ID note with 25 ETH
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 1, "Expected exactly 1 P2ID note");

    let p2id_assets = output_notes.get_note(0).assets();
    assert_eq!(p2id_assets.num_assets(), 1);
    if let Asset::Fungible(f) = p2id_assets.iter().next().unwrap() {
        assert_eq!(f.faucet_id(), eth_faucet.id());
        assert_eq!(f.amount(), 25);
    } else {
        panic!("Expected fungible asset in P2ID note");
    }

    // Verify Bob's vault delta: +50 USDC, -25 ETH
    let vault_delta = executed_transaction.account_delta().vault();
    let added: Vec<Asset> = vault_delta.added_assets().collect();
    let removed: Vec<Asset> = vault_delta.removed_assets().collect();

    assert_eq!(added.len(), 1);
    assert_eq!(removed.len(), 1);
    if let Asset::Fungible(f) = &added[0] {
        assert_eq!(f.faucet_id(), usdc_faucet.id());
        assert_eq!(f.amount(), 50);
    }
    if let Asset::Fungible(f) = &removed[0] {
        assert_eq!(f.faucet_id(), eth_faucet.id());
        assert_eq!(f.amount(), 25);
    }

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    let _ = mock_chain.prove_next_block();

    Ok(())
}

#[tokio::test]
async fn pswap_note_partial_fill_test() -> anyhow::Result<()> {
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
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(alice.id())
        .build();
    let pswap_note: Note = PswapNote::builder()
        .sender(alice.id())
        .storage(storage)
        .serial_number(rng.draw_word())
        .note_type(NoteType::Public)
        .offered_asset(offered_asset)
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));

    let mut mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), Word::from([Felt::from(20u32), Felt::from(0u32), ZERO, ZERO]));

    let pswap = PswapNote::try_from(&pswap_note)?;
    let (p2id_note, remainder_pswap) =
        pswap.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 20)?), None)?;
    let remainder_note =
        Note::from(remainder_pswap.expect("partial fill should produce remainder"));

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(p2id_note),
            RawOutputNote::Full(remainder_note),
        ])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify: 2 output notes (P2ID + remainder)
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 2);

    // P2ID note: 20 ETH
    if let Asset::Fungible(f) = output_notes.get_note(0).assets().iter().next().unwrap() {
        assert_eq!(f.faucet_id(), eth_faucet.id());
        assert_eq!(f.amount(), 20);
    }

    // SWAPp remainder: 10 USDC
    if let Asset::Fungible(f) = output_notes.get_note(1).assets().iter().next().unwrap() {
        assert_eq!(f.faucet_id(), usdc_faucet.id());
        assert_eq!(f.amount(), 10);
    }

    // Bob's vault: +40 USDC, -20 ETH
    let vault_delta = executed_transaction.account_delta().vault();
    let added: Vec<Asset> = vault_delta.added_assets().collect();
    let removed: Vec<Asset> = vault_delta.removed_assets().collect();
    assert_eq!(added.len(), 1);
    assert_eq!(removed.len(), 1);
    if let Asset::Fungible(f) = &added[0] {
        assert_eq!(f.faucet_id(), usdc_faucet.id());
        assert_eq!(f.amount(), 40);
    }
    if let Asset::Fungible(f) = &removed[0] {
        assert_eq!(f.faucet_id(), eth_faucet.id());
        assert_eq!(f.amount(), 20);
    }

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    let _ = mock_chain.prove_next_block();

    Ok(())
}

#[tokio::test]
async fn pswap_note_inflight_cross_swap_test() -> anyhow::Result<()> {
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
    let alice_requested_asset = FungibleAsset::new(eth_faucet.id(), 25)?;
    let storage = PswapNoteStorage::builder()
        .requested_asset(alice_requested_asset)
        .creator_account_id(alice.id())
        .build();
    let alice_pswap_note: Note = PswapNote::builder()
        .sender(alice.id())
        .storage(storage)
        .serial_number(rng.draw_word())
        .note_type(NoteType::Public)
        .offered_asset(FungibleAsset::new(usdc_faucet.id(), 50)?)
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(alice_pswap_note.clone()));

    // Bob's note: offers 25 ETH, requests 50 USDC
    let bob_requested_asset = FungibleAsset::new(usdc_faucet.id(), 50)?;
    let storage = PswapNoteStorage::builder()
        .requested_asset(bob_requested_asset)
        .creator_account_id(bob.id())
        .build();
    let bob_pswap_note: Note = PswapNote::builder()
        .sender(bob.id())
        .storage(storage)
        .serial_number(rng.draw_word())
        .note_type(NoteType::Public)
        .offered_asset(FungibleAsset::new(eth_faucet.id(), 25)?)
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(bob_pswap_note.clone()));

    let mock_chain = builder.build()?;

    // Note args: pure inflight (input=0, inflight=full amount)
    let mut note_args_map = BTreeMap::new();
    note_args_map
        .insert(alice_pswap_note.id(), Word::from([Felt::from(0u32), Felt::from(25u32), ZERO, ZERO]));
    note_args_map
        .insert(bob_pswap_note.id(), Word::from([Felt::from(0u32), Felt::from(50u32), ZERO, ZERO]));

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
    let requested_asset = FungibleAsset::new(eth_faucet.id(), 25)?;
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(alice.id())
        .build();
    let pswap_note: Note = PswapNote::builder()
        .sender(alice.id())
        .storage(storage)
        .serial_number(rng.draw_word())
        .note_type(NoteType::Public)
        .offered_asset(FungibleAsset::new(usdc_faucet.id(), 50)?)
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));

    let mock_chain = builder.build()?;

    let tx_context = mock_chain.build_tx_context(alice.id(), &[pswap_note.id()], &[])?.build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify: 0 output notes, Alice gets 50 USDC back
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 0, "Expected 0 output notes for reclaim");

    let account_delta = executed_transaction.account_delta();
    let vault_delta = account_delta.vault();
    let added_assets: Vec<Asset> = vault_delta.added_assets().collect();

    assert_eq!(added_assets.len(), 1, "Alice should receive 1 asset back");
    let usdc_reclaimed = match added_assets[0] {
        Asset::Fungible(f) => f,
        _ => panic!("Expected fungible USDC asset"),
    };
    assert_eq!(usdc_reclaimed.faucet_id(), usdc_faucet.id());
    assert_eq!(usdc_reclaimed.amount(), 50);

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
    let requested_asset = FungibleAsset::new(eth_faucet.id(), 25)?;
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(alice.id())
        .build();
    let pswap_note: Note = PswapNote::builder()
        .sender(alice.id())
        .storage(storage)
        .serial_number(rng.draw_word())
        .note_type(NoteType::Public)
        .offered_asset(FungibleAsset::new(usdc_faucet.id(), 50)?)
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));
    let mock_chain = builder.build()?;

    // Try to fill with 30 ETH when only 25 is requested - should fail
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(pswap_note.id(), Word::from([Felt::from(30u32), Felt::from(0u32), ZERO, ZERO]));

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_note_args(note_args_map)
        .build()?;

    let result = tx_context.execute().await;
    assert!(
        result.is_err(),
        "Transaction should fail when input_amount > requested_asset_total"
    );

    Ok(())
}

#[tokio::test]
async fn pswap_note_multiple_partial_fills_test() -> anyhow::Result<()> {
    let test_scenarios = vec![
        (5u64, "5 ETH - 20% fill"),
        (7, "7 ETH - 28% fill"),
        (10, "10 ETH - 40% fill"),
        (13, "13 ETH - 52% fill"),
        (15, "15 ETH - 60% fill"),
        (19, "19 ETH - 76% fill"),
        (20, "20 ETH - 80% fill"),
        (23, "23 ETH - 92% fill"),
        (25, "25 ETH - 100% fill (full)"),
    ];

    for (input_amount, _description) in test_scenarios {
        let mut builder = MockChain::builder();
        let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
        let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

        let alice = builder.add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
        )?;

        let bob = builder.add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(eth_faucet.id(), input_amount)?.into()],
        )?;

        let mut rng = RandomCoin::new(Word::default());
        let requested_asset = FungibleAsset::new(eth_faucet.id(), 25)?;
        let storage = PswapNoteStorage::builder()
            .requested_asset(requested_asset)
            .creator_account_id(alice.id())
            .build();
        let pswap_note: Note = PswapNote::builder()
            .sender(alice.id())
            .storage(storage)
            .serial_number(rng.draw_word())
            .note_type(NoteType::Public)
            .offered_asset(FungibleAsset::new(usdc_faucet.id(), 50)?)
            .build()?
            .into();
        builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));

        let mock_chain = builder.build()?;

        let mut note_args_map = BTreeMap::new();
        note_args_map.insert(
            pswap_note.id(),
            Word::from([Felt::try_from(input_amount).unwrap(), Felt::from(0u32), ZERO, ZERO]),
        );

        let pswap = PswapNote::try_from(&pswap_note)?;
        let offered_out = pswap.calculate_offered_for_requested(input_amount);
        let (p2id_note, remainder_pswap) = pswap.execute(
            bob.id(),
            Some(FungibleAsset::new(eth_faucet.id(), input_amount)?),
            None,
        )?;

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
        let expected_count = if input_amount < 25 { 2 } else { 1 };
        assert_eq!(output_notes.num_notes(), expected_count);

        // Verify Bob's vault
        let vault_delta = executed_transaction.account_delta().vault();
        let added: Vec<Asset> = vault_delta.added_assets().collect();
        assert_eq!(added.len(), 1);
        if let Asset::Fungible(f) = added[0] {
            assert_eq!(f.amount(), offered_out);
        }
    }

    Ok(())
}

#[tokio::test]
async fn pswap_note_non_exact_ratio_partial_fill_test() -> anyhow::Result<()> {
    let offered_total = 100u64;
    let requested_total = 30u64;
    let input_amount = 7u64;

    let mut builder = MockChain::builder();
    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 10000, Some(1000))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 10000, Some(100))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), offered_total)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), input_amount)?.into()],
    )?;

    let mut rng = RandomCoin::new(Word::default());
    let requested_asset = FungibleAsset::new(eth_faucet.id(), requested_total)?;
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(alice.id())
        .build();
    let pswap_note: Note = PswapNote::builder()
        .sender(alice.id())
        .storage(storage)
        .serial_number(rng.draw_word())
        .note_type(NoteType::Public)
        .offered_asset(FungibleAsset::new(usdc_faucet.id(), offered_total)?)
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));

    let mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map
        .insert(pswap_note.id(), Word::from([Felt::try_from(input_amount).unwrap(), Felt::from(0u32), ZERO, ZERO]));

    let pswap = PswapNote::try_from(&pswap_note)?;
    let expected_output = pswap.calculate_offered_for_requested(input_amount);
    let (p2id_note, remainder_pswap) = pswap.execute(
        bob.id(),
        Some(FungibleAsset::new(eth_faucet.id(), input_amount)?),
        None,
    )?;
    let remainder = Note::from(remainder_pswap.expect("partial fill should produce remainder"));

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[pswap_note.id()], &[])?
        .extend_expected_output_notes(vec![
            RawOutputNote::Full(p2id_note),
            RawOutputNote::Full(remainder),
        ])
        .extend_note_args(note_args_map)
        .build()?;

    let executed_tx = tx_context.execute().await?;

    let output_notes = executed_tx.output_notes();
    assert_eq!(output_notes.num_notes(), 2);

    let vault_delta = executed_tx.account_delta().vault();
    let added: Vec<Asset> = vault_delta.added_assets().collect();
    assert_eq!(added.len(), 1);
    if let Asset::Fungible(f) = &added[0] {
        assert_eq!(f.amount(), expected_output);
    }

    Ok(())
}

#[tokio::test]
async fn pswap_note_partial_fill_non_integer_ratio_fuzz_test() -> anyhow::Result<()> {
    // (offered_usdc, requested_eth, fill_eth)
    let test_cases: Vec<(u64, u64, u64)> = vec![
        (23, 20, 7),
        (23, 20, 13),
        (23, 20, 19),
        (17, 13, 5),
        (97, 89, 37),
        (53, 47, 23),
        (7, 5, 3),
        (7, 5, 1),
        (7, 5, 4),
        (89, 55, 21),
        (233, 144, 55),
        (34, 21, 8),
        (50, 97, 30),
        (13, 47, 20),
        (3, 7, 5),
        (101, 100, 50),
        (100, 99, 50),
        (997, 991, 500),
        (1000, 3, 1),
        (1000, 3, 2),
        (3, 1000, 500),
        (9999, 7777, 3333),
        (5000, 3333, 1111),
        (127, 63, 31),
        (255, 127, 63),
        (511, 255, 100),
    ];

    for (i, (offered_usdc, requested_eth, fill_eth)) in test_cases.iter().enumerate() {
        let remaining_requested = requested_eth - fill_eth;

        let mut builder = MockChain::builder();
        let max_supply = 100_000u64;

        let usdc_faucet = builder.add_existing_basic_faucet(
            BASIC_AUTH,
            "USDC",
            max_supply,
            Some(*offered_usdc),
        )?;
        let eth_faucet =
            builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", max_supply, Some(*fill_eth))?;

        let alice = builder.add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(usdc_faucet.id(), *offered_usdc)?.into()],
        )?;
        let bob = builder.add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(eth_faucet.id(), *fill_eth)?.into()],
        )?;

        let mut rng = RandomCoin::new(Word::default());
        let requested_asset = FungibleAsset::new(eth_faucet.id(), *requested_eth)?;
        let storage = PswapNoteStorage::builder()
            .requested_asset(requested_asset)
            .creator_account_id(alice.id())
            .build();
        let pswap_note: Note = PswapNote::builder()
            .sender(alice.id())
            .storage(storage)
            .serial_number(rng.draw_word())
            .note_type(NoteType::Public)
            .offered_asset(FungibleAsset::new(usdc_faucet.id(), *offered_usdc)?)
            .build()?
            .into();
        builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));

        let mock_chain = builder.build()?;

        let mut note_args_map = BTreeMap::new();
        note_args_map
            .insert(pswap_note.id(), Word::from([Felt::try_from(*fill_eth).unwrap(), Felt::from(0u32), ZERO, ZERO]));

        let pswap = PswapNote::try_from(&pswap_note)?;
        let offered_out = pswap.calculate_offered_for_requested(*fill_eth);
        let remaining_offered = offered_usdc - offered_out;

        assert!(offered_out > 0, "Case {}: offered_out must be > 0", i + 1);
        assert!(offered_out <= *offered_usdc, "Case {}: offered_out > offered", i + 1);
        let (p2id_note, remainder_pswap) = pswap.execute(
            bob.id(),
            Some(FungibleAsset::new(eth_faucet.id(), *fill_eth)?),
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
                "Case {} failed: {} (offered={}, requested={}, fill={})",
                i + 1,
                e,
                offered_usdc,
                requested_eth,
                fill_eth
            )
        })?;

        let output_notes = executed_tx.output_notes();
        let expected_count = if remaining_requested > 0 { 2 } else { 1 };
        assert_eq!(output_notes.num_notes(), expected_count, "Case {}", i + 1);

        let vault_delta = executed_tx.account_delta().vault();
        let added: Vec<Asset> = vault_delta.added_assets().collect();
        let removed: Vec<Asset> = vault_delta.removed_assets().collect();
        assert_eq!(added.len(), 1, "Case {}", i + 1);
        if let Asset::Fungible(f) = &added[0] {
            assert_eq!(f.amount(), offered_out, "Case {}", i + 1);
        }
        assert_eq!(removed.len(), 1, "Case {}", i + 1);
        if let Asset::Fungible(f) = &removed[0] {
            assert_eq!(f.amount(), *fill_eth, "Case {}", i + 1);
        }

        assert_eq!(offered_out + remaining_offered, *offered_usdc, "Case {}: conservation", i + 1);
    }

    Ok(())
}

#[tokio::test]
async fn pswap_note_chained_partial_fills_non_integer_ratio_test() -> anyhow::Result<()> {
    let test_chains: Vec<(u64, u64, Vec<u64>)> = vec![
        (100, 73, vec![17, 23, 19]),
        (53, 47, vec![7, 11, 13, 5]),
        (200, 137, vec![41, 37, 29]),
        (7, 5, vec![2, 1]),
        (1000, 777, vec![100, 200, 150, 100]),
        (50, 97, vec![20, 30, 15]),
        (89, 55, vec![13, 8, 21]),
        (23, 20, vec![3, 5, 4, 3]),
        (997, 991, vec![300, 300, 200]),
        (3, 2, vec![1]),
    ];

    for (chain_idx, (initial_offered, initial_requested, fills)) in test_chains.iter().enumerate() {
        let mut current_offered = *initial_offered;
        let mut current_requested = *initial_requested;
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
            let eth_faucet = builder.add_existing_basic_faucet(
                BASIC_AUTH,
                "ETH",
                max_supply,
                Some(*fill_amount),
            )?;

            let alice = builder.add_existing_wallet_with_assets(
                BASIC_AUTH,
                [FungibleAsset::new(usdc_faucet.id(), current_offered)?.into()],
            )?;
            let bob = builder.add_existing_wallet_with_assets(
                BASIC_AUTH,
                [FungibleAsset::new(eth_faucet.id(), *fill_amount)?.into()],
            )?;

            // Build storage and note manually to use the correct serial for chain position
            let offered_fungible =
                FungibleAsset::new(usdc_faucet.id(), current_offered)?;
            let requested_fungible =
                FungibleAsset::new(eth_faucet.id(), current_requested)?;

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
            note_args_map.insert(
                pswap_note.id(),
                Word::from([Felt::try_from(*fill_amount).unwrap(), Felt::from(0u32), ZERO, ZERO]),
            );

            let pswap = PswapNote::try_from(&pswap_note)?;
            let offered_out = pswap.calculate_offered_for_requested(*fill_amount);
            let remaining_offered = current_offered - offered_out;
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
                    "Chain {} fill {} failed: {} (offered={}, requested={}, fill={})",
                    chain_idx + 1,
                    current_swap_count + 1,
                    e,
                    current_offered,
                    current_requested,
                    fill_amount
                )
            })?;

            let output_notes = executed_tx.output_notes();
            let expected_count = if remaining_requested > 0 { 2 } else { 1 };
            assert_eq!(
                output_notes.num_notes(),
                expected_count,
                "Chain {} fill {}",
                chain_idx + 1,
                current_swap_count + 1
            );

            let vault_delta = executed_tx.account_delta().vault();
            let added: Vec<Asset> = vault_delta.added_assets().collect();
            assert_eq!(added.len(), 1, "Chain {} fill {}", chain_idx + 1, current_swap_count + 1);
            if let Asset::Fungible(f) = &added[0] {
                assert_eq!(
                    f.amount(),
                    offered_out,
                    "Chain {} fill {}: Bob should get {} USDC",
                    chain_idx + 1,
                    current_swap_count + 1,
                    offered_out
                );
            }

            // Update state for next fill
            total_usdc_to_bob += offered_out;
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
        assert_eq!(total_eth_from_bob, total_fills, "Chain {}: ETH conservation", chain_idx + 1);
        assert_eq!(
            total_usdc_to_bob + current_offered,
            *initial_offered,
            "Chain {}: USDC conservation",
            chain_idx + 1
        );
    }

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
    let (p2id_note, remainder) =
        pswap.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 25).unwrap()), None).unwrap();
    assert!(remainder.is_none(), "Full fill should not produce remainder");

    // Verify P2ID note properties
    assert_eq!(p2id_note.metadata().sender(), bob.id(), "P2ID sender should be consumer");
    assert_eq!(p2id_note.metadata().note_type(), NoteType::Public, "P2ID note type mismatch");
    assert_eq!(p2id_note.assets().num_assets(), 1, "P2ID should have 1 asset");
    if let Asset::Fungible(f) = p2id_note.assets().iter().next().unwrap() {
        assert_eq!(f.faucet_id(), eth_faucet.id(), "P2ID asset faucet mismatch");
        assert_eq!(f.amount(), 25, "P2ID asset amount mismatch");
    } else {
        panic!("Expected fungible asset in P2ID note");
    }

    // Partial fill: should produce P2ID note + remainder
    let (p2id_partial, remainder_partial) =
        pswap.execute(bob.id(), Some(FungibleAsset::new(eth_faucet.id(), 10).unwrap()), None).unwrap();
    let remainder_pswap = remainder_partial.expect("Partial fill should produce remainder");

    assert_eq!(p2id_partial.assets().num_assets(), 1);
    if let Asset::Fungible(f) = p2id_partial.assets().iter().next().unwrap() {
        assert_eq!(f.faucet_id(), eth_faucet.id());
        assert_eq!(f.amount(), 10);
    }

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
    let requested_asset = FungibleAsset::new(eth_faucet.id(), 25).unwrap();
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(alice.id())
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

    let storage = pswap_note.recipient().storage();
    let items = storage.items();

    let parsed = PswapNoteStorage::try_from(items).unwrap();

    assert_eq!(parsed.creator_account_id(), alice.id(), "Creator ID roundtrip failed!");
    assert_eq!(parsed.swap_count(), 0, "Swap count should be 0");

    // Verify requested amount from value word
    assert_eq!(parsed.requested_asset_amount(), 25, "Requested amount should be 25");
}

/// Test that a PSWAP note can be consumed by a network account (full fill, no note_args).
///
/// Alice (local) creates a PSWAP note offering 50 USDC for 25 ETH. A network account with a
/// BasicWallet consumes it. Since no note_args are provided, the script defaults to a full fill.
#[tokio::test]
async fn pswap_note_network_account_full_fill_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;

    // Create a network account with BasicWallet that holds 25 ETH
    let seed: [u8; 32] = builder.rng_mut().draw_word().into();
    let network_consumer = builder.add_account_from_builder(
        BASIC_AUTH,
        Account::builder(seed)
            .storage_mode(AccountStorageMode::Network)
            .with_component(BasicWallet)
            .with_assets([FungibleAsset::new(eth_faucet.id(), 25)?.into()]),
        miden_testing::AccountState::Exists,
    )?;

    let requested_asset = FungibleAsset::new(eth_faucet.id(), 25)?;

    let mut rng = RandomCoin::new(Word::default());
    let storage = PswapNoteStorage::builder()
        .requested_asset(requested_asset)
        .creator_account_id(alice.id())
        .build();
    let pswap_note: Note = PswapNote::builder()
        .sender(alice.id())
        .storage(storage)
        .serial_number(rng.draw_word())
        .note_type(NoteType::Public)
        .offered_asset(FungibleAsset::new(usdc_faucet.id(), 50)?)
        .build()?
        .into();
    builder.add_output_note(RawOutputNote::Full(pswap_note.clone()));

    let mut mock_chain = builder.build()?;

    // No note_args — simulates a network transaction where args default to [0, 0, 0, 0].
    // The PSWAP script defaults to a full fill when both input and inflight are 0.
    let pswap = PswapNote::try_from(&pswap_note)?;
    let p2id_note = pswap.execute_full_fill_network(network_consumer.id())?;

    let tx_context = mock_chain
        .build_tx_context(network_consumer.id(), &[pswap_note.id()], &[])?
        .extend_expected_output_notes(vec![RawOutputNote::Full(p2id_note.clone())])
        .build()?;

    let executed_transaction = tx_context.execute().await?;

    // Verify: 1 P2ID note with 25 ETH for Alice
    let output_notes = executed_transaction.output_notes();
    assert_eq!(output_notes.num_notes(), 1, "Expected exactly 1 P2ID note");

    let actual_recipient = output_notes.get_note(0).recipient_digest();
    let expected_recipient = p2id_note.recipient().digest();
    assert_eq!(actual_recipient, expected_recipient, "Recipient mismatch");

    let p2id_assets = output_notes.get_note(0).assets();
    assert_eq!(p2id_assets.num_assets(), 1);
    if let Asset::Fungible(f) = p2id_assets.iter().next().unwrap() {
        assert_eq!(f.faucet_id(), eth_faucet.id());
        assert_eq!(f.amount(), 25);
    } else {
        panic!("Expected fungible asset in P2ID note");
    }

    // Verify network consumer's vault delta: +50 USDC, -25 ETH
    let vault_delta = executed_transaction.account_delta().vault();
    let added: Vec<Asset> = vault_delta.added_assets().collect();
    let removed: Vec<Asset> = vault_delta.removed_assets().collect();

    assert_eq!(added.len(), 1);
    assert_eq!(removed.len(), 1);
    if let Asset::Fungible(f) = &added[0] {
        assert_eq!(f.faucet_id(), usdc_faucet.id());
        assert_eq!(f.amount(), 50);
    }
    if let Asset::Fungible(f) = &removed[0] {
        assert_eq!(f.faucet_id(), eth_faucet.id());
        assert_eq!(f.amount(), 25);
    }

    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    let _ = mock_chain.prove_next_block();

    Ok(())
}
