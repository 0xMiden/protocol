use std::collections::BTreeMap;

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::account::AccountId;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::{
    Note, NoteAssets, NoteAttachment, NoteMetadata, NoteRecipient, NoteStorage, NoteTag, NoteType,
};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word, ZERO};
use miden_standards::note::{PswapNote, PswapNoteStorage};
use miden_testing::{Auth, MockChain};

use crate::prove_and_verify_transaction;

// CONSTANTS
// ================================================================================================

const BASIC_AUTH: Auth = Auth::BasicAuth {
    auth_scheme: AuthScheme::Falcon512Poseidon2,
};

// HELPER FUNCTIONS
// ================================================================================================

/// Compute the P2ID tag for a local account
fn compute_p2id_tag_for_local_account(account_id: AccountId) -> NoteTag {
    NoteTag::with_account_target(account_id)
}

/// Helper function to compute P2ID tag as Felt for use in note storage
fn compute_p2id_tag_felt(account_id: AccountId) -> Felt {
    let p2id_tag = compute_p2id_tag_for_local_account(account_id);
    Felt::new(u32::from(p2id_tag) as u64)
}

/// Create a PSWAP note via PswapNote::create.
fn create_pswap_note(
    sender_id: AccountId,
    note_assets: NoteAssets,
    storage_items: Vec<Felt>,
    _note_tag: NoteTag,
) -> Note {
    create_pswap_note_with_type(sender_id, note_assets, storage_items, _note_tag, NoteType::Public)
}

/// Create a PSWAP note with specified note type via PswapNote::create.
fn create_pswap_note_with_type(
    sender_id: AccountId,
    note_assets: NoteAssets,
    storage_items: Vec<Felt>,
    _note_tag: NoteTag,
    note_type: NoteType,
) -> Note {
    let offered_asset = *note_assets.iter().next().expect("must have offered asset");
    let requested_asset = PswapNoteStorage::try_from(storage_items.as_slice())
        .expect("Failed to parse storage")
        .requested_asset()
        .expect("Failed to parse requested asset from storage");

    use miden_protocol::crypto::rand::RpoRandomCoin;
    let mut rng = RpoRandomCoin::new(Word::default());

    PswapNote::create(
        sender_id,
        offered_asset,
        requested_asset,
        note_type,
        NoteAttachment::default(),
        &mut rng,
    )
    .expect("Failed to create PSWAP note")
}

/// Delegates to PswapNote::calculate_output_amount.
fn calculate_output_amount(offered_total: u64, requested_total: u64, input_amount: u64) -> u64 {
    PswapNote::calculate_output_amount(offered_total, requested_total, input_amount)
}

/// Build 18-item storage vector for a PSWAP note (KEY+VALUE format).
/// Kept for tests that construct notes with custom serials (chained fills).
fn build_pswap_storage(
    requested_faucet_id: AccountId,
    requested_amount: u64,
    _pswap_tag_felt: Felt,
    _p2id_tag_felt: Felt,
    swap_count: u64,
    creator_id: AccountId,
) -> Vec<Felt> {
    let requested_asset = Asset::Fungible(
        FungibleAsset::new(requested_faucet_id, requested_amount)
            .expect("Failed to create requested fungible asset"),
    );
    let offered_dummy = Asset::Fungible(
        FungibleAsset::new(requested_faucet_id, 1).expect("dummy offered asset"),
    );
    let key_word = requested_asset.to_key_word();
    let value_word = requested_asset.to_value_word();
    let tag = PswapNote::build_tag(NoteType::Public, &offered_dummy, &requested_asset);
    let pswap_tag_felt = Felt::new(u32::from(tag) as u64);
    let p2id_tag = NoteTag::with_account_target(creator_id);
    let p2id_tag_felt = Felt::new(u32::from(p2id_tag) as u64);

    vec![
        key_word[0], key_word[1], key_word[2], key_word[3],
        value_word[0], value_word[1], value_word[2], value_word[3],
        pswap_tag_felt, p2id_tag_felt,
        ZERO, ZERO,
        Felt::new(swap_count), ZERO, ZERO, ZERO,
        creator_id.prefix().as_felt(), creator_id.suffix(),
    ]
}

/// Create expected P2ID note via PswapNote::create_p2id_payback_note.
fn create_expected_pswap_p2id_note(
    swap_note: &Note,
    consumer_id: AccountId,
    _creator_id: AccountId,
    _swap_count: u64,
    total_fill: u64,
    requested_faucet_id: AccountId,
    _p2id_tag: NoteTag,
) -> anyhow::Result<Note> {
    let note_type = swap_note.metadata().note_type();
    create_expected_pswap_p2id_note_with_type(
        swap_note,
        consumer_id,
        _creator_id,
        _swap_count,
        total_fill,
        requested_faucet_id,
        note_type,
    )
}

/// Create expected P2ID note via PswapNote::build_p2id_payback_note.
///
/// The P2ID note inherits its note type from the swap note.
fn create_expected_pswap_p2id_note_with_type(
    swap_note: &Note,
    consumer_id: AccountId,
    _creator_id: AccountId,
    _swap_count: u64,
    total_fill: u64,
    requested_faucet_id: AccountId,
    _note_type: NoteType,
) -> anyhow::Result<Note> {
    let pswap = PswapNote::try_from(swap_note)?;
    let payback_asset = Asset::Fungible(FungibleAsset::new(requested_faucet_id, total_fill)?);
    let aux_word = Word::from([Felt::new(total_fill), ZERO, ZERO, ZERO]);

    Ok(pswap.build_p2id_payback_note(consumer_id, payback_asset, aux_word)?)
}

/// Create NoteAssets with a single fungible asset
fn make_note_assets(faucet_id: AccountId, amount: u64) -> anyhow::Result<NoteAssets> {
    let asset = FungibleAsset::new(faucet_id, amount)?;
    Ok(NoteAssets::new(vec![asset.into()])?)
}

/// Create a dummy SWAPp tag and its Felt representation.
/// Kept for backward compatibility with test call sites.
fn make_pswap_tag() -> (NoteTag, Felt) {
    let tag = NoteTag::new(0xC0000000);
    let felt = Felt::new(u32::from(tag) as u64);
    (tag, felt)
}

/// Build note args Word from input and inflight amounts.
/// LE stack orientation: Word[0] = input_amount (on top), Word[1] = inflight_amount
fn make_note_args(input_amount: u64, inflight_amount: u64) -> Word {
    Word::from([
        Felt::new(input_amount),
        Felt::new(inflight_amount),
        ZERO,
        ZERO,
    ])
}

/// Create expected remainder note via PswapNote::create_remainder_note.
fn create_expected_pswap_remainder_note(
    swap_note: &Note,
    consumer_id: AccountId,
    _creator_id: AccountId,
    remaining_offered: u64,
    remaining_requested: u64,
    offered_out: u64,
    _swap_count: u64,
    offered_faucet_id: AccountId,
    _requested_faucet_id: AccountId,
    _pswap_tag: NoteTag,
    _pswap_tag_felt: Felt,
    _p2id_tag_felt: Felt,
) -> anyhow::Result<Note> {
    let pswap = PswapNote::try_from(swap_note)?;
    let remaining_offered_asset =
        Asset::Fungible(FungibleAsset::new(offered_faucet_id, remaining_offered)?);

    Ok(Note::from(pswap.build_remainder_pswap_note(
        consumer_id,
        remaining_offered_asset,
        remaining_requested,
        offered_out,
    )?))
}

// TESTS
// ================================================================================================

#[tokio::test]
async fn pswap_note_full_fill_test() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    let usdc_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 25)?.into()],
    )?;

    let (pswap_tag, pswap_tag_felt) = make_pswap_tag();
    let p2id_tag_felt = compute_p2id_tag_felt(alice.id());

    let storage_items = build_pswap_storage(
        eth_faucet.id(),
        25,
        pswap_tag_felt,
        p2id_tag_felt,
        0,
        alice.id(),
    );
    let note_assets = make_note_assets(usdc_faucet.id(), 50)?;
    let swap_note = create_pswap_note(alice.id(), note_assets, storage_items, pswap_tag);
    builder.add_output_note(RawOutputNote::Full(swap_note.clone()));

    let mut mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(swap_note.id(), make_note_args(25, 0));

    let p2id_note = create_expected_pswap_p2id_note(
        &swap_note,
        bob.id(),
        alice.id(),
        0,
        25,
        eth_faucet.id(),
        compute_p2id_tag_for_local_account(alice.id()),
    )?;

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[swap_note.id()], &[])?
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

    let usdc_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 25)?.into()],
    )?;

    let (pswap_tag, pswap_tag_felt) = make_pswap_tag();
    let p2id_tag_felt = compute_p2id_tag_felt(alice.id());

    let storage_items = build_pswap_storage(
        eth_faucet.id(),
        25,
        pswap_tag_felt,
        p2id_tag_felt,
        0,
        alice.id(),
    );
    let note_assets = make_note_assets(usdc_faucet.id(), 50)?;

    // Create a PRIVATE swap note (output notes should also be Private)
    let swap_note = create_pswap_note_with_type(
        alice.id(),
        note_assets,
        storage_items,
        pswap_tag,
        NoteType::Private,
    );
    builder.add_output_note(RawOutputNote::Full(swap_note.clone()));

    let mut mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(swap_note.id(), make_note_args(25, 0));

    // Expected P2ID note should inherit Private type from swap note
    let p2id_note = create_expected_pswap_p2id_note_with_type(
        &swap_note,
        bob.id(),
        alice.id(),
        0,
        25,
        eth_faucet.id(),
        compute_p2id_tag_for_local_account(alice.id()),
        NoteType::Private,
    )?;

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[swap_note.id()], &[])?
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

    let usdc_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), 20)?.into()],
    )?;

    let (pswap_tag, pswap_tag_felt) = make_pswap_tag();
    let p2id_tag_felt = compute_p2id_tag_felt(alice.id());

    let storage_items = build_pswap_storage(
        eth_faucet.id(),
        25,
        pswap_tag_felt,
        p2id_tag_felt,
        0,
        alice.id(),
    );
    let note_assets = make_note_assets(usdc_faucet.id(), 50)?;
    let swap_note = create_pswap_note(alice.id(), note_assets, storage_items, pswap_tag);
    builder.add_output_note(RawOutputNote::Full(swap_note.clone()));

    let mut mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(swap_note.id(), make_note_args(20, 0));

    // Expected P2ID note: 20 ETH for Alice
    let p2id_note = create_expected_pswap_p2id_note(
        &swap_note,
        bob.id(),
        alice.id(),
        0,
        20,
        eth_faucet.id(),
        compute_p2id_tag_for_local_account(alice.id()),
    )?;

    // Expected SWAPp remainder: 10 USDC for 5 ETH (offered_out=40, remaining=50-40=10)
    let remainder_note = create_expected_pswap_remainder_note(
        &swap_note,
        bob.id(),
        alice.id(),
        10,
        5,
        40,
        0,
        usdc_faucet.id(),
        eth_faucet.id(),
        pswap_tag,
        pswap_tag_felt,
        p2id_tag_felt,
    )?;

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[swap_note.id()], &[])?
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
    if let Asset::Fungible(f) = output_notes
        .get_note(0)
        .assets()
        .iter()
        .next()
        .unwrap()
    {
        assert_eq!(f.faucet_id(), eth_faucet.id());
        assert_eq!(f.amount(), 20);
    }

    // SWAPp remainder: 10 USDC
    if let Asset::Fungible(f) = output_notes
        .get_note(1)
        .assets()
        .iter()
        .next()
        .unwrap()
    {
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

    let usdc_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
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

    let (pswap_tag, pswap_tag_felt) = make_pswap_tag();

    // Alice's note: offers 50 USDC, requests 25 ETH
    let alice_storage = build_pswap_storage(
        eth_faucet.id(),
        25,
        pswap_tag_felt,
        compute_p2id_tag_felt(alice.id()),
        0,
        alice.id(),
    );
    let alice_swap_note = create_pswap_note(
        alice.id(),
        make_note_assets(usdc_faucet.id(), 50)?,
        alice_storage,
        pswap_tag,
    );
    builder.add_output_note(RawOutputNote::Full(alice_swap_note.clone()));

    // Bob's note: offers 25 ETH, requests 50 USDC
    let bob_storage = build_pswap_storage(
        usdc_faucet.id(),
        50,
        pswap_tag_felt,
        compute_p2id_tag_felt(bob.id()),
        0,
        bob.id(),
    );
    let bob_swap_note = create_pswap_note(
        bob.id(),
        make_note_assets(eth_faucet.id(), 25)?,
        bob_storage,
        pswap_tag,
    );
    builder.add_output_note(RawOutputNote::Full(bob_swap_note.clone()));

    let mock_chain = builder.build()?;

    // Note args: pure inflight (input=0, inflight=full amount)
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(alice_swap_note.id(), make_note_args(0, 25));
    note_args_map.insert(bob_swap_note.id(), make_note_args(0, 50));

    // Expected P2ID notes
    let alice_p2id_note = create_expected_pswap_p2id_note(
        &alice_swap_note,
        charlie.id(),
        alice.id(),
        0,
        25,
        eth_faucet.id(),
        compute_p2id_tag_for_local_account(alice.id()),
    )?;
    let bob_p2id_note = create_expected_pswap_p2id_note(
        &bob_swap_note,
        charlie.id(),
        bob.id(),
        0,
        50,
        usdc_faucet.id(),
        compute_p2id_tag_for_local_account(bob.id()),
    )?;

    let tx_context = mock_chain
        .build_tx_context(
            charlie.id(),
            &[alice_swap_note.id(), bob_swap_note.id()],
            &[],
        )?
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
        if let Asset::Fungible(f) = output_notes
            .get_note(idx)
            .assets()
            .iter()
            .next()
            .unwrap()
        {
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
    let _eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(25))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
    )?;

    let (pswap_tag, pswap_tag_felt) = make_pswap_tag();
    let p2id_tag_felt = compute_p2id_tag_felt(alice.id());

    let storage_items = build_pswap_storage(
        _eth_faucet.id(),
        25,
        pswap_tag_felt,
        p2id_tag_felt,
        0,
        alice.id(),
    );
    let swap_note = create_pswap_note(
        alice.id(),
        make_note_assets(usdc_faucet.id(), 50)?,
        storage_items,
        pswap_tag,
    );
    builder.add_output_note(RawOutputNote::Full(swap_note.clone()));

    let mock_chain = builder.build()?;

    let tx_context = mock_chain
        .build_tx_context(alice.id(), &[swap_note.id()], &[])?
        .build()?;

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

    let (pswap_tag, pswap_tag_felt) = make_pswap_tag();
    let p2id_tag_felt = compute_p2id_tag_felt(alice.id());

    let storage_items = build_pswap_storage(
        eth_faucet.id(),
        25,
        pswap_tag_felt,
        p2id_tag_felt,
        0,
        alice.id(),
    );
    let swap_note = create_pswap_note(
        alice.id(),
        make_note_assets(usdc_faucet.id(), 50)?,
        storage_items,
        pswap_tag,
    );
    builder.add_output_note(RawOutputNote::Full(swap_note.clone()));
    let mock_chain = builder.build()?;

    // Try to fill with 30 ETH when only 25 is requested - should fail
    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(swap_note.id(), make_note_args(30, 0));

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[swap_note.id()], &[])?
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
        let usdc_faucet =
            builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))?;
        let eth_faucet =
            builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))?;

        let alice = builder.add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(usdc_faucet.id(), 50)?.into()],
        )?;

        let bob = builder.add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(eth_faucet.id(), input_amount)?.into()],
        )?;

        let (pswap_tag, pswap_tag_felt) = make_pswap_tag();
        let p2id_tag_felt = compute_p2id_tag_felt(alice.id());

        let storage_items = build_pswap_storage(
            eth_faucet.id(),
            25,
            pswap_tag_felt,
            p2id_tag_felt,
            0,
            alice.id(),
        );
        let swap_note = create_pswap_note(
            alice.id(),
            make_note_assets(usdc_faucet.id(), 50)?,
            storage_items,
            pswap_tag,
        );
        builder.add_output_note(RawOutputNote::Full(swap_note.clone()));

        let mock_chain = builder.build()?;

        let offered_out = calculate_output_amount(50, 25, input_amount);
        let remaining_usdc = 50 - offered_out;
        let remaining_eth = 25 - input_amount;

        let mut note_args_map = BTreeMap::new();
        note_args_map.insert(swap_note.id(), make_note_args(input_amount, 0));

        let p2id_note = create_expected_pswap_p2id_note(
            &swap_note,
            bob.id(),
            alice.id(),
            0,
            input_amount,
            eth_faucet.id(),
            compute_p2id_tag_for_local_account(alice.id()),
        )?;

        let mut expected_notes = vec![RawOutputNote::Full(p2id_note)];

        if input_amount < 25 {
            let remainder_note = create_expected_pswap_remainder_note(
                &swap_note,
                bob.id(),
                alice.id(),
                remaining_usdc,
                remaining_eth,
                offered_out,
                0,
                usdc_faucet.id(),
                eth_faucet.id(),
                pswap_tag,
                pswap_tag_felt,
                p2id_tag_felt,
            )?;
            expected_notes.push(RawOutputNote::Full(remainder_note));
        }

        let tx_context = mock_chain
            .build_tx_context(bob.id(), &[swap_note.id()], &[])?
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
    let expected_output = calculate_output_amount(offered_total, requested_total, input_amount);

    let mut builder = MockChain::builder();
    let usdc_faucet =
        builder.add_existing_basic_faucet(BASIC_AUTH, "USDC", 10000, Some(1000))?;
    let eth_faucet = builder.add_existing_basic_faucet(BASIC_AUTH, "ETH", 10000, Some(100))?;

    let alice = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(usdc_faucet.id(), offered_total)?.into()],
    )?;
    let bob = builder.add_existing_wallet_with_assets(
        BASIC_AUTH,
        [FungibleAsset::new(eth_faucet.id(), input_amount)?.into()],
    )?;

    let pswap_tag = NoteTag::new(0xC0000000);
    let pswap_tag_felt = Felt::new(u32::from(pswap_tag) as u64);
    let p2id_tag_felt = compute_p2id_tag_felt(alice.id());

    let storage_items = build_pswap_storage(
        eth_faucet.id(),
        requested_total,
        pswap_tag_felt,
        p2id_tag_felt,
        0,
        alice.id(),
    );
    let note_assets = make_note_assets(usdc_faucet.id(), offered_total)?;
    let swap_note = create_pswap_note(alice.id(), note_assets, storage_items, pswap_tag);
    builder.add_output_note(RawOutputNote::Full(swap_note.clone()));

    let mock_chain = builder.build()?;

    let mut note_args_map = BTreeMap::new();
    note_args_map.insert(swap_note.id(), make_note_args(input_amount, 0));

    let remaining_offered = offered_total - expected_output;
    let remaining_requested = requested_total - input_amount;

    let p2id_note = create_expected_pswap_p2id_note(
        &swap_note,
        bob.id(),
        alice.id(),
        0,
        input_amount,
        eth_faucet.id(),
        compute_p2id_tag_for_local_account(alice.id()),
    )?;
    let remainder = create_expected_pswap_remainder_note(
        &swap_note,
        bob.id(),
        alice.id(),
        remaining_offered,
        remaining_requested,
        expected_output,
        0,
        usdc_faucet.id(),
        eth_faucet.id(),
        pswap_tag,
        pswap_tag_felt,
        p2id_tag_felt,
    )?;

    let tx_context = mock_chain
        .build_tx_context(bob.id(), &[swap_note.id()], &[])?
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
        let offered_out = calculate_output_amount(*offered_usdc, *requested_eth, *fill_eth);
        let remaining_offered = offered_usdc - offered_out;
        let remaining_requested = requested_eth - fill_eth;

        assert!(offered_out > 0, "Case {}: offered_out must be > 0", i + 1);
        assert!(
            offered_out <= *offered_usdc,
            "Case {}: offered_out > offered",
            i + 1
        );

        let mut builder = MockChain::builder();
        let max_supply = 100_000u64;

        let usdc_faucet = builder.add_existing_basic_faucet(
            BASIC_AUTH,
            "USDC",
            max_supply,
            Some(*offered_usdc),
        )?;
        let eth_faucet = builder.add_existing_basic_faucet(
            BASIC_AUTH,
            "ETH",
            max_supply,
            Some(*fill_eth),
        )?;

        let alice = builder.add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(usdc_faucet.id(), *offered_usdc)?.into()],
        )?;
        let bob = builder.add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(eth_faucet.id(), *fill_eth)?.into()],
        )?;

        let pswap_tag = NoteTag::new(0xC0000000);
        let pswap_tag_felt = Felt::new(u32::from(pswap_tag) as u64);
        let p2id_tag_felt = compute_p2id_tag_felt(alice.id());

        let storage_items = build_pswap_storage(
            eth_faucet.id(),
            *requested_eth,
            pswap_tag_felt,
            p2id_tag_felt,
            0,
            alice.id(),
        );
        let note_assets = make_note_assets(usdc_faucet.id(), *offered_usdc)?;
        let swap_note = create_pswap_note(alice.id(), note_assets, storage_items, pswap_tag);
        builder.add_output_note(RawOutputNote::Full(swap_note.clone()));

        let mock_chain = builder.build()?;

        let mut note_args_map = BTreeMap::new();
        note_args_map.insert(swap_note.id(), make_note_args(*fill_eth, 0));

        let p2id_note = create_expected_pswap_p2id_note(
            &swap_note,
            bob.id(),
            alice.id(),
            0,
            *fill_eth,
            eth_faucet.id(),
            compute_p2id_tag_for_local_account(alice.id()),
        )?;

        let mut expected_notes = vec![RawOutputNote::Full(p2id_note)];
        if remaining_requested > 0 {
            let remainder = create_expected_pswap_remainder_note(
                &swap_note,
                bob.id(),
                alice.id(),
                remaining_offered,
                remaining_requested,
                offered_out,
                0,
                usdc_faucet.id(),
                eth_faucet.id(),
                pswap_tag,
                pswap_tag_felt,
                p2id_tag_felt,
            )?;
            expected_notes.push(RawOutputNote::Full(remainder));
        }

        let tx_context = mock_chain
            .build_tx_context(bob.id(), &[swap_note.id()], &[])?
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

        assert_eq!(
            offered_out + remaining_offered,
            *offered_usdc,
            "Case {}: conservation",
            i + 1
        );
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
        let mut current_swap_count = 0u64;

        // Track serial for remainder chain
        use miden_protocol::crypto::rand::{FeltRng, RpoRandomCoin};
        let mut rng = RpoRandomCoin::new(Word::default());
        let mut current_serial = rng.draw_word();

        for (fill_idx, fill_amount) in fills.iter().enumerate() {
            let offered_out =
                calculate_output_amount(current_offered, current_requested, *fill_amount);
            let remaining_offered = current_offered - offered_out;
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

            let pswap_tag = NoteTag::new(0xC0000000);
            let pswap_tag_felt = Felt::new(u32::from(pswap_tag) as u64);
            let p2id_tag_felt = compute_p2id_tag_felt(alice.id());

            let storage_items = build_pswap_storage(
                eth_faucet.id(),
                current_requested,
                pswap_tag_felt,
                p2id_tag_felt,
                current_swap_count,
                alice.id(),
            );
            let note_assets = make_note_assets(usdc_faucet.id(), current_offered)?;

            // Create note with the correct serial for this chain position
            let note_storage = NoteStorage::new(storage_items)?;
            let recipient =
                NoteRecipient::new(current_serial, PswapNote::script(), note_storage);
            let metadata =
                NoteMetadata::new(alice.id(), NoteType::Public).with_tag(pswap_tag);
            let swap_note = Note::new(note_assets, metadata, recipient);

            builder.add_output_note(RawOutputNote::Full(swap_note.clone()));
            let mock_chain = builder.build()?;

            let mut note_args_map = BTreeMap::new();
            note_args_map.insert(swap_note.id(), make_note_args(*fill_amount, 0));

            let p2id_note = create_expected_pswap_p2id_note(
                &swap_note,
                bob.id(),
                alice.id(),
                current_swap_count,
                *fill_amount,
                eth_faucet.id(),
                compute_p2id_tag_for_local_account(alice.id()),
            )?;

            let mut expected_notes = vec![RawOutputNote::Full(p2id_note)];
            if remaining_requested > 0 {
                let remainder = create_expected_pswap_remainder_note(
                    &swap_note,
                    bob.id(),
                    alice.id(),
                    remaining_offered,
                    remaining_requested,
                    offered_out,
                    current_swap_count,
                    usdc_faucet.id(),
                    eth_faucet.id(),
                    pswap_tag,
                    pswap_tag_felt,
                    p2id_tag_felt,
                )?;
                expected_notes.push(RawOutputNote::Full(remainder));
            }

            let tx_context = mock_chain
                .build_tx_context(bob.id(), &[swap_note.id()], &[])?
                .extend_expected_output_notes(expected_notes)
                .extend_note_args(note_args_map)
                .build()?;

            let executed_tx = tx_context.execute().await.map_err(|e| {
                anyhow::anyhow!(
                    "Chain {} fill {} failed: {} (offered={}, requested={}, fill={})",
                    chain_idx + 1,
                    fill_idx + 1,
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
                fill_idx + 1
            );

            let vault_delta = executed_tx.account_delta().vault();
            let added: Vec<Asset> = vault_delta.added_assets().collect();
            assert_eq!(
                added.len(),
                1,
                "Chain {} fill {}",
                chain_idx + 1,
                fill_idx + 1
            );
            if let Asset::Fungible(f) = &added[0] {
                assert_eq!(
                    f.amount(),
                    offered_out,
                    "Chain {} fill {}: Bob should get {} USDC",
                    chain_idx + 1,
                    fill_idx + 1,
                    offered_out
                );
            }

            // Update state for next fill
            total_usdc_to_bob += offered_out;
            total_eth_from_bob += fill_amount;
            current_offered = remaining_offered;
            current_requested = remaining_requested;
            current_swap_count += 1;
            // Remainder serial: [0] + 1 (matching MASM LE orientation)
            current_serial = Word::from([
                Felt::new(current_serial[0].as_canonical_u64() + 1),
                current_serial[1],
                current_serial[2],
                current_serial[3],
            ]);
        }

        // Verify conservation
        let total_fills: u64 = fills.iter().sum();
        assert_eq!(
            total_eth_from_bob, total_fills,
            "Chain {}: ETH conservation",
            chain_idx + 1
        );
        assert_eq!(
            total_usdc_to_bob + current_offered,
            *initial_offered,
            "Chain {}: USDC conservation",
            chain_idx + 1
        );
    }

    Ok(())
}

/// Test that PswapNote::create and PswapNote::create_output_notes produce correct results
#[test]
fn compare_pswap_create_output_notes_vs_test_helper() {
    use miden_protocol::crypto::rand::{FeltRng, RpoRandomCoin};

    let mut builder = MockChain::builder();
    let usdc_faucet = builder
        .add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))
        .unwrap();
    let eth_faucet = builder
        .add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))
        .unwrap();
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

    // Create swap note using PswapNote::create
    let mut rng = RpoRandomCoin::new(Word::default());
    let swap_note_lib = PswapNote::create(
        alice.id(),
        Asset::Fungible(FungibleAsset::new(usdc_faucet.id(), 50).unwrap()),
        Asset::Fungible(FungibleAsset::new(eth_faucet.id(), 25).unwrap()),
        NoteType::Public,
        NoteAttachment::default(),
        &mut rng,
    )
    .unwrap();

    // Create output notes using library
    let pswap = PswapNote::try_from(&swap_note_lib).unwrap();
    let (lib_p2id, _) = pswap.execute(bob.id(), 25, 0).unwrap();

    // Create same swap note using test helper (same serial)
    let (_pswap_tag, pswap_tag_felt) = make_pswap_tag();
    let p2id_tag_felt = compute_p2id_tag_felt(alice.id());
    let storage_items = build_pswap_storage(
        eth_faucet.id(),
        25,
        pswap_tag_felt,
        p2id_tag_felt,
        0,
        alice.id(),
    );
    let note_assets = make_note_assets(usdc_faucet.id(), 50).unwrap();

    // Use the SAME serial as the library note
    let test_serial = swap_note_lib.recipient().serial_num();
    let test_storage = NoteStorage::new(storage_items).unwrap();
    let test_recipient = NoteRecipient::new(test_serial, PswapNote::script(), test_storage);
    let test_metadata =
        NoteMetadata::new(alice.id(), NoteType::Public).with_tag(NoteTag::new(0xC0000000));
    let swap_note_test = Note::new(note_assets, test_metadata, test_recipient);

    // Create expected P2ID using test helper
    let test_p2id = create_expected_pswap_p2id_note(
        &swap_note_test,
        bob.id(),
        alice.id(),
        0,
        25,
        eth_faucet.id(),
        compute_p2id_tag_for_local_account(alice.id()),
    )
    .unwrap();

    // Compare components
    assert_eq!(
        lib_p2id.recipient().serial_num(),
        test_p2id.recipient().serial_num(),
        "Serial mismatch!"
    );
    assert_eq!(
        lib_p2id.recipient().script().root(),
        test_p2id.recipient().script().root(),
        "Script root mismatch!"
    );
    assert_eq!(
        lib_p2id.recipient().digest(),
        test_p2id.recipient().digest(),
        "Recipient digest mismatch!"
    );
    assert_eq!(
        lib_p2id.metadata().tag(),
        test_p2id.metadata().tag(),
        "Tag mismatch!"
    );
    assert_eq!(
        lib_p2id.metadata().sender(),
        test_p2id.metadata().sender(),
        "Sender mismatch!"
    );
    assert_eq!(
        lib_p2id.metadata().note_type(),
        test_p2id.metadata().note_type(),
        "Note type mismatch!"
    );
    assert_eq!(lib_p2id.id(), test_p2id.id(), "NOTE ID MISMATCH!");
}

/// Test that PswapNote::parse_inputs roundtrips correctly
#[test]
fn pswap_parse_inputs_roundtrip() {
    use miden_protocol::crypto::rand::{FeltRng, RpoRandomCoin};

    let mut builder = MockChain::builder();
    let usdc_faucet = builder
        .add_existing_basic_faucet(BASIC_AUTH, "USDC", 1000, Some(150))
        .unwrap();
    let eth_faucet = builder
        .add_existing_basic_faucet(BASIC_AUTH, "ETH", 1000, Some(50))
        .unwrap();
    let alice = builder
        .add_existing_wallet_with_assets(
            BASIC_AUTH,
            [FungibleAsset::new(usdc_faucet.id(), 50).unwrap().into()],
        )
        .unwrap();

    let mut rng = RpoRandomCoin::new(Word::default());
    let swap_note = PswapNote::create(
        alice.id(),
        Asset::Fungible(FungibleAsset::new(usdc_faucet.id(), 50).unwrap()),
        Asset::Fungible(FungibleAsset::new(eth_faucet.id(), 25).unwrap()),
        NoteType::Public,
        NoteAttachment::default(),
        &mut rng,
    )
    .unwrap();

    let storage = swap_note.recipient().storage();
    let items = storage.items();

    let parsed = PswapNoteStorage::try_from(items).unwrap();

    assert_eq!(parsed.creator_account_id(), alice.id(), "Creator ID roundtrip failed!");
    assert_eq!(parsed.swap_count(), 0, "Swap count should be 0");

    // Verify requested amount from value word
    assert_eq!(parsed.requested_amount(), 25, "Requested amount should be 25");
}
