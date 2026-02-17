extern crate alloc;

use miden_agglayer::errors::ERR_B2AGG_TARGET_ACCOUNT_MISMATCH;
use miden_agglayer::{B2AggNote, EthAddressFormat, ExitRoot, create_existing_bridge_account};
use miden_crypto::rand::FeltRng;
use miden_protocol::Felt;
use miden_protocol::account::{
    Account,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::NoteAssets;
use miden_protocol::transaction::OutputNote;
use miden_standards::account::faucets::TokenMetadata;
use miden_testing::{Auth, MockChain, assert_transaction_executor_error};
use miden_tx::utils::hex_to_bytes;

use super::test_utils::SOLIDITY_MMR_FRONTIER_VECTORS;

/// Reads the Local Exit Root (double-word) from the bridge account's storage.
///
/// The Local Exit Root is stored in two dedicated value slots:
/// - `"miden::agglayer::let::root_lo"` — low word of the root
/// - `"miden::agglayer::let::root_hi"` — high word of the root
///
/// Returns the 256-bit root as 8 `Felt`s: first the 4 elements of `root_lo` (in
/// reverse of their storage order), followed by the 4 elements of `root_hi` (also in
/// reverse of their storage order). For an empty/uninitialized tree, all elements are
/// zeros.
fn read_local_exit_root(account: &Account) -> Vec<Felt> {
    let root_lo_slot =
        StorageSlotName::new("miden::agglayer::let::root_lo").expect("slot name should be valid");
    let root_hi_slot =
        StorageSlotName::new("miden::agglayer::let::root_hi").expect("slot name should be valid");

    let root_lo = account
        .storage()
        .get_item(&root_lo_slot)
        .expect("should be able to read LET root lo");
    let root_hi = account
        .storage()
        .get_item(&root_hi_slot)
        .expect("should be able to read LET root hi");

    let mut root = Vec::with_capacity(8);
    root.extend(root_lo.to_vec().into_iter().rev());
    root.extend(root_hi.to_vec().into_iter().rev());
    root
}

fn read_let_num_leaves(account: &Account) -> u64 {
    let num_leaves_slot = StorageSlotName::new("miden::agglayer::let::num_leaves")
        .expect("slot name should be valid");
    let value = account
        .storage()
        .get_item(&num_leaves_slot)
        .expect("should be able to read LET num leaves");
    value.to_vec()[0].as_int()
}

/// Tests that 32 sequential B2AGG note consumptions match all 32 Solidity MMR roots.
///
/// This test flow:
/// 1. Creates a network faucet to provide assets
/// 2. Creates a bridge account with the bridge_out component (using network storage)
/// 3. Creates a B2AGG note with assets from the network faucet
/// 4. Executes the B2AGG note consumption via network transaction
/// 5. Consumes the BURN note
#[tokio::test]
async fn bridge_out_consecutive() -> anyhow::Result<()> {
    let vectors = &*SOLIDITY_MMR_FRONTIER_VECTORS;
    let note_count = 32usize;
    assert_eq!(vectors.amounts.len(), note_count, "amount vectors should contain 32 entries");
    assert_eq!(vectors.roots.len(), note_count, "root vectors should contain 32 entries");
    assert_eq!(
        vectors.destination_networks.len(),
        note_count,
        "destination network vectors should contain 32 entries"
    );
    assert_eq!(
        vectors.destination_addresses.len(),
        note_count,
        "destination address vectors should contain 32 entries"
    );

    let mut builder = MockChain::builder();
    let faucet_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    // We burn all 32 produced burn notes at the end; initial supply must cover their total amount.
    let faucet = builder.add_existing_network_faucet(
        "AGG",
        10_000,
        faucet_owner_account_id,
        Some(10_000),
    )?;

    let mut bridge_account = create_existing_bridge_account(builder.rng_mut().draw_word());
    builder.add_account(bridge_account.clone())?;

    let mut notes = Vec::with_capacity(note_count);
    let mut expected_amounts = Vec::with_capacity(note_count);
    for i in 0..note_count {
        let amount: u64 = vectors.amounts[i].parse().expect("valid amount decimal string");
        expected_amounts.push(amount);
        let destination_network = vectors.destination_networks[i];
        let eth_address = EthAddressFormat::from_hex(&vectors.destination_addresses[i])
            .expect("valid destination address");

        let bridge_asset: Asset = FungibleAsset::new(faucet.id(), amount).unwrap().into();
        let note = B2AggNote::create(
            destination_network,
            eth_address,
            NoteAssets::new(vec![bridge_asset])?,
            bridge_account.id(),
            faucet.id(),
            builder.rng_mut(),
        )?;
        builder.add_output_note(OutputNote::Full(note.clone()));
        notes.push(note);
    }

    let mut mock_chain = builder.build()?;
    let mut burn_note_ids = Vec::with_capacity(note_count);

    for (i, note) in notes.iter().enumerate() {
        let executed_tx = mock_chain
            .build_tx_context(bridge_account.id(), &[note.id()], &[])?
            .build()?
            .execute()
            .await?;

        assert_eq!(
            executed_tx.output_notes().num_notes(),
            1,
            "Expected one BURN note after consume #{}",
            i + 1
        );
        let burn_note = match executed_tx.output_notes().get_note(0) {
            OutputNote::Full(note) => note,
            _ => panic!("Expected OutputNote::Full variant for BURN note"),
        };
        burn_note_ids.push(burn_note.id());

        let expected_asset = Asset::from(FungibleAsset::new(faucet.id(), expected_amounts[i])?);
        assert!(
            burn_note.assets().iter().any(|asset| asset == &expected_asset),
            "BURN note after consume #{} should contain the bridged asset",
            i + 1
        );

        bridge_account.apply_delta(executed_tx.account_delta())?;
        assert_eq!(
            read_let_num_leaves(&bridge_account),
            (i + 1) as u64,
            "LET leaf count should match consumed notes"
        );

        let expected_ler =
            ExitRoot::new(hex_to_bytes(&vectors.roots[i]).expect("valid root hex")).to_elements();
        assert_eq!(
            read_local_exit_root(&bridge_account),
            expected_ler,
            "Local Exit Root after {} leaves should match the Solidity-generated root",
            i + 1
        );

        mock_chain.add_pending_executed_transaction(&executed_tx)?;
        mock_chain.prove_next_block()?;
    }

    let initial_token_supply = TokenMetadata::try_from(faucet.storage())?.token_supply();
    let total_burned: u64 = expected_amounts.iter().sum();

    let mut faucet = faucet;
    for burn_note_id in burn_note_ids {
        let burn_executed_tx = mock_chain
            .build_tx_context(faucet.id(), &[burn_note_id], &[])?
            .build()?
            .execute()
            .await?;
        assert_eq!(
            burn_executed_tx.output_notes().num_notes(),
            0,
            "Burn transaction should not create output notes"
        );
        faucet.apply_delta(burn_executed_tx.account_delta())?;
        mock_chain.add_pending_executed_transaction(&burn_executed_tx)?;
        mock_chain.prove_next_block()?;
    }

    let final_token_supply = TokenMetadata::try_from(faucet.storage())?.token_supply();
    assert_eq!(
        final_token_supply,
        Felt::new(initial_token_supply.as_int() - total_burned),
        "Token supply should decrease by the sum of 32 bridged amounts"
    );

    Ok(())
}

/// Tests the B2AGG (Bridge to AggLayer) note script reclaim functionality.
///
/// This test covers the "reclaim" branch where the note creator consumes their own B2AGG note.
/// In this scenario, the assets are simply added back to the account without creating a BURN note.
///
/// Test flow:
/// 1. Creates a network faucet to provide assets
/// 2. Creates a user account that will create and consume the B2AGG note
/// 3. Creates a B2AGG note with the user account as sender
/// 4. The same user account consumes the B2AGG note (triggering reclaim branch)
/// 5. Verifies that assets are added back to the account and no BURN note is created
#[tokio::test]
async fn b2agg_note_reclaim_scenario() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Create a network faucet owner account
    let faucet_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    // Create a network faucet to provide assets for the B2AGG note
    let faucet =
        builder.add_existing_network_faucet("AGG", 1000, faucet_owner_account_id, Some(100))?;

    // Create a bridge account (includes a `bridge_out` component tested here)
    let bridge_account = create_existing_bridge_account(builder.rng_mut().draw_word());
    builder.add_account(bridge_account.clone())?;

    // Create a user account that will create and consume the B2AGG note
    let mut user_account = builder.add_existing_wallet(Auth::BasicAuth)?;

    // CREATE B2AGG NOTE WITH USER ACCOUNT AS SENDER
    // --------------------------------------------------------------------------------------------

    let amount = Felt::new(50);
    let bridge_asset: Asset = FungibleAsset::new(faucet.id(), amount.into()).unwrap().into();

    // Create note storage with destination network and address
    let destination_network = 1u32;
    let destination_address = "0x1234567890abcdef1122334455667788990011aa";
    let eth_address =
        EthAddressFormat::from_hex(destination_address).expect("Valid Ethereum address");

    let assets = NoteAssets::new(vec![bridge_asset])?;

    // Create the B2AGG note with the USER ACCOUNT as the sender
    // This is the key difference - the note sender will be the same as the consuming account
    let b2agg_note = B2AggNote::create(
        destination_network,
        eth_address,
        assets,
        bridge_account.id(),
        user_account.id(),
        builder.rng_mut(),
    )?;

    // Add the B2AGG note to the mock chain
    builder.add_output_note(OutputNote::Full(b2agg_note.clone()));
    let mut mock_chain = builder.build()?;

    // Store the initial asset balance of the user account
    let initial_balance = user_account.vault().get_balance(faucet.id()).unwrap_or(0u64);

    // EXECUTE B2AGG NOTE WITH THE SAME USER ACCOUNT (RECLAIM SCENARIO)
    // --------------------------------------------------------------------------------------------
    let tx_context = mock_chain
        .build_tx_context(user_account.id(), &[b2agg_note.id()], &[])?
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    // VERIFY NO BURN NOTE WAS CREATED (RECLAIM BRANCH)
    // --------------------------------------------------------------------------------------------
    // In the reclaim scenario, no BURN note should be created
    assert_eq!(
        executed_transaction.output_notes().num_notes(),
        0,
        "Reclaim scenario should not create any output notes"
    );

    // Apply the delta to the user account
    user_account.apply_delta(executed_transaction.account_delta())?;

    // VERIFY ASSETS WERE ADDED BACK TO THE ACCOUNT
    // --------------------------------------------------------------------------------------------
    let final_balance = user_account.vault().get_balance(faucet.id()).unwrap_or(0u64);
    let expected_balance = initial_balance + amount.as_int();

    assert_eq!(
        final_balance, expected_balance,
        "User account should have received the assets back from the B2AGG note"
    );

    // Apply the transaction to the mock chain
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    Ok(())
}

/// Tests that a non-target account cannot consume a B2AGG note (non-reclaim branch).
///
/// This test covers the security check in the B2AGG note script that ensures only the
/// designated target account (specified in the note attachment) can consume the note
/// when not in reclaim mode.
///
/// Test flow:
/// 1. Creates a network faucet to provide assets
/// 2. Creates a bridge account as the designated target for the B2AGG note
/// 3. Creates a user account as the sender (creator) of the B2AGG note
/// 4. Creates a "malicious" account with a bridge interface
/// 5. Attempts to consume the B2AGG note with the malicious account
/// 6. Verifies that the transaction fails with ERR_B2AGG_TARGET_ACCOUNT_MISMATCH
#[tokio::test]
async fn b2agg_note_non_target_account_cannot_consume() -> anyhow::Result<()> {
    let mut builder = MockChain::builder();

    // Create a network faucet owner account
    let faucet_owner_account_id = AccountId::dummy(
        [1; 15],
        AccountIdVersion::Version0,
        AccountType::RegularAccountImmutableCode,
        AccountStorageMode::Private,
    );

    // Create a network faucet to provide assets for the B2AGG note
    let faucet =
        builder.add_existing_network_faucet("AGG", 1000, faucet_owner_account_id, Some(100))?;

    // Create a bridge account as the designated TARGET for the B2AGG note
    let bridge_account = create_existing_bridge_account(builder.rng_mut().draw_word());
    builder.add_account(bridge_account.clone())?;

    // Create a user account as the SENDER of the B2AGG note
    let sender_account = builder.add_existing_wallet(Auth::BasicAuth)?;

    // Create a "malicious" account with a bridge interface
    let malicious_account = create_existing_bridge_account(builder.rng_mut().draw_word());
    builder.add_account(malicious_account.clone())?;

    // CREATE B2AGG NOTE
    // --------------------------------------------------------------------------------------------

    let amount = Felt::new(50);
    let bridge_asset: Asset = FungibleAsset::new(faucet.id(), amount.into()).unwrap().into();

    // Create note storage with destination network and address
    let destination_network = 1u32;
    let destination_address = "0x1234567890abcdef1122334455667788990011aa";
    let eth_address =
        EthAddressFormat::from_hex(destination_address).expect("Valid Ethereum address");

    let assets = NoteAssets::new(vec![bridge_asset])?;

    // Create the B2AGG note
    let b2agg_note = B2AggNote::create(
        destination_network,
        eth_address,
        assets,
        bridge_account.id(),
        sender_account.id(),
        builder.rng_mut(),
    )?;

    // Add the B2AGG note to the mock chain
    builder.add_output_note(OutputNote::Full(b2agg_note.clone()));
    let mock_chain = builder.build()?;

    // ATTEMPT TO CONSUME B2AGG NOTE WITH MALICIOUS ACCOUNT (SHOULD FAIL)
    // --------------------------------------------------------------------------------------------
    let result = mock_chain
        .build_tx_context(malicious_account.id(), &[], &[b2agg_note])?
        .build()?
        .execute()
        .await;

    assert_transaction_executor_error!(result, ERR_B2AGG_TARGET_ACCOUNT_MISMATCH);

    Ok(())
}
