extern crate alloc;

use miden_agglayer::{EthAddressFormat, b2agg_script, bridge_out_component};
use miden_protocol::account::{
    Account,
    AccountId,
    AccountIdVersion,
    AccountStorageMode,
    AccountType,
    StorageSlot,
    StorageSlotName,
};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::{
    Note,
    NoteAssets,
    NoteMetadata,
    NoteRecipient,
    NoteScript,
    NoteStorage,
    NoteTag,
    NoteType,
};
use miden_protocol::transaction::OutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::account::faucets::NetworkFungibleFaucet;
use miden_standards::note::StandardNote;
use miden_testing::{AccountState, Auth, MockChain};
use rand::Rng;

/// Tests the B2AGG (Bridge to AggLayer) note script with bridge_out account component.
///
/// This test flow:
/// 1. Creates a network faucet to provide assets
/// 2. Creates a bridge account with the bridge_out component (using network storage)
/// 3. Creates a B2AGG note with assets from the network faucet
/// 4. Executes the B2AGG note consumption via network transaction
/// 5. Consumes the BURN note
#[tokio::test]
async fn test_bridge_out_consumes_b2agg_note() -> anyhow::Result<()> {
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

    // Create a bridge account with the bridge_out component using network (public) storage
    // Add a storage map for the bridge component to store MMR frontier data
    let storage_slot_name = StorageSlotName::new("miden::agglayer::let").unwrap();
    let storage_slots = vec![StorageSlot::with_empty_map(storage_slot_name)];
    let bridge_component = bridge_out_component(storage_slots);
    let account_builder = Account::builder(builder.rng_mut().random())
        .storage_mode(AccountStorageMode::Public)
        .with_component(bridge_component);
    let mut bridge_account =
        builder.add_account_from_builder(Auth::IncrNonce, account_builder, AccountState::Exists)?;

    // CREATE B2AGG NOTE WITH ASSETS
    // --------------------------------------------------------------------------------------------

    let amount = Felt::new(100);
    let bridge_asset: Asset = FungibleAsset::new(faucet.id(), amount.into()).unwrap().into();
    let tag = NoteTag::new(0);
    let note_type = NoteType::Public; // Use Public note type for network transaction

    // Get the B2AGG note script
    let b2agg_script = b2agg_script();

    // Create note storage with destination network and address
    // destination_network: u32 (AggLayer-assigned network ID)
    // destination_address: 20 bytes (Ethereum address) split into 5 u32 values
    let destination_network = Felt::new(1); // Example network ID
    let destination_address = "0x1234567890abcdef1122334455667788990011aa";
    let eth_address =
        EthAddressFormat::from_hex(destination_address).expect("Valid Ethereum address");
    let address_felts = eth_address.to_elements().to_vec();

    // Combine network ID and address felts into note storage (6 felts total)
    let mut input_felts = vec![destination_network];
    input_felts.extend(address_felts);

    let inputs = NoteStorage::new(input_felts.clone())?;

    // Create the B2AGG note with assets from the faucet
    let b2agg_note_metadata = NoteMetadata::new(faucet.id(), note_type, tag);
    let b2agg_note_assets = NoteAssets::new(vec![bridge_asset])?;
    let serial_num = Word::from([1, 2, 3, 4u32]);
    let b2agg_note_script = NoteScript::new(b2agg_script);
    let b2agg_note_recipient = NoteRecipient::new(serial_num, b2agg_note_script, inputs);
    let b2agg_note = Note::new(b2agg_note_assets, b2agg_note_metadata, b2agg_note_recipient);

    // Add the B2AGG note to the mock chain
    builder.add_output_note(OutputNote::Full(b2agg_note.clone()));
    let mut mock_chain = builder.build()?;

    // Get BURN note script to add to the transaction context
    let burn_note_script: NoteScript = StandardNote::BURN.script();

    // EXECUTE B2AGG NOTE AGAINST BRIDGE ACCOUNT (NETWORK TRANSACTION)
    // --------------------------------------------------------------------------------------------
    let tx_context = mock_chain
        .build_tx_context(bridge_account.id(), &[b2agg_note.id()], &[])?
        .add_note_script(burn_note_script.clone())
        .build()?;
    let executed_transaction = tx_context.execute().await?;

    // VERIFY PUBLIC BURN NOTE WAS CREATED
    // --------------------------------------------------------------------------------------------
    // The bridge_out component should create a PUBLIC BURN note addressed to the faucet
    assert_eq!(
        executed_transaction.output_notes().num_notes(),
        1,
        "Expected one BURN note to be created"
    );

    let output_note = executed_transaction.output_notes().get_note(0);

    // Extract the full note from the OutputNote enum
    let burn_note = match output_note {
        OutputNote::Full(note) => note,
        _ => panic!("Expected OutputNote::Full variant for BURN note"),
    };

    // Verify the BURN note is public
    assert_eq!(burn_note.metadata().note_type(), NoteType::Public, "BURN note should be public");

    // Verify the BURN note contains the bridged asset
    let expected_asset = FungibleAsset::new(faucet.id(), amount.into())?;
    let expected_asset_obj = Asset::from(expected_asset);
    assert!(
        burn_note.assets().iter().any(|asset| asset == &expected_asset_obj),
        "BURN note should contain the bridged asset"
    );

    assert_eq!(
        burn_note.metadata().tag(),
        NoteTag::with_account_target(faucet.id()),
        "BURN note should have the correct tag"
    );

    // Verify the BURN note uses the correct script
    assert_eq!(
        burn_note.recipient().script().root(),
        burn_note_script.root(),
        "BURN note should use the BURN script"
    );

    // Apply the delta to the bridge account
    bridge_account.apply_delta(executed_transaction.account_delta())?;

    // Apply the transaction to the mock chain
    mock_chain.add_pending_executed_transaction(&executed_transaction)?;
    mock_chain.prove_next_block()?;

    // CONSUME THE BURN NOTE WITH THE NETWORK FAUCET
    // --------------------------------------------------------------------------------------------
    // Check the initial token issuance before burning
    let initial_token_supply = NetworkFungibleFaucet::try_from(&faucet)?.token_supply();
    assert_eq!(initial_token_supply, Felt::new(100), "Initial issuance should be 100");

    // Execute the BURN note against the network faucet
    let burn_tx_context =
        mock_chain.build_tx_context(faucet.id(), &[burn_note.id()], &[])?.build()?;
    let burn_executed_transaction = burn_tx_context.execute().await?;

    // Verify the burn transaction was successful - no output notes should be created
    assert_eq!(
        burn_executed_transaction.output_notes().num_notes(),
        0,
        "Burn transaction should not create output notes"
    );

    // Apply the delta to the faucet account and verify the token issuance decreased
    let mut faucet = faucet;
    faucet.apply_delta(burn_executed_transaction.account_delta())?;

    let final_token_supply = NetworkFungibleFaucet::try_from(&faucet)?.token_supply();
    assert_eq!(
        final_token_supply,
        Felt::new(initial_token_supply.as_int() - amount.as_int()),
        "Token issuance should decrease by the burned amount"
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
async fn test_b2agg_note_reclaim_scenario() -> anyhow::Result<()> {
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

    // Create a user account that will create and consume the B2AGG note
    let mut user_account = builder.add_existing_wallet(Auth::BasicAuth)?;

    // CREATE B2AGG NOTE WITH USER ACCOUNT AS SENDER
    // --------------------------------------------------------------------------------------------

    let amount = Felt::new(50);
    let bridge_asset: Asset = FungibleAsset::new(faucet.id(), amount.into()).unwrap().into();
    let tag = NoteTag::new(0);
    let note_type = NoteType::Public;

    // Get the B2AGG note script
    let b2agg_script = b2agg_script();

    // Create note storage with destination network and address
    let destination_network = Felt::new(1);
    let destination_address = "0x1234567890abcdef1122334455667788990011aa";
    let eth_address =
        EthAddressFormat::from_hex(destination_address).expect("Valid Ethereum address");
    let address_felts = eth_address.to_elements().to_vec();

    // Combine network ID and address felts into note storage (6 felts total)
    let mut input_felts = vec![destination_network];
    input_felts.extend(address_felts);

    let inputs = NoteStorage::new(input_felts.clone())?;

    // Create the B2AGG note with the USER ACCOUNT as the sender
    // This is the key difference - the note sender will be the same as the consuming account
    let b2agg_note_metadata = NoteMetadata::new(user_account.id(), note_type, tag);
    let b2agg_note_assets = NoteAssets::new(vec![bridge_asset])?;
    let serial_num = Word::from([1, 2, 3, 4u32]);
    let b2agg_note_script = NoteScript::new(b2agg_script);
    let b2agg_note_recipient = NoteRecipient::new(serial_num, b2agg_note_script, inputs);
    let b2agg_note = Note::new(b2agg_note_assets, b2agg_note_metadata, b2agg_note_recipient);

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
